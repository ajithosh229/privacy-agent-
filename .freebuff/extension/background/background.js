/**
 * Sentinel background orchestrator (MV3 service worker / FF background page).
 *
 * Turn pipeline:
 *   capture tab → extract DOM state + text-PII rects → vision host detects &
 *   redacts (local models) → build placeholder-only payload → privacy gate →
 *   server (TASK_START/SCREEN_STATE) → execute returned actions locally →
 *   repeat until done/fail/maxSteps.
 *
 * Secrets (passwords/OTP/CVV) never leave the device: the server sees only
 * [PASSWORD_1]-style placeholders; the real values are injected from the
 * local vault at the last moment, directly into the page's inputs.
 */
import { PROTOCOL_VERSION, MSG_TYPES, DEFAULT_SETTINGS, MSG, TAB_MSG, TURN_TIMEOUT_MS, MAX_META_CHARS, SECRET_ROLES } from '../shared/protocol.js';
import { looksLikePII } from '../shared/pii-patterns.js';
import { hasOffscreen, isFirefox } from './env.js';
import { sendVisionMessage, warmVisionHost, ensureVisionHost } from './offscreen-manager.js';
import { initVisionHost } from './vision-host.js';

initVisionHost();

const settings = { ...DEFAULT_SETTINGS };
let vault = {};          // { "[PASSWORD_1]": "real secret" } — local only
let task = null;         // active task state
let lastPayload = null;  // for the popup inspector

/* ---------------- settings & storage ---------------- */

chrome.storage?.local.get(['settings', 'vault']).then(({ settings: s, vault: v }) => {
  if (s) Object.assign(settings, s);
  if (v) vault = v;
});
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg?.type === 'SETTINGS_SET') {
    Object.assign(settings, msg.settings);
    chrome.storage.local.set({ settings });
    sendResponse({ ok: true, settings });
  } else if (msg?.type === 'SETTINGS_GET') {
    sendResponse({ ok: true, settings });
  } else if (msg?.type === MSG.SET_VAULT) {
    vault = msg.vault || {};
    chrome.storage.local.set({ vault });
    sendResponse({ ok: true, count: Object.keys(vault).length });
  } else if (msg?.type === MSG.GET_VAULT) {
    sendResponse({ ok: true, vault });
  }
  return false; // synchronous
});

/* ---------------- popup messaging ---------------- */

function emitState() {
  const snapshot = task ? { ...task, vaultKeys: Object.keys(vault) } : null;
  chrome.runtime.sendMessage({ type: MSG.TASK_STATE, task: snapshot }).catch(() => {});
}

function toast(tabId, message, kind = 'info') {
  chrome.tabs.sendMessage(tabId, { type: 'SENTINEL_TOAST', message, kind }).catch(() => {});
}

/* ---------------- helpers ---------------- */

async function captureTab(tabId) {
  return new Promise((resolve, reject) => {
    chrome.tabs.captureVisibleTab(tabId, { format: 'png' }, dataUrl => {
      if (chrome.runtime.lastError) reject(new Error(chrome.runtime.lastError.message));
      else resolve(dataUrl);
    });
  });
}

function tabMsg(tabId, payload) {
  return new Promise((resolve, reject) => {
    chrome.tabs.sendMessage(tabId, payload, res => {
      if (chrome.runtime.lastError) reject(new Error(chrome.runtime.lastError.message));
      else resolve(res);
    });
  });
}

async function serverCall(route, body) {
  const url = settings.serverUrl.replace(/\/$/, '') + route;
  const ctrl = new AbortController();
  const to = setTimeout(() => ctrl.abort(), TURN_TIMEOUT_MS);
  try {
    const res = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
      signal: ctrl.signal,
    });
    if (!res.ok) throw new Error(`server ${res.status}`);
    return await res.json();
  } finally { clearTimeout(to); }
}

/** Defense in depth: re-verify metadata client-side before transmit. */
function privacyGate(payload) {
  const metaStr = JSON.stringify(payload.meta) + ' ' + (payload.prompt || '');
  if (looksLikePII(metaStr)) {
    throw new Error('Privacy gate blocked transmission: raw PII detected in metadata (should never happen).');
  }
  return true;
}

function injectSecrets(actions, phMap) {
  // Swap [PASSWORD_1] → real value, locally, at the last moment. Non-secret
  // placeholders ([EMAIL_1], [PERSON_1]…) are resolved by the content script
  // from phMap — the value never crosses a network boundary either way.
  return actions.map(a => {
    if ((a.action === 'type' || a.action === 'set') && typeof a.value === 'string' && /^\[[A-Z_]+_\d+\]$/.test(a.value)) {
      const kind = a.value.slice(1, a.value.indexOf('_'));
      if (SECRET_ROLES.some(r => r.toUpperCase().includes(kind))) {
        const real = vault[a.value];
        if (real !== undefined) return { ...a, value: real };
        return { ...a, _needsSecret: a.value };
      }
      if (phMap[a.value] !== undefined) return { ...a, value: phMap[a.value] };
    }
    return a;
  });
}

/* ---------------- main task loop ---------------- */

async function runTask(tabId, prompt) {
  task = {
    tabId, prompt, status: 'running', step: 0, maxSteps: 8,
    log: [], timings: [], lastActions: [], startedAt: Date.now(),
    device: null, redactions: 0, transportBlocked: false,
  };
  emitState();
  await ensureVisionHost();

  for (let step = 1; step <= task.maxSteps; step++) {
    if (task.status !== 'running') break;
    task.step = step;
    const turn = { step, t0: Date.now() };

    try {
      // 1. extract (state + text pii) & capture
      const [{ state, piiRects }, shot] = await Promise.all([
        tabMsg(tabId, { type: TAB_MSG.EXTRACT_STATE }),
        captureTab(tabId),
      ]);
      turn.tCapture = Date.now();

      // 2. local vision: NER fusion + placeholder assignment + redaction
      const domTexts = [];
      for (const el of state.elements) {
        if (el.txt) domTexts.push({ ref: el.ref, rect: el.rect, text: el.txt });
      }
      const vision = await sendVisionMessage({
        type: 'VISION_PROCESS',
        imageDataUrl: shot,
        textHits: piiRects,
        domTexts,
        maskMode: settings.maskMode,
      });
      task.device = vision.device;
      turn.tVision = Date.now();
      turn.redactions = vision.rects.length;
      task.redactions += vision.rects.length;
      // Local placeholder→value map (from the redaction pass) — stays in the
      // browser; used by the executor to type real values for non-secret
      // placeholders and by the vault path for secrets.
      task.phMap = Object.fromEntries(vision.rects.filter(r => r.text).map(r => [r.ph, r.text]));

      // 3. overlays for the user (shows exactly what got redacted)
      if (settings.showOverlays) {
        tabMsg(tabId, { type: TAB_MSG.APPLY_OVERLAY, rects: vision.rects, mode: settings.maskMode }).catch(() => {});
      }

      // 4. build payload — placeholders only
      lastPayload = {
        protocol: PROTOCOL_VERSION,
        type: step === 1 ? MSG_TYPES.TASK_START : MSG_TYPES.SCREEN_STATE,
        prompt,
        image: vision.jpegB64,
        redactionMap: vision.rects.map(r => ({ ph: r.ph, type: r.type, rect: r.rect })),
        meta: { ...state, hints: state.hints },
        timings: { capture: turn.tCapture - turn.t0, vision: turn.tVision - turn.tCapture },
      };
      privacyGate(lastPayload);
      if (JSON.stringify(lastPayload.meta).length > MAX_META_CHARS) {
        lastPayload.meta.elements = lastPayload.meta.elements.slice(0, 60);
      }

      // 5. server turn
      const route = step === 1 ? '/v1/task' : '/v1/agent';
      const resp = await serverCall(route, lastPayload);
      turn.tServer = Date.now();

      // 6. local execution
      const actions = resp.actions || [];
      task.lastActions = actions;
      const executable = injectSecrets(actions, task.phMap || {});
      const execRes = executable.length
        ? (await tabMsg(tabId, { type: TAB_MSG.EXECUTE_ACTIONS, actions: executable })).results
        : [];
      turn.tExecute = Date.now();
      task.timings.push(turn);
      task.log.push({
        step,
        summary: resp.summary || '',
        actions: actions.map(a => a.action + (a.el?.txt ? ` "${a.el.txt}"` : a.el?.key ? ` → ${a.el.key}` : '')),
        exec: execRes.map(r => ({ ok: r.ok, error: r.error })),
        redactions: turn.redactions,
        ms: { vision: turn.tVision - turn.tCapture, server: turn.tServer - turn.tVision, exec: turn.tExecute - turn.tServer },
      });

      if (execRes.some(r => r.done)) { task.status = 'done'; break; }
      if (execRes.some(r => r.failed)) { task.status = 'failed'; break; }
      const allBad = executable.length > 0 && execRes.every(r => !r.ok);
      if (allBad && step > 1) { task.status = 'stuck'; break; }
      if (actions.length === 0) { task.status = 'no-actions'; break; }
      await new Promise(r => setTimeout(r, 350)); // let page settle before next capture
    } catch (e) {
      task.log.push({ step, error: String(e?.message || e) });
      if (/Privacy gate/.test(String(e))) { task.transportBlocked = true; task.status = 'blocked'; }
      else task.status = 'error';
      break;
    }
    emitState();
  }
  if (task.status === 'running') task.status = 'max-steps';
  emitState();
  chrome.runtime.sendMessage({ type: MSG.LAST_PAYLOAD, payload: lastPayload }).catch(() => {});
  return task.status;
}

/* ---------------- message router (popup) ---------------- */

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  (async () => {
    try {
      if (msg?.type === MSG.RUN_TASK) {
        if (task && task.status === 'running') { sendResponse({ ok: false, error: 'task already running' }); return; }
        const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
        if (!tab?.id) throw new Error('no active tab');
        sendResponse({ ok: true });
        runTask(tab.id, msg.prompt || '').catch(e => console.error('[sentinel]', e));
      } else if (msg?.type === MSG.STOP_TASK) {
        if (task) { task.status = 'stopped'; emitState(); }
        sendResponse({ ok: true });
      } else if (msg?.type === MSG.TASK_STATE) {
        sendResponse({ ok: true, task: task ? { ...task, vaultKeys: Object.keys(vault) } : null });
      } else if (msg?.type === MSG.LAST_PAYLOAD) {
        sendResponse({ ok: true, payload: lastPayload ? { ...lastPayload, image: undefined, imageSize: (lastPayload.image || '').length } : null });
      } else if (msg?.type === MSG.PING) {
        sendResponse({ ok: true, hasOffscreen, isFirefox });
      }
    } catch (e) {
      sendResponse({ ok: false, error: String(e?.message || e) });
    }
  })();
  return true; // async
});

// Warm up the model host on install / startup for snappy first turn.
chrome.runtime.onInstalled.addListener(() => { warmVisionHost(); });
chrome.runtime.onStartup?.addListener(() => { warmVisionHost(); });
