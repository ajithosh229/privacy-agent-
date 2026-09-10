/**
 * Sentinel content script — runs in the page. Responsibilities:
 *  1. Collect visible-text PII candidate rects (for the vision redactor's
 *     text channel, and for placeholder assignment).
 *  2. Extract the non-sensitive screen state (DOM metadata).
 *  3. Apply / clear redaction overlays (canvas-based per-rect).
 *  4. Execute approved server actions locally (click/type/scroll/submit).
 *  5. Keep a local audit ledger of everything that was redacted.
 */
import { extractScreenState } from './dom.js';
import { PII_PATTERNS, PII_PATTERNS_CTX, SENSITIVE_LABELS } from '../shared/pii-patterns.js';

const audit = []; // {type, text, rect, ts} — stays local
let overlayRoot = null;
let pageHints = { sensitiveInputs: [] };

/* ------------------------------------------------------------------ */
/* 1. Text PII scanning                                                */
/* ------------------------------------------------------------------ */

function* textNodesUnder(root) {
  const walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT, {
    acceptNode(n) {
      if (!n.textContent || !n.textContent.trim()) return NodeFilter.FILTER_REJECT;
      const p = n.parentElement;
      if (!p) return NodeFilter.FILTER_REJECT;
      const tag = p.tagName;
      if (tag === 'SCRIPT' || tag === 'STYLE' || tag === 'NOSCRIPT' || tag === 'TEXTAREA') return NodeFilter.FILTER_REJECT;
      const r = p.getBoundingClientRect();
      if (r.width < 2 || r.height < 2) return NodeFilter.FILTER_REJECT;
      const s = getComputedStyle(p);
      if (s.visibility === 'hidden' || s.display === 'none') return NodeFilter.FILTER_REJECT;
      return NodeFilter.FILTER_ACCEPT;
    },
  });
  let n;
  while ((n = walker.nextNode())) yield n;
}

/** Find text PII and record rects + audit entries. Types follow the shared
 *  pattern library. Values never leave this function except into the local
 *  audit ledger. */
export function scanTextPii() {
  const found = [];
  for (const node of textNodesUnder(document.body)) {
    const text = node.textContent;
    const patterns = [...PII_PATTERNS, ...PII_PATTERNS_CTX];
    for (const { type, re } of patterns) {
      re.lastIndex = 0;
      let m;
      while ((m = re.exec(text))) {
        const raw = m[0];
        // length filter: avoid absurd matches like "11" for phone
        if (raw.length < 4) continue;
        const range = document.createRange();
        range.setStart(node, m.index);
        range.setEnd(node, m.index + raw.length);
        const rect = range.getBoundingClientRect();
        if (rect.width < 1 || rect.height < 1) continue;
        found.push({ type, text: raw, rect: [rect.left, rect.top, rect.width, rect.height] });
        audit.push({ type, text: raw, rect: found[found.length - 1].rect, ts: Date.now(), src: 'text' });
      }
    }
  }
  // label-adjacent heuristic: input value next to a sensitive label
  for (const inp of document.querySelectorAll('input,textarea')) {
    const hay = `${inp.id} ${inp.name || ''} ${inp.placeholder || ''}`.toLowerCase();
    if (!hay) continue;
    const hit = SENSITIVE_LABELS.find(s => hay.includes(s));
    if (hit && inp.value && inp.type !== 'password') {
      const r = inp.getBoundingClientRect();
      if (r.width > 2) {
        found.push({ type: 'SECRET_FIELD', text: inp.value, rect: [r.left, r.top, r.width, r.height] });
        audit.push({ type: 'SECRET_FIELD', text: inp.value, rect: found[found.length - 1].rect, ts: Date.now(), src: 'field' });
      }
    }
  }
  // password inputs (mask even when empty — the field itself is sensitive)
  for (const inp of document.querySelectorAll('input[type="password"]')) {
    const r = inp.getBoundingClientRect();
    if (r.width > 2) {
      found.push({ type: 'PASSWORD_FIELD', text: inp.value || 'password', rect: [r.left, r.top, r.width, r.height] });
      audit.push({ type: 'PASSWORD_FIELD', rect: found[found.length - 1].rect, ts: Date.now(), src: 'field' });
    }
  }
  return found;
}

/* ------------------------------------------------------------------ */
/* 2. Screen state collection                                          */
/* ------------------------------------------------------------------ */

function collectSensitiveInputMap() {
  const map = [];
  for (const el of document.querySelectorAll('input,textarea')) {
    const s = roleOfSensitive(el);
    if (s) map.push({ ref: el.dataset.sref || null, selector: cssPath(el), role: s, hasValue: !!el.value });
  }
  return map;
}

function roleOfSensitive(el) {
  const ac = (el.getAttribute('autocomplete') || '').toLowerCase();
  if (ac && /password|otp|one-time-code|cc-|card/.test(ac)) return ac;
  const type = (el.getAttribute('type') || '').toLowerCase();
  if (type === 'password') return 'password';
  const hay = `${el.id} ${el.name || ''} ${el.placeholder || ''} ${labelText(el)}`.toLowerCase();
  for (const s of SENSITIVE_LABELS) if (hay.includes(s)) return s.replace(/\s+/g, '-');
  return '';
}

function labelText(el) {
  if (el.id) {
    const l = document.querySelector(`label[for="${CSS.escape(el.id)}"]`);
    if (l) return l.textContent || '';
  }
  const wrap = el.closest('label');
  return wrap ? (wrap.textContent || '') : '';
}

function cssPath(el) {
  const parts = [];
  let cur = el;
  while (cur && cur !== document.body && parts.length < 5) {
    let sel = cur.tagName.toLowerCase();
    if (cur.id) { sel += `#${cur.id}`; parts.unshift(sel); break; }
    const parent = cur.parentElement;
    if (parent) {
      const same = Array.from(parent.children).filter(c => c.tagName === cur.tagName);
      if (same.length > 1) sel += `:nth-of-type(${same.indexOf(cur) + 1})`;
    }
    parts.unshift(sel);
    cur = parent;
  }
  return parts.join(' > ') || el.tagName.toLowerCase();
}

export function collect() {
  const state = extractScreenState();
  pageHints = { sensitiveInputs: collectSensitiveInputMap() };
  return { ...state, hints: pageHints };
}

/* ------------------------------------------------------------------ */
/* 3. Overlay rendering                                                */
/* ------------------------------------------------------------------ */

function ensureOverlayRoot() {
  if (overlayRoot && document.documentElement.contains(overlayRoot)) return overlayRoot;
  overlayRoot = document.createElement('div');
  overlayRoot.id = 'sentinel-overlay-root';
  overlayRoot.style.cssText = 'position:fixed;inset:0;pointer-events:none;z-index:2147483646;';
  document.documentElement.appendChild(overlayRoot);
  return overlayRoot;
}

/** Draw an SVG overlay marking redacted regions. Mode: blur is simulated via
 *  a repeated svg filter; pixelate via a pattern; solid via a filled rect. */
export function applyOverlay(rects, mode = 'blur', labels = true) {
  const root = ensureOverlayRoot();
  root.innerHTML = '';
  const NS = 'http://www.w3.org/2000/svg';
  const svg = document.createElementNS(NS, 'svg');
  svg.setAttribute('width', '100%');
  svg.setAttribute('height', '100%');
  const defs = document.createElementNS(NS, 'defs');

  const blurF = document.createElementNS(NS, 'filter');
  blurF.id = 's-blur';
  blurF.innerHTML = '<feGaussianBlur stdDeviation="6"/>';
  defs.appendChild(blurF);

  const pixF = document.createElementNS(NS, 'filter');
  pixF.id = 's-pix';
  pixF.innerHTML = '<feFlood flood-color="#111" result="b"/><feComposite in="b" in2="SourceGraphic" operator="in"/><feTile/>';
  defs.appendChild(pixF);
  svg.appendChild(defs);

  for (const r of rects) {
    const [x, y, w, h] = r.rect;
    const g = document.createElementNS(NS, 'g');
    const bg = document.createElementNS(NS, 'rect');
    bg.setAttribute('x', x); bg.setAttribute('y', y);
    bg.setAttribute('width', w); bg.setAttribute('height', h);
    bg.setAttribute('fill', mode === 'solid' ? '#000' : 'rgba(10,10,14,0.88)');
    if (mode === 'blur') bg.setAttribute('filter', 'url(#s-blur)');
    if (mode === 'pixelate') bg.setAttribute('filter', 'url(#s-pix)');
    bg.setAttribute('rx', 3);
    g.appendChild(bg);
    if (labels) {
      const t = document.createElementNS(NS, 'text');
      t.setAttribute('x', x + 4);
      t.setAttribute('y', y + h - 4);
      t.setAttribute('font-size', Math.max(9, Math.min(14, h / 2.4)));
      t.setAttribute('font-family', 'monospace');
      t.setAttribute('fill', '#00e5a0');
      t.textContent = `🛡 ${r.type}${r.ph ? ' → ' + r.ph : ''}`;
      g.appendChild(t);
    }
    svg.appendChild(g);
  }
  root.appendChild(svg);
}

export function clearOverlay() {
  if (overlayRoot) overlayRoot.innerHTML = '';
}

/* ------------------------------------------------------------------ */
/* 4. Action executor                                                  */
/* ------------------------------------------------------------------ */

function findByRef(ref) {
  return document.querySelector(`[data-sref="${CSS.escape(ref)}"]`);
}

function findBySelector(sel) {
  try { return document.querySelector(sel); } catch { return null; }
}

function findByDescriptor(el) {
  if (!el) return null;
  if (el.ref) { const byRef = findByRef(el.ref); if (byRef) return byRef; }
  if (el.selector) { const bySel = findBySelector(el.selector); if (bySel) return bySel; }
  // text-based fallback for buttons/links
  if (el.txt) {
    const cands = Array.from(document.querySelectorAll('button, a, [role="button"]'));
    const m = cands.find(c => (c.textContent || '').trim().toLowerCase().includes(String(el.txt).toLowerCase()));
    if (m) return m;
  }
  return null;
}

function fireClick(el) {
  el.scrollIntoView({ block: 'center', behavior: 'instant' });
  el.dispatchEvent(new PointerEvent('pointerdown', { bubbles: true }));
  el.dispatchEvent(new MouseEvent('mousedown', { bubbles: true }));
  el.dispatchEvent(new PointerEvent('pointerup', { bubbles: true }));
  el.dispatchEvent(new MouseEvent('mouseup', { bubbles: true }));
  el.click();
}

function setValue(el, value) {
  el.scrollIntoView({ block: 'center', behavior: 'instant' });
  el.focus();
  // React-controlled inputs
  const proto = el instanceof HTMLTextAreaElement ? HTMLTextAreaElement.prototype : HTMLInputElement.prototype;
  const desc = Object.getOwnPropertyDescriptor(proto, 'value');
  if (desc && desc.set) desc.set.call(el, value); else el.value = value;
  el.dispatchEvent(new Event('input', { bubbles: true }));
  el.dispatchEvent(new Event('change', { bubbles: true }));
}

/** Execute a list of server-issued actions. `phMap` is the LOCAL
 *  placeholder→value map produced by the on-device redaction pass — it is
 *  passed tab→background→tab and never leaves the browser. */
export async function executeActions(actions, phMap = {}) {
  const results = [];
  for (const a of actions) {
    const res = { action: a.action, ok: false };
    try {
      switch (a.action) {
        case 'click': {
          const el = findByDescriptor(a.el || a);
          if (!el) throw new Error('target not found');
          fireClick(el);
          res.ok = true;
          break;
        }
        case 'type':
        case 'set': {
          const el = findByDescriptor(a.el || a);
          if (!el) throw new Error('target not found');
          let value = a.value ?? '';
          // Placeholder resolution (LOCAL only): the server plans with
          // [EMAIL_1]-style tokens; the real value comes from the local
          // redaction map (or the private vault for secrets, resolved by the
          // background before this message was sent).
          if (/^\[[A-Z_]+_\d+\]$/.test(String(value)) && phMap[value] !== undefined) {
            value = phMap[value];
          }
          setValue(el, value);
          res.ok = true;
          break;
        }
        case 'submit': {
          const el = findByDescriptor(a.el || a);
          const form = el && el.closest('form');
          if (form) { form.requestSubmit ? form.requestSubmit() : form.submit(); }
          else if (el) fireClick(el);
          res.ok = true;
          break;
        }
        case 'scroll': {
          const amount = a.amount || 600;
          window.scrollBy({ top: amount, behavior: 'instant' });
          res.ok = true;
          break;
        }
        case 'navigate': {
          if (a.url && /^https?:/i.test(a.url)) { location.href = a.url; res.ok = true; }
          else throw new Error('bad url');
          break;
        }
        case 'wait': {
          await new Promise(r => setTimeout(r, Math.min(5000, a.ms || 800)));
          res.ok = true;
          break;
        }
        case 'done': res.ok = true; res.done = true; break;
        case 'fail': res.ok = true; res.failed = true; break;
        default: throw new Error(`unknown action ${a.action}`);
      }
    } catch (e) {
      res.error = String(e.message || e);
    }
    results.push(res);
  }
  return results;
}

/* ------------------------------------------------------------------ */
/* 5. Message plumbing                                                 */
/* ------------------------------------------------------------------ */

chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  (async () => {
    switch (msg?.type) {
      case 'EXTRACT_STATE': {
        sendResponse({ ok: true, state: collect(), piiRects: scanTextPii().map(p => ({ type: p.type, rect: p.rect, text: p.text })) });
        break;
      }
      case 'APPLY_OVERLAY': {
        applyOverlay(msg.rects || [], msg.mode || 'blur', msg.labels !== false);
        sendResponse({ ok: true });
        break;
      }
      case 'CLEAR_OVERLAY': {
        clearOverlay();
        sendResponse({ ok: true });
        break;
      }
      case 'EXECUTE_ACTIONS': {
        const results = await executeActions(msg.actions || [], msg.phMap || {});
        sendResponse({ ok: true, results });
        break;
      }
      case 'GET_AUDIT': {
        sendResponse({ ok: true, audit });
        break;
      }
      default:
        sendResponse({ ok: false, error: 'unknown msg' });
    }
  })();
  return true; // async sendResponse
});
