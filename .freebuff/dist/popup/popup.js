/** Popup logic: task control, live stats, privacy ledger, payload inspector. */
const $ = id => document.getElementById(id);

function fmtMs(v) { return v == null ? '–' : v; }

function renderState(t) {
  const dot = $('dot');
  dot.className = 'dot' + (t ? (t.status === 'running' ? ' on' : (t.status === 'error' || t.status === 'blocked' || t.status === 'failed' ? ' err' : '')) : '');
  $('status').textContent = t
    ? `step ${t.step}/${t.maxSteps} · ${t.status}${t.transportBlocked ? ' — TRANSMISSION BLOCKED' : ''}`
    : 'Idle — nothing leaves this device un-redacted.';

  if (!t) { $('run').disabled = false; return; }
  $('run').disabled = t.status === 'running';

  const last = t.timings?.[t.timings.length - 1];
  if (last) {
    $('liveSection').hidden = false;
    $('stVision').textContent = fmtMs(last.tVision - last.tCapture);
    $('stServer').textContent = fmtMs(last.tServer ? last.tServer - last.tVision : null);
    $('stRedact').textContent = t.redactions;
  }

  if (t.log?.length) {
    $('log').innerHTML = t.log.map(l => {
      if (l.error) return `<div class="err">step ${l.step}: ${l.error}</div>`;
      const actions = (l.actions || []).join(', ') || '(no actions)';
      const exec = (l.exec || []).map(e => e.ok ? '✓' : `✗ ${e.error || ''}`).join(' ');
      return `<div><span class="step">step ${l.step}</span> ${l.summary || ''}<br>${actions}<br>exec: ${exec} · vision ${l.ms?.vision}ms · server ${l.ms?.server}ms</div>`;
    }).join('');
    $('log').scrollTop = 1e9;
  }
}

async function refreshLedger() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab?.id) return;
  chrome.tabs.sendMessage(tab.id, { type: 'GET_AUDIT' }).then(r => {
    if (!r?.ok || !r.audit?.length) { $('ledger').textContent = 'Nothing redacted on this page.'; return; }
    const counts = {};
    for (const a of r.audit) counts[a.type] = (counts[a.type] || 0) + 1;
    $('ledger').innerHTML = Object.entries(counts)
      .map(([k, v]) => `<div class="kv"><span class="k">${k}</span><b>${v}</b></div>`).join('');
  }).catch(() => { $('ledger').textContent = 'Open a page to see redactions.'; });
}

$('run').addEventListener('click', async () => {
  const prompt = $('prompt').value.trim();
  if (!prompt) { $('status').textContent = 'Type a task first.'; return; }
  const r = await chrome.runtime.sendMessage({ type: 'RUN_TASK', prompt });
  if (!r?.ok) $('status').textContent = r?.error || 'failed to start';
});

$('stop').addEventListener('click', () => chrome.runtime.sendMessage({ type: 'STOP_TASK' }));

chrome.runtime.onMessage.addListener(msg => {
  if (msg?.type === 'TASK_STATE') renderState(msg.task);
  if (msg?.type === 'LAST_PAYLOAD' && msg.payload) {
    const p = msg.payload;
    const preview = {
      protocol: p.protocol, type: p.type,
      image: `<${p.imageSize} bytes, redacted JPEG>`,
      redactionMap: p.redactionMap?.slice(0, 8),
      metaKeys: Object.keys(p.meta || {}),
      elementCount: p.meta?.elements?.length,
      timings: p.timings,
    };
    $('payload').textContent = JSON.stringify(preview, null, 2);
  }
});

(async function init() {
  const r = await chrome.runtime.sendMessage({ type: 'TASK_STATE' }).catch(() => null);
  renderState(r?.task || null);
  refreshLedger();
  setInterval(refreshLedger, 2500);
})();
