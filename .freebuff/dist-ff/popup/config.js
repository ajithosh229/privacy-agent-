/** Config page logic: load/save settings and vault via the background. */
const $ = id => document.getElementById(id);

function parseVault(text) {
  const out = {};
  for (const line of (text || '').split('\n')) {
    const i = line.indexOf('=');
    if (i > 0) out[line.slice(0, i).trim()] = line.slice(i + 1);
  }
  return out;
}

function serializeVault(v) {
  return Object.entries(v || {}).map(([k, val]) => `${k}=${val}`).join('\n');
}

chrome.runtime.sendMessage({ type: 'SETTINGS_GET' }).then(r => {
  if (!r?.ok) return;
  $('serverUrl').value = r.settings.serverUrl;
  $('serverMode').value = r.settings.serverMode;
  $('maskMode').value = r.settings.maskMode;
});

chrome.runtime.sendMessage({ type: 'GET_VAULT' }).then(r => {
  if (r?.ok) $('vault').value = serializeVault(r.vault);
});

$('save').addEventListener('click', async () => {
  await chrome.runtime.sendMessage({
    type: 'SETTINGS_SET',
    settings: {
      serverUrl: $('serverUrl').value.trim(),
      serverMode: $('serverMode').value,
      maskMode: $('maskMode').value,
    },
  });
  $('status').textContent = 'saved ✓';
  setTimeout(() => { $('status').textContent = ''; }, 1500);
});

$('saveVault').addEventListener('click', async () => {
  await chrome.runtime.sendMessage({ type: 'SET_VAULT', vault: parseVault($('vault').value) });
  $('vaultStatus').textContent = 'saved ✓ (local only)';
  setTimeout(() => { $('vaultStatus').textContent = ''; }, 1500);
});
