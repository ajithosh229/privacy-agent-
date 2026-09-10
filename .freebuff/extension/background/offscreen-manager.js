/**
 * Chrome MV3 offscreen lifecycle management. Creates (or reuses) the offscreen
 * document that hosts the vision pipeline. Firefox has no offscreen API; its
 * background page (non-persistent) hosts the pipeline directly, so these
 * helpers are no-ops there.
 */
import { hasOffscreen } from './env.js';

let creating; // in-flight create promise

export async function ensureVisionHost() {
  if (!hasOffscreen) return; // FF: vision runs in the background page itself
  const OFFSCREEN_URL = 'offscreen.html';
  const contexts = await chrome.runtime.getContexts({
    contextTypes: ['OFFSCREEN_DOCUMENT'],
    documentUrls: [chrome.runtime.getURL(OFFSCREEN_URL)],
  });
  if (contexts.length > 0) return;

  if (creating) { await creating; return; }
  creating = chrome.offscreen.createDocument({
    url: OFFSCREEN_URL,
    reasons: ['DOM_SCRAPING', 'CANVAS',
'WORKERS'],
    justification: 'Run local vision models (Transformers.js) to detect and redact PII before any data leaves the device.',
  });
  try { await creating; } finally { creating = null; }
}

export async function closeVisionHost() {
  if (!hasOffscreen) return;
  try {
    const contexts = await chrome.runtime.getContexts({
      contextTypes: ['OFFSCREEN_DOCUMENT'],
      documentUrls: [chrome.runtime.getURL(OFFSCREEN_URL)],
    });
    if (contexts.length > 0) await chrome.offscreen.closeDocument();
  } catch { /* already closed */ }
}

/** Fire-and-forget model warm-up so the first real turn is fast. */
export function warmVisionHost() {
  ensureVisionHost().then(() => sendVisionMessage({ type: 'VISION_LOAD' })).catch(() => {});
}

/** Send a message to the vision host (offscreen doc on Chrome, background
 *  page itself on Firefox — handled by vision-host.js there). */
export async function sendVisionMessage(payload) {
  await ensureVisionHost();
  return new Promise((resolve, reject) => {
    chrome.runtime.sendMessage(payload, res => {
      if (chrome.runtime.lastError) return reject(new Error(chrome.runtime.lastError.message));
      if (!res) return reject(new Error('vision host unreachable'));
      if (res.ok === false) return reject(new Error(res.error || 'vision error'));
      resolve(res);
    });
  });
}
