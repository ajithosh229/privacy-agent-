/**
 * Firefox support: the background page has DOM access, so it hosts the vision
 * pipeline directly (no offscreen API there). This registers the same message
 * handlers the offscreen document exposes on Chrome.
 */
import { getModels, fusePII, dedupeAndPlacehold, finalizeRects, createRedactor, encodeUpload } from '../offscreen/vision.js';
import { isFirefox } from './env.js';

export function initVisionHost() {
  if (!isFirefox) return; // Chrome: the offscreen doc handles these messages.

  try { if (navigator.gpu) self.SENTINEL_DEVICE = 'webgpu'; } catch { /* wasm */ }

  chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
    (async () => {
      try {
        if (msg.type === 'VISION_LOAD') {
          const t0 = performance.now();
          const { deviceUsed } = await getModels();
          sendResponse({ ok: true, device: deviceUsed, ms: Math.round(performance.now() - t0) });
        } else if (msg.type === 'VISION_PROCESS') {
          const t0 = performance.now();
          await getModels();
          const img = new Image();
          await new Promise((res, rej) => { img.onload = res; img.onerror = rej; img.src = msg.imageDataUrl; });
          const canvas = document.createElement('canvas');
          canvas.width = img.naturalWidth; canvas.height = img.naturalHeight;
          canvas.getContext('2d').drawImage(img, 0, 0);

          const fused = await fusePII(msg.textHits || [], msg.domTexts || []);
          const withPh = dedupeAndPlacehold(fused);
          const rects = finalizeRects(withPh);

          const red = createRedactor(canvas);
          red.applyAll(rects, msg.maskMode || 'blur');
          const jpegB64 = await encodeUpload(canvas, 1280, 0.72);

          sendResponse({
            ok: true,
            device: (await getModels()).deviceUsed,
            ms: Math.round(performance.now() - t0),
            rects,
            jpegB64,
          });
        }
      } catch (e) {
        sendResponse({ ok: false, error: String(e?.message || e) });
      }
    })();
    return true;
  });
}
