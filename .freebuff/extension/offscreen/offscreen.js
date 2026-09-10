/**
 * Offscreen host (Chrome MV3) / hidden host page (Firefox).
 * Message router: loads models, redacts bitmaps, encodes uploads.
 * All heavy vision work lives here so the MV3 service worker can sleep.
 */
import { getModels, fusePII, dedupeAndPlacehold, finalizeRects, createRedactor, encodeUpload } from './vision.js';

self.SENTINEL_DEVICE = 'wasm';
try {
  if (navigator.gpu) self.SENTINEL_DEVICE = 'webgpu';
} catch { /* ignore */ }

chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  (async () => {
    try {
      if (msg.type === 'VISION_LOAD') {
        const t0 = performance.now();
        const { deviceUsed } = await getModels();
        sendResponse({ ok: true, device: deviceUsed, ms: Math.round(performance.now() - t0) });
      } else if (msg.type === 'VISION_PROCESS') {
        // msg: { imageDataUrl, textHits, domTexts, maskMode }
        const t0 = performance.now();
        await getModels();
        const img = new Image();
        await new Promise((res, rej) => { img.onload = res; img.onerror = rej; img.src = msg.imageDataUrl; });
        const canvas = document.createElement('canvas');
        canvas.width = img.naturalWidth; canvas.height = img.naturalHeight;
        canvas.getContext('2d').drawImage(img, 0, 0);

        // Fuse text-pattern hits with NER over visible texts.
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
      } else {
        sendResponse({ ok: false, error: 'unknown vision msg' });
      }
    } catch (e) {
      sendResponse({ ok: false, error: String(e?.message || e) });
    }
  })();
  return true;
});
