/**
 * Sentinel vision pipeline — pure logic for model loading, NER parsing and
 * redaction decisioning. Runs inside an offscreen document (Chrome) or a
 * hidden page host (Firefox). No DOM assumptions beyond Web Workers/Canvas.
 */
import { pipeline, env } from '@huggingface/transformers';

// Local model assets only: never fetch from the HF hub at runtime.
env.allowRemoteModels = false;
env.allowLocalModels = true;

// Vendored ONNX Runtime WASM (copied to models/wasm/ by the build) so the
// extension works fully offline; falls back to the library default if absent.
let wasmConfigured = false;
async function configureWasmPaths() {
  if (wasmConfigured) return;
  wasmConfigured = true;
  try {
    const url = chrome.runtime.getURL('models/wasm/ort-wasm-simd-threaded.jsep.wasm');
    const head = await fetch(url, { method: 'HEAD' });
    if (head.ok) env.backends.onnx.wasm.wasmPaths = chrome.runtime.getURL('models/wasm/');
  } catch { /* FF or missing — use library default */ }
}

const DEVICE = self.SENTINEL_DEVICE || 'wasm';

/** Lazy model registry. deviceUsed is 'wasm' | 'webgpu' | 'pattern-only'. */
const models = { ner: null, det: null, deviceUsed: null };

export async function getModels() {
  if (models.ner || models.patternOnly) return models;
  await configureWasmPaths();
  try {
    // Token classification: distilbert-NER (CONLL2003) → 4-class head.
    models.ner = await pipeline('token-classification', 'Xenova/distilbert-base-cased-finetuned-conll03-english', {
      device: DEVICE,
      dtype: self.SENTINEL_DTYPE || 'q8',
    });
  } catch (e) {
    // Documented pattern-only mode (see README "Local models"): no vendored
    // weights or model load failed → fall back to the shared regex library so
    // redaction still works. Never hard-fail the whole task here.
    console.warn('[sentinel-vision] NER unavailable, pattern-only mode:', e);
    models.ner = null;
    models.patternOnly = true;
    models.deviceUsed = 'pattern-only';
    return models;
  }
  try {
    models.det = await pipeline('object-detection', 'Xenova/yolos-tiny', {
      device: DEVICE,
      dtype: self.SENTINEL_DTYPE || 'q8',
    });
  } catch (e) {
    console.warn('[sentinel-vision] detector unavailable, text-only redaction:', e);
    models.det = null;
  }
  models.deviceUsed = DEVICE;
  return models;
}

/** Text-Pii + NER fusion → unified redaction rects with placeholders.
 *  textHits: [{type,text,rect}] from the content script scan.
 *  domText:  [{ref,rect,text}] of visible element texts to NER-scan. */
export async function fusePII(textHits, domTexts) {
  const entities = [];
  for (const h of textHits) {
    entities.push({
      type: h.type === 'SECRET_FIELD' ? 'PASSWORD' : h.type === 'PASSWORD_FIELD' ? 'PASSWORD' : h.type,
      text: h.text,
      rect: h.rect,
      src: 'pattern',
    });
  }
  const m = await getModels();
  if (!m.ner) return entities; // pattern-only mode: regex hits only
  for (const t of domTexts) {
    // placeholder integrity: never re-redact already-redacted
    if (/\[[A-Z]+_\d+\]/.test(t.text)) continue;
    let out = [];
    try {
      out = await m.ner(t.text, { aggregation_strategy: 'simple' });
    } catch (e) {
      console.warn('[sentinel-vision] NER failed on text:', e);
    }
    for (const e of out) {
      if (!['PER', 'ORG', 'LOC', 'MISC'].includes(e.entity_group)) continue;
      entities.push({ type: mapNerType(e.entity_group), text: e.word, rect: t.rect || null, src: 'ner', ref: t.ref });
    }
  }
  return entities;
}

function mapNerType(g) {
  return { PER: 'PERSON', ORG: 'ORG', LOC: 'ADDRESS', MISC: 'MISC' }[g] || 'MISC';
}

/** Fuse duplicates: same text redacted once, placeholder numbering stable. */
export function dedupeAndPlacehold(entities) {
  const seen = new Map(); // key: type+text → ph
  const counters = {};
  const out = [];
  for (const e of entities) {
    const key = e.type + '|' + e.text;
    if (!seen.has(key)) {
      counters[e.type] = (counters[e.type] || 0) + 1;
      seen.set(key, `[${e.type}_${counters[e.type]}]`);
    }
    out.push({ ...e, ph: seen.get(key) });
  }
  return out;
}

/** Decide final rect list for overlay + screenshot redaction. */
export function finalizeRects(entities) {
  const rects = [];
  for (const e of entities) {
    if (!e.rect) continue;
    // pad 2px, clamp positive size
    const [x, y, w, h] = e.rect;
    if (w <= 0 || h <= 0) continue;
    rects.push({ type: e.type, text: e.text, ph: e.ph, rect: [Math.max(0, x - 2), Math.max(0, y - 2), w + 4, h + 4] });
  }
  // remove contained rects
  return rects.filter(r1 => !rects.some(r2 => r2 !== r1 && contains(r2.rect, r1.rect)));
}

function contains(a, b) {
  const [ax, ay, aw, ah] = a; const [bx, by, bw, bh] = b;
  return bx >= ax && by >= ay && bx + bw <= ax + aw && by + bh <= ay + ah;
}

/* ------------------------------------------------------------------ */
/* Canvas redactor                                                     */
/* ------------------------------------------------------------------ */

/** Canvas redactor — draws redaction marks over detected rects. Produces:
 *  (1) redacted canvas, (2) JPEG blob for upload. */
export function createRedactor(sourceCanvas) {
  return {
    applyAll(rects, mode = 'blur') {
      const ctx = sourceCanvas.getContext('2d');
      for (const r of rects) {
        const [x, y, w, h] = r.rect;
        if (mode === 'solid') {
          ctx.fillStyle = '#000';
          ctx.fillRect(x, y, w, h);
        } else if (mode === 'pixelate') {
          const block = 10;
          const off = document.createElement('canvas');
          off.width = Math.max(1, Math.floor(w / block));
          off.height = Math.max(1, Math.floor(h / block));
          const octx = off.getContext('2d');
          octx.drawImage(sourceCanvas, x, y, w, h, 0, 0, off.width, off.height);
          ctx.imageSmoothingEnabled = false;
          ctx.drawImage(off, 0, 0, off.width, off.height, x, y, w, h);
        } else { // blur
          const tmp = document.createElement('canvas');
          tmp.width = sourceCanvas.width; tmp.height = sourceCanvas.height;
          const tctx = tmp.getContext('2d');
          tctx.filter = 'blur(12px)';
          tctx.drawImage(sourceCanvas, 0, 0);
          ctx.save();
          ctx.beginPath();
          ctx.rect(x, y, w, h);
          ctx.clip();
          ctx.drawImage(tmp, 0, 0);
          ctx.restore();
        }
      }
      return sourceCanvas;
    },
    toBlob(quality = 0.72, type = 'image/jpeg') {
      return new Promise(res => sourceCanvas.toBlob(res, type, quality));
    },
  };
}

/** Downscale + encode the redacted canvas for upload (bounded bytes). */
export async function encodeUpload(canvas, maxSide = 1280, quality = 0.72) {
  let c = canvas;
  const m = Math.max(canvas.width, canvas.height);
  if (m > maxSide) {
    const s = maxSide / m;
    c = document.createElement('canvas');
    c.width = Math.round(canvas.width * s);
    c.height = Math.round(canvas.height * s);
    c.getContext('2d').drawImage(canvas, 0, 0, c.width, c.height);
  }
  const blob = await new Promise(res => c.toBlob(res, 'image/jpeg', quality));
  const buf = await blob.arrayBuffer();
  let bin = '';
  const u8 = new Uint8Array(buf);
  const CHUNK = 0x8000;
  for (let i = 0; i < u8.length; i += CHUNK) bin += String.fromCharCode.apply(null, u8.subarray(i, i + CHUNK));
  return btoa(bin);
}

export function now() { return performance.now(); }
