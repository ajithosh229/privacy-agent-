# 🛡️ Sentinel — Privacy-First Vision Browser Agent

A hybrid browser-agent architecture: **lightweight vision + PII detection runs on-device** (Transformers.js / WebGPU / WASM), **sensitive data is redacted before any network request**, and a **cloud LLM/VLM reasons only over placeholders and structural metadata**, returning actions the extension executes locally.

> The cloud never sees a password, card number, face, or name — only `[PASSWORD_1]`, a black box, and a button labeled "Pay now".

```
┌──────────────────────────── BROWSER (client) ────────────────────────────┐
│  content script         offscreen doc (Chrome) / background page (FF)    │
│  ┌───────────────┐      ┌───────────────────────────────┐                │
│  │ DOM extract   │      │ Transformers.js (local)       │                │
│  │ text-PII scan │─────▶│  • token-classification (NER) │                │
│  │ action exec   │ rects│  • object detection (faces)   │                │
│  │ audit ledger  │      │  • canvas redaction engine    │                │
│  └───────────────┘      └──────────────┬────────────────┘                │
│         ▲                              │ placeholder-only payload        │
│         │  execute actions             │ (privacy gate re-check)         │
│  ┌──────┴──────────────────────────────▼────────────────┐                │
│  │ background orchestrator (service worker)             │                │
│  └──────┬───────────────────────────────────────────────┘                │
└─────────┼────────────────────────────────────────────────────────────────┘
          │ HTTPS: {redacted JPEG, [TYPE_N] placeholders, DOM metadata}
          ▼
┌──────────────────────────── SERVER ──────────────────────────────────────┐
│  privacy gate (leak tripwire) → LLM/VLM adapter                          │
│  • mock   — deterministic planner (offline demo/tests)                   │
│  • remote — any OpenAI-compatible VLM (Ollama / vLLM / OpenRouter…)      │
│  • hybrid — remote first, mock fallback                                  │
└──────────────────────────────────────────────────────────────────────────┘
```

## The privacy contract

1. **Structural data only by default.** DOM metadata is shape, not content: roles, refs, rects, placeholders. Interactive sensitive fields (`password`, `cc-number`, `otp`, `aadhaar`…) are *never* serialized with values — they appear only as `[TYPE_N]` typed placeholders assigned on-device.
2. **Redaction before transmission.** Screenshot PII (names, emails, phones, IDs, card numbers, faces via the person detector) is localized with bounding boxes and destroyed on a canvas (blur / pixelate / solid) **before** encoding to JPEG. Only the redacted frame is uploaded.
3. **Secrets never leave the device at all.** Passwords/OTP/CVV live in a local vault. The server plans `type → [PASSWORD_1]`; the client substitutes the real value at the last moment, directly into the page input.
4. **Server-side tripwire.** The server re-scans every payload with the same PII pattern library and rejects (HTTP 422) anything that looks like raw PII — defense in depth against client bugs. Rejections are logged without recording the raw value.
5. **Local audit ledger.** Every redaction (type, placeholder, timestamp) is kept in the page session and shown in the popup. "Trust, but verify" — the user can see exactly what was withheld.

## Repo layout

```
extension/            client (bundles to dist/ for Chrome, dist-ff/ for Firefox)
  shared/             protocol + PII pattern library (single source of truth)
  content/            DOM extraction, text-PII rects, overlays, executor
  offscreen/          vision pipeline (Transformers.js, NER, redactor)
  background/         orchestrator, offscreen lifecycle, FF host shim
  popup/              task UI, privacy ledger, payload inspector, vault/config
server/               zero-dependency Node server
  privacy-gate.js     leak tripwire (shared patterns + schema checks)
  mock-planner.js     deterministic intent planner (offline demo/tests)
  remote-adapter.js   OpenAI-compatible VLM/LLM adapter + prompt
tests/                e2e protocol test, PII P/R eval, micro-benchmarks
demo/                 self-contained demo pages with fake PII (checkout, mail…)
scripts/              build (esbuild), zip, icon generator
```

## Quick start

### 1. Server

```bash
npm start                      # mock mode on :8787 (zero deps)
# hybrid with a real VLM:
SENTINEL_MODE=hybrid \
SENTINEL_REMOTE_BASE_URL=http://localhost:11434/v1 \
SENTINEL_REMOTE_MODEL=qwen2.5-vl:7b npm start
```

### 2. Extension

```bash
npm install
npm run build
```

- **Chrome/Edge/Brave**: `chrome://extensions` → Developer mode → *Load unpacked* → select `dist/`.
- **Firefox**: `about:debugging#/runtime/this-firefox` → *Load Temporary Add-on* → pick `manifest.json` inside `dist-ff/`.
- In the extension popup → *Settings & vault*: point the server URL at your deployment, and put secrets in the vault as `[PASSWORD_1]=hunter2`.

### 3. Demo (end-to-end)

```bash
npx serve demo        # or: python3 -m http.server 8080 -d demo
```

Then, with the `dist/` extension loaded and the mock server running:

| Page | Prompt | What it proves |
|---|---|---|
| `demo/shop/checkout.html` | "Buy this cart" | card/CVV/`[PASSWORD]` never transmitted; action plan fills only placeholders, clicks **Pay now** |
| `demo/email/inbox.html` | "Find the OTP code and open it" | PII in mail body redacted on-page; agent navigates to OTP |
| `demo/profile/account.html` | "Update my profile" | PERSON/PHONE/DATE redaction rects + structural actions |
| `demo/shop/search.html` | "Search for wireless headphones" | non-sensitive flow: no redactions needed, plain actions |

Watch the popup: **Privacy ledger** (what was redacted, counts by type), **Turn log** (per-step vision/server/exec timings + executed actions), and **Outbound payload** (exactly what the server received — placeholders, never values).

## Local models (fully offline client)

The vision host loads models with `allowRemoteModels = false`. To vendor weights:

1. `pip install -U huggingface_hub` (or use the CLI you have)
2. Download into `models/`:
   - `Xenova/distilbert-base-cased-finetuned-conll03-english` (NER, ~65 MB q8)
   - optional: `Xenova/yolos-tiny` (person/face detector)
3. `npm run build` — weights are copied to `dist/models/` under their model id paths.

Without local weights the extension runs in **pattern-only mode**: the shared regex library (Aadhaar/PAN/card/email/phone/SSN/money/date + label-adjacent heuristics) still redacts, and the mock server still works — useful for CI and for low-end machines (metric 4).

## Protocol

`POST /v1/task` (first turn) and `POST /v1/agent` (subsequent) with:

```jsonc
{
  "protocol": "sentinel-protocol/1.1",
  "type": "SCREEN_STATE",
  "prompt": "user goal",
  "image": "<redacted JPEG, base64>",
  "redactionMap": [{ "ph": "[EMAIL_1]", "type": "EMAIL", "rect": [120,300,180,22] }],
  "meta": { "url", "title", "heading", "viewport", "elements": [{ "ref", "tag", "role", "rect", "key", "ph", "txt", "opts", "empty" }] }
}
```

Response:

```jsonc
{
  "ok": true,
  "summary": "filled 3 fields, clicking Pay now",
  "actions": [{ "action": "click", "el": { "ref": "e7", "txt": "Pay now" } }, ...],
  "adapter": "remote|mock",
  "privacy": { "gate": "pass", "placeholders": ["EMAIL:1", "PASSWORD:1"] }
}
```

Actions: `click · type · scroll · submit · wait · navigate · done · fail · ask_user`. The client executes them in the page (React-safe value setters, `requestSubmit`, pointer-event chains, ref→selector→text fallback matching).

## Evaluation mapping (SIH metrics)

| Metric | Weight | Where it lives |
|---|---|---|
| 1. Accuracy of visual context | 25% | DOM extractor (`extension/content/dom.js`) + screenshot fusion in `VISION_PROCESS`; NER + detector fusion in `extension/offscreen/vision.js`; demo ground truth in `demo/` |
| 2. PII recall & precision | 20% | `tests/eval-pii.js` over labeled corpus (`tests/pii-corpus.js`): strict typed matching, reports P/R/F1 and every FP/FN |
| 3. Precision of redaction | 20% | Rect padding/containment pruning + placeholder mapping (`finalizeRects`); overlay + canvas mark the *same* rects the server receives; nothing outside a detected box is altered |
| 4. Client resource utilization | 20% | q8-quantized local models (~65 MB NER, tiny detector), single capture per turn, bounded DOM (`≤120 elements`, 24 KB metadata cap), JPEG-only upload (~200–400 KB), `perfMode` switch; `tests/bench.js` sizes payloads/latency |
| 5. End-to-end latency | 15% | Waterfall per turn in the popup (capture → vision → server → exec); warm model host (`VISION_LOAD` on install); e2e asserts mock turns < 250 ms; remote adapter timeout-bounded |

Run the checks:

```bash
npm test           # headless e2e: protocol, gate rejects, rate limit, latency
npm run eval:pii   # P/R/F1 on the labeled corpus
npm run eval:protocol
npm run bench
```

## Security notes & roadmap

- Transport: run the server behind HTTPS/WSS in production; the extension currently talks HTTP to `localhost` for the hackathon demo.
- The privacy gate is *advisory-in-depth*, not a sandbox: its strength is the shared pattern library, so new PII types should be added there first.
- Roadmap: WebGPU person-blurring on video elements, session-scoped vault with TTL, a Firefox WebGPU path via `browser.dom`, per-site action allow-lists, and a signed redaction receipt the server returns so clients can verify what the server retained.
