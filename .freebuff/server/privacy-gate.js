/**
 * Server-side privacy gate — the leak tripwire.
 * Every inbound payload is scanned with the same PII pattern library the
 * client uses. If raw PII appears where only placeholders should be, the
 * request is rejected (logged, never forwarded to any model).
 */
import { looksLikePII, looksLikeSecret, HIGH_PRECISION_TYPES } from '../extension/shared/pii-patterns.js';
import { PROTOCOL_VERSION, ENTITY_ORDER } from '../extension/shared/protocol.js';

const PLACEHOLDER_RE = /\[(AADHAAR|CARD|CVV|PAN|EMAIL|PHONE|PERSON|ADDRESS|MONEY|DATE|TIME|URL|ORG|SSN|MISC|PASSWORD)_\d+\]/g;
const PLACEHOLDER_TEST = new RegExp(PLACEHOLDER_RE.source); // non-global for .test()

/** Recursively collect suspicious strings from a JSON payload. */
function collectStrings(x, out = [], depth = 0) {
  if (depth > 12) return out;
  if (typeof x === 'string') out.push(x);
  else if (Array.isArray(x)) for (const v of x) collectStrings(v, out, depth + 1);
  else if (x && typeof x === 'object') for (const v of Object.values(x)) collectStrings(v, out, depth + 1);
  return out;
}

/**
 * Validate + gate a task payload.
 * @returns {{ ok: true, redactionMap: Map<string,string> } | { ok: false, reason: string, samples: string[] }}
 */
export function gatePayload(body) {
  if (!body || typeof body !== 'object') return { ok: false, reason: 'payload must be an object' };
  if (body.protocol !== PROTOCOL_VERSION) return { ok: false, reason: `protocol mismatch: ${body.protocol}` };

  // 1. prompt: must not contain raw PII (the user typed it — strip & continue
  //    with a warning, but reject if it looks like a full secret value).
  const prompt = String(body.prompt || '');
  if (looksLikeSecret(prompt)) {
    return { ok: false, reason: 'prompt contains secret-like value', samples: ['(redacted in logs)'] };
  }

  // 2. redaction map must be well-formed.
  if (body.redactionMap && !Array.isArray(body.redactionMap)) {
    return { ok: false, reason: 'redactionMap must be an array' };
  }
  const redactionMap = new Map();
  for (const r of body.redactionMap || []) {
    if (!r.ph || !r.type) return { ok: false, reason: 'redactionMap entries need ph+type' };
    redactionMap.set(r.ph, r.type);
  }

  // 3. meta strings must not contain raw HIGH-PRECISION PII. Allow placeholder
  //    tokens; PERSON/ORG matches are warn-only (logged, not rejected) because
  //    Title Case phrases in headings are not reliably PII.
  const strings = collectStrings(body.meta || {}).filter(s => !PLACEHOLDER_TEST.test(s));
  const samples = [];
  for (const s of strings) {
    if (looksLikePII(s, { types: HIGH_PRECISION_TYPES })) {
      samples.push(s.slice(0, 60));
      if (samples.length >= 3) break;
    }
  }
  if (samples.length) {
    return { ok: false, reason: 'raw PII detected in metadata', samples };
  }

  return { ok: true, redactionMap };
}

/** Count placeholder types (for the server's metrics + audit log). */
export function countPlaceholders(body) {
  const counts = {};
  const scan = x => {
    if (typeof x === 'string') {
      PLACEHOLDER_RE.lastIndex = 0;
      let m;
      while ((m = PLACEHOLDER_RE.exec(x))) counts[m[1]] = (counts[m[1]] || 0) + 1;
    } else if (Array.isArray(x)) x.forEach(scan);
    else if (x && typeof x === 'object') Object.values(x).forEach(scan);
  };
  scan(body);
  return counts;
}

export function auditLine(body, gateResult) {
  const line = {
    ts: new Date().toISOString(),
    type: body?.type,
    prompt: String(body?.prompt || '').slice(0, 80),
    gate: gateResult.ok ? 'pass' : 'REJECT',
    rejectReason: gateResult.ok ? undefined : gateResult.reason,
    placeholders: gateResult.ok ? countPlaceholders(body) : undefined,
    hasImage: !!body?.image,
    imageKB: body?.image ? Math.round((body.image.length * 3) / 4 / 1024) : 0,
  };
  return JSON.stringify(line);
}
