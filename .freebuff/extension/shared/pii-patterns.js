/**
 * Shared PII pattern library (used by both the content script for text-Pii
 * candidates, the redactor for placeholder integrity, and by the server-side
 * privacy gate to verify no raw PII slipped through in metadata/prompt).
 *
 * IMPORTANT: These regexes power BOTH detection (client) and the server's
 * leak-tripwire. If a pattern is removed from here, the privacy gate gets
 * weaker too. Keep conservative (precision-first for the tripwire).
 */
export const PII_PATTERNS = [
  { type: 'AADHAAR', re: /\b[2-9]\d{3}\s\d{4}\s\d{4}\b/g },
  { type: 'AADHAAR', re: /\b[2-9]\d{11}\b/g },
  { type: 'PAN', re: /\b[A-Z]{5}\d{4}[A-Z]\b/g },
  { type: 'EMAIL', re: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g },
  { type: 'PHONE', re: /\b(?:\+91[-.\s]?)?\d{2}[-.\s]?\d{4}[-.\s]?\d{4}\b/g },
  { type: 'PHONE', re: /\b(?:\+?\d{1,3}[-.\s]?)?\d{5}[-.\s]?\d{5}\b/g },
  { type: 'PHONE', re: /(?:\+?\d{1,3}[-.\s]?)?(?:\(\d{2,4}\)|\d{2,4})[-.\s]?\d{3,4}[-.\s]?\d{4}\b/g },
  { type: 'CARD', re: /\b(?:\d[ -]?){13,19}\b/g },
  { type: 'CVV', re: /\bCVV(?:\s*\/?\s*CVC)?\s*[:\-]?\s*\d{3,4}\b/gi },
  { type: 'MONEY', re: /(?:₹|Rs\.?|INR|USD|\$|€|£)\s?\d[\d,]*(?:\.\d+)?/g },
  { type: 'DATE', re: /\b(?:0?[1-9]|[12]\d|3[01])[-\/](?:0?[1-9]|1[0-2])[-\/](?:\d{2}|\d{4})\b/g },
  { type: 'DATE', re: /\b(?:0?[1-9]|1[0-2])\/(?:\d{2}|\d{4})\b/g }, // MM/YY card expiry
  { type: 'TIME', re: /\b(?:[01]?\d|2[0-3]):[0-5]\d(?::[0-5]\d)?\b/g },
  { type: 'URL', re: /\bhttps?:\/\/[^\s<>"']+/g },
];

/**
 * Word-boundary + context patterns for names, SSN and addresses (regex-only
 * approximations; NER model catches the rest). These run in the content
 * script to catch things the NER misses (and for browsers without WebGPU).
 */
export const PII_PATTERNS_CTX = [
  { type: 'SSN', re: /\b(?:SSN|Social Security)\s*[:\-]?\s*\d{3}-?\d{2}-?\d{4}\b/gi },
  { type: 'SSN', re: /\b\d{3}-\d{2}-\d{4}\b/g },
  { type: 'PERSON', re: /\b(?:mr\.?|mrs\.?|ms\.?|dr\.?|prof\.?)\s+[A-Z][a-z]+(?:\s+[A-Z][a-z]+){0,2}\b/g },
  { type: 'PERSON', re: /\b[A-Z][a-z]+\s+[A-Z][a-z]+(?:\s+[A-Z][a-z]+)?\b/g },
  { type: 'ADDRESS', re: /\b\d{1,5}\s+[A-Z][a-z]+(?:\s+[A-Za-z0-9'.-]+)*\s+(?:Street|St|Avenue|Ave|Road|Rd|Lane|Ln|Boulevard|Blvd|Drive|Dr|Nagar|Marg|Colony)\b\.?/g },
];

/** Labels whose neighbouring text is considered PII even if the value
 *  doesn't match a pattern (used by content-script DOM heuristics). */
export const SENSITIVE_LABELS = [
  'password', 'passcode', 'pass phrase', 'passphrase', 'otp', 'one time password',
  'card number', 'card no', 'cvv', 'cvc', 'card verification',
  'aadhaar', 'aadhar', 'aadhahaar', 'pan', 'ssn', 'social security',
  'dob', 'date of birth', 'expiry', 'expires', 'account number', 'ifsc',
];

/** Names of people used by the e2e mock server to check the privacy gate. */
export const PERSON_TEST_NAMES = [
  'John Doe', 'Priya Sharma', 'Aarav Mehta', 'Ananya Iyer', 'Rohan Verma',
];

/** Common sentence words that start capitalized but never begin a person's
 *  name — used to suppress the bare Title-Case PERSON heuristic. */
export const NAME_STOPWORDS = new Set([
  'my', 'this', 'that', 'your', 'our', 'the', 'welcome', 'team', 'order',
  'sign', 'log', 'pay', 'store', 'shop', 'cart', 'hello', 'hi', 'dear', 'kind',
  'regards', 'thanks', 'thank', 'please', 'account', 'profile', 'user', 'member',
]);

/** Street suffixes — "Baker Street" is an address, not a person. */
export const STREET_SUFFIXES = new Set([
  'street', 'st', 'avenue', 'ave', 'road', 'rd', 'lane', 'ln', 'boulevard',
  'blvd', 'drive', 'dr', 'nagar', 'marg', 'colony', 'park', 'place',
]);

/** High-precision types: near-zero false positives → server hard-rejects. */
export const HIGH_PRECISION_TYPES = ['EMAIL', 'PHONE', 'AADHAAR', 'PAN', 'CARD', 'CVV', 'SSN', 'ADDRESS'];

/** Types the client redacts by default (visual + text). MONEY/DATE/TIME/URL
 *  appear constantly in normal UI (prices, timestamps, links) — redacting
 *  them would destroy usability, so they are detected for the eval but not
 *  redacted by default. */
export const REDACT_TYPES = [...HIGH_PRECISION_TYPES, 'PERSON'];

/**
 * Sentinel's placeholder format: [TYPE_N]. Used by redactor & executor.
 */
export const PLACEHOLDER_RE = /^\[(AADHAAR|CARD|CVV|PAN|EMAIL|PHONE|PERSON|ADDRESS|MONEY|DATE|TIME|URL|ORG|SSN|MISC)_(\d+)\]$/;

export function placeholder(type, n) { return `[${type}_${n}]`; }

/** Suppress Title-Case false positives: sentence-initial common words and
 *  street-name tails are not people. */
function isFalseName(value) {
  const words = value.toLowerCase().split(/\s+/).filter(Boolean);
  if (!words.length) return true;
  if (NAME_STOPWORDS.has(words[0]) || NAME_STOPWORDS.has(words[words.length - 1])) return true;
  if (STREET_SUFFIXES.has(words[words.length - 1])) return true;
  return false;
}

/**
 * Find PII in a text blob. `opts.types` restricts which entity types are
 * considered (the privacy gate scans only high-precision types; the eval
 * scans everything).
 */
export function findPII(text, opts = {}) {
  const out = [];
  if (!text) return out;
  const allow = opts.types;
  const want = t => !allow || allow.includes(t);
  for (const p of [...PII_PATTERNS, ...PII_PATTERNS_CTX]) {
    if (!want(p.type)) continue;
    // keep the 'g' flag: exec must advance to avoid an infinite loop
    const re = new RegExp(p.re.source, p.re.flags);
    let m;
    while ((m = re.exec(text))) {
      const value = m[0].trim();
      if (value.length < 4) continue;
      if (p.type === 'PERSON' && isFalseName(value)) continue;
      out.push({ type: p.type, value, index: m.index, length: m[0].length });
    }
  }
  // same-span duplicates (multiple patterns matching the same span): keep the
  // most specific type (structured IDs beat generic numeric types)
  const SPECIFICITY = ['AADHAAR', 'PAN', 'CARD', 'CVV', 'SSN', 'EMAIL', 'PHONE', 'ADDRESS', 'PERSON', 'MONEY', 'ORG', 'DATE', 'TIME', 'URL', 'MISC'];
  const bySpan = new Map();
  for (const d of out) {
    const key = `${d.index}:${d.length}`;
    const prev = bySpan.get(key);
    if (!prev || SPECIFICITY.indexOf(d.type) < SPECIFICITY.indexOf(prev.type)) bySpan.set(key, d);
  }
  const deduped = [...bySpan.values()].sort((a, b) => b.length - a.length);
  // containment pruning: drop detections fully inside a strictly longer one
  return deduped.filter(d => !deduped.some(o =>
    o !== d && o.length > d.length && o.index <= d.index && o.index + o.length >= d.index + d.length));
}

/**
 * Non-sensitivity gate helper (server-side): a text blob fails if it looks
 * like it contains raw high-precision PII. Run AFTER the client already sent
 * placeholders only.
 */
export function looksLikePII(text, opts = {}) {
  return findPII(text, opts).length > 0;
}

/** Stricter server gate: reject values that look like raw secrets. */
export function looksLikeSecret(text) {
  if (!text) return false;
  if (/\b\d{13,19}\b/.test(text)) return true; // card-like
  if (/\b[2-9]\d{11}\b/.test(text)) return true; // aadhaar-like
  return false;
}
