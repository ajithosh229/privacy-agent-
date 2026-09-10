/**
 * PII eval: precision/recall/F1 of the detection stack over the labeled
 * corpus. Uses the same regex library the client ships. Matching is
 * type-aware and substring-tolerant (detection often captures label prefixes
 * like "CVV 123" or "Dr. Priya Sharma"); greedy overlap resolution ensures
 * one detection can satisfy at most one ground-truth entity.
 *
 * Run: npm run eval:pii
 */
import { findPII } from '../extension/shared/pii-patterns.js';
import { CORPUS } from './pii-corpus.js';

const norm = s => s.toLowerCase().replace(/\s+/g, ' ').trim();

/** A detection matches a truth entity if types are compatible and the
 *  detection covers the value (or vice versa for prefix-label captures). */
const TYPE_COMPAT = {
  PERSON: ['PERSON'],
  EMAIL: ['EMAIL'], PHONE: ['PHONE', 'CARD'],
  AADHAAR: ['AADHAAR', 'CARD'], PAN: ['PAN'],
  CARD: ['CARD', 'PHONE'], CVV: ['CVV'],
  SSN: ['SSN'], ADDRESS: ['ADDRESS'],
  MONEY: ['MONEY'], DATE: ['DATE'], TIME: ['TIME'], URL: ['URL'], ORG: ['ORG'], MISC: ['MISC'],
};

function score(cases) {
  let tp = 0, fp = 0, fn = 0;
  const details = [];
  for (const c of cases) {
    const got = findPII(c.text).map(g => ({ ...g, used: false }));
    const truth = c.truth.map(t => ({ ...t, matched: false }));

    // one detection may only satisfy one truth entity; greedy in order
    for (const g of got) {
      const hit = truth.find(t => {
        if (t.matched) return false;
        if (!(TYPE_COMPAT[t.type] || [t.type]).includes(g.type)) return false;
        const a = norm(g.value), b = norm(t.value);
        return a.includes(b) || b.includes(a);
      });
      if (hit) { hit.matched = true; g.used = true; tp++; }
    }
    for (const g of got.filter(g => !g.used)) {
      fp++; details.push(`FP: "${g.value}" [${g.type}] in "${c.text.slice(0, 60)}"`);
    }
    for (const t of truth.filter(t => !t.matched)) {
      fn++; details.push(`FN: "${t.value}" [${t.type}] in "${c.text.slice(0, 60)}"`);
    }
  }
  const precision = tp / (tp + fp || 1);
  const recall = tp / (tp + fn || 1);
  const f1 = 2 * precision * recall / (precision + recall || 1);
  return { tp, fp, fn, precision, recall, f1, details };
}

const res = score(CORPUS);
console.log('═══ PII detection eval ═══');
console.log(`TP=${res.tp}  FP=${res.fp}  FN=${res.fn}`);
console.log(`precision=${(res.precision * 100).toFixed(1)}%  recall=${(res.recall * 100).toFixed(1)}%  F1=${(res.f1 * 100).toFixed(1)}%`);
if (res.details.length) {
  console.log('\ndetails:');
  for (const d of res.details) console.log('  ' + d);
}
process.exit(res.f1 >= 0.8 ? 0 : 1);
