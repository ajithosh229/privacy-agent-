/**
 * Micro-benchmarks for the resource/latency budgets:
 *  - mock planner latency over synthetic screens
 *  - payload byte size vs element count (with + without image)
 *  - privacy gate throughput
 * Run: npm run bench
 */
import { planNextActions } from '../server/mock-planner.js';
import { gatePayload } from '../server/privacy-gate.js';
import { PROTOCOL_VERSION } from '../extension/shared/protocol.js';

function synthScreen(nEl) {
  const elements = [];
  for (let i = 0; i < nEl; i++) {
    elements.push({
      ref: `e${i}`, tag: i % 3 === 0 ? 'button' : 'input',
      key: `field_${i}`, txt: i % 3 === 0 ? `Action ${i}` : undefined,
      rect: [i * 20, i * 30, 120, 24], empty: 1,
    });
  }
  return { url: 'https://shop.example/checkout', title: 'Checkout', elements };
}

function bench(fn, iters, label) {
  const t0 = process.hrtime.bigint();
  for (let i = 0; i < iters; i++) fn(i);
  const ms = Number(process.hrtime.bigint() - t0) / 1e6;
  console.log(`${label}: ${iters} iters in ${ms.toFixed(1)}ms → ${(ms / iters).toFixed(3)}ms/iter`);
}

console.log('═══ Sentinel micro-benchmarks ═══\n');

for (const n of [20, 60, 120]) {
  const meta = synthScreen(n);
  bench(i => planNextActions({ prompt: 'checkout my cart', meta, step: 1 }), 2000, `planner(${n} els)`);
}

const payload = {
  protocol: PROTOCOL_VERSION, type: 'SCREEN_STATE',
  prompt: 'checkout', image: null, redactionMap: [],
  meta: synthScreen(120),
};
const gateBody = JSON.parse(JSON.stringify(payload));
bench(() => gatePayload(gateBody), 2000, 'privacy-gate(120 els)');

const jsonNoImg = JSON.stringify(payload).length;
payload.image = 'A'.repeat(300 * 1024); // ~300 KB redacted JPEG
const jsonImg = JSON.stringify(payload).length;
console.log(`payload size: ${jsonNoImg} B (meta only) → ${(jsonImg / 1024).toFixed(0)} KB (with 300KB image)`);

// image byte budget table
for (const dim of [720, 1280, 1920]) {
  const jpegKB = Math.round((dim * dim * 0.08) / 1024); // crude JPEG estimate
  console.log(`redacted frame @${dim}px ≈ ${jpegKB} KB JPEG (q0.72) — upload time @1Mbps ≈ ${(jpegKB * 8 / 1000).toFixed(1)}s, @10Mbps ≈ ${(jpegKB * 8 / 10000).toFixed(2)}s`);
}
