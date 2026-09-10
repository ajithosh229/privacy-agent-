/**
 * Protocol tests: privacy gate + mock planner + remote response parser.
 * Run: npm run eval:protocol
 */
import assert from 'node:assert/strict';
import { gatePayload } from '../server/privacy-gate.js';
import { planNextActions } from '../server/mock-planner.js';
import { parseModelResponse } from '../server/remote-adapter.js';
import { PROTOCOL_VERSION } from '../extension/shared/protocol.js';

const base = { protocol: PROTOCOL_VERSION, type: 'TASK_START', prompt: 'test', image: null, redactionMap: [], meta: { url: 'https://x', title: 't', elements: [] } };

// gate: pass on clean payload
{
  const r = gatePayload(base);
  assert.equal(r.ok, true, 'clean payload should pass');
}

// gate: reject raw email in meta
{
  const bad = { ...base, meta: { ...base.meta, elements: [{ ref: 'e1', txt: 'mail me at john@example.com' }] } };
  const r = gatePayload(bad);
  assert.equal(r.ok, false, 'raw email in meta must be rejected');
}

// gate: accept placeholder tokens
{
  const okP = { ...base, meta: { ...base.meta, elements: [{ ref: 'e1', txt: 'Hi [PERSON_1], receipt sent to [EMAIL_1]' }] } };
  const r = gatePayload(okP);
  assert.equal(r.ok, true, 'placeholders must pass');
}

// gate: reject raw aadhaar-like number
{
  const bad = { ...base, meta: { ...base.meta, elements: [{ ref: 'e1', txt: 'ID 456789213456 verified' }] } };
  const r = gatePayload(bad);
  assert.equal(r.ok, false, 'aadhaar-like raw number must be rejected');
}

// planner: login intent types placeholder password, not a raw secret
{
  const meta = { elements: [
    { ref: 'e1', tag: 'input', key: 'email', empty: 1 },
    { ref: 'e2', tag: 'input', key: 'password', empty: 1 },
    { ref: 'e3', tag: 'button', txt: 'Sign in' },
  ]};
  const { actions } = planNextActions({ prompt: 'log me in', meta, step: 1 });
  const types = actions.filter(a => a.action === 'type');
  assert.ok(types.some(a => a.value === '[EMAIL_1]'), 'should type EMAIL placeholder');
  assert.ok(types.some(a => a.value === '[PASSWORD_1]'), 'should type PASSWORD placeholder');
  assert.ok(actions.some(a => a.action === 'click' && a.el?.txt === 'Sign in'), 'should click Sign in');
}

// planner: checkout intent
{
  const meta = { elements: [
    { ref: 'e1', tag: 'input', key: 'email', empty: 1 },
    { ref: 'e2', tag: 'input', key: 'card-number', empty: 1 },
    { ref: 'e3', tag: 'input', key: 'cvv', empty: 1 },
    { ref: 'e4', tag: 'button', txt: 'Pay now' },
  ]};
  const { actions } = planNextActions({ prompt: 'checkout my cart', meta, step: 1 });
  assert.ok(actions.some(a => a.value === '[CARD_1]'), 'should type CARD placeholder');
  assert.ok(actions.some(a => a.value === '[CVV_1]'), 'should type CVV placeholder');
  assert.ok(actions.some(a => a.action === 'click'), 'should click pay button');
}

// remote parser: fenced JSON → actions
{
  const out = parseModelResponse('```json\n{"summary":"s","actions":[{"action":"click","el":{"ref":"e1","txt":"Buy"}}]}```');
  assert.equal(out.actions[0].action, 'click');
}

// remote parser: rejects garbage
{
  assert.throws(() => parseModelResponse('I cannot do that in JSON, sorry.'));
}

console.log('✔ all protocol tests passed');
