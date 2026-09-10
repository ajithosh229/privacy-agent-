/**
 * Headless e2e: boots the server (mock mode) on an ephemeral port and drives
 * the two-turn protocol exactly like the extension would — TASK_START with a
 * placeholder-only payload, then a SCREEN_STATE turn with a fresh redaction
 * map. Verifies actions, privacy accounting, and turn latency.
 * Run: npm test
 */
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { setTimeout as sleep } from 'node:timers/promises';

const PORT = 8791;
const BASE = `http://127.0.0.1:${PORT}`;

function startServer() {
  const child = spawn(process.execPath, ['server/server.js'], {
    env: { ...process.env, SENTINEL_PORT: String(PORT), SENTINEL_MODE: 'mock' },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  child.stdout.on('data', d => process.stdout.write(`[srv] ${d}`));
  child.stderr.on('data', d => process.stderr.write(`[srv!] ${d}`));
  return child;
}

async function waitHealthy() {
  for (let i = 0; i < 40; i++) {
    try {
      const r = await fetch(`${BASE}/healthz`);
      if (r.ok) return true;
    } catch { /* not up yet */ }
    await sleep(100);
  }
  throw new Error('server did not become healthy');
}

async function post(path, body) {
  const r = await fetch(BASE + path, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  return { status: r.status, json: await r.json().catch(() => ({})) };
}

const PROTO = 'sentinel-protocol/1.1';

async function main() {
  const srv = startServer();
  try {
    await waitHealthy();

    // health
    {
      const r = await fetch(`${BASE}/healthz`).then(r => r.json());
      assert.equal(r.ok, true);
      assert.equal(r.mode, 'mock');
    }

    // ---- turn 1: TASK_START — login intent on a sanitized gmail-like page
    const t1 = {
      protocol: PROTO,
      type: 'TASK_START',
      sessionKey: 'e2e-1',
      prompt: 'Log me into my GitHub account',
      image: null, // pretend redacted jpeg b64; mock planner ignores it
      redactionMap: [
        { ph: '[EMAIL_1]', type: 'EMAIL', rect: [120, 300, 180, 22] },
        { ph: '[PASSWORD_1]', type: 'PASSWORD', rect: [120, 340, 180, 22] },
      ],
      meta: {
        url: 'https://github.com/login',
        title: 'Sign in to GitHub',
        heading: 'Sign in',
        elements: [
          { ref: 'e1', tag: 'input', key: 'login', ph: 'Email or username', empty: 1 },
          { ref: 'e2', tag: 'input', key: 'password', empty: 1 },
          { ref: 'e3', tag: 'button', txt: 'Sign in' },
        ],
      },
    };
    const r1 = await post('/v1/task', t1);
    assert.equal(r1.status, 200, `turn1 status ${r1.status}: ${JSON.stringify(r1.json)}`);
    assert.equal(r1.json.ok, true);
    assert.ok(r1.json.actions.some(a => a.action === 'type' && a.value === '[PASSWORD_1]'), 'plan types PASSWORD placeholder');
    assert.ok(r1.json.actions.some(a => a.action === 'click'), 'plan clicks sign-in');
    assert.equal(r1.json.privacy.gate, 'pass');
    assert.ok(r1.json.ms < 250, `mock turn should be <250ms, got ${r1.json.ms}`);

    // ---- turn 2: SCREEN_STATE — same task, new screen state
    const t2 = {
      ...t1,
      type: 'SCREEN_STATE',
      sessionKey: 'e2e-1',
      redactionMap: [],
      meta: { ...t1.meta, elements: [
        { ref: 'e4', tag: 'div', txt: 'Welcome back, [PERSON_1]!' },
        { ref: 'e5', tag: 'a', txt: 'Your repositories' },
      ] },
    };
    const r2 = await post('/v1/agent', t2);
    assert.equal(r2.json.ok, true);
    assert.ok(r2.json.actions.some(a => a.action === 'done'), 'server should conclude task done on welcome screen');

    // ---- privacy gate: raw PII must be rejected with 422
    const bad = {
      ...t1,
      sessionKey: 'e2e-bad',
      meta: { ...t1.meta, elements: [
        { ref: 'e1', tag: 'input', key: 'email', empty: 1 },
        { ref: 'e2', tag: 'div', txt: 'Contact john.doe@example.com for help' },
        { ref: 'e3', tag: 'button', txt: 'Sign in' },
      ] },
    };
    const rb = await post('/v1/task', bad);
    assert.equal(rb.status, 422, `expected 422 for raw PII, got ${rb.status}`);
    assert.equal(rb.json.error, 'privacy-gate-reject');

    // ---- rate limiting exists (burst > limit → 429)
    let saw429 = false;
    for (let i = 0; i < 80; i++) {
      const rr = await fetch(`${BASE}/healthz`);
      if (rr.status === 429) { saw429 = true; break; }
    }
    assert.ok(saw429, 'rate limiter should trip under burst');

    console.log('\n✔ e2e passed: protocol, placeholder planning, privacy gate, rate limit, latency');
  } finally {
    srv.kill('SIGTERM');
    await sleep(200);
  }
}

main().catch(e => { console.error(e); process.exit(1); });
