/**
 * Sentinel server — central reasoning node. Receives ONLY sanitized payloads
 * (placeholders + structural metadata + redacted JPEG). Enforces the privacy
 * contract at the door (leak tripwire) and plans actions via a pluggable
 * adapter:
 *   mock   — deterministic heuristic planner (offline demo / e2e tests)
 *   remote — OpenAI-compatible endpoint (Ollama, vLLM, OpenRouter, OpenAI…)
 *   hybrid — remote first, mock fallback if remote fails or is unconfigured
 *
 * Zero npm dependencies for the server runtime (node >= 18).
 *
 * Env:
 *   SENTINEL_PORT=8787
 *   SENTINEL_MODE=hybrid|remote|mock
 *   SENTINEL_REMOTE_BASE_URL=http://localhost:11434/v1   (Ollama example)
 *   SENTINEL_REMOTE_API_KEY=...
 *   SENTINEL_REMOTE_MODEL=qwen2.5-vl:7b
 *   SENTINEL_REMOTE_VISION=1|0
 *   SENTINEL_RATE_LIMIT=60
 */
import http from 'node:http';
import { readFileSync, existsSync, statSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { gatePayload, auditLine, countPlaceholders } from './privacy-gate.js';
import { planNextActions } from './mock-planner.js';
import { callRemote } from './remote-adapter.js';

const PORT = Number(process.env.SENTINEL_PORT || 8787);
const MODE = (process.env.SENTINEL_MODE || 'hybrid').toLowerCase();

const remoteCfg = {
  baseUrl: process.env.SENTINEL_REMOTE_BASE_URL || '',
  apiKey: process.env.SENTINEL_REMOTE_API_KEY || '',
  model: process.env.SENTINEL_REMOTE_MODEL || 'qwen2.5-vl:7b',
  vision: (process.env.SENTINEL_REMOTE_VISION ?? '1') === '1',
};

/* ---------------- in-memory session store ---------------- */

const sessions = new Map(); // sessionKey → {prompt, step, history}
setInterval(() => {
  const now = Date.now();
  for (const [k, s] of sessions) if (now - s.lastSeen > 30 * 60_000) sessions.delete(k);
}, 60_000).unref();

/* ---------------- rate limiting ---------------- */

const hits = new Map(); // ip → count
const RATE_LIMIT = Number(process.env.SENTINEL_RATE_LIMIT || 60);
setInterval(() => hits.clear(), 60_000).unref();

function rateLimit(ip) {
  const n = (hits.get(ip) || 0) + 1;
  hits.set(ip, n);
  return n <= RATE_LIMIT;
}

/* ---------------- agent turn ---------------- */

async function handleAgent(body, res) {
  const gate = gatePayload(body);
  console.log(auditLine(body, gate));
  if (!gate.ok) {
    console.warn(`[privacy-gate] REJECTED: ${gate.reason} samples=${JSON.stringify(gate.samples || [])}`);
    res.writeHead(422, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ ok: false, error: 'privacy-gate-reject', reason: gate.reason, samples: gate.samples }));
    return;
  }

  const sessionKey = String(body.sessionKey || 'default');
  let session = sessions.get(sessionKey);
  if (!session || body.type === 'TASK_START') {
    session = { prompt: body.prompt, step: 0, history: [] };
    sessions.set(sessionKey, session);
  }
  session.step++;
  session.lastSeen = Date.now();

  const ctx = {
    prompt: session.prompt,
    meta: body.meta,
    imageB64: body.image,
    redactionMap: body.redactionMap || [],
    step: session.step,
    history: session.history,
  };

  let plan = null;
  let adapter = 'mock';
  const t0 = Date.now();

  if (MODE === 'remote' || MODE === 'hybrid') {
    if (remoteCfg.baseUrl) {
      try {
        plan = await callRemote(remoteCfg, ctx);
        adapter = 'remote';
      } catch (e) {
        console.warn(`[remote] failed: ${e.message}${MODE === 'hybrid' ? ' — falling back to mock' : ''}`);
        plan = null;
      }
      if (MODE === 'remote' && !plan) {
        res.writeHead(502, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ ok: false, error: 'remote adapter failed' }));
        return;
      }
    } else if (MODE === 'remote') {
      res.writeHead(500, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ ok: false, error: 'SENTINEL_REMOTE_BASE_URL not set' }));
      return;
    }
    // hybrid + no remote configured → mock
  }

  if (!plan) {
    plan = planNextActions({ prompt: ctx.prompt, meta: body.meta, redactionMap: gate.redactionMap, step: session.step });
    adapter = 'mock';
  }

  session.history.push({ role: 'assistant', content: plan.summary });

  res.writeHead(200, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify({
    ok: true,
    summary: plan.summary,
    actions: plan.actions,
    adapter,
    sessionStep: session.step,
    ms: Date.now() - t0,
    privacy: {
      gate: 'pass',
      placeholders: Object.entries(countPlaceholders(body)).map(([type, n]) => `${type}:${n}`),
      note: 'Server operates exclusively on placeholders and redacted imagery.',
    },
  }));
}

/* ---------------- HTTP plumbing ---------------- */

const server = http.createServer(async (req, res) => {
  const ip = req.socket.remoteAddress || 'unknown';
  if (!rateLimit(ip)) {
    res.writeHead(429, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ ok: false, error: 'rate limited' }));
    return;
  }

  if (req.method === 'GET' && req.url === '/healthz') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ ok: true, mode: MODE, remoteConfigured: !!remoteCfg.baseUrl }));
    return;
  }

  if (req.method === 'GET' && req.url === '/v1/stats') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({
      ok: true,
      sessions: sessions.size,
      mode: MODE,
      remoteConfigured: !!remoteCfg.baseUrl,
    }));
    return;
  }

  if (req.method === 'POST' && (req.url === '/v1/task' || req.url === '/v1/agent')) {
    let raw = '';
    let size = 0;
    const MAX = 6 * 1024 * 1024; // redacted JPEG ≈ 200–400 KB; hard cap 6 MB
    let tooBig = false;
    req.on('data', c => {
      size += c.length;
      if (size > MAX) { tooBig = true; req.destroy(); }
      else raw += c;
    });
    req.on('end', () => {
      if (tooBig) return;
      try {
        const body = JSON.parse(raw || '{}');
        handleAgent(body, res).catch(e => {
          console.error('[agent]', e);
          if (!res.headersSent) {
            res.writeHead(500, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ ok: false, error: String(e?.message || e) }));
          }
        });
      } catch (e) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ ok: false, error: 'bad json' }));
      }
    });
    return;
  }

  // static demo hosting (same origin as the API — mirrors production layout)
  if (req.method === 'GET' && serveStatic(req.url, res)) return;

  res.writeHead(404, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify({ ok: false, error: 'not found' }));
});

/* ---------------- static files (demo/) ---------------- */

const DEMO_DIR = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', 'demo');
const MIME = {
  '.html': 'text/html; charset=utf-8', '.css': 'text/css', '.js': 'text/javascript',
  '.png': 'image/png', '.svg': 'image/svg+xml', '.ico': 'image/x-icon', '.json': 'application/json',
};

function serveStatic(url, res) {
  let p;
  try { p = decodeURIComponent(url.split('?')[0]); } catch { return false; }
  if (p === '/' || p === '') p = '/index.html';
  const full = path.normalize(path.join(DEMO_DIR, p));
  if (!full.startsWith(DEMO_DIR + path.sep) && full !== DEMO_DIR) return false; // traversal guard
  if (!existsSync(full) || !statSync(full).isFile()) return false;
  res.writeHead(200, { 'Content-Type': MIME[path.extname(full).toLowerCase()] || 'application/octet-stream' });
  res.end(readFileSync(full));
  return true;
}

server.listen(PORT, () => {
  console.log(`🛡  Sentinel server on :${PORT} (mode=${MODE}${remoteCfg.baseUrl ? ', remote=' + remoteCfg.baseUrl : ', mock-only'})`);
});

function shutdown() {
  server.close(() => process.exit(0));
  setTimeout(() => process.exit(0), 1500).unref();
}
process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);
