/**
 * Remote adapter — OpenAI-compatible chat-completions endpoint
 * (works with OpenAI, OpenRouter, Together, Groq, vLLM, Ollama /v1, LM Studio).
 *
 * The system prompt teaches the model the redaction scheme: it sees
 * placeholders like [EMAIL_1] and must reference them (or element refs) in
 * its action plan. Secrets are never resolved server-side.
 */
import { ACTION_TYPES } from '../extension/shared/protocol.js';

const SYSTEM_PROMPT = `You are Sentinel's server-side reasoning core for a privacy-preserving browser agent.

The client redacted sensitive content BEFORE sending this payload:
- Screenshot: regions containing PII/secrets are blurred/pixelated/blacked-out.
- Text: sensitive values are replaced by typed placeholders like [EMAIL_1], [PERSON_2], [CARD_1].
- Secret values (passwords, OTP, CVV) appear ONLY as [PASSWORD_N] / [OTP_N] / [CVV_N] placeholders. The client will substitute the real value locally from its vault when executing a "type" action. NEVER invent a secret value; just reference the placeholder.
- Redaction map entries give the placeholder → bounding box on the image.

You receive: the user's goal, a redacted screenshot (base64 JPEG, when vision is enabled), and DOM metadata: elements[] with {ref, tag, role, rect:[x,y,w,h], key, ph, txt, opts, empty}.

Respond with STRICT JSON only:
{
  "summary": "one short sentence of progress/plan",
  "actions": [
    {"action":"click","el":{"ref":"e12","txt":"Buy now"}},
    {"action":"type","el":{"ref":"e7"},"value":"[EMAIL_1]"},
    {"action":"type","el":{"ref":"e8"},"value":"[PASSWORD_1]"},
    {"action":"scroll","amount":600},
    {"action":"submit","el":{"ref":"e15"}},
    {"action":"wait","ms":1200},
    {"action":"done"},
    {"action":"fail","reason":"not found"}
  ],
  "confidence": 0.0-1.0
}

Rules:
- Prefer 1-3 actions per turn. The client re-captures the screen after each turn, so plan incrementally.
- Use el.ref from metadata. Include el.txt for click targets to aid the client's fallback matching.
- Only reference placeholders that appear in the provided context — do not fabricate values that look like real PII or secrets.
- If the goal is complete, return {"action":"done"}.
- If the screen cannot serve the goal, return {"action":"fail"} or "ask_user".
- Actions allowed: ${ACTION_TYPES.join(', ')}.`;

/** Parse the model response into actions; throws on non-JSON. */
export function parseModelResponse(content) {
  let text = content.trim();
  // strip markdown fences if present
  const fence = /```(?:json)?\s*([\s\S]*?)```/.exec(text);
  if (fence) text = fence[1].trim();
  const start = text.indexOf('{');
  const end = text.lastIndexOf('}');
  if (start === -1 || end === -1) throw new Error('model did not return JSON');
  const obj = JSON.parse(text.slice(start, end + 1));
  const actions = Array.isArray(obj.actions) ? obj.actions : [];
  const valid = actions.filter(a =>
    a && typeof a.action === 'string' && ACTION_TYPES.includes(a.action) &&
    (a.action === 'done' || a.action === 'fail' || a.action === 'ask_user' || a.action === 'wait' || a.action === 'scroll' || a.el || a.url || a.value !== undefined)
  );
  return { summary: String(obj.summary || ''), actions: valid, confidence: Number(obj.confidence || 0.5) };
}

/**
 * @param {{baseUrl, apiKey, model, vision}} cfg
 * @param {{prompt, meta, imageB64, redactionMap, step, history}} ctx
 */
export async function callRemote(cfg, ctx) {
  const userContent = [];
  const metaStr = JSON.stringify({
    url: ctx.meta?.url,
    title: ctx.meta?.title,
    heading: ctx.meta?.heading,
    elements: ctx.meta?.elements,
    redactionMap: ctx.redactionMap,
  });
  userContent.push({ type: 'text', text: `USER GOAL: ${ctx.prompt}\n\nSTEP: ${ctx.step}\n\nPAGE METADATA (sanitized):\n${metaStr}` });
  if (cfg.vision && ctx.imageB64) {
    userContent.push({ type: 'image_url', image_url: { url: `data:image/jpeg;base64,${ctx.imageB64}` } });
  }

  const messages = [
    { role: 'system', content: SYSTEM_PROMPT },
    ...ctx.history.slice(-6),
    { role: 'user', content: cfg.vision ? userContent : userContent.map(c => ({ type: 'text', text: c.text })).filter(Boolean) },
  ];

  const ctrl = new AbortController();
  const to = setTimeout(() => ctrl.abort(), 25000);
  try {
    const res = await fetch(cfg.baseUrl.replace(/\/$/, '') + '/chat/completions', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        ...(cfg.apiKey ? { Authorization: `Bearer ${cfg.apiKey}` } : {}),
      },
      body: JSON.stringify({
        model: cfg.model,
        messages,
        temperature: 0.1,
        max_tokens: 700,
        response_format: { type: 'json_object' },
      }),
      signal: ctrl.signal,
    });
    if (!res.ok) throw new Error(`remote ${res.status}: ${(await res.text()).slice(0, 200)}`);
    const data = await res.json();
    const content = data.choices?.[0]?.message?.content || '';
    return parseModelResponse(content);
  } finally {
    clearTimeout(to);
  }
}
