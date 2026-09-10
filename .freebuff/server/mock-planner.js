/**
 * Deterministic heuristic planner — the offline brain of the demo & tests.
 * Understands the redaction scheme: it plans typing with [TYPE_N]
 * placeholders and leaves secrets ([PASSWORD_N]) to the client vault.
 *
 * This is intentionally "good enough" for the demo pages so the whole
 * end-to-end loop (redact → server → execute → verify) runs without any
 * cloud dependency. The remote adapter handles the general case.
 */
import { PERSON_TEST_NAMES } from '../extension/shared/pii-patterns.js';

function findEl(meta, pred) {
  return (meta?.elements || []).find(pred);
}

/** Wrap a branch result: an intent that matched but found no actionable
 *  elements means the task is (likely) already complete. */
function finish(actions, summary) {
  if (!actions.length) return { actions: [{ action: 'done' }], summary: `${summary} — nothing to do, task complete` };
  return { actions, summary };
}

function byKeyAny(meta, ...keys) {
  return findEl(meta, el => keys.some(k => (el.key || '').includes(k)));
}

function byTextAny(meta, ...texts) {
  return findEl(meta, el => el.txt && texts.some(t => el.txt.toLowerCase().includes(t)));
}

/** Fake known-credential store: [PASSWORD_1] belongs to [EMAIL_1]'s account. */
function knownSecretFor(emailPh) {
  // The mock planner "knows" that gmail/github demo forms want the vault's
  // first password. The client resolves the placeholder locally.
  return '[PASSWORD_1]';
}

/**
 * @param {{prompt:string, meta:object, redactionMap:Map, step:number}} ctx
 * @returns {{actions: object[], summary: string}}
 */
export function planNextActions({ prompt, meta, redactionMap, step }) {
  const p = (prompt || '').toLowerCase();
  const actions = [];
  const add = a => actions.push(a);

  // ---------- intent: checkout / purchase ----------
  if (/checkout|buy|purchase|pay|order/.test(p)) {
    const email = byKeyAny(meta, 'email');
    if (email && email.empty) add({ action: 'type', el: { ref: email.ref }, value: '[EMAIL_1]' });
    const name = byKeyAny(meta, 'name', 'fname', 'fullname') || byTextAny(meta, 'name');
    if (name && name.empty) add({ action: 'type', el: { ref: name.ref }, value: '[PERSON_1]' });
    const addr = byKeyAny(meta, 'address', 'street', 'addr');
    if (addr && addr.empty) add({ action: 'type', el: { ref: addr.ref }, value: '[ADDRESS_1]' });
    const city = byKeyAny(meta, 'city');
    if (city && city.empty) add({ action: 'type', el: { ref: city.ref }, value: 'Mumbai' });
    const zip = byKeyAny(meta, 'zip', 'postal', 'pincode');
    if (zip && zip.empty) add({ action: 'type', el: { ref: zip.ref }, value: '400001' });
    const card = byKeyAny(meta, 'card', 'cc-number');
    if (card && card.empty) add({ action: 'type', el: { ref: card.ref }, value: '[CARD_1]' });
    const cvv = byKeyAny(meta, 'cvv', 'cvc');
    if (cvv && cvv.empty) add({ action: 'type', el: { ref: cvv.ref }, value: '[CVV_1]' });
    const pay = byTextAny(meta, 'pay now', 'place order', 'checkout', 'buy now', 'confirm');
    if (pay) { add({ action: 'click', el: { ref: pay.ref, txt: pay.txt } }); return finish(actions, `checkout: filled ${actions.filter(a => a.action === 'type').length} fields, clicking "${pay.txt}"`); }
    const submit = byTextAny(meta, 'submit', 'continue', 'next');
    if (submit) add({ action: 'click', el: { ref: submit.ref, txt: submit.txt } });
    return finish(actions, `checkout step: ${actions.length} action(s)`);
  }

  // ---------- intent: login / sign in ----------
  if (/\b(?:log ?(?:me ?)?(?:in|into|on)|sign ?(?:in|on)|authenticate)\b/.test(p) || /\blogin\b/.test(p)) {
    const user = byKeyAny(meta, 'email', 'username', 'user', 'login');
    if (user && user.empty) add({ action: 'type', el: { ref: user.ref }, value: user.key.includes('user') ? '[PERSON_1]' : '[EMAIL_1]' });
    const pass = byKeyAny(meta, 'password', 'passphrase');
    if (pass) add({ action: 'type', el: { ref: pass.ref }, value: knownSecretFor('[EMAIL_1]') });
    const btn = byTextAny(meta, 'sign in', 'log in', 'login', 'submit') || findEl(meta, el => el.tag === 'button');
    if (btn) add({ action: 'click', el: { ref: btn.ref, txt: btn.txt } });
    return finish(actions, `login: ${actions.length} action(s)`);
  }

  // ---------- intent: search ----------
  if (/search|find|look up/.test(p)) {
    const box = byKeyAny(meta, 'search', 'q') || findEl(meta, el => el.tag === 'input' && !el.role);
    if (box) {
      const m = /(?:search|find|look up)(?:\s+for)?\s+"([^"]+)"/i.exec(prompt) || /(?:search|find)\s+(?:for\s+)?(.+)$/i.exec(prompt);
      const term = m ? m[1] : 'headphones';
      add({ action: 'type', el: { ref: box.ref }, value: term });
      const btn = byTextAny(meta, 'search', 'go') || findEl(meta, el => el.tag === 'button');
      if (btn) add({ action: 'click', el: { ref: btn.ref, txt: btn.txt } });
    }
    return finish(actions, 'search: typed query and submitted');
  }

  // ---------- intent: newsletter / form fill ----------
  if (/subscribe|newsletter|register|sign ?up|feedback|contact/.test(p) || /email/.test(p)) {
    const email = byKeyAny(meta, 'email') || findEl(meta, el => el.tag === 'input' && (el.key.includes('email') || el.ph?.includes('@')));
    if (email && email.empty) add({ action: 'type', el: { ref: email.ref }, value: '[EMAIL_1]' });
    const msg = byKeyAny(meta, 'message', 'comment', 'feedback');
    if (msg && msg.empty) add({ action: 'type', el: { ref: msg.ref }, value: 'Great product — keep it up!' });
    const btn = byTextAny(meta, 'subscribe', 'submit', 'send', 'sign up', 'register') || findEl(meta, el => el.tag === 'button');
    if (btn) add({ action: 'click', el: { ref: btn.ref, txt: btn.txt } });
    return finish(actions, `form: ${actions.length} action(s)`);
  }

  // ---------- fallback: navigation / scroll ----------
  if (/scroll|down|more|read/.test(p)) {
    add({ action: 'scroll', amount: 700 });
    return finish(actions, 'scrolled down');
  }

  return { actions: [{ action: 'done' }], summary: 'no matching intent — task marked done' };
}
