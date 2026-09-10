/**
 * Sentinel — Privacy-first browser vision agent.
 * Shared DOM extraction: traverses the DOM and produces a compact, structured
 * "screen state" of interactive elements with stable refs and visual geometry.
 *
 * The screen state is the NON-SENSITIVE part of the page: it contains
 * element descriptors (role, visible text, bounding boxes). Sensitive *values*
 * are replaced by place-holders by the caller (see content.js collect()).
 */
import { SENSITIVE_LABELS } from '../shared/pii-patterns.js';

let refCounter = 0;
export function resetRefs() { refCounter = 0; }

export function assignRef(el) {
  if (el.dataset.sref) return el.dataset.sref;
  const ref = `e${(++refCounter).toString(36)}`;
  try { el.dataset.sref = ref; } catch { /* svg etc. */ }
  return ref;
}

function isVisible(el) {
  const r = el.getBoundingClientRect();
  if (r.width < 2 || r.height < 2) return false;
  const s = getComputedStyle(el);
  if (s.visibility === 'hidden' || s.display === 'none') return false;
  if (parseFloat(s.opacity || '1') < 0.15) return false;
  // element must intersect the viewport (it is what a screenshot sees)
  const vw = window.innerWidth, vh = window.innerHeight;
  if (r.bottom < -40 || r.top > vh + 40 || r.right < -40 || r.left > vw + 40) return false;
  return true;
}

function roleOf(el) {
  const tag = el.tagName.toLowerCase();
  if (tag === 'button' || (el.getAttribute('role') === 'button')) return 'button';
  if (tag === 'a' && el.hasAttribute('href')) return 'link';
  if (tag === 'select') return 'select';
  if (tag === 'textarea') return 'textarea';
  if (tag === 'input') {
    const t = (el.getAttribute('type') || 'text').toLowerCase();
    return t;
  }
  if (el.isContentEditable) return 'textbox';
  return tag;
}

function sensitivityRoleOf(el) {
  const ac = (el.getAttribute('autocomplete') || '').toLowerCase();
  if (ac) return ac;
  const type = (el.getAttribute('type') || '').toLowerCase();
  if (type === 'password') return 'password';
  const hay = `${el.id} ${el.getAttribute('name') || ''} ${el.getAttribute('placeholder') || ''} ${labelFor(el)}`.toLowerCase();
  for (const s of SENSITIVE_LABELS) {
    if (hay.includes(s)) return s.replace(/\s+/g, '-');
  }
  return '';
}

function labelFor(el) {
  if (el.id) {
    const l = document.querySelector(`label[for="${CSS.escape(el.id)}"]`);
    if (l) return l.textContent || '';
  }
  const wrap = el.closest('label');
  if (wrap) return wrap.textContent || '';
  return '';
}

function ownText(el) {
  let out = '';
  for (const n of el.childNodes) {
    if (n.nodeType === Node.TEXT_NODE) out += n.textContent;
  }
  return out.replace(/\s+/g, ' ').trim();
}

function nearestHeading() {
  let h = null;
  for (const cand of document.querySelectorAll('h1,h2,h3,legend,[role="heading"]')) {
    const r = cand.getBoundingClientRect();
    if (r.width > 0) h = cand; // last visible heading above? keep simple: last visible
  }
  return h ? ownText(h) : document.title;
}

function fieldKeyOf(el) {
  return (el.getAttribute('name') || el.id || el.getAttribute('placeholder') || labelFor(el) || roleOf(el)).toString().toLowerCase().slice(0, 40);
}

function describe(el) {
  const tag = roleOf(el);
  const rect = el.getBoundingClientRect();
  const d = {
    ref: assignRef(el),
    tag,
    role: sensitivityRoleOf(el) || undefined,
    rect: [Math.round(rect.left), Math.round(rect.top), Math.round(rect.width), Math.round(rect.height)],
    key: fieldKeyOf(el),
  };
  if (tag === 'input' || tag === 'textarea') {
    const ph = el.getAttribute('placeholder');
    if (ph) d.ph = ph.slice(0, 60);
    if (el.required) d.req = 1;
    const t = el.value || '';
    if (t) d.empty = 0;
  } else if (tag === 'select') {
    d.opts = Array.from(el.querySelectorAll('option')).map(o => (o.textContent || '').trim().slice(0, 30)).filter(Boolean).slice(0, 6);
    d.empty = el.selectedIndex <= 0 ? 1 : 0;
  } else if (tag === 'button' || tag === 'link') {
    const txt = ownText(el) || el.getAttribute('aria-label') || el.getAttribute('title') || '';
    if (txt) d.txt = txt.slice(0, 60);
  }
  return d;
}

export function extractScreenState() {
  resetRefs();
  const selectors = 'a[href], button, input, select, textarea, [role="button"], [role="tab"], [contenteditable="true"], [onclick]';
  const els = Array.from(document.querySelectorAll(selectors)).filter(isVisible);
  // de-dup overlapping (e.g. <a><button/></a>): keep outermost
  const kept = [];
  for (const el of els) {
    const r = el.getBoundingClientRect();
    const dup = kept.some(k => {
      const kr = k.getBoundingClientRect();
      return Math.abs(kr.left - r.left) < 4 && Math.abs(kr.top - r.top) < 4 && Math.abs(kr.width - r.width) < 4;
    });
    if (!dup) kept.push(el);
  }
  const elements = kept.slice(0, 120).map(describe);
  return {
    url: location.origin + location.pathname,
    title: (document.title || '').slice(0, 80),
    heading: nearestHeading(),
    viewport: [window.innerWidth, window.innerHeight],
    scrollY: Math.round(window.scrollY),
    docHeight: Math.round(document.documentElement.scrollHeight),
    elements,
  };
}
