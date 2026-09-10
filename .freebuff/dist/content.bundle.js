(() => {
  // extension/shared/pii-patterns.js
  var PII_PATTERNS = [
    { type: "AADHAAR", re: /\b[2-9]\d{3}\s\d{4}\s\d{4}\b/g },
    { type: "AADHAAR", re: /\b[2-9]\d{11}\b/g },
    { type: "PAN", re: /\b[A-Z]{5}\d{4}[A-Z]\b/g },
    { type: "EMAIL", re: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g },
    { type: "PHONE", re: /\b(?:\+91[-.\s]?)?\d{2}[-.\s]?\d{4}[-.\s]?\d{4}\b/g },
    { type: "PHONE", re: /\b(?:\+?\d{1,3}[-.\s]?)?\d{5}[-.\s]?\d{5}\b/g },
    { type: "PHONE", re: /(?:\+?\d{1,3}[-.\s]?)?(?:\(\d{2,4}\)|\d{2,4})[-.\s]?\d{3,4}[-.\s]?\d{4}\b/g },
    { type: "CARD", re: /\b(?:\d[ -]?){13,19}\b/g },
    { type: "CVV", re: /\bCVV(?:\s*\/?\s*CVC)?\s*[:\-]?\s*\d{3,4}\b/gi },
    { type: "MONEY", re: /(?:₹|Rs\.?|INR|USD|\$|€|£)\s?\d[\d,]*(?:\.\d+)?/g },
    { type: "DATE", re: /\b(?:0?[1-9]|[12]\d|3[01])[-\/](?:0?[1-9]|1[0-2])[-\/](?:\d{2}|\d{4})\b/g },
    { type: "DATE", re: /\b(?:0?[1-9]|1[0-2])\/(?:\d{2}|\d{4})\b/g },
    // MM/YY card expiry
    { type: "TIME", re: /\b(?:[01]?\d|2[0-3]):[0-5]\d(?::[0-5]\d)?\b/g },
    { type: "URL", re: /\bhttps?:\/\/[^\s<>"']+/g }
  ];
  var PII_PATTERNS_CTX = [
    { type: "SSN", re: /\b(?:SSN|Social Security)\s*[:\-]?\s*\d{3}-?\d{2}-?\d{4}\b/gi },
    { type: "SSN", re: /\b\d{3}-\d{2}-\d{4}\b/g },
    { type: "PERSON", re: /\b(?:mr\.?|mrs\.?|ms\.?|dr\.?|prof\.?)\s+[A-Z][a-z]+(?:\s+[A-Z][a-z]+){0,2}\b/g },
    { type: "PERSON", re: /\b[A-Z][a-z]+\s+[A-Z][a-z]+(?:\s+[A-Z][a-z]+)?\b/g },
    { type: "ADDRESS", re: /\b\d{1,5}\s+[A-Z][a-z]+(?:\s+[A-Za-z0-9'.-]+)*\s+(?:Street|St|Avenue|Ave|Road|Rd|Lane|Ln|Boulevard|Blvd|Drive|Dr|Nagar|Marg|Colony)\b\.?/g }
  ];
  var SENSITIVE_LABELS = [
    "password",
    "passcode",
    "pass phrase",
    "passphrase",
    "otp",
    "one time password",
    "card number",
    "card no",
    "cvv",
    "cvc",
    "card verification",
    "aadhaar",
    "aadhar",
    "aadhahaar",
    "pan",
    "ssn",
    "social security",
    "dob",
    "date of birth",
    "expiry",
    "expires",
    "account number",
    "ifsc"
  ];
  var HIGH_PRECISION_TYPES = ["EMAIL", "PHONE", "AADHAAR", "PAN", "CARD", "CVV", "SSN", "ADDRESS"];
  var REDACT_TYPES = [...HIGH_PRECISION_TYPES, "PERSON"];

  // extension/content/dom.js
  var refCounter = 0;
  function resetRefs() {
    refCounter = 0;
  }
  function assignRef(el) {
    if (el.dataset.sref) return el.dataset.sref;
    const ref = `e${(++refCounter).toString(36)}`;
    try {
      el.dataset.sref = ref;
    } catch {
    }
    return ref;
  }
  function isVisible(el) {
    const r = el.getBoundingClientRect();
    if (r.width < 2 || r.height < 2) return false;
    const s = getComputedStyle(el);
    if (s.visibility === "hidden" || s.display === "none") return false;
    if (parseFloat(s.opacity || "1") < 0.15) return false;
    const vw = window.innerWidth, vh = window.innerHeight;
    if (r.bottom < -40 || r.top > vh + 40 || r.right < -40 || r.left > vw + 40) return false;
    return true;
  }
  function roleOf(el) {
    const tag = el.tagName.toLowerCase();
    if (tag === "button" || el.getAttribute("role") === "button") return "button";
    if (tag === "a" && el.hasAttribute("href")) return "link";
    if (tag === "select") return "select";
    if (tag === "textarea") return "textarea";
    if (tag === "input") {
      const t = (el.getAttribute("type") || "text").toLowerCase();
      return t;
    }
    if (el.isContentEditable) return "textbox";
    return tag;
  }
  function sensitivityRoleOf(el) {
    const ac = (el.getAttribute("autocomplete") || "").toLowerCase();
    if (ac) return ac;
    const type = (el.getAttribute("type") || "").toLowerCase();
    if (type === "password") return "password";
    const hay = `${el.id} ${el.getAttribute("name") || ""} ${el.getAttribute("placeholder") || ""} ${labelFor(el)}`.toLowerCase();
    for (const s of SENSITIVE_LABELS) {
      if (hay.includes(s)) return s.replace(/\s+/g, "-");
    }
    return "";
  }
  function labelFor(el) {
    if (el.id) {
      const l = document.querySelector(`label[for="${CSS.escape(el.id)}"]`);
      if (l) return l.textContent || "";
    }
    const wrap = el.closest("label");
    if (wrap) return wrap.textContent || "";
    return "";
  }
  function ownText(el) {
    let out = "";
    for (const n of el.childNodes) {
      if (n.nodeType === Node.TEXT_NODE) out += n.textContent;
    }
    return out.replace(/\s+/g, " ").trim();
  }
  function nearestHeading() {
    let h = null;
    for (const cand of document.querySelectorAll('h1,h2,h3,legend,[role="heading"]')) {
      const r = cand.getBoundingClientRect();
      if (r.width > 0) h = cand;
    }
    return h ? ownText(h) : document.title;
  }
  function fieldKeyOf(el) {
    return (el.getAttribute("name") || el.id || el.getAttribute("placeholder") || labelFor(el) || roleOf(el)).toString().toLowerCase().slice(0, 40);
  }
  function describe(el) {
    const tag = roleOf(el);
    const rect = el.getBoundingClientRect();
    const d = {
      ref: assignRef(el),
      tag,
      role: sensitivityRoleOf(el) || void 0,
      rect: [Math.round(rect.left), Math.round(rect.top), Math.round(rect.width), Math.round(rect.height)],
      key: fieldKeyOf(el)
    };
    if (tag === "input" || tag === "textarea") {
      const ph = el.getAttribute("placeholder");
      if (ph) d.ph = ph.slice(0, 60);
      if (el.required) d.req = 1;
      const t = el.value || "";
      if (t) d.empty = 0;
    } else if (tag === "select") {
      d.opts = Array.from(el.querySelectorAll("option")).map((o) => (o.textContent || "").trim().slice(0, 30)).filter(Boolean).slice(0, 6);
      d.empty = el.selectedIndex <= 0 ? 1 : 0;
    } else if (tag === "button" || tag === "link") {
      const txt = ownText(el) || el.getAttribute("aria-label") || el.getAttribute("title") || "";
      if (txt) d.txt = txt.slice(0, 60);
    }
    return d;
  }
  function extractScreenState() {
    resetRefs();
    const selectors = 'a[href], button, input, select, textarea, [role="button"], [role="tab"], [contenteditable="true"], [onclick]';
    const els = Array.from(document.querySelectorAll(selectors)).filter(isVisible);
    const kept = [];
    for (const el of els) {
      const r = el.getBoundingClientRect();
      const dup = kept.some((k) => {
        const kr = k.getBoundingClientRect();
        return Math.abs(kr.left - r.left) < 4 && Math.abs(kr.top - r.top) < 4 && Math.abs(kr.width - r.width) < 4;
      });
      if (!dup) kept.push(el);
    }
    const elements = kept.slice(0, 120).map(describe);
    return {
      url: location.origin + location.pathname,
      title: (document.title || "").slice(0, 80),
      heading: nearestHeading(),
      viewport: [window.innerWidth, window.innerHeight],
      scrollY: Math.round(window.scrollY),
      docHeight: Math.round(document.documentElement.scrollHeight),
      elements
    };
  }

  // extension/content/content.js
  var audit = [];
  var overlayRoot = null;
  var pageHints = { sensitiveInputs: [] };
  function* textNodesUnder(root) {
    const walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT, {
      acceptNode(n2) {
        if (!n2.textContent || !n2.textContent.trim()) return NodeFilter.FILTER_REJECT;
        const p = n2.parentElement;
        if (!p) return NodeFilter.FILTER_REJECT;
        const tag = p.tagName;
        if (tag === "SCRIPT" || tag === "STYLE" || tag === "NOSCRIPT" || tag === "TEXTAREA") return NodeFilter.FILTER_REJECT;
        const r = p.getBoundingClientRect();
        if (r.width < 2 || r.height < 2) return NodeFilter.FILTER_REJECT;
        const s = getComputedStyle(p);
        if (s.visibility === "hidden" || s.display === "none") return NodeFilter.FILTER_REJECT;
        return NodeFilter.FILTER_ACCEPT;
      }
    });
    let n;
    while (n = walker.nextNode()) yield n;
  }
  function scanTextPii() {
    const found = [];
    for (const node of textNodesUnder(document.body)) {
      const text = node.textContent;
      const patterns = [...PII_PATTERNS, ...PII_PATTERNS_CTX];
      for (const { type, re } of patterns) {
        re.lastIndex = 0;
        let m;
        while (m = re.exec(text)) {
          const raw = m[0];
          if (raw.length < 4) continue;
          const range = document.createRange();
          range.setStart(node, m.index);
          range.setEnd(node, m.index + raw.length);
          const rect = range.getBoundingClientRect();
          if (rect.width < 1 || rect.height < 1) continue;
          found.push({ type, text: raw, rect: [rect.left, rect.top, rect.width, rect.height] });
          audit.push({ type, text: raw, rect: found[found.length - 1].rect, ts: Date.now(), src: "text" });
        }
      }
    }
    for (const inp of document.querySelectorAll("input,textarea")) {
      const hay = `${inp.id} ${inp.name || ""} ${inp.placeholder || ""}`.toLowerCase();
      if (!hay) continue;
      const hit = SENSITIVE_LABELS.find((s) => hay.includes(s));
      if (hit && inp.value && inp.type !== "password") {
        const r = inp.getBoundingClientRect();
        if (r.width > 2) {
          found.push({ type: "SECRET_FIELD", text: inp.value, rect: [r.left, r.top, r.width, r.height] });
          audit.push({ type: "SECRET_FIELD", text: inp.value, rect: found[found.length - 1].rect, ts: Date.now(), src: "field" });
        }
      }
    }
    for (const inp of document.querySelectorAll('input[type="password"]')) {
      const r = inp.getBoundingClientRect();
      if (r.width > 2) {
        found.push({ type: "PASSWORD_FIELD", text: inp.value || "password", rect: [r.left, r.top, r.width, r.height] });
        audit.push({ type: "PASSWORD_FIELD", rect: found[found.length - 1].rect, ts: Date.now(), src: "field" });
      }
    }
    return found;
  }
  function collectSensitiveInputMap() {
    const map = [];
    for (const el of document.querySelectorAll("input,textarea")) {
      const s = roleOfSensitive(el);
      if (s) map.push({ ref: el.dataset.sref || null, selector: cssPath(el), role: s, hasValue: !!el.value });
    }
    return map;
  }
  function roleOfSensitive(el) {
    const ac = (el.getAttribute("autocomplete") || "").toLowerCase();
    if (ac && /password|otp|one-time-code|cc-|card/.test(ac)) return ac;
    const type = (el.getAttribute("type") || "").toLowerCase();
    if (type === "password") return "password";
    const hay = `${el.id} ${el.name || ""} ${el.placeholder || ""} ${labelText(el)}`.toLowerCase();
    for (const s of SENSITIVE_LABELS) if (hay.includes(s)) return s.replace(/\s+/g, "-");
    return "";
  }
  function labelText(el) {
    if (el.id) {
      const l = document.querySelector(`label[for="${CSS.escape(el.id)}"]`);
      if (l) return l.textContent || "";
    }
    const wrap = el.closest("label");
    return wrap ? wrap.textContent || "" : "";
  }
  function cssPath(el) {
    const parts = [];
    let cur = el;
    while (cur && cur !== document.body && parts.length < 5) {
      let sel = cur.tagName.toLowerCase();
      if (cur.id) {
        sel += `#${cur.id}`;
        parts.unshift(sel);
        break;
      }
      const parent = cur.parentElement;
      if (parent) {
        const same = Array.from(parent.children).filter((c) => c.tagName === cur.tagName);
        if (same.length > 1) sel += `:nth-of-type(${same.indexOf(cur) + 1})`;
      }
      parts.unshift(sel);
      cur = parent;
    }
    return parts.join(" > ") || el.tagName.toLowerCase();
  }
  function collect() {
    const state = extractScreenState();
    pageHints = { sensitiveInputs: collectSensitiveInputMap() };
    return { ...state, hints: pageHints };
  }
  function ensureOverlayRoot() {
    if (overlayRoot && document.documentElement.contains(overlayRoot)) return overlayRoot;
    overlayRoot = document.createElement("div");
    overlayRoot.id = "sentinel-overlay-root";
    overlayRoot.style.cssText = "position:fixed;inset:0;pointer-events:none;z-index:2147483646;";
    document.documentElement.appendChild(overlayRoot);
    return overlayRoot;
  }
  function applyOverlay(rects, mode = "blur", labels = true) {
    const root = ensureOverlayRoot();
    root.innerHTML = "";
    const NS = "http://www.w3.org/2000/svg";
    const svg = document.createElementNS(NS, "svg");
    svg.setAttribute("width", "100%");
    svg.setAttribute("height", "100%");
    const defs = document.createElementNS(NS, "defs");
    const blurF = document.createElementNS(NS, "filter");
    blurF.id = "s-blur";
    blurF.innerHTML = '<feGaussianBlur stdDeviation="6"/>';
    defs.appendChild(blurF);
    const pixF = document.createElementNS(NS, "filter");
    pixF.id = "s-pix";
    pixF.innerHTML = '<feFlood flood-color="#111" result="b"/><feComposite in="b" in2="SourceGraphic" operator="in"/><feTile/>';
    defs.appendChild(pixF);
    svg.appendChild(defs);
    for (const r of rects) {
      const [x, y, w, h] = r.rect;
      const g = document.createElementNS(NS, "g");
      const bg = document.createElementNS(NS, "rect");
      bg.setAttribute("x", x);
      bg.setAttribute("y", y);
      bg.setAttribute("width", w);
      bg.setAttribute("height", h);
      bg.setAttribute("fill", mode === "solid" ? "#000" : "rgba(10,10,14,0.88)");
      if (mode === "blur") bg.setAttribute("filter", "url(#s-blur)");
      if (mode === "pixelate") bg.setAttribute("filter", "url(#s-pix)");
      bg.setAttribute("rx", 3);
      g.appendChild(bg);
      if (labels) {
        const t = document.createElementNS(NS, "text");
        t.setAttribute("x", x + 4);
        t.setAttribute("y", y + h - 4);
        t.setAttribute("font-size", Math.max(9, Math.min(14, h / 2.4)));
        t.setAttribute("font-family", "monospace");
        t.setAttribute("fill", "#00e5a0");
        t.textContent = `\u{1F6E1} ${r.type}${r.ph ? " \u2192 " + r.ph : ""}`;
        g.appendChild(t);
      }
      svg.appendChild(g);
    }
    root.appendChild(svg);
  }
  function clearOverlay() {
    if (overlayRoot) overlayRoot.innerHTML = "";
  }
  function findByRef(ref) {
    return document.querySelector(`[data-sref="${CSS.escape(ref)}"]`);
  }
  function findBySelector(sel) {
    try {
      return document.querySelector(sel);
    } catch {
      return null;
    }
  }
  function findByDescriptor(el) {
    if (!el) return null;
    if (el.ref) {
      const byRef = findByRef(el.ref);
      if (byRef) return byRef;
    }
    if (el.selector) {
      const bySel = findBySelector(el.selector);
      if (bySel) return bySel;
    }
    if (el.txt) {
      const cands = Array.from(document.querySelectorAll('button, a, [role="button"]'));
      const m = cands.find((c) => (c.textContent || "").trim().toLowerCase().includes(String(el.txt).toLowerCase()));
      if (m) return m;
    }
    return null;
  }
  function fireClick(el) {
    el.scrollIntoView({ block: "center", behavior: "instant" });
    el.dispatchEvent(new PointerEvent("pointerdown", { bubbles: true }));
    el.dispatchEvent(new MouseEvent("mousedown", { bubbles: true }));
    el.dispatchEvent(new PointerEvent("pointerup", { bubbles: true }));
    el.dispatchEvent(new MouseEvent("mouseup", { bubbles: true }));
    el.click();
  }
  function setValue(el, value) {
    el.scrollIntoView({ block: "center", behavior: "instant" });
    el.focus();
    const proto = el instanceof HTMLTextAreaElement ? HTMLTextAreaElement.prototype : HTMLInputElement.prototype;
    const desc = Object.getOwnPropertyDescriptor(proto, "value");
    if (desc && desc.set) desc.set.call(el, value);
    else el.value = value;
    el.dispatchEvent(new Event("input", { bubbles: true }));
    el.dispatchEvent(new Event("change", { bubbles: true }));
  }
  async function executeActions(actions, phMap = {}) {
    const results = [];
    for (const a of actions) {
      const res = { action: a.action, ok: false };
      try {
        switch (a.action) {
          case "click": {
            const el = findByDescriptor(a.el || a);
            if (!el) throw new Error("target not found");
            fireClick(el);
            res.ok = true;
            break;
          }
          case "type":
          case "set": {
            const el = findByDescriptor(a.el || a);
            if (!el) throw new Error("target not found");
            let value = a.value ?? "";
            if (/^\[[A-Z_]+_\d+\]$/.test(String(value)) && phMap[value] !== void 0) {
              value = phMap[value];
            }
            setValue(el, value);
            res.ok = true;
            break;
          }
          case "submit": {
            const el = findByDescriptor(a.el || a);
            const form = el && el.closest("form");
            if (form) {
              form.requestSubmit ? form.requestSubmit() : form.submit();
            } else if (el) fireClick(el);
            res.ok = true;
            break;
          }
          case "scroll": {
            const amount = a.amount || 600;
            window.scrollBy({ top: amount, behavior: "instant" });
            res.ok = true;
            break;
          }
          case "navigate": {
            if (a.url && /^https?:/i.test(a.url)) {
              location.href = a.url;
              res.ok = true;
            } else throw new Error("bad url");
            break;
          }
          case "wait": {
            await new Promise((r) => setTimeout(r, Math.min(5e3, a.ms || 800)));
            res.ok = true;
            break;
          }
          case "done":
            res.ok = true;
            res.done = true;
            break;
          case "fail":
            res.ok = true;
            res.failed = true;
            break;
          default:
            throw new Error(`unknown action ${a.action}`);
        }
      } catch (e) {
        res.error = String(e.message || e);
      }
      results.push(res);
    }
    return results;
  }
  chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
    (async () => {
      switch (msg?.type) {
        case "EXTRACT_STATE": {
          sendResponse({ ok: true, state: collect(), piiRects: scanTextPii().map((p) => ({ type: p.type, rect: p.rect, text: p.text })) });
          break;
        }
        case "APPLY_OVERLAY": {
          applyOverlay(msg.rects || [], msg.mode || "blur", msg.labels !== false);
          sendResponse({ ok: true });
          break;
        }
        case "CLEAR_OVERLAY": {
          clearOverlay();
          sendResponse({ ok: true });
          break;
        }
        case "EXECUTE_ACTIONS": {
          const results = await executeActions(msg.actions || [], msg.phMap || {});
          sendResponse({ ok: true, results });
          break;
        }
        case "GET_AUDIT": {
          sendResponse({ ok: true, audit });
          break;
        }
        default:
          sendResponse({ ok: false, error: "unknown msg" });
      }
    })();
    return true;
  });
})();
//# sourceMappingURL=data:application/json;base64,ewogICJ2ZXJzaW9uIjogMywKICAic291cmNlcyI6IFsiLi4vZXh0ZW5zaW9uL3NoYXJlZC9waWktcGF0dGVybnMuanMiLCAiLi4vZXh0ZW5zaW9uL2NvbnRlbnQvZG9tLmpzIiwgIi4uL2V4dGVuc2lvbi9jb250ZW50L2NvbnRlbnQuanMiXSwKICAic291cmNlc0NvbnRlbnQiOiBbIi8qKlxuICogU2hhcmVkIFBJSSBwYXR0ZXJuIGxpYnJhcnkgKHVzZWQgYnkgYm90aCB0aGUgY29udGVudCBzY3JpcHQgZm9yIHRleHQtUGlpXG4gKiBjYW5kaWRhdGVzLCB0aGUgcmVkYWN0b3IgZm9yIHBsYWNlaG9sZGVyIGludGVncml0eSwgYW5kIGJ5IHRoZSBzZXJ2ZXItc2lkZVxuICogcHJpdmFjeSBnYXRlIHRvIHZlcmlmeSBubyByYXcgUElJIHNsaXBwZWQgdGhyb3VnaCBpbiBtZXRhZGF0YS9wcm9tcHQpLlxuICpcbiAqIElNUE9SVEFOVDogVGhlc2UgcmVnZXhlcyBwb3dlciBCT1RIIGRldGVjdGlvbiAoY2xpZW50KSBhbmQgdGhlIHNlcnZlcidzXG4gKiBsZWFrLXRyaXB3aXJlLiBJZiBhIHBhdHRlcm4gaXMgcmVtb3ZlZCBmcm9tIGhlcmUsIHRoZSBwcml2YWN5IGdhdGUgZ2V0c1xuICogd2Vha2VyIHRvby4gS2VlcCBjb25zZXJ2YXRpdmUgKHByZWNpc2lvbi1maXJzdCBmb3IgdGhlIHRyaXB3aXJlKS5cbiAqL1xuZXhwb3J0IGNvbnN0IFBJSV9QQVRURVJOUyA9IFtcbiAgeyB0eXBlOiAnQUFESEFBUicsIHJlOiAvXFxiWzItOV1cXGR7M31cXHNcXGR7NH1cXHNcXGR7NH1cXGIvZyB9LFxuICB7IHR5cGU6ICdBQURIQUFSJywgcmU6IC9cXGJbMi05XVxcZHsxMX1cXGIvZyB9LFxuICB7IHR5cGU6ICdQQU4nLCByZTogL1xcYltBLVpdezV9XFxkezR9W0EtWl1cXGIvZyB9LFxuICB7IHR5cGU6ICdFTUFJTCcsIHJlOiAvXFxiW0EtWmEtejAtOS5fJSstXStAW0EtWmEtejAtOS4tXStcXC5bQS1aYS16XXsyLH1cXGIvZyB9LFxuICB7IHR5cGU6ICdQSE9ORScsIHJlOiAvXFxiKD86XFwrOTFbLS5cXHNdPyk/XFxkezJ9Wy0uXFxzXT9cXGR7NH1bLS5cXHNdP1xcZHs0fVxcYi9nIH0sXG4gIHsgdHlwZTogJ1BIT05FJywgcmU6IC9cXGIoPzpcXCs/XFxkezEsM31bLS5cXHNdPyk/XFxkezV9Wy0uXFxzXT9cXGR7NX1cXGIvZyB9LFxuICB7IHR5cGU6ICdQSE9ORScsIHJlOiAvKD86XFwrP1xcZHsxLDN9Wy0uXFxzXT8pPyg/OlxcKFxcZHsyLDR9XFwpfFxcZHsyLDR9KVstLlxcc10/XFxkezMsNH1bLS5cXHNdP1xcZHs0fVxcYi9nIH0sXG4gIHsgdHlwZTogJ0NBUkQnLCByZTogL1xcYig/OlxcZFsgLV0/KXsxMywxOX1cXGIvZyB9LFxuICB7IHR5cGU6ICdDVlYnLCByZTogL1xcYkNWVig/OlxccypcXC8/XFxzKkNWQyk/XFxzKls6XFwtXT9cXHMqXFxkezMsNH1cXGIvZ2kgfSxcbiAgeyB0eXBlOiAnTU9ORVknLCByZTogLyg/Olx1MjBCOXxSc1xcLj98SU5SfFVTRHxcXCR8XHUyMEFDfFx1MDBBMylcXHM/XFxkW1xcZCxdKig/OlxcLlxcZCspPy9nIH0sXG4gIHsgdHlwZTogJ0RBVEUnLCByZTogL1xcYig/OjA/WzEtOV18WzEyXVxcZHwzWzAxXSlbLVxcL10oPzowP1sxLTldfDFbMC0yXSlbLVxcL10oPzpcXGR7Mn18XFxkezR9KVxcYi9nIH0sXG4gIHsgdHlwZTogJ0RBVEUnLCByZTogL1xcYig/OjA/WzEtOV18MVswLTJdKVxcLyg/OlxcZHsyfXxcXGR7NH0pXFxiL2cgfSwgLy8gTU0vWVkgY2FyZCBleHBpcnlcbiAgeyB0eXBlOiAnVElNRScsIHJlOiAvXFxiKD86WzAxXT9cXGR8MlswLTNdKTpbMC01XVxcZCg/OjpbMC01XVxcZCk/XFxiL2cgfSxcbiAgeyB0eXBlOiAnVVJMJywgcmU6IC9cXGJodHRwcz86XFwvXFwvW15cXHM8PlwiJ10rL2cgfSxcbl07XG5cbi8qKlxuICogV29yZC1ib3VuZGFyeSArIGNvbnRleHQgcGF0dGVybnMgZm9yIG5hbWVzLCBTU04gYW5kIGFkZHJlc3NlcyAocmVnZXgtb25seVxuICogYXBwcm94aW1hdGlvbnM7IE5FUiBtb2RlbCBjYXRjaGVzIHRoZSByZXN0KS4gVGhlc2UgcnVuIGluIHRoZSBjb250ZW50XG4gKiBzY3JpcHQgdG8gY2F0Y2ggdGhpbmdzIHRoZSBORVIgbWlzc2VzIChhbmQgZm9yIGJyb3dzZXJzIHdpdGhvdXQgV2ViR1BVKS5cbiAqL1xuZXhwb3J0IGNvbnN0IFBJSV9QQVRURVJOU19DVFggPSBbXG4gIHsgdHlwZTogJ1NTTicsIHJlOiAvXFxiKD86U1NOfFNvY2lhbCBTZWN1cml0eSlcXHMqWzpcXC1dP1xccypcXGR7M30tP1xcZHsyfS0/XFxkezR9XFxiL2dpIH0sXG4gIHsgdHlwZTogJ1NTTicsIHJlOiAvXFxiXFxkezN9LVxcZHsyfS1cXGR7NH1cXGIvZyB9LFxuICB7IHR5cGU6ICdQRVJTT04nLCByZTogL1xcYig/Om1yXFwuP3xtcnNcXC4/fG1zXFwuP3xkclxcLj98cHJvZlxcLj8pXFxzK1tBLVpdW2Etel0rKD86XFxzK1tBLVpdW2Etel0rKXswLDJ9XFxiL2cgfSxcbiAgeyB0eXBlOiAnUEVSU09OJywgcmU6IC9cXGJbQS1aXVthLXpdK1xccytbQS1aXVthLXpdKyg/OlxccytbQS1aXVthLXpdKyk/XFxiL2cgfSxcbiAgeyB0eXBlOiAnQUREUkVTUycsIHJlOiAvXFxiXFxkezEsNX1cXHMrW0EtWl1bYS16XSsoPzpcXHMrW0EtWmEtejAtOScuLV0rKSpcXHMrKD86U3RyZWV0fFN0fEF2ZW51ZXxBdmV8Um9hZHxSZHxMYW5lfExufEJvdWxldmFyZHxCbHZkfERyaXZlfERyfE5hZ2FyfE1hcmd8Q29sb255KVxcYlxcLj8vZyB9LFxuXTtcblxuLyoqIExhYmVscyB3aG9zZSBuZWlnaGJvdXJpbmcgdGV4dCBpcyBjb25zaWRlcmVkIFBJSSBldmVuIGlmIHRoZSB2YWx1ZVxuICogIGRvZXNuJ3QgbWF0Y2ggYSBwYXR0ZXJuICh1c2VkIGJ5IGNvbnRlbnQtc2NyaXB0IERPTSBoZXVyaXN0aWNzKS4gKi9cbmV4cG9ydCBjb25zdCBTRU5TSVRJVkVfTEFCRUxTID0gW1xuICAncGFzc3dvcmQnLCAncGFzc2NvZGUnLCAncGFzcyBwaHJhc2UnLCAncGFzc3BocmFzZScsICdvdHAnLCAnb25lIHRpbWUgcGFzc3dvcmQnLFxuICAnY2FyZCBudW1iZXInLCAnY2FyZCBubycsICdjdnYnLCAnY3ZjJywgJ2NhcmQgdmVyaWZpY2F0aW9uJyxcbiAgJ2FhZGhhYXInLCAnYWFkaGFyJywgJ2FhZGhhaGFhcicsICdwYW4nLCAnc3NuJywgJ3NvY2lhbCBzZWN1cml0eScsXG4gICdkb2InLCAnZGF0ZSBvZiBiaXJ0aCcsICdleHBpcnknLCAnZXhwaXJlcycsICdhY2NvdW50IG51bWJlcicsICdpZnNjJyxcbl07XG5cbi8qKiBOYW1lcyBvZiBwZW9wbGUgdXNlZCBieSB0aGUgZTJlIG1vY2sgc2VydmVyIHRvIGNoZWNrIHRoZSBwcml2YWN5IGdhdGUuICovXG5leHBvcnQgY29uc3QgUEVSU09OX1RFU1RfTkFNRVMgPSBbXG4gICdKb2huIERvZScsICdQcml5YSBTaGFybWEnLCAnQWFyYXYgTWVodGEnLCAnQW5hbnlhIEl5ZXInLCAnUm9oYW4gVmVybWEnLFxuXTtcblxuLyoqIENvbW1vbiBzZW50ZW5jZSB3b3JkcyB0aGF0IHN0YXJ0IGNhcGl0YWxpemVkIGJ1dCBuZXZlciBiZWdpbiBhIHBlcnNvbidzXG4gKiAgbmFtZSBcdTIwMTQgdXNlZCB0byBzdXBwcmVzcyB0aGUgYmFyZSBUaXRsZS1DYXNlIFBFUlNPTiBoZXVyaXN0aWMuICovXG5leHBvcnQgY29uc3QgTkFNRV9TVE9QV09SRFMgPSBuZXcgU2V0KFtcbiAgJ215JywgJ3RoaXMnLCAndGhhdCcsICd5b3VyJywgJ291cicsICd0aGUnLCAnd2VsY29tZScsICd0ZWFtJywgJ29yZGVyJyxcbiAgJ3NpZ24nLCAnbG9nJywgJ3BheScsICdzdG9yZScsICdzaG9wJywgJ2NhcnQnLCAnaGVsbG8nLCAnaGknLCAnZGVhcicsICdraW5kJyxcbiAgJ3JlZ2FyZHMnLCAndGhhbmtzJywgJ3RoYW5rJywgJ3BsZWFzZScsICdhY2NvdW50JywgJ3Byb2ZpbGUnLCAndXNlcicsICdtZW1iZXInLFxuXSk7XG5cbi8qKiBTdHJlZXQgc3VmZml4ZXMgXHUyMDE0IFwiQmFrZXIgU3RyZWV0XCIgaXMgYW4gYWRkcmVzcywgbm90IGEgcGVyc29uLiAqL1xuZXhwb3J0IGNvbnN0IFNUUkVFVF9TVUZGSVhFUyA9IG5ldyBTZXQoW1xuICAnc3RyZWV0JywgJ3N0JywgJ2F2ZW51ZScsICdhdmUnLCAncm9hZCcsICdyZCcsICdsYW5lJywgJ2xuJywgJ2JvdWxldmFyZCcsXG4gICdibHZkJywgJ2RyaXZlJywgJ2RyJywgJ25hZ2FyJywgJ21hcmcnLCAnY29sb255JywgJ3BhcmsnLCAncGxhY2UnLFxuXSk7XG5cbi8qKiBIaWdoLXByZWNpc2lvbiB0eXBlczogbmVhci16ZXJvIGZhbHNlIHBvc2l0aXZlcyBcdTIxOTIgc2VydmVyIGhhcmQtcmVqZWN0cy4gKi9cbmV4cG9ydCBjb25zdCBISUdIX1BSRUNJU0lPTl9UWVBFUyA9IFsnRU1BSUwnLCAnUEhPTkUnLCAnQUFESEFBUicsICdQQU4nLCAnQ0FSRCcsICdDVlYnLCAnU1NOJywgJ0FERFJFU1MnXTtcblxuLyoqIFR5cGVzIHRoZSBjbGllbnQgcmVkYWN0cyBieSBkZWZhdWx0ICh2aXN1YWwgKyB0ZXh0KS4gTU9ORVkvREFURS9USU1FL1VSTFxuICogIGFwcGVhciBjb25zdGFudGx5IGluIG5vcm1hbCBVSSAocHJpY2VzLCB0aW1lc3RhbXBzLCBsaW5rcykgXHUyMDE0IHJlZGFjdGluZ1xuICogIHRoZW0gd291bGQgZGVzdHJveSB1c2FiaWxpdHksIHNvIHRoZXkgYXJlIGRldGVjdGVkIGZvciB0aGUgZXZhbCBidXQgbm90XG4gKiAgcmVkYWN0ZWQgYnkgZGVmYXVsdC4gKi9cbmV4cG9ydCBjb25zdCBSRURBQ1RfVFlQRVMgPSBbLi4uSElHSF9QUkVDSVNJT05fVFlQRVMsICdQRVJTT04nXTtcblxuLyoqXG4gKiBTZW50aW5lbCdzIHBsYWNlaG9sZGVyIGZvcm1hdDogW1RZUEVfTl0uIFVzZWQgYnkgcmVkYWN0b3IgJiBleGVjdXRvci5cbiAqL1xuZXhwb3J0IGNvbnN0IFBMQUNFSE9MREVSX1JFID0gL15cXFsoQUFESEFBUnxDQVJEfENWVnxQQU58RU1BSUx8UEhPTkV8UEVSU09OfEFERFJFU1N8TU9ORVl8REFURXxUSU1FfFVSTHxPUkd8U1NOfE1JU0MpXyhcXGQrKVxcXSQvO1xuXG5leHBvcnQgZnVuY3Rpb24gcGxhY2Vob2xkZXIodHlwZSwgbikgeyByZXR1cm4gYFske3R5cGV9XyR7bn1dYDsgfVxuXG4vKiogU3VwcHJlc3MgVGl0bGUtQ2FzZSBmYWxzZSBwb3NpdGl2ZXM6IHNlbnRlbmNlLWluaXRpYWwgY29tbW9uIHdvcmRzIGFuZFxuICogIHN0cmVldC1uYW1lIHRhaWxzIGFyZSBub3QgcGVvcGxlLiAqL1xuZnVuY3Rpb24gaXNGYWxzZU5hbWUodmFsdWUpIHtcbiAgY29uc3Qgd29yZHMgPSB2YWx1ZS50b0xvd2VyQ2FzZSgpLnNwbGl0KC9cXHMrLykuZmlsdGVyKEJvb2xlYW4pO1xuICBpZiAoIXdvcmRzLmxlbmd0aCkgcmV0dXJuIHRydWU7XG4gIGlmIChOQU1FX1NUT1BXT1JEUy5oYXMod29yZHNbMF0pIHx8IE5BTUVfU1RPUFdPUkRTLmhhcyh3b3Jkc1t3b3Jkcy5sZW5ndGggLSAxXSkpIHJldHVybiB0cnVlO1xuICBpZiAoU1RSRUVUX1NVRkZJWEVTLmhhcyh3b3Jkc1t3b3Jkcy5sZW5ndGggLSAxXSkpIHJldHVybiB0cnVlO1xuICByZXR1cm4gZmFsc2U7XG59XG5cbi8qKlxuICogRmluZCBQSUkgaW4gYSB0ZXh0IGJsb2IuIGBvcHRzLnR5cGVzYCByZXN0cmljdHMgd2hpY2ggZW50aXR5IHR5cGVzIGFyZVxuICogY29uc2lkZXJlZCAodGhlIHByaXZhY3kgZ2F0ZSBzY2FucyBvbmx5IGhpZ2gtcHJlY2lzaW9uIHR5cGVzOyB0aGUgZXZhbFxuICogc2NhbnMgZXZlcnl0aGluZykuXG4gKi9cbmV4cG9ydCBmdW5jdGlvbiBmaW5kUElJKHRleHQsIG9wdHMgPSB7fSkge1xuICBjb25zdCBvdXQgPSBbXTtcbiAgaWYgKCF0ZXh0KSByZXR1cm4gb3V0O1xuICBjb25zdCBhbGxvdyA9IG9wdHMudHlwZXM7XG4gIGNvbnN0IHdhbnQgPSB0ID0+ICFhbGxvdyB8fCBhbGxvdy5pbmNsdWRlcyh0KTtcbiAgZm9yIChjb25zdCBwIG9mIFsuLi5QSUlfUEFUVEVSTlMsIC4uLlBJSV9QQVRURVJOU19DVFhdKSB7XG4gICAgaWYgKCF3YW50KHAudHlwZSkpIGNvbnRpbnVlO1xuICAgIC8vIGtlZXAgdGhlICdnJyBmbGFnOiBleGVjIG11c3QgYWR2YW5jZSB0byBhdm9pZCBhbiBpbmZpbml0ZSBsb29wXG4gICAgY29uc3QgcmUgPSBuZXcgUmVnRXhwKHAucmUuc291cmNlLCBwLnJlLmZsYWdzKTtcbiAgICBsZXQgbTtcbiAgICB3aGlsZSAoKG0gPSByZS5leGVjKHRleHQpKSkge1xuICAgICAgY29uc3QgdmFsdWUgPSBtWzBdLnRyaW0oKTtcbiAgICAgIGlmICh2YWx1ZS5sZW5ndGggPCA0KSBjb250aW51ZTtcbiAgICAgIGlmIChwLnR5cGUgPT09ICdQRVJTT04nICYmIGlzRmFsc2VOYW1lKHZhbHVlKSkgY29udGludWU7XG4gICAgICBvdXQucHVzaCh7IHR5cGU6IHAudHlwZSwgdmFsdWUsIGluZGV4OiBtLmluZGV4LCBsZW5ndGg6IG1bMF0ubGVuZ3RoIH0pO1xuICAgIH1cbiAgfVxuICAvLyBzYW1lLXNwYW4gZHVwbGljYXRlcyAobXVsdGlwbGUgcGF0dGVybnMgbWF0Y2hpbmcgdGhlIHNhbWUgc3Bhbik6IGtlZXAgdGhlXG4gIC8vIG1vc3Qgc3BlY2lmaWMgdHlwZSAoc3RydWN0dXJlZCBJRHMgYmVhdCBnZW5lcmljIG51bWVyaWMgdHlwZXMpXG4gIGNvbnN0IFNQRUNJRklDSVRZID0gWydBQURIQUFSJywgJ1BBTicsICdDQVJEJywgJ0NWVicsICdTU04nLCAnRU1BSUwnLCAnUEhPTkUnLCAnQUREUkVTUycsICdQRVJTT04nLCAnTU9ORVknLCAnT1JHJywgJ0RBVEUnLCAnVElNRScsICdVUkwnLCAnTUlTQyddO1xuICBjb25zdCBieVNwYW4gPSBuZXcgTWFwKCk7XG4gIGZvciAoY29uc3QgZCBvZiBvdXQpIHtcbiAgICBjb25zdCBrZXkgPSBgJHtkLmluZGV4fToke2QubGVuZ3RofWA7XG4gICAgY29uc3QgcHJldiA9IGJ5U3Bhbi5nZXQoa2V5KTtcbiAgICBpZiAoIXByZXYgfHwgU1BFQ0lGSUNJVFkuaW5kZXhPZihkLnR5cGUpIDwgU1BFQ0lGSUNJVFkuaW5kZXhPZihwcmV2LnR5cGUpKSBieVNwYW4uc2V0KGtleSwgZCk7XG4gIH1cbiAgY29uc3QgZGVkdXBlZCA9IFsuLi5ieVNwYW4udmFsdWVzKCldLnNvcnQoKGEsIGIpID0+IGIubGVuZ3RoIC0gYS5sZW5ndGgpO1xuICAvLyBjb250YWlubWVudCBwcnVuaW5nOiBkcm9wIGRldGVjdGlvbnMgZnVsbHkgaW5zaWRlIGEgc3RyaWN0bHkgbG9uZ2VyIG9uZVxuICByZXR1cm4gZGVkdXBlZC5maWx0ZXIoZCA9PiAhZGVkdXBlZC5zb21lKG8gPT5cbiAgICBvICE9PSBkICYmIG8ubGVuZ3RoID4gZC5sZW5ndGggJiYgby5pbmRleCA8PSBkLmluZGV4ICYmIG8uaW5kZXggKyBvLmxlbmd0aCA+PSBkLmluZGV4ICsgZC5sZW5ndGgpKTtcbn1cblxuLyoqXG4gKiBOb24tc2Vuc2l0aXZpdHkgZ2F0ZSBoZWxwZXIgKHNlcnZlci1zaWRlKTogYSB0ZXh0IGJsb2IgZmFpbHMgaWYgaXQgbG9va3NcbiAqIGxpa2UgaXQgY29udGFpbnMgcmF3IGhpZ2gtcHJlY2lzaW9uIFBJSS4gUnVuIEFGVEVSIHRoZSBjbGllbnQgYWxyZWFkeSBzZW50XG4gKiBwbGFjZWhvbGRlcnMgb25seS5cbiAqL1xuZXhwb3J0IGZ1bmN0aW9uIGxvb2tzTGlrZVBJSSh0ZXh0LCBvcHRzID0ge30pIHtcbiAgcmV0dXJuIGZpbmRQSUkodGV4dCwgb3B0cykubGVuZ3RoID4gMDtcbn1cblxuLyoqIFN0cmljdGVyIHNlcnZlciBnYXRlOiByZWplY3QgdmFsdWVzIHRoYXQgbG9vayBsaWtlIHJhdyBzZWNyZXRzLiAqL1xuZXhwb3J0IGZ1bmN0aW9uIGxvb2tzTGlrZVNlY3JldCh0ZXh0KSB7XG4gIGlmICghdGV4dCkgcmV0dXJuIGZhbHNlO1xuICBpZiAoL1xcYlxcZHsxMywxOX1cXGIvLnRlc3QodGV4dCkpIHJldHVybiB0cnVlOyAvLyBjYXJkLWxpa2VcbiAgaWYgKC9cXGJbMi05XVxcZHsxMX1cXGIvLnRlc3QodGV4dCkpIHJldHVybiB0cnVlOyAvLyBhYWRoYWFyLWxpa2VcbiAgcmV0dXJuIGZhbHNlO1xufVxuIiwgIi8qKlxuICogU2VudGluZWwgXHUyMDE0IFByaXZhY3ktZmlyc3QgYnJvd3NlciB2aXNpb24gYWdlbnQuXG4gKiBTaGFyZWQgRE9NIGV4dHJhY3Rpb246IHRyYXZlcnNlcyB0aGUgRE9NIGFuZCBwcm9kdWNlcyBhIGNvbXBhY3QsIHN0cnVjdHVyZWRcbiAqIFwic2NyZWVuIHN0YXRlXCIgb2YgaW50ZXJhY3RpdmUgZWxlbWVudHMgd2l0aCBzdGFibGUgcmVmcyBhbmQgdmlzdWFsIGdlb21ldHJ5LlxuICpcbiAqIFRoZSBzY3JlZW4gc3RhdGUgaXMgdGhlIE5PTi1TRU5TSVRJVkUgcGFydCBvZiB0aGUgcGFnZTogaXQgY29udGFpbnNcbiAqIGVsZW1lbnQgZGVzY3JpcHRvcnMgKHJvbGUsIHZpc2libGUgdGV4dCwgYm91bmRpbmcgYm94ZXMpLiBTZW5zaXRpdmUgKnZhbHVlcypcbiAqIGFyZSByZXBsYWNlZCBieSBwbGFjZS1ob2xkZXJzIGJ5IHRoZSBjYWxsZXIgKHNlZSBjb250ZW50LmpzIGNvbGxlY3QoKSkuXG4gKi9cbmltcG9ydCB7IFNFTlNJVElWRV9MQUJFTFMgfSBmcm9tICcuLi9zaGFyZWQvcGlpLXBhdHRlcm5zLmpzJztcblxubGV0IHJlZkNvdW50ZXIgPSAwO1xuZXhwb3J0IGZ1bmN0aW9uIHJlc2V0UmVmcygpIHsgcmVmQ291bnRlciA9IDA7IH1cblxuZXhwb3J0IGZ1bmN0aW9uIGFzc2lnblJlZihlbCkge1xuICBpZiAoZWwuZGF0YXNldC5zcmVmKSByZXR1cm4gZWwuZGF0YXNldC5zcmVmO1xuICBjb25zdCByZWYgPSBgZSR7KCsrcmVmQ291bnRlcikudG9TdHJpbmcoMzYpfWA7XG4gIHRyeSB7IGVsLmRhdGFzZXQuc3JlZiA9IHJlZjsgfSBjYXRjaCB7IC8qIHN2ZyBldGMuICovIH1cbiAgcmV0dXJuIHJlZjtcbn1cblxuZnVuY3Rpb24gaXNWaXNpYmxlKGVsKSB7XG4gIGNvbnN0IHIgPSBlbC5nZXRCb3VuZGluZ0NsaWVudFJlY3QoKTtcbiAgaWYgKHIud2lkdGggPCAyIHx8IHIuaGVpZ2h0IDwgMikgcmV0dXJuIGZhbHNlO1xuICBjb25zdCBzID0gZ2V0Q29tcHV0ZWRTdHlsZShlbCk7XG4gIGlmIChzLnZpc2liaWxpdHkgPT09ICdoaWRkZW4nIHx8IHMuZGlzcGxheSA9PT0gJ25vbmUnKSByZXR1cm4gZmFsc2U7XG4gIGlmIChwYXJzZUZsb2F0KHMub3BhY2l0eSB8fCAnMScpIDwgMC4xNSkgcmV0dXJuIGZhbHNlO1xuICAvLyBlbGVtZW50IG11c3QgaW50ZXJzZWN0IHRoZSB2aWV3cG9ydCAoaXQgaXMgd2hhdCBhIHNjcmVlbnNob3Qgc2VlcylcbiAgY29uc3QgdncgPSB3aW5kb3cuaW5uZXJXaWR0aCwgdmggPSB3aW5kb3cuaW5uZXJIZWlnaHQ7XG4gIGlmIChyLmJvdHRvbSA8IC00MCB8fCByLnRvcCA+IHZoICsgNDAgfHwgci5yaWdodCA8IC00MCB8fCByLmxlZnQgPiB2dyArIDQwKSByZXR1cm4gZmFsc2U7XG4gIHJldHVybiB0cnVlO1xufVxuXG5mdW5jdGlvbiByb2xlT2YoZWwpIHtcbiAgY29uc3QgdGFnID0gZWwudGFnTmFtZS50b0xvd2VyQ2FzZSgpO1xuICBpZiAodGFnID09PSAnYnV0dG9uJyB8fCAoZWwuZ2V0QXR0cmlidXRlKCdyb2xlJykgPT09ICdidXR0b24nKSkgcmV0dXJuICdidXR0b24nO1xuICBpZiAodGFnID09PSAnYScgJiYgZWwuaGFzQXR0cmlidXRlKCdocmVmJykpIHJldHVybiAnbGluayc7XG4gIGlmICh0YWcgPT09ICdzZWxlY3QnKSByZXR1cm4gJ3NlbGVjdCc7XG4gIGlmICh0YWcgPT09ICd0ZXh0YXJlYScpIHJldHVybiAndGV4dGFyZWEnO1xuICBpZiAodGFnID09PSAnaW5wdXQnKSB7XG4gICAgY29uc3QgdCA9IChlbC5nZXRBdHRyaWJ1dGUoJ3R5cGUnKSB8fCAndGV4dCcpLnRvTG93ZXJDYXNlKCk7XG4gICAgcmV0dXJuIHQ7XG4gIH1cbiAgaWYgKGVsLmlzQ29udGVudEVkaXRhYmxlKSByZXR1cm4gJ3RleHRib3gnO1xuICByZXR1cm4gdGFnO1xufVxuXG5mdW5jdGlvbiBzZW5zaXRpdml0eVJvbGVPZihlbCkge1xuICBjb25zdCBhYyA9IChlbC5nZXRBdHRyaWJ1dGUoJ2F1dG9jb21wbGV0ZScpIHx8ICcnKS50b0xvd2VyQ2FzZSgpO1xuICBpZiAoYWMpIHJldHVybiBhYztcbiAgY29uc3QgdHlwZSA9IChlbC5nZXRBdHRyaWJ1dGUoJ3R5cGUnKSB8fCAnJykudG9Mb3dlckNhc2UoKTtcbiAgaWYgKHR5cGUgPT09ICdwYXNzd29yZCcpIHJldHVybiAncGFzc3dvcmQnO1xuICBjb25zdCBoYXkgPSBgJHtlbC5pZH0gJHtlbC5nZXRBdHRyaWJ1dGUoJ25hbWUnKSB8fCAnJ30gJHtlbC5nZXRBdHRyaWJ1dGUoJ3BsYWNlaG9sZGVyJykgfHwgJyd9ICR7bGFiZWxGb3IoZWwpfWAudG9Mb3dlckNhc2UoKTtcbiAgZm9yIChjb25zdCBzIG9mIFNFTlNJVElWRV9MQUJFTFMpIHtcbiAgICBpZiAoaGF5LmluY2x1ZGVzKHMpKSByZXR1cm4gcy5yZXBsYWNlKC9cXHMrL2csICctJyk7XG4gIH1cbiAgcmV0dXJuICcnO1xufVxuXG5mdW5jdGlvbiBsYWJlbEZvcihlbCkge1xuICBpZiAoZWwuaWQpIHtcbiAgICBjb25zdCBsID0gZG9jdW1lbnQucXVlcnlTZWxlY3RvcihgbGFiZWxbZm9yPVwiJHtDU1MuZXNjYXBlKGVsLmlkKX1cIl1gKTtcbiAgICBpZiAobCkgcmV0dXJuIGwudGV4dENvbnRlbnQgfHwgJyc7XG4gIH1cbiAgY29uc3Qgd3JhcCA9IGVsLmNsb3Nlc3QoJ2xhYmVsJyk7XG4gIGlmICh3cmFwKSByZXR1cm4gd3JhcC50ZXh0Q29udGVudCB8fCAnJztcbiAgcmV0dXJuICcnO1xufVxuXG5mdW5jdGlvbiBvd25UZXh0KGVsKSB7XG4gIGxldCBvdXQgPSAnJztcbiAgZm9yIChjb25zdCBuIG9mIGVsLmNoaWxkTm9kZXMpIHtcbiAgICBpZiAobi5ub2RlVHlwZSA9PT0gTm9kZS5URVhUX05PREUpIG91dCArPSBuLnRleHRDb250ZW50O1xuICB9XG4gIHJldHVybiBvdXQucmVwbGFjZSgvXFxzKy9nLCAnICcpLnRyaW0oKTtcbn1cblxuZnVuY3Rpb24gbmVhcmVzdEhlYWRpbmcoKSB7XG4gIGxldCBoID0gbnVsbDtcbiAgZm9yIChjb25zdCBjYW5kIG9mIGRvY3VtZW50LnF1ZXJ5U2VsZWN0b3JBbGwoJ2gxLGgyLGgzLGxlZ2VuZCxbcm9sZT1cImhlYWRpbmdcIl0nKSkge1xuICAgIGNvbnN0IHIgPSBjYW5kLmdldEJvdW5kaW5nQ2xpZW50UmVjdCgpO1xuICAgIGlmIChyLndpZHRoID4gMCkgaCA9IGNhbmQ7IC8vIGxhc3QgdmlzaWJsZSBoZWFkaW5nIGFib3ZlPyBrZWVwIHNpbXBsZTogbGFzdCB2aXNpYmxlXG4gIH1cbiAgcmV0dXJuIGggPyBvd25UZXh0KGgpIDogZG9jdW1lbnQudGl0bGU7XG59XG5cbmZ1bmN0aW9uIGZpZWxkS2V5T2YoZWwpIHtcbiAgcmV0dXJuIChlbC5nZXRBdHRyaWJ1dGUoJ25hbWUnKSB8fCBlbC5pZCB8fCBlbC5nZXRBdHRyaWJ1dGUoJ3BsYWNlaG9sZGVyJykgfHwgbGFiZWxGb3IoZWwpIHx8IHJvbGVPZihlbCkpLnRvU3RyaW5nKCkudG9Mb3dlckNhc2UoKS5zbGljZSgwLCA0MCk7XG59XG5cbmZ1bmN0aW9uIGRlc2NyaWJlKGVsKSB7XG4gIGNvbnN0IHRhZyA9IHJvbGVPZihlbCk7XG4gIGNvbnN0IHJlY3QgPSBlbC5nZXRCb3VuZGluZ0NsaWVudFJlY3QoKTtcbiAgY29uc3QgZCA9IHtcbiAgICByZWY6IGFzc2lnblJlZihlbCksXG4gICAgdGFnLFxuICAgIHJvbGU6IHNlbnNpdGl2aXR5Um9sZU9mKGVsKSB8fCB1bmRlZmluZWQsXG4gICAgcmVjdDogW01hdGgucm91bmQocmVjdC5sZWZ0KSwgTWF0aC5yb3VuZChyZWN0LnRvcCksIE1hdGgucm91bmQocmVjdC53aWR0aCksIE1hdGgucm91bmQocmVjdC5oZWlnaHQpXSxcbiAgICBrZXk6IGZpZWxkS2V5T2YoZWwpLFxuICB9O1xuICBpZiAodGFnID09PSAnaW5wdXQnIHx8IHRhZyA9PT0gJ3RleHRhcmVhJykge1xuICAgIGNvbnN0IHBoID0gZWwuZ2V0QXR0cmlidXRlKCdwbGFjZWhvbGRlcicpO1xuICAgIGlmIChwaCkgZC5waCA9IHBoLnNsaWNlKDAsIDYwKTtcbiAgICBpZiAoZWwucmVxdWlyZWQpIGQucmVxID0gMTtcbiAgICBjb25zdCB0ID0gZWwudmFsdWUgfHwgJyc7XG4gICAgaWYgKHQpIGQuZW1wdHkgPSAwO1xuICB9IGVsc2UgaWYgKHRhZyA9PT0gJ3NlbGVjdCcpIHtcbiAgICBkLm9wdHMgPSBBcnJheS5mcm9tKGVsLnF1ZXJ5U2VsZWN0b3JBbGwoJ29wdGlvbicpKS5tYXAobyA9PiAoby50ZXh0Q29udGVudCB8fCAnJykudHJpbSgpLnNsaWNlKDAsIDMwKSkuZmlsdGVyKEJvb2xlYW4pLnNsaWNlKDAsIDYpO1xuICAgIGQuZW1wdHkgPSBlbC5zZWxlY3RlZEluZGV4IDw9IDAgPyAxIDogMDtcbiAgfSBlbHNlIGlmICh0YWcgPT09ICdidXR0b24nIHx8IHRhZyA9PT0gJ2xpbmsnKSB7XG4gICAgY29uc3QgdHh0ID0gb3duVGV4dChlbCkgfHwgZWwuZ2V0QXR0cmlidXRlKCdhcmlhLWxhYmVsJykgfHwgZWwuZ2V0QXR0cmlidXRlKCd0aXRsZScpIHx8ICcnO1xuICAgIGlmICh0eHQpIGQudHh0ID0gdHh0LnNsaWNlKDAsIDYwKTtcbiAgfVxuICByZXR1cm4gZDtcbn1cblxuZXhwb3J0IGZ1bmN0aW9uIGV4dHJhY3RTY3JlZW5TdGF0ZSgpIHtcbiAgcmVzZXRSZWZzKCk7XG4gIGNvbnN0IHNlbGVjdG9ycyA9ICdhW2hyZWZdLCBidXR0b24sIGlucHV0LCBzZWxlY3QsIHRleHRhcmVhLCBbcm9sZT1cImJ1dHRvblwiXSwgW3JvbGU9XCJ0YWJcIl0sIFtjb250ZW50ZWRpdGFibGU9XCJ0cnVlXCJdLCBbb25jbGlja10nO1xuICBjb25zdCBlbHMgPSBBcnJheS5mcm9tKGRvY3VtZW50LnF1ZXJ5U2VsZWN0b3JBbGwoc2VsZWN0b3JzKSkuZmlsdGVyKGlzVmlzaWJsZSk7XG4gIC8vIGRlLWR1cCBvdmVybGFwcGluZyAoZS5nLiA8YT48YnV0dG9uLz48L2E+KToga2VlcCBvdXRlcm1vc3RcbiAgY29uc3Qga2VwdCA9IFtdO1xuICBmb3IgKGNvbnN0IGVsIG9mIGVscykge1xuICAgIGNvbnN0IHIgPSBlbC5nZXRCb3VuZGluZ0NsaWVudFJlY3QoKTtcbiAgICBjb25zdCBkdXAgPSBrZXB0LnNvbWUoayA9PiB7XG4gICAgICBjb25zdCBrciA9IGsuZ2V0Qm91bmRpbmdDbGllbnRSZWN0KCk7XG4gICAgICByZXR1cm4gTWF0aC5hYnMoa3IubGVmdCAtIHIubGVmdCkgPCA0ICYmIE1hdGguYWJzKGtyLnRvcCAtIHIudG9wKSA8IDQgJiYgTWF0aC5hYnMoa3Iud2lkdGggLSByLndpZHRoKSA8IDQ7XG4gICAgfSk7XG4gICAgaWYgKCFkdXApIGtlcHQucHVzaChlbCk7XG4gIH1cbiAgY29uc3QgZWxlbWVudHMgPSBrZXB0LnNsaWNlKDAsIDEyMCkubWFwKGRlc2NyaWJlKTtcbiAgcmV0dXJuIHtcbiAgICB1cmw6IGxvY2F0aW9uLm9yaWdpbiArIGxvY2F0aW9uLnBhdGhuYW1lLFxuICAgIHRpdGxlOiAoZG9jdW1lbnQudGl0bGUgfHwgJycpLnNsaWNlKDAsIDgwKSxcbiAgICBoZWFkaW5nOiBuZWFyZXN0SGVhZGluZygpLFxuICAgIHZpZXdwb3J0OiBbd2luZG93LmlubmVyV2lkdGgsIHdpbmRvdy5pbm5lckhlaWdodF0sXG4gICAgc2Nyb2xsWTogTWF0aC5yb3VuZCh3aW5kb3cuc2Nyb2xsWSksXG4gICAgZG9jSGVpZ2h0OiBNYXRoLnJvdW5kKGRvY3VtZW50LmRvY3VtZW50RWxlbWVudC5zY3JvbGxIZWlnaHQpLFxuICAgIGVsZW1lbnRzLFxuICB9O1xufVxuIiwgIi8qKlxuICogU2VudGluZWwgY29udGVudCBzY3JpcHQgXHUyMDE0IHJ1bnMgaW4gdGhlIHBhZ2UuIFJlc3BvbnNpYmlsaXRpZXM6XG4gKiAgMS4gQ29sbGVjdCB2aXNpYmxlLXRleHQgUElJIGNhbmRpZGF0ZSByZWN0cyAoZm9yIHRoZSB2aXNpb24gcmVkYWN0b3Inc1xuICogICAgIHRleHQgY2hhbm5lbCwgYW5kIGZvciBwbGFjZWhvbGRlciBhc3NpZ25tZW50KS5cbiAqICAyLiBFeHRyYWN0IHRoZSBub24tc2Vuc2l0aXZlIHNjcmVlbiBzdGF0ZSAoRE9NIG1ldGFkYXRhKS5cbiAqICAzLiBBcHBseSAvIGNsZWFyIHJlZGFjdGlvbiBvdmVybGF5cyAoY2FudmFzLWJhc2VkIHBlci1yZWN0KS5cbiAqICA0LiBFeGVjdXRlIGFwcHJvdmVkIHNlcnZlciBhY3Rpb25zIGxvY2FsbHkgKGNsaWNrL3R5cGUvc2Nyb2xsL3N1Ym1pdCkuXG4gKiAgNS4gS2VlcCBhIGxvY2FsIGF1ZGl0IGxlZGdlciBvZiBldmVyeXRoaW5nIHRoYXQgd2FzIHJlZGFjdGVkLlxuICovXG5pbXBvcnQgeyBleHRyYWN0U2NyZWVuU3RhdGUgfSBmcm9tICcuL2RvbS5qcyc7XG5pbXBvcnQgeyBQSUlfUEFUVEVSTlMsIFBJSV9QQVRURVJOU19DVFgsIFNFTlNJVElWRV9MQUJFTFMgfSBmcm9tICcuLi9zaGFyZWQvcGlpLXBhdHRlcm5zLmpzJztcblxuY29uc3QgYXVkaXQgPSBbXTsgLy8ge3R5cGUsIHRleHQsIHJlY3QsIHRzfSBcdTIwMTQgc3RheXMgbG9jYWxcbmxldCBvdmVybGF5Um9vdCA9IG51bGw7XG5sZXQgcGFnZUhpbnRzID0geyBzZW5zaXRpdmVJbnB1dHM6IFtdIH07XG5cbi8qIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLSAqL1xuLyogMS4gVGV4dCBQSUkgc2Nhbm5pbmcgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAqL1xuLyogLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tICovXG5cbmZ1bmN0aW9uKiB0ZXh0Tm9kZXNVbmRlcihyb290KSB7XG4gIGNvbnN0IHdhbGtlciA9IGRvY3VtZW50LmNyZWF0ZVRyZWVXYWxrZXIocm9vdCwgTm9kZUZpbHRlci5TSE9XX1RFWFQsIHtcbiAgICBhY2NlcHROb2RlKG4pIHtcbiAgICAgIGlmICghbi50ZXh0Q29udGVudCB8fCAhbi50ZXh0Q29udGVudC50cmltKCkpIHJldHVybiBOb2RlRmlsdGVyLkZJTFRFUl9SRUpFQ1Q7XG4gICAgICBjb25zdCBwID0gbi5wYXJlbnRFbGVtZW50O1xuICAgICAgaWYgKCFwKSByZXR1cm4gTm9kZUZpbHRlci5GSUxURVJfUkVKRUNUO1xuICAgICAgY29uc3QgdGFnID0gcC50YWdOYW1lO1xuICAgICAgaWYgKHRhZyA9PT0gJ1NDUklQVCcgfHwgdGFnID09PSAnU1RZTEUnIHx8IHRhZyA9PT0gJ05PU0NSSVBUJyB8fCB0YWcgPT09ICdURVhUQVJFQScpIHJldHVybiBOb2RlRmlsdGVyLkZJTFRFUl9SRUpFQ1Q7XG4gICAgICBjb25zdCByID0gcC5nZXRCb3VuZGluZ0NsaWVudFJlY3QoKTtcbiAgICAgIGlmIChyLndpZHRoIDwgMiB8fCByLmhlaWdodCA8IDIpIHJldHVybiBOb2RlRmlsdGVyLkZJTFRFUl9SRUpFQ1Q7XG4gICAgICBjb25zdCBzID0gZ2V0Q29tcHV0ZWRTdHlsZShwKTtcbiAgICAgIGlmIChzLnZpc2liaWxpdHkgPT09ICdoaWRkZW4nIHx8IHMuZGlzcGxheSA9PT0gJ25vbmUnKSByZXR1cm4gTm9kZUZpbHRlci5GSUxURVJfUkVKRUNUO1xuICAgICAgcmV0dXJuIE5vZGVGaWx0ZXIuRklMVEVSX0FDQ0VQVDtcbiAgICB9LFxuICB9KTtcbiAgbGV0IG47XG4gIHdoaWxlICgobiA9IHdhbGtlci5uZXh0Tm9kZSgpKSkgeWllbGQgbjtcbn1cblxuLyoqIEZpbmQgdGV4dCBQSUkgYW5kIHJlY29yZCByZWN0cyArIGF1ZGl0IGVudHJpZXMuIFR5cGVzIGZvbGxvdyB0aGUgc2hhcmVkXG4gKiAgcGF0dGVybiBsaWJyYXJ5LiBWYWx1ZXMgbmV2ZXIgbGVhdmUgdGhpcyBmdW5jdGlvbiBleGNlcHQgaW50byB0aGUgbG9jYWxcbiAqICBhdWRpdCBsZWRnZXIuICovXG5leHBvcnQgZnVuY3Rpb24gc2NhblRleHRQaWkoKSB7XG4gIGNvbnN0IGZvdW5kID0gW107XG4gIGZvciAoY29uc3Qgbm9kZSBvZiB0ZXh0Tm9kZXNVbmRlcihkb2N1bWVudC5ib2R5KSkge1xuICAgIGNvbnN0IHRleHQgPSBub2RlLnRleHRDb250ZW50O1xuICAgIGNvbnN0IHBhdHRlcm5zID0gWy4uLlBJSV9QQVRURVJOUywgLi4uUElJX1BBVFRFUk5TX0NUWF07XG4gICAgZm9yIChjb25zdCB7IHR5cGUsIHJlIH0gb2YgcGF0dGVybnMpIHtcbiAgICAgIHJlLmxhc3RJbmRleCA9IDA7XG4gICAgICBsZXQgbTtcbiAgICAgIHdoaWxlICgobSA9IHJlLmV4ZWModGV4dCkpKSB7XG4gICAgICAgIGNvbnN0IHJhdyA9IG1bMF07XG4gICAgICAgIC8vIGxlbmd0aCBmaWx0ZXI6IGF2b2lkIGFic3VyZCBtYXRjaGVzIGxpa2UgXCIxMVwiIGZvciBwaG9uZVxuICAgICAgICBpZiAocmF3Lmxlbmd0aCA8IDQpIGNvbnRpbnVlO1xuICAgICAgICBjb25zdCByYW5nZSA9IGRvY3VtZW50LmNyZWF0ZVJhbmdlKCk7XG4gICAgICAgIHJhbmdlLnNldFN0YXJ0KG5vZGUsIG0uaW5kZXgpO1xuICAgICAgICByYW5nZS5zZXRFbmQobm9kZSwgbS5pbmRleCArIHJhdy5sZW5ndGgpO1xuICAgICAgICBjb25zdCByZWN0ID0gcmFuZ2UuZ2V0Qm91bmRpbmdDbGllbnRSZWN0KCk7XG4gICAgICAgIGlmIChyZWN0LndpZHRoIDwgMSB8fCByZWN0LmhlaWdodCA8IDEpIGNvbnRpbnVlO1xuICAgICAgICBmb3VuZC5wdXNoKHsgdHlwZSwgdGV4dDogcmF3LCByZWN0OiBbcmVjdC5sZWZ0LCByZWN0LnRvcCwgcmVjdC53aWR0aCwgcmVjdC5oZWlnaHRdIH0pO1xuICAgICAgICBhdWRpdC5wdXNoKHsgdHlwZSwgdGV4dDogcmF3LCByZWN0OiBmb3VuZFtmb3VuZC5sZW5ndGggLSAxXS5yZWN0LCB0czogRGF0ZS5ub3coKSwgc3JjOiAndGV4dCcgfSk7XG4gICAgICB9XG4gICAgfVxuICB9XG4gIC8vIGxhYmVsLWFkamFjZW50IGhldXJpc3RpYzogaW5wdXQgdmFsdWUgbmV4dCB0byBhIHNlbnNpdGl2ZSBsYWJlbFxuICBmb3IgKGNvbnN0IGlucCBvZiBkb2N1bWVudC5xdWVyeVNlbGVjdG9yQWxsKCdpbnB1dCx0ZXh0YXJlYScpKSB7XG4gICAgY29uc3QgaGF5ID0gYCR7aW5wLmlkfSAke2lucC5uYW1lIHx8ICcnfSAke2lucC5wbGFjZWhvbGRlciB8fCAnJ31gLnRvTG93ZXJDYXNlKCk7XG4gICAgaWYgKCFoYXkpIGNvbnRpbnVlO1xuICAgIGNvbnN0IGhpdCA9IFNFTlNJVElWRV9MQUJFTFMuZmluZChzID0+IGhheS5pbmNsdWRlcyhzKSk7XG4gICAgaWYgKGhpdCAmJiBpbnAudmFsdWUgJiYgaW5wLnR5cGUgIT09ICdwYXNzd29yZCcpIHtcbiAgICAgIGNvbnN0IHIgPSBpbnAuZ2V0Qm91bmRpbmdDbGllbnRSZWN0KCk7XG4gICAgICBpZiAoci53aWR0aCA+IDIpIHtcbiAgICAgICAgZm91bmQucHVzaCh7IHR5cGU6ICdTRUNSRVRfRklFTEQnLCB0ZXh0OiBpbnAudmFsdWUsIHJlY3Q6IFtyLmxlZnQsIHIudG9wLCByLndpZHRoLCByLmhlaWdodF0gfSk7XG4gICAgICAgIGF1ZGl0LnB1c2goeyB0eXBlOiAnU0VDUkVUX0ZJRUxEJywgdGV4dDogaW5wLnZhbHVlLCByZWN0OiBmb3VuZFtmb3VuZC5sZW5ndGggLSAxXS5yZWN0LCB0czogRGF0ZS5ub3coKSwgc3JjOiAnZmllbGQnIH0pO1xuICAgICAgfVxuICAgIH1cbiAgfVxuICAvLyBwYXNzd29yZCBpbnB1dHMgKG1hc2sgZXZlbiB3aGVuIGVtcHR5IFx1MjAxNCB0aGUgZmllbGQgaXRzZWxmIGlzIHNlbnNpdGl2ZSlcbiAgZm9yIChjb25zdCBpbnAgb2YgZG9jdW1lbnQucXVlcnlTZWxlY3RvckFsbCgnaW5wdXRbdHlwZT1cInBhc3N3b3JkXCJdJykpIHtcbiAgICBjb25zdCByID0gaW5wLmdldEJvdW5kaW5nQ2xpZW50UmVjdCgpO1xuICAgIGlmIChyLndpZHRoID4gMikge1xuICAgICAgZm91bmQucHVzaCh7IHR5cGU6ICdQQVNTV09SRF9GSUVMRCcsIHRleHQ6IGlucC52YWx1ZSB8fCAncGFzc3dvcmQnLCByZWN0OiBbci5sZWZ0LCByLnRvcCwgci53aWR0aCwgci5oZWlnaHRdIH0pO1xuICAgICAgYXVkaXQucHVzaCh7IHR5cGU6ICdQQVNTV09SRF9GSUVMRCcsIHJlY3Q6IGZvdW5kW2ZvdW5kLmxlbmd0aCAtIDFdLnJlY3QsIHRzOiBEYXRlLm5vdygpLCBzcmM6ICdmaWVsZCcgfSk7XG4gICAgfVxuICB9XG4gIHJldHVybiBmb3VuZDtcbn1cblxuLyogLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tICovXG4vKiAyLiBTY3JlZW4gc3RhdGUgY29sbGVjdGlvbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICovXG4vKiAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0gKi9cblxuZnVuY3Rpb24gY29sbGVjdFNlbnNpdGl2ZUlucHV0TWFwKCkge1xuICBjb25zdCBtYXAgPSBbXTtcbiAgZm9yIChjb25zdCBlbCBvZiBkb2N1bWVudC5xdWVyeVNlbGVjdG9yQWxsKCdpbnB1dCx0ZXh0YXJlYScpKSB7XG4gICAgY29uc3QgcyA9IHJvbGVPZlNlbnNpdGl2ZShlbCk7XG4gICAgaWYgKHMpIG1hcC5wdXNoKHsgcmVmOiBlbC5kYXRhc2V0LnNyZWYgfHwgbnVsbCwgc2VsZWN0b3I6IGNzc1BhdGgoZWwpLCByb2xlOiBzLCBoYXNWYWx1ZTogISFlbC52YWx1ZSB9KTtcbiAgfVxuICByZXR1cm4gbWFwO1xufVxuXG5mdW5jdGlvbiByb2xlT2ZTZW5zaXRpdmUoZWwpIHtcbiAgY29uc3QgYWMgPSAoZWwuZ2V0QXR0cmlidXRlKCdhdXRvY29tcGxldGUnKSB8fCAnJykudG9Mb3dlckNhc2UoKTtcbiAgaWYgKGFjICYmIC9wYXNzd29yZHxvdHB8b25lLXRpbWUtY29kZXxjYy18Y2FyZC8udGVzdChhYykpIHJldHVybiBhYztcbiAgY29uc3QgdHlwZSA9IChlbC5nZXRBdHRyaWJ1dGUoJ3R5cGUnKSB8fCAnJykudG9Mb3dlckNhc2UoKTtcbiAgaWYgKHR5cGUgPT09ICdwYXNzd29yZCcpIHJldHVybiAncGFzc3dvcmQnO1xuICBjb25zdCBoYXkgPSBgJHtlbC5pZH0gJHtlbC5uYW1lIHx8ICcnfSAke2VsLnBsYWNlaG9sZGVyIHx8ICcnfSAke2xhYmVsVGV4dChlbCl9YC50b0xvd2VyQ2FzZSgpO1xuICBmb3IgKGNvbnN0IHMgb2YgU0VOU0lUSVZFX0xBQkVMUykgaWYgKGhheS5pbmNsdWRlcyhzKSkgcmV0dXJuIHMucmVwbGFjZSgvXFxzKy9nLCAnLScpO1xuICByZXR1cm4gJyc7XG59XG5cbmZ1bmN0aW9uIGxhYmVsVGV4dChlbCkge1xuICBpZiAoZWwuaWQpIHtcbiAgICBjb25zdCBsID0gZG9jdW1lbnQucXVlcnlTZWxlY3RvcihgbGFiZWxbZm9yPVwiJHtDU1MuZXNjYXBlKGVsLmlkKX1cIl1gKTtcbiAgICBpZiAobCkgcmV0dXJuIGwudGV4dENvbnRlbnQgfHwgJyc7XG4gIH1cbiAgY29uc3Qgd3JhcCA9IGVsLmNsb3Nlc3QoJ2xhYmVsJyk7XG4gIHJldHVybiB3cmFwID8gKHdyYXAudGV4dENvbnRlbnQgfHwgJycpIDogJyc7XG59XG5cbmZ1bmN0aW9uIGNzc1BhdGgoZWwpIHtcbiAgY29uc3QgcGFydHMgPSBbXTtcbiAgbGV0IGN1ciA9IGVsO1xuICB3aGlsZSAoY3VyICYmIGN1ciAhPT0gZG9jdW1lbnQuYm9keSAmJiBwYXJ0cy5sZW5ndGggPCA1KSB7XG4gICAgbGV0IHNlbCA9IGN1ci50YWdOYW1lLnRvTG93ZXJDYXNlKCk7XG4gICAgaWYgKGN1ci5pZCkgeyBzZWwgKz0gYCMke2N1ci5pZH1gOyBwYXJ0cy51bnNoaWZ0KHNlbCk7IGJyZWFrOyB9XG4gICAgY29uc3QgcGFyZW50ID0gY3VyLnBhcmVudEVsZW1lbnQ7XG4gICAgaWYgKHBhcmVudCkge1xuICAgICAgY29uc3Qgc2FtZSA9IEFycmF5LmZyb20ocGFyZW50LmNoaWxkcmVuKS5maWx0ZXIoYyA9PiBjLnRhZ05hbWUgPT09IGN1ci50YWdOYW1lKTtcbiAgICAgIGlmIChzYW1lLmxlbmd0aCA+IDEpIHNlbCArPSBgOm50aC1vZi10eXBlKCR7c2FtZS5pbmRleE9mKGN1cikgKyAxfSlgO1xuICAgIH1cbiAgICBwYXJ0cy51bnNoaWZ0KHNlbCk7XG4gICAgY3VyID0gcGFyZW50O1xuICB9XG4gIHJldHVybiBwYXJ0cy5qb2luKCcgPiAnKSB8fCBlbC50YWdOYW1lLnRvTG93ZXJDYXNlKCk7XG59XG5cbmV4cG9ydCBmdW5jdGlvbiBjb2xsZWN0KCkge1xuICBjb25zdCBzdGF0ZSA9IGV4dHJhY3RTY3JlZW5TdGF0ZSgpO1xuICBwYWdlSGludHMgPSB7IHNlbnNpdGl2ZUlucHV0czogY29sbGVjdFNlbnNpdGl2ZUlucHV0TWFwKCkgfTtcbiAgcmV0dXJuIHsgLi4uc3RhdGUsIGhpbnRzOiBwYWdlSGludHMgfTtcbn1cblxuLyogLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tICovXG4vKiAzLiBPdmVybGF5IHJlbmRlcmluZyAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICovXG4vKiAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0gKi9cblxuZnVuY3Rpb24gZW5zdXJlT3ZlcmxheVJvb3QoKSB7XG4gIGlmIChvdmVybGF5Um9vdCAmJiBkb2N1bWVudC5kb2N1bWVudEVsZW1lbnQuY29udGFpbnMob3ZlcmxheVJvb3QpKSByZXR1cm4gb3ZlcmxheVJvb3Q7XG4gIG92ZXJsYXlSb290ID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgnZGl2Jyk7XG4gIG92ZXJsYXlSb290LmlkID0gJ3NlbnRpbmVsLW92ZXJsYXktcm9vdCc7XG4gIG92ZXJsYXlSb290LnN0eWxlLmNzc1RleHQgPSAncG9zaXRpb246Zml4ZWQ7aW5zZXQ6MDtwb2ludGVyLWV2ZW50czpub25lO3otaW5kZXg6MjE0NzQ4MzY0NjsnO1xuICBkb2N1bWVudC5kb2N1bWVudEVsZW1lbnQuYXBwZW5kQ2hpbGQob3ZlcmxheVJvb3QpO1xuICByZXR1cm4gb3ZlcmxheVJvb3Q7XG59XG5cbi8qKiBEcmF3IGFuIFNWRyBvdmVybGF5IG1hcmtpbmcgcmVkYWN0ZWQgcmVnaW9ucy4gTW9kZTogYmx1ciBpcyBzaW11bGF0ZWQgdmlhXG4gKiAgYSByZXBlYXRlZCBzdmcgZmlsdGVyOyBwaXhlbGF0ZSB2aWEgYSBwYXR0ZXJuOyBzb2xpZCB2aWEgYSBmaWxsZWQgcmVjdC4gKi9cbmV4cG9ydCBmdW5jdGlvbiBhcHBseU92ZXJsYXkocmVjdHMsIG1vZGUgPSAnYmx1cicsIGxhYmVscyA9IHRydWUpIHtcbiAgY29uc3Qgcm9vdCA9IGVuc3VyZU92ZXJsYXlSb290KCk7XG4gIHJvb3QuaW5uZXJIVE1MID0gJyc7XG4gIGNvbnN0IE5TID0gJ2h0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnJztcbiAgY29uc3Qgc3ZnID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudE5TKE5TLCAnc3ZnJyk7XG4gIHN2Zy5zZXRBdHRyaWJ1dGUoJ3dpZHRoJywgJzEwMCUnKTtcbiAgc3ZnLnNldEF0dHJpYnV0ZSgnaGVpZ2h0JywgJzEwMCUnKTtcbiAgY29uc3QgZGVmcyA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnROUyhOUywgJ2RlZnMnKTtcblxuICBjb25zdCBibHVyRiA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnROUyhOUywgJ2ZpbHRlcicpO1xuICBibHVyRi5pZCA9ICdzLWJsdXInO1xuICBibHVyRi5pbm5lckhUTUwgPSAnPGZlR2F1c3NpYW5CbHVyIHN0ZERldmlhdGlvbj1cIjZcIi8+JztcbiAgZGVmcy5hcHBlbmRDaGlsZChibHVyRik7XG5cbiAgY29uc3QgcGl4RiA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnROUyhOUywgJ2ZpbHRlcicpO1xuICBwaXhGLmlkID0gJ3MtcGl4JztcbiAgcGl4Ri5pbm5lckhUTUwgPSAnPGZlRmxvb2QgZmxvb2QtY29sb3I9XCIjMTExXCIgcmVzdWx0PVwiYlwiLz48ZmVDb21wb3NpdGUgaW49XCJiXCIgaW4yPVwiU291cmNlR3JhcGhpY1wiIG9wZXJhdG9yPVwiaW5cIi8+PGZlVGlsZS8+JztcbiAgZGVmcy5hcHBlbmRDaGlsZChwaXhGKTtcbiAgc3ZnLmFwcGVuZENoaWxkKGRlZnMpO1xuXG4gIGZvciAoY29uc3QgciBvZiByZWN0cykge1xuICAgIGNvbnN0IFt4LCB5LCB3LCBoXSA9IHIucmVjdDtcbiAgICBjb25zdCBnID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudE5TKE5TLCAnZycpO1xuICAgIGNvbnN0IGJnID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudE5TKE5TLCAncmVjdCcpO1xuICAgIGJnLnNldEF0dHJpYnV0ZSgneCcsIHgpOyBiZy5zZXRBdHRyaWJ1dGUoJ3knLCB5KTtcbiAgICBiZy5zZXRBdHRyaWJ1dGUoJ3dpZHRoJywgdyk7IGJnLnNldEF0dHJpYnV0ZSgnaGVpZ2h0JywgaCk7XG4gICAgYmcuc2V0QXR0cmlidXRlKCdmaWxsJywgbW9kZSA9PT0gJ3NvbGlkJyA/ICcjMDAwJyA6ICdyZ2JhKDEwLDEwLDE0LDAuODgpJyk7XG4gICAgaWYgKG1vZGUgPT09ICdibHVyJykgYmcuc2V0QXR0cmlidXRlKCdmaWx0ZXInLCAndXJsKCNzLWJsdXIpJyk7XG4gICAgaWYgKG1vZGUgPT09ICdwaXhlbGF0ZScpIGJnLnNldEF0dHJpYnV0ZSgnZmlsdGVyJywgJ3VybCgjcy1waXgpJyk7XG4gICAgYmcuc2V0QXR0cmlidXRlKCdyeCcsIDMpO1xuICAgIGcuYXBwZW5kQ2hpbGQoYmcpO1xuICAgIGlmIChsYWJlbHMpIHtcbiAgICAgIGNvbnN0IHQgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50TlMoTlMsICd0ZXh0Jyk7XG4gICAgICB0LnNldEF0dHJpYnV0ZSgneCcsIHggKyA0KTtcbiAgICAgIHQuc2V0QXR0cmlidXRlKCd5JywgeSArIGggLSA0KTtcbiAgICAgIHQuc2V0QXR0cmlidXRlKCdmb250LXNpemUnLCBNYXRoLm1heCg5LCBNYXRoLm1pbigxNCwgaCAvIDIuNCkpKTtcbiAgICAgIHQuc2V0QXR0cmlidXRlKCdmb250LWZhbWlseScsICdtb25vc3BhY2UnKTtcbiAgICAgIHQuc2V0QXR0cmlidXRlKCdmaWxsJywgJyMwMGU1YTAnKTtcbiAgICAgIHQudGV4dENvbnRlbnQgPSBgXHVEODNEXHVERUUxICR7ci50eXBlfSR7ci5waCA/ICcgXHUyMTkyICcgKyByLnBoIDogJyd9YDtcbiAgICAgIGcuYXBwZW5kQ2hpbGQodCk7XG4gICAgfVxuICAgIHN2Zy5hcHBlbmRDaGlsZChnKTtcbiAgfVxuICByb290LmFwcGVuZENoaWxkKHN2Zyk7XG59XG5cbmV4cG9ydCBmdW5jdGlvbiBjbGVhck92ZXJsYXkoKSB7XG4gIGlmIChvdmVybGF5Um9vdCkgb3ZlcmxheVJvb3QuaW5uZXJIVE1MID0gJyc7XG59XG5cbi8qIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLSAqL1xuLyogNC4gQWN0aW9uIGV4ZWN1dG9yICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAqL1xuLyogLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tICovXG5cbmZ1bmN0aW9uIGZpbmRCeVJlZihyZWYpIHtcbiAgcmV0dXJuIGRvY3VtZW50LnF1ZXJ5U2VsZWN0b3IoYFtkYXRhLXNyZWY9XCIke0NTUy5lc2NhcGUocmVmKX1cIl1gKTtcbn1cblxuZnVuY3Rpb24gZmluZEJ5U2VsZWN0b3Ioc2VsKSB7XG4gIHRyeSB7IHJldHVybiBkb2N1bWVudC5xdWVyeVNlbGVjdG9yKHNlbCk7IH0gY2F0Y2ggeyByZXR1cm4gbnVsbDsgfVxufVxuXG5mdW5jdGlvbiBmaW5kQnlEZXNjcmlwdG9yKGVsKSB7XG4gIGlmICghZWwpIHJldHVybiBudWxsO1xuICBpZiAoZWwucmVmKSB7IGNvbnN0IGJ5UmVmID0gZmluZEJ5UmVmKGVsLnJlZik7IGlmIChieVJlZikgcmV0dXJuIGJ5UmVmOyB9XG4gIGlmIChlbC5zZWxlY3RvcikgeyBjb25zdCBieVNlbCA9IGZpbmRCeVNlbGVjdG9yKGVsLnNlbGVjdG9yKTsgaWYgKGJ5U2VsKSByZXR1cm4gYnlTZWw7IH1cbiAgLy8gdGV4dC1iYXNlZCBmYWxsYmFjayBmb3IgYnV0dG9ucy9saW5rc1xuICBpZiAoZWwudHh0KSB7XG4gICAgY29uc3QgY2FuZHMgPSBBcnJheS5mcm9tKGRvY3VtZW50LnF1ZXJ5U2VsZWN0b3JBbGwoJ2J1dHRvbiwgYSwgW3JvbGU9XCJidXR0b25cIl0nKSk7XG4gICAgY29uc3QgbSA9IGNhbmRzLmZpbmQoYyA9PiAoYy50ZXh0Q29udGVudCB8fCAnJykudHJpbSgpLnRvTG93ZXJDYXNlKCkuaW5jbHVkZXMoU3RyaW5nKGVsLnR4dCkudG9Mb3dlckNhc2UoKSkpO1xuICAgIGlmIChtKSByZXR1cm4gbTtcbiAgfVxuICByZXR1cm4gbnVsbDtcbn1cblxuZnVuY3Rpb24gZmlyZUNsaWNrKGVsKSB7XG4gIGVsLnNjcm9sbEludG9WaWV3KHsgYmxvY2s6ICdjZW50ZXInLCBiZWhhdmlvcjogJ2luc3RhbnQnIH0pO1xuICBlbC5kaXNwYXRjaEV2ZW50KG5ldyBQb2ludGVyRXZlbnQoJ3BvaW50ZXJkb3duJywgeyBidWJibGVzOiB0cnVlIH0pKTtcbiAgZWwuZGlzcGF0Y2hFdmVudChuZXcgTW91c2VFdmVudCgnbW91c2Vkb3duJywgeyBidWJibGVzOiB0cnVlIH0pKTtcbiAgZWwuZGlzcGF0Y2hFdmVudChuZXcgUG9pbnRlckV2ZW50KCdwb2ludGVydXAnLCB7IGJ1YmJsZXM6IHRydWUgfSkpO1xuICBlbC5kaXNwYXRjaEV2ZW50KG5ldyBNb3VzZUV2ZW50KCdtb3VzZXVwJywgeyBidWJibGVzOiB0cnVlIH0pKTtcbiAgZWwuY2xpY2soKTtcbn1cblxuZnVuY3Rpb24gc2V0VmFsdWUoZWwsIHZhbHVlKSB7XG4gIGVsLnNjcm9sbEludG9WaWV3KHsgYmxvY2s6ICdjZW50ZXInLCBiZWhhdmlvcjogJ2luc3RhbnQnIH0pO1xuICBlbC5mb2N1cygpO1xuICAvLyBSZWFjdC1jb250cm9sbGVkIGlucHV0c1xuICBjb25zdCBwcm90byA9IGVsIGluc3RhbmNlb2YgSFRNTFRleHRBcmVhRWxlbWVudCA/IEhUTUxUZXh0QXJlYUVsZW1lbnQucHJvdG90eXBlIDogSFRNTElucHV0RWxlbWVudC5wcm90b3R5cGU7XG4gIGNvbnN0IGRlc2MgPSBPYmplY3QuZ2V0T3duUHJvcGVydHlEZXNjcmlwdG9yKHByb3RvLCAndmFsdWUnKTtcbiAgaWYgKGRlc2MgJiYgZGVzYy5zZXQpIGRlc2Muc2V0LmNhbGwoZWwsIHZhbHVlKTsgZWxzZSBlbC52YWx1ZSA9IHZhbHVlO1xuICBlbC5kaXNwYXRjaEV2ZW50KG5ldyBFdmVudCgnaW5wdXQnLCB7IGJ1YmJsZXM6IHRydWUgfSkpO1xuICBlbC5kaXNwYXRjaEV2ZW50KG5ldyBFdmVudCgnY2hhbmdlJywgeyBidWJibGVzOiB0cnVlIH0pKTtcbn1cblxuLyoqIEV4ZWN1dGUgYSBsaXN0IG9mIHNlcnZlci1pc3N1ZWQgYWN0aW9ucy4gYHBoTWFwYCBpcyB0aGUgTE9DQUxcbiAqICBwbGFjZWhvbGRlclx1MjE5MnZhbHVlIG1hcCBwcm9kdWNlZCBieSB0aGUgb24tZGV2aWNlIHJlZGFjdGlvbiBwYXNzIFx1MjAxNCBpdCBpc1xuICogIHBhc3NlZCB0YWJcdTIxOTJiYWNrZ3JvdW5kXHUyMTkydGFiIGFuZCBuZXZlciBsZWF2ZXMgdGhlIGJyb3dzZXIuICovXG5leHBvcnQgYXN5bmMgZnVuY3Rpb24gZXhlY3V0ZUFjdGlvbnMoYWN0aW9ucywgcGhNYXAgPSB7fSkge1xuICBjb25zdCByZXN1bHRzID0gW107XG4gIGZvciAoY29uc3QgYSBvZiBhY3Rpb25zKSB7XG4gICAgY29uc3QgcmVzID0geyBhY3Rpb246IGEuYWN0aW9uLCBvazogZmFsc2UgfTtcbiAgICB0cnkge1xuICAgICAgc3dpdGNoIChhLmFjdGlvbikge1xuICAgICAgICBjYXNlICdjbGljayc6IHtcbiAgICAgICAgICBjb25zdCBlbCA9IGZpbmRCeURlc2NyaXB0b3IoYS5lbCB8fCBhKTtcbiAgICAgICAgICBpZiAoIWVsKSB0aHJvdyBuZXcgRXJyb3IoJ3RhcmdldCBub3QgZm91bmQnKTtcbiAgICAgICAgICBmaXJlQ2xpY2soZWwpO1xuICAgICAgICAgIHJlcy5vayA9IHRydWU7XG4gICAgICAgICAgYnJlYWs7XG4gICAgICAgIH1cbiAgICAgICAgY2FzZSAndHlwZSc6XG4gICAgICAgIGNhc2UgJ3NldCc6IHtcbiAgICAgICAgICBjb25zdCBlbCA9IGZpbmRCeURlc2NyaXB0b3IoYS5lbCB8fCBhKTtcbiAgICAgICAgICBpZiAoIWVsKSB0aHJvdyBuZXcgRXJyb3IoJ3RhcmdldCBub3QgZm91bmQnKTtcbiAgICAgICAgICBsZXQgdmFsdWUgPSBhLnZhbHVlID8/ICcnO1xuICAgICAgICAgIC8vIFBsYWNlaG9sZGVyIHJlc29sdXRpb24gKExPQ0FMIG9ubHkpOiB0aGUgc2VydmVyIHBsYW5zIHdpdGhcbiAgICAgICAgICAvLyBbRU1BSUxfMV0tc3R5bGUgdG9rZW5zOyB0aGUgcmVhbCB2YWx1ZSBjb21lcyBmcm9tIHRoZSBsb2NhbFxuICAgICAgICAgIC8vIHJlZGFjdGlvbiBtYXAgKG9yIHRoZSBwcml2YXRlIHZhdWx0IGZvciBzZWNyZXRzLCByZXNvbHZlZCBieSB0aGVcbiAgICAgICAgICAvLyBiYWNrZ3JvdW5kIGJlZm9yZSB0aGlzIG1lc3NhZ2Ugd2FzIHNlbnQpLlxuICAgICAgICAgIGlmICgvXlxcW1tBLVpfXStfXFxkK1xcXSQvLnRlc3QoU3RyaW5nKHZhbHVlKSkgJiYgcGhNYXBbdmFsdWVdICE9PSB1bmRlZmluZWQpIHtcbiAgICAgICAgICAgIHZhbHVlID0gcGhNYXBbdmFsdWVdO1xuICAgICAgICAgIH1cbiAgICAgICAgICBzZXRWYWx1ZShlbCwgdmFsdWUpO1xuICAgICAgICAgIHJlcy5vayA9IHRydWU7XG4gICAgICAgICAgYnJlYWs7XG4gICAgICAgIH1cbiAgICAgICAgY2FzZSAnc3VibWl0Jzoge1xuICAgICAgICAgIGNvbnN0IGVsID0gZmluZEJ5RGVzY3JpcHRvcihhLmVsIHx8IGEpO1xuICAgICAgICAgIGNvbnN0IGZvcm0gPSBlbCAmJiBlbC5jbG9zZXN0KCdmb3JtJyk7XG4gICAgICAgICAgaWYgKGZvcm0pIHsgZm9ybS5yZXF1ZXN0U3VibWl0ID8gZm9ybS5yZXF1ZXN0U3VibWl0KCkgOiBmb3JtLnN1Ym1pdCgpOyB9XG4gICAgICAgICAgZWxzZSBpZiAoZWwpIGZpcmVDbGljayhlbCk7XG4gICAgICAgICAgcmVzLm9rID0gdHJ1ZTtcbiAgICAgICAgICBicmVhaztcbiAgICAgICAgfVxuICAgICAgICBjYXNlICdzY3JvbGwnOiB7XG4gICAgICAgICAgY29uc3QgYW1vdW50ID0gYS5hbW91bnQgfHwgNjAwO1xuICAgICAgICAgIHdpbmRvdy5zY3JvbGxCeSh7IHRvcDogYW1vdW50LCBiZWhhdmlvcjogJ2luc3RhbnQnIH0pO1xuICAgICAgICAgIHJlcy5vayA9IHRydWU7XG4gICAgICAgICAgYnJlYWs7XG4gICAgICAgIH1cbiAgICAgICAgY2FzZSAnbmF2aWdhdGUnOiB7XG4gICAgICAgICAgaWYgKGEudXJsICYmIC9eaHR0cHM/Oi9pLnRlc3QoYS51cmwpKSB7IGxvY2F0aW9uLmhyZWYgPSBhLnVybDsgcmVzLm9rID0gdHJ1ZTsgfVxuICAgICAgICAgIGVsc2UgdGhyb3cgbmV3IEVycm9yKCdiYWQgdXJsJyk7XG4gICAgICAgICAgYnJlYWs7XG4gICAgICAgIH1cbiAgICAgICAgY2FzZSAnd2FpdCc6IHtcbiAgICAgICAgICBhd2FpdCBuZXcgUHJvbWlzZShyID0+IHNldFRpbWVvdXQociwgTWF0aC5taW4oNTAwMCwgYS5tcyB8fCA4MDApKSk7XG4gICAgICAgICAgcmVzLm9rID0gdHJ1ZTtcbiAgICAgICAgICBicmVhaztcbiAgICAgICAgfVxuICAgICAgICBjYXNlICdkb25lJzogcmVzLm9rID0gdHJ1ZTsgcmVzLmRvbmUgPSB0cnVlOyBicmVhaztcbiAgICAgICAgY2FzZSAnZmFpbCc6IHJlcy5vayA9IHRydWU7IHJlcy5mYWlsZWQgPSB0cnVlOyBicmVhaztcbiAgICAgICAgZGVmYXVsdDogdGhyb3cgbmV3IEVycm9yKGB1bmtub3duIGFjdGlvbiAke2EuYWN0aW9ufWApO1xuICAgICAgfVxuICAgIH0gY2F0Y2ggKGUpIHtcbiAgICAgIHJlcy5lcnJvciA9IFN0cmluZyhlLm1lc3NhZ2UgfHwgZSk7XG4gICAgfVxuICAgIHJlc3VsdHMucHVzaChyZXMpO1xuICB9XG4gIHJldHVybiByZXN1bHRzO1xufVxuXG4vKiAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0gKi9cbi8qIDUuIE1lc3NhZ2UgcGx1bWJpbmcgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgKi9cbi8qIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLSAqL1xuXG5jaHJvbWUucnVudGltZS5vbk1lc3NhZ2UuYWRkTGlzdGVuZXIoKG1zZywgX3NlbmRlciwgc2VuZFJlc3BvbnNlKSA9PiB7XG4gIChhc3luYyAoKSA9PiB7XG4gICAgc3dpdGNoIChtc2c/LnR5cGUpIHtcbiAgICAgIGNhc2UgJ0VYVFJBQ1RfU1RBVEUnOiB7XG4gICAgICAgIHNlbmRSZXNwb25zZSh7IG9rOiB0cnVlLCBzdGF0ZTogY29sbGVjdCgpLCBwaWlSZWN0czogc2NhblRleHRQaWkoKS5tYXAocCA9PiAoeyB0eXBlOiBwLnR5cGUsIHJlY3Q6IHAucmVjdCwgdGV4dDogcC50ZXh0IH0pKSB9KTtcbiAgICAgICAgYnJlYWs7XG4gICAgICB9XG4gICAgICBjYXNlICdBUFBMWV9PVkVSTEFZJzoge1xuICAgICAgICBhcHBseU92ZXJsYXkobXNnLnJlY3RzIHx8IFtdLCBtc2cubW9kZSB8fCAnYmx1cicsIG1zZy5sYWJlbHMgIT09IGZhbHNlKTtcbiAgICAgICAgc2VuZFJlc3BvbnNlKHsgb2s6IHRydWUgfSk7XG4gICAgICAgIGJyZWFrO1xuICAgICAgfVxuICAgICAgY2FzZSAnQ0xFQVJfT1ZFUkxBWSc6IHtcbiAgICAgICAgY2xlYXJPdmVybGF5KCk7XG4gICAgICAgIHNlbmRSZXNwb25zZSh7IG9rOiB0cnVlIH0pO1xuICAgICAgICBicmVhaztcbiAgICAgIH1cbiAgICAgIGNhc2UgJ0VYRUNVVEVfQUNUSU9OUyc6IHtcbiAgICAgICAgY29uc3QgcmVzdWx0cyA9IGF3YWl0IGV4ZWN1dGVBY3Rpb25zKG1zZy5hY3Rpb25zIHx8IFtdLCBtc2cucGhNYXAgfHwge30pO1xuICAgICAgICBzZW5kUmVzcG9uc2UoeyBvazogdHJ1ZSwgcmVzdWx0cyB9KTtcbiAgICAgICAgYnJlYWs7XG4gICAgICB9XG4gICAgICBjYXNlICdHRVRfQVVESVQnOiB7XG4gICAgICAgIHNlbmRSZXNwb25zZSh7IG9rOiB0cnVlLCBhdWRpdCB9KTtcbiAgICAgICAgYnJlYWs7XG4gICAgICB9XG4gICAgICBkZWZhdWx0OlxuICAgICAgICBzZW5kUmVzcG9uc2UoeyBvazogZmFsc2UsIGVycm9yOiAndW5rbm93biBtc2cnIH0pO1xuICAgIH1cbiAgfSkoKTtcbiAgcmV0dXJuIHRydWU7IC8vIGFzeW5jIHNlbmRSZXNwb25zZVxufSk7XG4iXSwKICAibWFwcGluZ3MiOiAiOztBQVNPLE1BQU0sZUFBZTtBQUFBLElBQzFCLEVBQUUsTUFBTSxXQUFXLElBQUksZ0NBQWdDO0FBQUEsSUFDdkQsRUFBRSxNQUFNLFdBQVcsSUFBSSxtQkFBbUI7QUFBQSxJQUMxQyxFQUFFLE1BQU0sT0FBTyxJQUFJLDBCQUEwQjtBQUFBLElBQzdDLEVBQUUsTUFBTSxTQUFTLElBQUksc0RBQXNEO0FBQUEsSUFDM0UsRUFBRSxNQUFNLFNBQVMsSUFBSSxxREFBcUQ7QUFBQSxJQUMxRSxFQUFFLE1BQU0sU0FBUyxJQUFJLCtDQUErQztBQUFBLElBQ3BFLEVBQUUsTUFBTSxTQUFTLElBQUksNkVBQTZFO0FBQUEsSUFDbEcsRUFBRSxNQUFNLFFBQVEsSUFBSSwwQkFBMEI7QUFBQSxJQUM5QyxFQUFFLE1BQU0sT0FBTyxJQUFJLGdEQUFnRDtBQUFBLElBQ25FLEVBQUUsTUFBTSxTQUFTLElBQUksbURBQW1EO0FBQUEsSUFDeEUsRUFBRSxNQUFNLFFBQVEsSUFBSSwyRUFBMkU7QUFBQSxJQUMvRixFQUFFLE1BQU0sUUFBUSxJQUFJLDJDQUEyQztBQUFBO0FBQUEsSUFDL0QsRUFBRSxNQUFNLFFBQVEsSUFBSSwrQ0FBK0M7QUFBQSxJQUNuRSxFQUFFLE1BQU0sT0FBTyxJQUFJLDJCQUEyQjtBQUFBLEVBQ2hEO0FBT08sTUFBTSxtQkFBbUI7QUFBQSxJQUM5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
