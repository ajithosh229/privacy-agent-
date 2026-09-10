/**
 * Shared protocol between the Sentinel extension (client) and the server.
 *
 * Core principle: the client NEVER sends raw sensitive values. Interactive
 * sensitive fields (passwords, OTP, card numbers, ...) are replaced by opaque
 * place-holders BEFORE serialization. Detected PII text (names, emails,
 * phones, IDs, addresses) is replaced by typed place-holders such as
 * [NAME_1] / [EMAIL_2]. The server reasons only over place-holders and
 * structural data, and returns actions that reference place-holders.
 */
export const PROTOCOL_VERSION = 'sentinel-protocol/1.1';

export const SENSITIVE_ROLES = [
  'password', 'new-password', 'current-password',
  'otp', 'one-time-code',
  'card-number', 'card-exp', 'card-cvv',
  'ssn', 'aadhaar', 'pan',
];

/** Roles that are secret-like: never leave the client even as placeholders
 *  in prompts; the executor types them locally from the private vault. */
export const SECRET_ROLES = ['password', 'new-password', 'current-password', 'card-cvv', 'otp', 'one-time-code'];

export const NON_SENSITIVE_ROLES = [
  'search', 'text', 'email', 'tel', 'url', 'name', 'username', 'address', 'date',
];

export const ENTITY_TYPES = {
  PERSON: 'PERSON', EMAIL: 'EMAIL', PHONE: 'PHONE', DATE: 'DATE',
  ADDRESS: 'ADDRESS', ORG: 'ORG', MONEY: 'MONEY', AADHAAR: 'AADHAAR',
  PAN: 'PAN', CARD: 'CARD', CVV: 'CVV', URL: 'URL', TIME: 'TIME', MISC: 'MISC',
};

export const ENTITY_ORDER = ['AADHAAR', 'CARD', 'CVV', 'PAN', 'EMAIL', 'PHONE', 'PERSON', 'ADDRESS', 'MONEY', 'DATE', 'TIME', 'URL', 'ORG', 'MISC'];

/** Payload types for server routes. */
export const MSG_TYPES = {
  // POST /v1/task  body:
  TASK_START: 'TASK_START',
  // POST /v1/agent  body (screen-state turn):
  SCREEN_STATE: 'SCREEN_STATE',
};

export const ACTION_TYPES = ['click', 'type', 'scroll', 'submit', 'wait', 'set', 'navigate', 'done', 'fail', 'ask_user'];

export const DEFAULT_SETTINGS = {
  serverUrl: 'http://localhost:8787',
  /** 'mock' | 'remote' | 'hybrid' (remote w/ local validator + mock fallback) */
  serverMode: 'hybrid',
  /** deita/vision det: 'normal' | 'low' — 'low' uses q8 models + maxDet 10 */
  perfMode: 'normal',
  autoApprove: true,        // auto-approve server plan (with server non-sensitivity gate)
  showOverlays: true,       // draw redaction overlays on page
  maskMode: 'blur',         // 'blur' | 'pixelate' | 'solid'
  device: 'auto',           // 'auto' | 'webgpu' | 'wasm'
  localReranker: true,      // enable local heuristic fallback when server down
};

export const MSG = {
  PING: 'PING',
  RUN_TASK: 'RUN_TASK',
  TASK_STATE: 'TASK_STATE',
  STOP_TASK: 'STOP_TASK',
  CAPTURE_STATE: 'CAPTURE_STATE',
  LAST_PAYLOAD: 'LAST_PAYLOAD',
  GET_VAULT: 'GET_VAULT',
  SET_VAULT: 'SET_VAULT',
  TOAST: 'TOAST',
};

export const TAB_MSG = {
  EXTRACT_STATE: 'EXTRACT_STATE',
  EXECUTE_ACTIONS: 'EXECUTE_ACTIONS',
  APPLY_OVERLAY: 'APPLY_OVERLAY',
  CLEAR_OVERLAY: 'CLEAR_OVERLAY',
  PAGE_HINT: 'PAGE_HINT',
};

/** Max chars for DOM metadata sent per turn (server-side non-sensitivity cap). */
export const MAX_META_CHARS = 24000;

/** Timeout per agent turn (ms). */
export const TURN_TIMEOUT_MS = 30000;
