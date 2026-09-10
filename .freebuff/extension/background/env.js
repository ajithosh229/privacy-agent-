/** Environment detection shared by the background context. */
export const hasOffscreen = typeof chrome !== 'undefined' && !!chrome.offscreen && !!chrome.runtime.getContexts;
export const isFirefox = typeof navigator !== 'undefined' && /firefox/i.test(navigator.userAgent);
export const UA = typeof navigator !== 'undefined' ? navigator.userAgent : '';
