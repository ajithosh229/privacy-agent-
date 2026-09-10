/**
 * Labeled corpus for PII precision/recall evaluation (metric 2).
 * Each case: text + ground-truth entities (type, value). The eval runs the
 * client's exact detection stack (shared pattern library + NER when weights
 * are present) and scores strict span match.
 */
export const CORPUS = [
  { text: 'Contact John Doe at john.doe@example.com or +91 98765 43210.', truth: [
    { type: 'PERSON', value: 'John Doe' },
    { type: 'EMAIL', value: 'john.doe@example.com' },
    { type: 'PHONE', value: '+91 98765 43210' },
  ]},
  { text: 'My Aadhaar is 4567 8921 3456 and PAN is ABCDE1234F.', truth: [
    { type: 'AADHAAR', value: '4567 8921 3456' },
    { type: 'PAN', value: 'ABCDE1234F' },
  ]},
  { text: 'Card 4111 1111 1111 1111, CVV 123, exp 09/27.', truth: [
    { type: 'CARD', value: '4111 1111 1111 1111' },
    { type: 'CVV', value: '123' },
    { type: 'DATE', value: '09/27' },
  ]},
  { text: 'SSN: 123-45-6789 for processing.', truth: [
    { type: 'SSN', value: '123-45-6789' },
  ]},
  { text: 'Ship to 221B Baker Street, London NW1 6XE, UK.', truth: [] },
  { text: 'Meeting on 12/08/2026 at 14:30 in Room 4.', truth: [
    { type: 'DATE', value: '12/08/2026' },
    { type: 'TIME', value: '14:30' },
  ]},
  { text: 'Invoice total ₹1,29,999 for order #88123.', truth: [
    { type: 'MONEY', value: '₹1,29,999' },
  ]},
  { text: 'Welcome to our quarterly product update newsletter!', truth: [] },
  { text: 'Login with user "admin" and change the password soon.', truth: [] },
  { text: 'Account 4532015112830366 verified successfully today.', truth: [
    { type: 'CARD', value: '4532015112830366' },
  ]},
  { text: 'Dr. Priya Sharma will see you now.', truth: [
    { type: 'PERSON', value: 'Dr. Priya Sharma' },
  ]},
  { text: 'The weather is nice and the stock market is up 2.4%.', truth: [] },
  { text: 'Transaction of USD 2500 failed at 23:59.', truth: [
    { type: 'MONEY', value: 'USD 2500' },
    { type: 'TIME', value: '23:59' },
  ]},
  { text: 'Ref code: TS-99120. No action needed.', truth: [] },
  { text: 'Update your records: ananya.iyer@corp.in, +91 86 5555 5555.', truth: [
    { type: 'EMAIL', value: 'ananya.iyer@corp.in' },
    { type: 'PHONE', value: '+91 86 5555 5555' },
  ]},
];
