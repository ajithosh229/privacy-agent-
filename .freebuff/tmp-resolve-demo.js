const path = require('path');
const fs = require('fs');
const m = require('module');
const require = m.createRequire(__filename);

// This is the path the running server resolved for server.js when launched as:
//   node server/server.js   (cwd = D:\SIH\.freebuff)
const rp = require.resolve('./server/server.js');
console.log('resolved server.js =', rp);
const d = path.resolve(path.dirname(rp), '..', 'demo');
console.log('DEMO_DIR          =', d);
console.log('demo exists       =', fs.existsSync(d));
console.log('checkout exists   =', fs.existsSync(path.join(d, 'shop', 'checkout.html')));
console.log('server cwd        =', process.cwd());
