'use strict';
// Usage:  node hash-password.js "your password"      -> prints the value to use for AUTH_PASS_HASH
const crypto = require('crypto');
const pw = process.argv[2];
if (!pw) { console.error('Usage: node hash-password.js "your password"'); process.exit(1); }
const N = 16384, r = 8, p = 1, salt = crypto.randomBytes(16);
console.log(['scrypt', N, r, p, salt.toString('hex'), crypto.scryptSync(pw, salt, 32, { N, r, p }).toString('hex')].join('$'));
