'use strict';
/* Zero-dependency Node.js server: real server-side login for the AASTU AI & Robotics CoE lab.
   - The password is never stored in code: only a scrypt hash, read from an environment variable.
   - The protected site (protected/index.html) is sent ONLY after a valid session cookie.
   Required environment variables: AUTH_USER, AUTH_PASS_HASH, SESSION_SECRET (32+ characters). */
const http = require('http'), fs = require('fs'), path = require('path'), crypto = require('crypto');
const PORT = process.env.PORT || 3000;
const USER = process.env.AUTH_USER, HASH = process.env.AUTH_PASS_HASH, SECRET = process.env.SESSION_SECRET;
if (!USER || !HASH || !SECRET || SECRET.length < 32) {
  console.error('Missing config. Set AUTH_USER, AUTH_PASS_HASH and SESSION_SECRET (at least 32 characters). See README.md.');
  process.exit(1);
}
const SITE = fs.readFileSync(path.join(__dirname, 'protected', 'index.html'));
const LOGIN = fs.readFileSync(path.join(__dirname, 'public', 'login.html'), 'utf8');
const SESSION_MS = 8 * 60 * 60 * 1000;           // sessions last 8 hours
const sha = (s) => crypto.createHash('sha256').update(String(s)).digest();
const safeEq = (a, b) => crypto.timingSafeEqual(sha(a), sha(b));

function checkPassword(pw) {
  const [alg, N, r, p, salt, hash] = HASH.split('$');
  if (alg !== 'scrypt') return false;
  const want = Buffer.from(hash, 'hex');
  const got = crypto.scryptSync(pw, Buffer.from(salt, 'hex'), want.length, { N: +N, r: +r, p: +p, maxmem: 256 * 1024 * 1024 });
  return got.length === want.length && crypto.timingSafeEqual(got, want);
}
const sign = (v) => crypto.createHmac('sha256', SECRET).update(v).digest('base64url');
function makeToken(u) {
  const b = Buffer.from(JSON.stringify({ u, exp: Date.now() + SESSION_MS })).toString('base64url');
  return b + '.' + sign(b);
}
function readToken(tok) {
  if (!tok || tok.indexOf('.') < 0) return null;
  const [b, sig] = tok.split('.');
  const good = sign(b);
  if (!sig || sig.length !== good.length || !crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(good))) return null;
  try { const d = JSON.parse(Buffer.from(b, 'base64url').toString()); return d.exp > Date.now() ? d : null; } catch (e) { return null; }
}
const cookies = (req) => Object.fromEntries((req.headers.cookie || '').split(';').map((c) => c.trim()).filter(Boolean).map((c) => { const i = c.indexOf('='); return [c.slice(0, i), c.slice(i + 1)]; }));
const isHttps = (req) => process.env.NODE_ENV === 'production' || req.headers['x-forwarded-proto'] === 'https';
const authed = (req) => { const d = readToken(cookies(req).sid); return !!d && safeEq(d.u, USER); };

// in-memory rate limit: 5 failed logins per 15 minutes per IP
const fails = new Map();
const ipOf = (req) => (req.headers['x-forwarded-for'] || req.socket.remoteAddress || '').split(',')[0].trim();
const limited = (ip) => { const f = fails.get(ip); return !!f && f.n >= 5 && Date.now() - f.t < 15 * 60 * 1000; };
function fail(ip) { const f = fails.get(ip); if (!f || Date.now() - f.t > 15 * 60 * 1000) fails.set(ip, { n: 1, t: Date.now() }); else f.n++; }

function headers(req, extra) {
  const h = Object.assign({
    'X-Content-Type-Options': 'nosniff', 'X-Frame-Options': 'DENY', 'Referrer-Policy': 'no-referrer',
    'Permissions-Policy': 'camera=(), microphone=(), geolocation=()',
    'Content-Security-Policy': "default-src 'self' data: blob:; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; form-action 'self'"
  }, extra || {});
  if (isHttps(req)) h['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains';
  return h;
}
const send = (req, res, code, type, data, extra) => { res.writeHead(code, headers(req, Object.assign({ 'Content-Type': type }, extra))); res.end(data); };
const redirect = (req, res, to, extra) => { res.writeHead(302, headers(req, Object.assign({ Location: to }, extra))); res.end(); };
function readBody(req, cb) {
  let b = ''; req.on('data', (c) => { b += c; if (b.length > 2048) req.destroy(); });
  req.on('end', () => cb(new URLSearchParams(b)));
}
const sameOrigin = (req) => { const o = req.headers.origin; if (!o) return true; try { return new URL(o).host === req.headers.host; } catch (e) { return false; } };

http.createServer((req, res) => {
  const url = req.url.split('?')[0];
  if (url === '/healthz') return send(req, res, 200, 'text/plain', 'ok');
  if (req.method === 'POST' && url === '/login') {
    if (!sameOrigin(req)) return send(req, res, 403, 'text/plain', 'Forbidden');
    const ip = ipOf(req);
    if (limited(ip)) return send(req, res, 429, 'text/html; charset=utf-8', LOGIN.replace('__ERR__', 'Too many attempts. Try again in 15 minutes.'), { 'Cache-Control': 'no-store' });
    return readBody(req, (f) => {
      const u = (f.get('username') || '').trim(), p = f.get('password') || '';
      const okUser = safeEq(u.toLowerCase(), USER.toLowerCase());
      const okPass = checkPassword(p);                      // always run, so timing does not reveal the username
      if (okUser && okPass) {
        fails.delete(ip);
        const cookie = 'sid=' + makeToken(USER) + '; HttpOnly; SameSite=Lax; Path=/; Max-Age=' + SESSION_MS / 1000 + (isHttps(req) ? '; Secure' : '');
        return redirect(req, res, '/', { 'Set-Cookie': cookie, 'Cache-Control': 'no-store' });
      }
      fail(ip);
      return send(req, res, 401, 'text/html; charset=utf-8', LOGIN.replace('__ERR__', 'Wrong username or password'), { 'Cache-Control': 'no-store' });
    });
  }
  if (req.method === 'POST' && url === '/logout') {
    if (!sameOrigin(req)) return send(req, res, 403, 'text/plain', 'Forbidden');
    return send(req, res, 204, 'text/plain', '', { 'Set-Cookie': 'sid=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0' + (isHttps(req) ? '; Secure' : '') });
  }
  if (req.method !== 'GET' && req.method !== 'HEAD') return send(req, res, 405, 'text/plain', 'Method not allowed');
  if (url === '/login') return authed(req) ? redirect(req, res, '/') : send(req, res, 200, 'text/html; charset=utf-8', LOGIN.replace('__ERR__', ''), { 'Cache-Control': 'no-store' });
  if (url === '/') return authed(req) ? send(req, res, 200, 'text/html; charset=utf-8', SITE, { 'Cache-Control': 'no-store, private' }) : redirect(req, res, '/login');
  return send(req, res, 404, 'text/plain', 'Not found');
}).listen(PORT, () => console.log('Lab server running on port ' + PORT));
