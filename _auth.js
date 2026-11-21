// Shared helpers for LiquixTune serverless functions (underscore prefix = not exposed as a route).
const crypto = require('crypto');

const ADMIN_TTL = 8 * 60 * 60 * 1000;          // admin session: 8 hours
const PRO_TTL = 30 * 24 * 60 * 60 * 1000;      // Pro on a browser: 30 days

function secret() {
  const s = process.env.SESSION_SECRET;
  if (!s || s.length < 32) throw new Error('SESSION_SECRET missing or shorter than 32 chars');
  return s;
}
const hmac = (body) => crypto.createHmac('sha256', secret()).update(body).digest('base64url');

function sign(payload) {
  const body = Buffer.from(JSON.stringify(payload)).toString('base64url');
  return body + '.' + hmac(body);
}

function verify(token) {
  if (!token || typeof token !== 'string') return null;
  const [body, sig] = token.split('.');
  if (!body || !sig) return null;
  const a = Buffer.from(sig), b = Buffer.from(hmac(body));
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
  try {
    const p = JSON.parse(Buffer.from(body, 'base64url').toString());
    return p && p.exp > Date.now() ? p : null;
  } catch { return null; }
}

function parseCookies(req) {
  const out = {};
  (req.headers.cookie || '').split(';').forEach((c) => {
    const i = c.indexOf('=');
    if (i > 0) out[c.slice(0, i).trim()] = c.slice(i + 1).trim();
  });
  return out;
}

function cookie(req, name, value, maxAgeSec) {
  const secure = (req.headers['x-forwarded-proto'] || '').split(',')[0] === 'https';
  return `${name}=${value}; Path=/; HttpOnly; SameSite=Strict; Max-Age=${maxAgeSec}${secure ? '; Secure' : ''}`;
}

// Returns what the server believes about this browser. Nothing here is trusted from the client.
function getAuth(req) {
  const c = parseCookies(req);
  const admin = !!(verify(c.lq_admin) || {}).r;
  const pro = verify(c.lq_pro);
  const proCookie = !!(pro && pro.r === 'pro');
  return {
    admin,
    proCookie,
    pro: admin || proCookie,
    proUntil: proCookie ? pro.exp : null,
  };
}

// Reject cross-site POSTs (cookies are SameSite=Strict too; this is defence in depth).
function sameOrigin(req) {
  const o = req.headers.origin;
  if (!o) return true;
  try { return new URL(o).host === req.headers.host; } catch { return false; }
}

// Best-effort in-memory limiter (per warm serverless instance).
function limiter(max, windowMs) {
  const hits = new Map();
  return {
    check(key) {
      const now = Date.now();
      const arr = (hits.get(key) || []).filter((t) => now - t < windowMs);
      if (arr.length >= max) { hits.set(key, arr); return Math.ceil((windowMs - (now - arr[0])) / 1000); }
      arr.push(now); hits.set(key, arr);
      if (hits.size > 5000) hits.delete(hits.keys().next().value);
      return 0;
    },
    reset(key) { hits.delete(key); },
  };
}

const ip = (req) => String(req.headers['x-forwarded-for'] || req.socket?.remoteAddress || 'unknown').split(',')[0].trim();

module.exports = { ADMIN_TTL, PRO_TTL, sign, verify, cookie, getAuth, sameOrigin, limiter, ip };
