// POST /api/admin-login  { username, password }
// Env: SESSION_SECRET (32+ chars), ADMIN_PASSWORD_HASH (scrypt$salt$hash) or ADMIN_PASSWORD, optional ADMIN_USER (default "admin").
const crypto = require('crypto');
const A = require('./_auth');
const fails = A.limiter(5, 15 * 60 * 1000);

const sha = (s) => crypto.createHash('sha256').update(String(s)).digest();
const same = (a, b) => crypto.timingSafeEqual(sha(a), sha(b));

function passwordOk(pw) {
  const h = process.env.ADMIN_PASSWORD_HASH;
  if (h) {
    const [alg, salt, hash] = h.split('$');
    if (alg !== 'scrypt' || !salt || !hash) return false;
    const d = crypto.scryptSync(String(pw), Buffer.from(salt, 'base64url'), 64);
    const e = Buffer.from(hash, 'base64url');
    return d.length === e.length && crypto.timingSafeEqual(d, e);
  }
  return process.env.ADMIN_PASSWORD ? same(pw, process.env.ADMIN_PASSWORD) : false;
}

module.exports = async (req, res) => {
  res.setHeader('Cache-Control', 'no-store');
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });
  if (!A.sameOrigin(req)) return res.status(403).json({ error: 'Forbidden' });
  if (!process.env.ADMIN_PASSWORD_HASH && !process.env.ADMIN_PASSWORD)
    return res.status(503).json({ error: 'Admin login is not configured on the server' });

  const key = A.ip(req);
  const wait = fails.check(key);
  if (wait) { res.setHeader('Retry-After', wait); return res.status(429).json({ error: 'Too many attempts. Try again later.' }); }

  const body = typeof req.body === 'string' ? (() => { try { return JSON.parse(req.body); } catch { return {}; } })() : (req.body || {});
  try {
    const userOk = same(body.username || '', process.env.ADMIN_USER || 'admin');
    const pwOk = passwordOk(body.password || '');
    if (!(userOk && pwOk)) {
      await new Promise((r) => setTimeout(r, 400));
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    fails.reset(key);
    const token = A.sign({ r: 'admin', exp: Date.now() + A.ADMIN_TTL });
    res.setHeader('Set-Cookie', A.cookie(req, 'lq_admin', token, A.ADMIN_TTL / 1000));
    res.status(200).json({ ok: true });
  } catch (e) {
    console.error('admin-login:', e.message);
    res.status(500).json({ error: 'Server auth is misconfigured' });
  }
};
