// POST /api/pro -> admin-only. Grants Pro on this browser for 30 days via a signed HttpOnly cookie.
const A = require('./_auth');

module.exports = (req, res) => {
  res.setHeader('Cache-Control', 'no-store');
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });
  if (!A.sameOrigin(req)) return res.status(403).json({ error: 'Forbidden' });
  try {
    if (!A.getAuth(req).admin) return res.status(403).json({ error: 'Administrator sign-in required' });
    const token = A.sign({ r: 'pro', exp: Date.now() + A.PRO_TTL });
    res.setHeader('Set-Cookie', A.cookie(req, 'lq_pro', token, A.PRO_TTL / 1000));
    res.status(200).json({ ok: true, proUntil: Date.now() + A.PRO_TTL });
  } catch (e) {
    console.error('pro:', e.message);
    res.status(500).json({ error: 'Server auth is misconfigured' });
  }
};
