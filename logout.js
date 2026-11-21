// POST /api/logout -> ends the admin session (a saved Pro cookie is kept).
const A = require('./_auth');

module.exports = (req, res) => {
  res.setHeader('Cache-Control', 'no-store');
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });
  if (!A.sameOrigin(req)) return res.status(403).json({ error: 'Forbidden' });
  res.setHeader('Set-Cookie', A.cookie(req, 'lq_admin', '', 0));
  res.status(200).json({ ok: true });
};
