// GET /api/session -> what the server says this browser is allowed to do.
const A = require('./_auth');

module.exports = (req, res) => {
  res.setHeader('Cache-Control', 'no-store');
  if (req.method !== 'GET') return res.status(405).json({ error: 'Method not allowed' });
  try {
    const a = A.getAuth(req);
    const out = { admin: a.admin, pro: a.pro, proCookie: a.proCookie, proUntil: a.proUntil };
    if (a.admin) out.youtubeConfigured = !!process.env.YOUTUBE_API_KEY;   // only admins see config state
    res.status(200).json(out);
  } catch (e) {
    console.error('session:', e.message);
    res.status(200).json({ admin: false, pro: false, proCookie: false, proUntil: null });
  }
};
