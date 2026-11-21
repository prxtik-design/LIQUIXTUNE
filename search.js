// GET /api/search?q=...&max=12 -> YouTube Data API v3 proxy. The key never reaches the browser.
// Env: YOUTUBE_API_KEY (required), YT_DAILY_SEARCH_LIMIT (optional, default 80 uncached searches/day/instance).
// NOTE: search.list costs 100 quota units; the default 10,000/day quota is only ~99 uncached searches.
const A = require('./_auth');

const cache = new Map();                 // key -> { t, items }
const TTL = 10 * 60 * 1000, MAX_CACHE = 300;
const perIp = A.limiter(30, 60 * 1000);  // 30 requests / minute / IP
let day = '', used = 0;

const dec = (s) => String(s || '')
  .replace(/&amp;/g, '&').replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&quot;/g, '"')
  .replace(/&#x27;|&#39;/g, "'").replace(/&#(\d+);/g, (_, n) => String.fromCharCode(+n));

function dur(iso) {
  const m = /^PT(?:(\d+)H)?(?:(\d+)M)?(?:(\d+)S)?$/.exec(iso || '');
  if (!m) return { sec: 0, label: '' };
  const h = +m[1] || 0, mi = +m[2] || 0, s = +m[3] || 0, sec = h * 3600 + mi * 60 + s;
  if (!sec) return { sec: 0, label: '' };
  const p = (n) => String(n).padStart(2, '0');
  return { sec, label: h ? `${h}:${p(mi)}:${p(s)}` : `${mi}:${p(s)}` };
}

async function yt(path, params) {
  const url = 'https://www.googleapis.com/youtube/v3/' + path + '?' + new URLSearchParams({ ...params, key: process.env.YOUTUBE_API_KEY });
  const r = await fetch(url, { signal: AbortSignal.timeout(8000) });
  const j = await r.json().catch(() => ({}));
  if (!r.ok) {
    const reason = j.error?.errors?.[0]?.reason || '';
    const e = new Error('YouTube API ' + r.status + ' ' + reason);
    e.quota = /quota|rateLimit/i.test(reason);
    throw e;
  }
  return j;
}

module.exports = async (req, res) => {
  if (req.method !== 'GET') return res.status(405).json({ error: 'Method not allowed' });
  if (!process.env.YOUTUBE_API_KEY) return res.status(503).json({ error: 'Search is not configured yet' });

  const q = String(req.query.q || '').trim().slice(0, 100);
  if (q.length < 2) return res.status(400).json({ error: 'Query too short' });
  const max = Math.min(25, Math.max(1, parseInt(req.query.max, 10) || 12));

  const wait = perIp.check(A.ip(req));
  if (wait) { res.setHeader('Retry-After', wait); return res.status(429).json({ error: 'Too many searches, slow down a little' }); }

  const ck = q.toLowerCase() + '|' + max;
  const hit = cache.get(ck);
  const ok = (items, tag) => {
    res.setHeader('X-Cache', tag);
    res.setHeader('Cache-Control', 'public, s-maxage=600, stale-while-revalidate=3600');
    return res.status(200).json({ items });
  };
  if (hit && Date.now() - hit.t < TTL) return ok(hit.items, 'HIT');

  const today = new Date().toISOString().slice(0, 10);
  if (today !== day) { day = today; used = 0; }
  if (used >= (parseInt(process.env.YT_DAILY_SEARCH_LIMIT, 10) || 80)) {
    if (hit) return ok(hit.items, 'STALE');
    return res.status(429).json({ error: 'Daily YouTube search limit reached. Try again tomorrow.' });
  }

  try {
    used++;
    const s = await yt('search', { part: 'snippet', type: 'video', videoCategoryId: '10', videoEmbeddable: 'true', maxResults: String(max), q });
    const base = (s.items || []).filter((i) => /^[\w-]{11}$/.test(i.id?.videoId || ''));
    let details = {};
    if (base.length) {
      const v = await yt('videos', { part: 'contentDetails', id: base.map((i) => i.id.videoId).join(',') });
      (v.items || []).forEach((i) => { details[i.id] = dur(i.contentDetails?.duration); });
    }
    const items = base.map((i) => {
      const t = i.snippet.thumbnails || {};
      const d = details[i.id.videoId] || { sec: 0, label: '' };
      return {
        id: i.id.videoId,
        title: dec(i.snippet.title),
        channel: dec(i.snippet.channelTitle).replace(/ - Topic$/, ''),
        thumb: (t.medium || t.high || t.default || {}).url || '',
        duration: d.label,
        durationSec: d.sec,
      };
    });
    if (cache.size >= MAX_CACHE) cache.delete(cache.keys().next().value);
    cache.set(ck, { t: Date.now(), items });
    return ok(items, 'MISS');
  } catch (e) {
    console.error('search:', e.message);
    if (hit) return ok(hit.items, 'STALE');
    if (e.quota) return res.status(429).json({ error: 'YouTube quota reached for today' });
    return res.status(502).json({ error: 'YouTube search is unavailable right now' });
  }
};
