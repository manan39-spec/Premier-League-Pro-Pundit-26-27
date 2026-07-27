// Shared JSON store backed by Upstash Redis (REST).
// Same contract the app expects:
//   GET  ?health=1                     -> { ok: true }
//   GET  ?key=<k>                      -> { value: <parsed|null> }
//   GET  ?prefix=<p>                   -> { keys: [...] }
//   POST { key, value }               -> { ok: true }
//   POST { action:"delete", keys:[] } -> { ok: true }
//   POST { action:"wipe", prefix }    -> { ok: true }
//
// Requires env vars (set in Vercel project settings, provided automatically
// when you attach an Upstash Redis integration):
//   UPSTASH_REDIS_REST_URL, UPSTASH_REDIS_REST_TOKEN
import { Redis } from '@upstash/redis';

const redis = Redis.fromEnv();

export default async function handler(req, res) {
  res.setHeader('Cache-Control', 'no-store');
  try {
    if (req.method === 'GET') {
      if (req.query.health) return res.status(200).json({ ok: true });

      if (typeof req.query.key === 'string') {
        const raw = await redis.get(req.query.key);
        // @upstash/redis auto-parses JSON; normalise to a plain value or null.
        return res.status(200).json({ value: raw ?? null });
      }

      if (typeof req.query.prefix === 'string') {
        const keys = [];
        let cursor = 0;
        do {
          const [next, batch] = await redis.scan(cursor, {
            match: req.query.prefix + '*',
            count: 200,
          });
          cursor = Number(next);
          if (Array.isArray(batch)) keys.push(...batch);
        } while (cursor !== 0);
        return res.status(200).json({ keys });
      }

      return res.status(400).json({ error: 'bad GET request' });
    }

    if (req.method === 'POST') {
      const body = typeof req.body === 'string' ? JSON.parse(req.body || '{}') : (req.body || {});

      if (body.action === 'delete' && Array.isArray(body.keys)) {
        if (body.keys.length) await redis.del(...body.keys);
        return res.status(200).json({ ok: true });
      }

      if (body.action === 'wipe' && typeof body.prefix === 'string') {
        let cursor = 0;
        do {
          const [next, batch] = await redis.scan(cursor, {
            match: body.prefix + '*',
            count: 200,
          });
          cursor = Number(next);
          if (Array.isArray(batch) && batch.length) await redis.del(...batch);
        } while (cursor !== 0);
        return res.status(200).json({ ok: true });
      }

      if (typeof body.key === 'string') {
        await redis.set(body.key, body.value);
        return res.status(200).json({ ok: true });
      }

      return res.status(400).json({ error: 'bad POST body' });
    }

    return res.status(405).json({ error: 'method not allowed' });
  } catch (err) {
    console.error('store error', err);
    return res.status(500).json({ error: String(err && err.message || err) });
  }
}
