// Shared JSON store backed by Upstash Redis (REST).
//
// The request/response contract your front-end already uses is UNCHANGED:
//   GET  ?health=1                     -> { ok: true }
//   GET  ?key=<k>                      -> { value: <parsed|null> }
//   GET  ?prefix=<p>                   -> { keys: [...] }
//   POST { key, value }                -> { ok: true }
//   POST { action:"delete", keys:[] }  -> { ok: true }
//   POST { action:"wipe", prefix }     -> { ok: true }
//
// ===========================================================================
// WHY THIS FILE WAS THE HOLE
// The previous version took any key and any value from any caller with no
// login check whatsoever. That is precisely how your friend created accounts
// without Google: a single POST to /api/store with
//     { "key": "pp_pred:SomeName", "value": { "name": "SomeName" } }
// created a pundit, no sign-in involved. The same open door made
// action:"wipe" and action:"delete" callable by anyone who found the endpoint.
//
// WHAT IT ENFORCES NOW — every request needs the signed session cookie that
// /api/auth issues after verifying a real Google ID token, and then:
//
//   pp_pred:<name>    you may only write a record that is linked to YOUR
//                     Google sub. The googleSub/email fields are stamped from
//                     the verified session and never taken from the request
//                     body, so a POST claiming someone else's sub does nothing.
//                     Creating an account with NO Google link is admin-only.
//   pp_google:<sub>   only your own sub.
//   everything else   (pp_state, pp_epoch, pp_survivor_on, pp_ver, all deletes,
//                     the wipe action) is admin-only, checked against the
//                     ADMIN_EMAILS env var on the server.
//
// Env vars: your existing UPSTASH_REDIS_REST_URL / UPSTASH_REDIS_REST_TOKEN,
// plus SESSION_SECRET and ADMIN_EMAILS (see api/auth.js).
// ===========================================================================
import { Redis } from '@upstash/redis';
import { readSession, isAdminEmail } from './_session.js';

const redis = Redis.fromEnv();

// Only these key shapes may ever be written. Without this, any signed-in user
// could stuff unlimited arbitrary keys into your Redis and burn the quota.
const KEY_OK = k => typeof k === 'string' && k.length <= 200 && (
  k.startsWith('pp_pred:') || k.startsWith('pp_google:') ||
  ['pp_state', 'pp_epoch', 'pp_survivor_on', 'pp_ver'].includes(k)
);
const isPlainObject = v => !!v && typeof v === 'object' && !Array.isArray(v);
const MAX_ACCOUNTS_PER_GOOGLE = 2;   // 1 real account + 1 in-flight during a rename

async function scanKeys(prefix) {
  const keys = [];
  let cursor = 0;
  do {
    const [next, batch] = await redis.scan(cursor, { match: prefix + '*', count: 200 });
    cursor = Number(next);
    if (Array.isArray(batch)) keys.push(...batch);
  } while (cursor !== 0);
  return keys;
}

// May this session delete this key?
async function mayDelete(key, session, admin) {
  if (admin) return true;
  if (key.startsWith('pp_pred:')) {
    const existing = await redis.get(key);
    return !!existing && existing.googleSub === session.sub;   // only your own account
  }
  if (key.startsWith('pp_google:')) return key === `pp_google:${session.sub}`;
  return false;
}

// Returns the value to actually store, or null to refuse with 403.
async function authorizeWrite(key, value, session, admin) {
  if (key.startsWith('pp_pred:')) {
    if (!isPlainObject(value)) return null;
    const existing = await redis.get(key);

    if (existing && existing.googleSub) {
      // Already linked to a Google account — only that account (or an admin).
      if (existing.googleSub !== session.sub && !admin) return null;
    } else if (!existing) {
      // Brand-new record. A normal signup always carries a googleSub because it
      // only happens straight after a verified login; an unlinked placeholder
      // account is the admin's "add pundit" tool and nobody else's.
      if (!value.googleSub && !admin) return null;
      if (!admin) {
        // Soft cap so one Google account can't spam the roster.
        const mine = [];
        for (const k of await scanKeys('pp_pred:')) {
          const rec = await redis.get(k);
          if (rec && rec.googleSub === session.sub) mine.push(k);
        }
        if (mine.length >= MAX_ACCOUNTS_PER_GOOGLE) return null;
      }
    }
    // else: existing record with no googleSub — a legacy name being claimed.
    // Allowed, and the claim gets stamped with the claimer's real identity below.

    if (admin) return value;
    const stamped = { ...value };
    // Identity always comes from the verified session (or from what was already
    // stored), never from the request body. This is the line that makes
    // "POST me an account as someone else" impossible.
    if (existing && existing.googleSub) {
      stamped.googleSub = existing.googleSub;
      stamped.email = existing.email;
    } else {
      stamped.googleSub = session.sub;
      stamped.email = session.email;
    }
    return stamped;
  }

  if (key.startsWith('pp_google:')) {
    if (!isPlainObject(value)) return null;
    if (key !== `pp_google:${session.sub}` && !admin) return null;
    return value;
  }

  // pp_state, pp_epoch, pp_survivor_on, pp_ver -> admin only.
  return admin ? value : null;
}

export default async function handler(req, res) {
  res.setHeader('Cache-Control', 'no-store');
  try {
    // Health check stays open: it only answers "is the API reachable", no data.
    if (req.method === 'GET' && req.query.health) return res.status(200).json({ ok: true });

    const session = readSession(req);
    if (!session) return res.status(401).json({ error: 'sign in required' });
    const admin = isAdminEmail(session.email);

    // ---- reads: any signed-in league member ------------------------------
    if (req.method === 'GET') {
      if (typeof req.query.key === 'string') {
        const raw = await redis.get(req.query.key);
        return res.status(200).json({ value: raw ?? null });
      }
      if (typeof req.query.prefix === 'string') {
        return res.status(200).json({ keys: await scanKeys(req.query.prefix) });
      }
      return res.status(400).json({ error: 'bad GET request' });
    }

    if (req.method === 'POST') {
      const body = typeof req.body === 'string' ? JSON.parse(req.body || '{}') : (req.body || {});

      // ---- delete -------------------------------------------------------
      if (body.action === 'delete' && Array.isArray(body.keys)) {
        if (body.keys.length > 500) return res.status(400).json({ error: 'too many keys' });
        for (const k of body.keys) {
          if (!(await mayDelete(k, session, admin))) {
            return res.status(403).json({ error: `not allowed to delete ${k}` });
          }
        }
        if (body.keys.length) await redis.del(...body.keys);
        return res.status(200).json({ ok: true });
      }

      // ---- wipe: admin only ---------------------------------------------
      if (body.action === 'wipe' && typeof body.prefix === 'string') {
        if (!admin) return res.status(403).json({ error: 'admin only' });
        if (!body.prefix.startsWith('pp_')) return res.status(400).json({ error: 'prefix must start with pp_' });
        let cursor = 0;
        do {
          const [next, batch] = await redis.scan(cursor, { match: body.prefix + '*', count: 200 });
          cursor = Number(next);
          if (Array.isArray(batch) && batch.length) await redis.del(...batch);
        } while (cursor !== 0);
        return res.status(200).json({ ok: true });
      }

      // ---- single write --------------------------------------------------
      if (typeof body.key === 'string') {
        if (!KEY_OK(body.key)) return res.status(400).json({ error: 'unrecognised key' });
        const safe = await authorizeWrite(body.key, body.value, session, admin);
        if (safe === null) return res.status(403).json({ error: `not allowed to write ${body.key}` });
        await redis.set(body.key, safe);
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
