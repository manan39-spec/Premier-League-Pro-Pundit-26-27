// Google Sign-In verification endpoint.
//
//   POST { credential }   -> verifies the Google ID token, SETS THE SESSION COOKIE,
//                            returns { ok, sub, email, emailVerified, name, picture, isAdmin }
//   GET                   -> "whoami": { ok, sub, email, name, isAdmin } from the cookie
//   POST ?logout=1        -> clears the session cookie
//
// The browser must NEVER be trusted to decode the Google ID token itself — this
// endpoint verifies the token's signature against Google's public keys and checks
// it was issued for THIS app before returning the identity.
//
// WHAT CHANGED FROM YOUR VERSION
//   1. On success it now sets a signed HttpOnly cookie (see _session.js). That
//      cookie is what /api/store trusts. Previously the verified identity was
//      handed to the browser and immediately forgotten by the server, so
//      /api/store had nothing to check and accepted anything.
//   2. Added GET (whoami) so a page reload restores the session without
//      re-running the Google button, and so the front-end can learn `isAdmin`
//      without that decision ever being made client-side.
//   3. Added ?logout=1 so "switch" actually ends the session instead of just
//      forgetting the display name on that device.
//   4. Requires email_verified — an unverified Google email can't claim admin.
//
// Requires env vars (Vercel -> Project -> Settings -> Environment Variables):
//   GOOGLE_CLIENT_ID  — the OAuth 2.0 "Web application" client ID
//   SESSION_SECRET    — NEW: long random string, `openssl rand -hex 32`
//   ADMIN_EMAILS      — NEW: e.g. "manan39@gmail.com"
import { OAuth2Client } from 'google-auth-library';
import { setSessionCookie, clearSessionCookie, readSession, isAdminEmail } from './_session.js';

export default async function handler(req, res) {
  res.setHeader('Cache-Control', 'no-store');

  // ---- whoami -------------------------------------------------------------
  if (req.method === 'GET') {
    const s = readSession(req);
    if (!s) return res.status(200).json({ ok: false });
    return res.status(200).json({
      ok: true, sub: s.sub, email: s.email, name: s.name,
      isAdmin: isAdminEmail(s.email),
    });
  }

  if (req.method !== 'POST') {
    return res.status(405).json({ ok: false, error: 'method not allowed' });
  }

  // ---- logout -------------------------------------------------------------
  if (req.query && req.query.logout) {
    clearSessionCookie(res);
    return res.status(200).json({ ok: true });
  }

  const CLIENT_ID = process.env.GOOGLE_CLIENT_ID || '';
  if (!CLIENT_ID) {
    return res.status(500).json({ ok: false, error: 'GOOGLE_CLIENT_ID not configured' });
  }
  if (!process.env.SESSION_SECRET) {
    return res.status(500).json({ ok: false, error: 'SESSION_SECRET not configured' });
  }

  // ---- verify a Google credential and start a session ---------------------
  try {
    const body = typeof req.body === 'string' ? JSON.parse(req.body || '{}') : (req.body || {});
    const credential = body.credential;
    if (!credential || typeof credential !== 'string') {
      return res.status(400).json({ ok: false, error: 'missing credential' });
    }

    const client = new OAuth2Client(CLIENT_ID);
    const ticket = await client.verifyIdToken({ idToken: credential, audience: CLIENT_ID });
    const p = ticket.getPayload();
    if (!p || !p.sub) return res.status(401).json({ ok: false, error: 'invalid token' });
    // An unverified email must never be able to match ADMIN_EMAILS.
    if (!p.email || !p.email_verified) {
      return res.status(401).json({ ok: false, error: 'Google email not verified' });
    }

    // THE one place identity is established. Everything downstream reads the
    // cookie set here — never a value the client repeats back to us.
    const session = { sub: p.sub, email: p.email, name: p.name || p.given_name || '' };
    setSessionCookie(res, session);

    return res.status(200).json({
      ok: true,
      sub: session.sub,
      email: session.email,
      emailVerified: true,
      name: session.name,
      picture: p.picture || '',
      isAdmin: isAdminEmail(session.email),
    });
  } catch (err) {
    console.error('auth verify error', err);
    return res.status(401).json({ ok: false, error: 'verification failed' });
  }
}
