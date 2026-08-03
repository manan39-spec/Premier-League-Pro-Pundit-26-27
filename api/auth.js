// Google Sign-In verification endpoint.
//   POST { credential }  ->  { ok:true, sub, email, emailVerified, name, picture }
//                            { ok:false, error }
//
// The browser must NEVER be trusted to decode the Google ID token itself — this
// endpoint verifies the token's signature against Google's public keys and checks
// it was issued for THIS app before returning the identity.
//
// Requires env var (set in Vercel project settings):
//   GOOGLE_CLIENT_ID  — the OAuth 2.0 "Web application" client ID from the
//                       Google Cloud console (looks like 1234-abc.apps.googleusercontent.com)
import { OAuth2Client } from 'google-auth-library';

export default async function handler(req, res) {
  res.setHeader('Cache-Control', 'no-store');

  if (req.method !== 'POST') {
    return res.status(405).json({ ok: false, error: 'method not allowed' });
  }

  const CLIENT_ID = process.env.GOOGLE_CLIENT_ID || '';
  if (!CLIENT_ID) {
    return res.status(500).json({ ok: false, error: 'GOOGLE_CLIENT_ID not configured' });
  }

  try {
    const body = typeof req.body === 'string' ? JSON.parse(req.body || '{}') : (req.body || {});
    const credential = body.credential;
    if (!credential || typeof credential !== 'string') {
      return res.status(400).json({ ok: false, error: 'missing credential' });
    }

    const client = new OAuth2Client(CLIENT_ID);
    const ticket = await client.verifyIdToken({ idToken: credential, audience: CLIENT_ID });
    const p = ticket.getPayload();
    if (!p || !p.sub) {
      return res.status(401).json({ ok: false, error: 'invalid token' });
    }

    return res.status(200).json({
      ok: true,
      sub: p.sub,                       // stable, unique Google account id
      email: p.email || '',
      emailVerified: !!p.email_verified,
      name: p.name || p.given_name || '',
      picture: p.picture || '',
    });
  } catch (err) {
    console.error('auth verify error', err);
    return res.status(401).json({ ok: false, error: 'verification failed' });
  }
}
