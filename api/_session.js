// api/_session.js  — NEW FILE
//
// Signed session cookies using Node's built-in `crypto`, so this adds ZERO new
// npm dependencies to your project.
//
// WHY THIS FILE HAS TO EXIST
// Your old api/auth.js verified the Google ID token correctly — that part was
// never the problem. The problem was what happened next: it returned the
// verified { sub, email } to the browser as plain JSON and then forgot about
// it. So when the browser later called /api/store, the server had no way to
// tell a genuinely-verified visitor from someone who had simply typed the
// request themselves. A signed cookie closes that gap: only the server can
// mint one (it needs SESSION_SECRET, which never leaves the server), and
// /api/store re-derives identity from it on every single request.
//
// New env var required:
//   SESSION_SECRET — any long random string, e.g. `openssl rand -hex 32`
//   ADMIN_EMAILS   — comma-separated Google emails allowed into the admin deck
import crypto from 'crypto';

const COOKIE = 'pp_session';
const TTL_SECONDS = 60 * 60 * 24 * 30;   // 30 days

function secret() { return process.env.SESSION_SECRET || ''; }
function hmac(data) { return crypto.createHmac('sha256', secret()).update(data).digest('base64url'); }

export function signSession(payload) {
  if (!secret()) throw new Error('SESSION_SECRET not configured');
  const body = { ...payload, exp: Math.floor(Date.now() / 1000) + TTL_SECONDS };
  const data = Buffer.from(JSON.stringify(body)).toString('base64url');
  return `${data}.${hmac(data)}`;
}

export function verifySession(token) {
  if (!secret() || !token) return null;
  const dot = token.lastIndexOf('.');
  if (dot < 1) return null;
  const data = token.slice(0, dot), sig = token.slice(dot + 1);
  const expected = hmac(data);
  // Constant-time compare so the signature can't be brute-forced byte by byte.
  const a = Buffer.from(sig), b = Buffer.from(expected);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;   // forged or tampered
  try {
    const payload = JSON.parse(Buffer.from(data, 'base64url').toString('utf8'));
    if (!payload.exp || payload.exp < Math.floor(Date.now() / 1000)) return null;   // expired
    return payload;
  } catch { return null; }
}

// HttpOnly => page JavaScript cannot read it, so an XSS bug or a rogue browser
// extension can't lift the session. Secure => HTTPS only. SameSite=Lax => it
// isn't sent on cross-site POSTs, which is what blocks CSRF.
export function setSessionCookie(res, payload) {
  res.setHeader('Set-Cookie',
    `${COOKIE}=${signSession(payload)}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=${TTL_SECONDS}`);
}

export function clearSessionCookie(res) {
  res.setHeader('Set-Cookie', `${COOKIE}=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0`);
}

export function readSession(req) {
  const header = req.headers.cookie || '';
  const hit = header.split(';').map(s => s.trim()).find(s => s.startsWith(COOKIE + '='));
  return hit ? verifySession(hit.slice(COOKIE.length + 1)) : null;
}

// The single source of truth for "who is an admin". Lives in an environment
// variable on the server, so it is not in the shipped HTML, not in the
// database (where a compromised write could edit it), and not something any
// request can influence.
export function isAdminEmail(email) {
  const admins = (process.env.ADMIN_EMAILS || '')
    .split(',').map(s => s.trim().toLowerCase()).filter(Boolean);
  return !!email && admins.includes(String(email).toLowerCase());
}
