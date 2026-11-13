const json = (data, status = 200) => new Response(JSON.stringify(data), { status, headers: { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store" } });
const enc = new TextEncoder();
const hex = (v) => [...new Uint8Array(v)].map((b) => b.toString(16).padStart(2, "0")).join("");
const randomToken = (n = 32) => [...crypto.getRandomValues(new Uint8Array(n))].map((b) => b.toString(16).padStart(2, "0")).join("");
const sha256 = async (v) => hex(await crypto.subtle.digest("SHA-256", enc.encode(v)));
const safeEqual = (a, b) => { if (typeof a !== "string" || typeof b !== "string" || a.length !== b.length) return false; let x = 0; for (let i = 0; i < a.length; i++) x |= a.charCodeAt(i) ^ b.charCodeAt(i); return x === 0; };
const clean = (v, n = 200) => String(v ?? "").trim().slice(0, n);
const validEmail = (v) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v);
const validPhone = (v) => /^\+[1-9]\d{7,14}$/.test(v);
const validPassword = (v) => typeof v === "string" && v.length >= 12 && v.length <= 128;
async function passwordHash(password, saltHex) {
  const salt = Uint8Array.from(saltHex.match(/.{2}/g).map((x) => parseInt(x, 16)));
  const key = await crypto.subtle.importKey("raw", enc.encode(password), "PBKDF2", false, ["deriveBits"]);
  return hex(await crypto.subtle.deriveBits({ name: "PBKDF2", salt, iterations: 210000, hash: "SHA-256" }, key, 256));
}
async function sendOtp(env, channel, destination, code, purpose) {
  const message = "Your PD Dashboard verification code is " + code + ". It expires in 10 minutes. If you did not request this, ignore this message.";
  if (channel === "email") {
    if (!env.RESEND_API_KEY || !env.RESEND_FROM_EMAIL) throw new Error("Email OTP is not configured yet.");
    const res = await fetch("https://api.resend.com/emails", { method: "POST", headers: { Authorization: "Bearer " + env.RESEND_API_KEY, "Content-Type": "application/json" }, body: JSON.stringify({ from: env.RESEND_FROM_EMAIL, to: [destination], subject: purpose === "reset" ? "PD Dashboard password reset code" : "PD Dashboard verification code", text: message }) });
    if (!res.ok) throw new Error("Email provider could not send the code.");
    return;
  }
  if (channel === "sms") {
    if (!env.TWILIO_ACCOUNT_SID || !env.TWILIO_AUTH_TOKEN || !env.TWILIO_FROM_NUMBER) throw new Error("SMS OTP is not configured yet.");
    const form = new URLSearchParams({ To: destination, From: env.TWILIO_FROM_NUMBER, Body: message });
    const credentials = btoa(env.TWILIO_ACCOUNT_SID + ":" + env.TWILIO_AUTH_TOKEN);
    const res = await fetch("https://api.twilio.com/2010-04-01/Accounts/" + env.TWILIO_ACCOUNT_SID + "/Messages.json", { method: "POST", headers: { Authorization: "Basic " + credentials, "Content-Type": "application/x-www-form-urlencoded" }, body: form });
    if (!res.ok) throw new Error("SMS provider could not send the code.");
    return;
  }
  throw new Error("Choose Email or SMS.");
}
async function issueChallenge(db, user, purpose, channel, destination, env) {
  const since = new Date(Date.now() - 15 * 60 * 1000).toISOString();
  const recent = await db.prepare("SELECT COUNT(*) AS n FROM auth_challenges WHERE user_id=? AND created_at>?").bind(user.id, since).first();
  if ((recent?.n || 0) >= 5) throw new Error("Too many codes requested. Try again in 15 minutes.");
  const code = String(crypto.getRandomValues(new Uint32Array(1))[0] % 1000000).padStart(6, "0");
  const id = randomToken(16);
  const expires = new Date(Date.now() + 10 * 60 * 1000).toISOString();
  const codeHash = await sha256(env.AUTH_PEPPER + ":" + id + ":" + code);
  await db.prepare("INSERT INTO auth_challenges (id,user_id,purpose,channel,code_hash,expires_at,attempts,created_at) VALUES (?,?,?,?,?,?,0,?)").bind(id, user.id, purpose, channel, codeHash, expires, new Date().toISOString()).run();
  try { await sendOtp(env, channel, destination, code, purpose); } catch (e) { await db.prepare("DELETE FROM auth_challenges WHERE id=?").bind(id).run(); throw e; }
  const masked = channel === "email" ? destination.replace(/^(.).+(@.*)$/, "$1•••$2") : destination.replace(/(\+\d{2})\d+(\d{3})$/, "$1••••••$2");
  return { challengeId: id, channel, maskedDestination: masked };
}
async function verifyChallenge(db, id, code, purpose, env) {
  const row = await db.prepare("SELECT * FROM auth_challenges WHERE id=? AND purpose=? AND consumed_at IS NULL").bind(id, purpose).first();
  if (!row || row.expires_at < new Date().toISOString() || row.attempts >= 5) return null;
  const expected = await sha256(env.AUTH_PEPPER + ":" + id + ":" + code);
  if (!safeEqual(expected, row.code_hash)) { await db.prepare("UPDATE auth_challenges SET attempts=attempts+1 WHERE id=?").bind(id).run(); return null; }
  await db.prepare("UPDATE auth_challenges SET consumed_at=? WHERE id=?").bind(new Date().toISOString(), id).run();
  return row;
}
async function createSession(db, user) {
  const token = randomToken(32);
  const expires = new Date(Date.now() + 12 * 60 * 60 * 1000).toISOString();
  await db.prepare("INSERT INTO auth_sessions (token_hash,user_id,expires_at,created_at) VALUES (?,?,?,?)").bind(await sha256(token), user.id, expires, new Date().toISOString()).run();
  return { token, expiresAt: expires };
}
async function getSession(request, db) {
  const h = request.headers.get("Authorization") || "";
  const token = h.startsWith("Bearer ") ? h.slice(7) : "";
  if (!token || token.length > 200) return null;
  const row = await db.prepare("SELECT u.id,u.user_id,u.display_name,u.email,u.phone,u.is_admin,u.two_factor_channel,s.expires_at FROM auth_sessions s JOIN auth_users u ON u.id=s.user_id WHERE s.token_hash=? AND s.expires_at>? AND u.is_active=1").bind(await sha256(token), new Date().toISOString()).first();
  return row ? { row, token } : null;
}
export async function handleAuth(request, env, url) {
  const db = env.DB;
  if (!db || !env.AUTH_PEPPER) return json({ error: "Authentication database or secret is not configured." }, 503);
  const path = url.pathname;
  const body = async () => { try { return await request.json(); } catch { return {}; } };
  if (path === "/api/auth/me" && request.method === "GET") {
    const s = await getSession(request, db);
    if (!s) return json({ error: "Not signed in." }, 401);
    const u = s.row;
    return json({ user: { userId: u.user_id, name: u.display_name, email: u.email, phone: u.phone, isAdmin: !!u.is_admin, twoFactorChannel: u.two_factor_channel }, expiresAt: u.expires_at });
  }
  if (path === "/api/auth/setup" && request.method === "POST") {
    const b = await body();
    if (!env.ADMIN_SETUP_TOKEN || !safeEqual(clean(b.setupToken, 300), env.ADMIN_SETUP_TOKEN)) return json({ error: "Setup code is invalid." }, 403);
    try {
      await db.prepare("INSERT INTO auth_setup_lock (id,created_at) VALUES (1,?)").bind(new Date().toISOString()).run();
    } catch {
      return json({ error: "Initial setup has already been completed." }, 409);
    }
    const userId = clean(b.userId, 40), name = clean(b.name, 80), email = clean(b.email, 160).toLowerCase(), phone = clean(b.phone, 20), password = b.password, channel = b.channel === "sms" ? "sms" : "email";
    if (!/^[a-zA-Z0-9._-]{3,40}$/.test(userId) || !name || !validEmail(email) || !validPassword(password)) return json({ error: "Enter a valid User ID, name, email and password (at least 12 characters)." }, 400);
    if (phone && !validPhone(phone)) return json({ error: "Use international phone format, e.g. +8801XXXXXXXXX." }, 400);
    if (channel === "sms" && !phone) return json({ error: "A mobile number is required for SMS verification." }, 400);
    const id = randomToken(16), salt = randomToken(16), hash = await passwordHash(password, salt);
    try {
      await db.prepare("INSERT INTO auth_users (id,user_id,display_name,email,phone,password_salt,password_hash,is_admin,is_active,two_factor_channel,email_verified,phone_verified,created_at) VALUES (?,?,?,?,?,?,?,1,0,?,0,0,?)").bind(id, userId, name, email, phone || null, salt, hash, channel, new Date().toISOString()).run();
    } catch {
      await db.prepare("DELETE FROM auth_setup_lock WHERE id=1").run();
      return json({ error: "Could not create account. User ID or email may already be used." }, 409);
    }
    try {
      const ch = await issueChallenge(db, { id }, "setup", channel, channel === "sms" ? phone : email, env);
      return json({ ok: true, ...ch, message: "Verification code sent." });
    } catch (e) {
      await db.prepare("DELETE FROM auth_users WHERE id=?").bind(id).run();
      await db.prepare("DELETE FROM auth_setup_lock WHERE id=1").run();
      return json({ error: e.message || "Could not send verification code." }, 503);
    }
  }
  if (path === "/api/auth/verify-setup" && request.method === "POST") {
    const b = await body(), row = await verifyChallenge(db, clean(b.challengeId, 100), clean(b.code, 6), "setup", env);
    if (!row) return json({ error: "Code is invalid or expired." }, 400);
    await db.prepare(row.channel === "email" ? "UPDATE auth_users SET is_active=1,email_verified=1 WHERE id=?" : "UPDATE auth_users SET is_active=1,phone_verified=1 WHERE id=?").bind(row.user_id).run();
    const user = await db.prepare("SELECT * FROM auth_users WHERE id=?").bind(row.user_id).first();
    const session = await createSession(db, user);
    return json({ ok: true, token: session.token, expiresAt: session.expiresAt, user: { userId: user.user_id, name: user.display_name, isAdmin: true } });
  }
  if (path === "/api/auth/login" && request.method === "POST") {
    const b = await body(), userId = clean(b.userId, 80), password = typeof b.password === "string" ? b.password : "";
    const ip = request.headers.get("CF-Connecting-IP") || "unknown";
    const rateKey = await sha256(ip + ":" + userId.toLowerCase());
    const since = new Date(Date.now() - 15 * 60 * 1000).toISOString();
    const attempts = await db.prepare("SELECT COUNT(*) AS n FROM auth_login_attempts WHERE key_hash=? AND attempted_at>?").bind(rateKey, since).first();
    if ((attempts?.n || 0) >= 10) return json({ error: "Too many login attempts. Try again in 15 minutes." }, 429);
    const user = await db.prepare("SELECT * FROM auth_users WHERE user_id=? COLLATE NOCASE AND is_active=1").bind(userId).first();
    if (!user || !validPassword(password) || !safeEqual(await passwordHash(password, user.password_salt), user.password_hash)) {
      await db.prepare("INSERT INTO auth_login_attempts (key_hash,attempted_at) VALUES (?,?)").bind(rateKey, new Date().toISOString()).run();
      return json({ error: "User ID or password is incorrect." }, 401);
    }
    await db.prepare("DELETE FROM auth_login_attempts WHERE key_hash=?").bind(rateKey).run();
    const channel = b.channel === "sms" ? "sms" : (user.two_factor_channel || "email");
    const dest = channel === "sms" ? user.phone : user.email;
    if (!dest || (channel === "sms" && !user.phone_verified) || (channel === "email" && !user.email_verified)) return json({ error: "That verification method is not registered and verified." }, 400);
    try { return json({ ok: true, ...(await issueChallenge(db, user, "login", channel, dest, env)) }); }
    catch (e) { return json({ error: e.message || "Could not send verification code." }, 503); }
  }
  if (path === "/api/auth/verify-login" && request.method === "POST") {
    const b = await body(), row = await verifyChallenge(db, clean(b.challengeId, 100), clean(b.code, 6), "login", env);
    if (!row) return json({ error: "Code is invalid or expired." }, 400);
    const user = await db.prepare("SELECT * FROM auth_users WHERE id=? AND is_active=1").bind(row.user_id).first();
    if (!user) return json({ error: "Account is inactive." }, 403);
    const session = await createSession(db, user);
    return json({ ok: true, token: session.token, expiresAt: session.expiresAt, user: { userId: user.user_id, name: user.display_name, email: user.email, isAdmin: !!user.is_admin } });
  }
  if (path === "/api/auth/forgot" && request.method === "POST") {
    const b = await body(), ident = clean(b.identifier, 160), channel = b.channel === "sms" ? "sms" : "email";
    const user = await db.prepare("SELECT * FROM auth_users WHERE is_active=1 AND (user_id=? COLLATE NOCASE OR email=? COLLATE NOCASE OR phone=?)").bind(ident, ident.toLowerCase(), ident).first();
    if (!user) return json({ ok: true, message: "If the account exists, a code will be sent." });
    const dest = channel === "sms" ? user.phone : user.email;
    if (!dest || (channel === "sms" && !user.phone_verified) || (channel === "email" && !user.email_verified)) return json({ ok: true, message: "If the account exists, a code will be sent." });
    try { return json({ ok: true, ...(await issueChallenge(db, user, "reset", channel, dest, env)), message: "If the account exists, a code will be sent." }); }
    catch (e) { return json({ error: e.message || "Could not send code." }, 503); }
  }
  if (path === "/api/auth/verify-reset" && request.method === "POST") {
    const b = await body();
    if (!validPassword(b.newPassword)) return json({ error: "New password must be at least 12 characters." }, 400);
    const row = await verifyChallenge(db, clean(b.challengeId, 100), clean(b.code, 6), "reset", env);
    if (!row) return json({ error: "Code is invalid or expired." }, 400);
    const salt = randomToken(16), hash = await passwordHash(b.newPassword, salt);
    await db.prepare("UPDATE auth_users SET password_salt=?,password_hash=? WHERE id=?").bind(salt, hash, row.user_id).run();
    await db.prepare("DELETE FROM auth_sessions WHERE user_id=?").bind(row.user_id).run();
    return json({ ok: true, message: "Password reset. Please sign in again." });
  }
  if (path === "/api/auth/logout" && request.method === "POST") {
    const s = await getSession(request, db);
    if (s) await db.prepare("DELETE FROM auth_sessions WHERE token_hash=?").bind(await sha256(s.token)).run();
    return json({ ok: true });
  }
  return json({ error: "Not found." }, 404);
}
export async function authorize(request, env) {
  if (!env.DB) return false;
  return !!(await getSession(request, env.DB));
}
