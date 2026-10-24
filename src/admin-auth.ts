import { Hono, type MiddlewareHandler } from "hono";
import { z } from "zod";
import { audit } from "./db";
import { hashPassword, newHumanCode, newTotpSecret, normalizeHumanCode, randomToken, sameSecret, sha256Hex, verifyPassword, verifyTotp, type KeyAlg } from "./crypto";
import { ApiError, parseJson, rawBody, readJson, type App } from "./http";
import { issueChallenge, signedHeaders, verifySigned } from "./signature";

const SESSION_TTL_MS = 8 * 60 * 60 * 1000;
const INVITE_TTL_MS = 24 * 60 * 60 * 1000;
const MAX_FAILED_LOGINS = 5;
const LOCKOUT_MS = 15 * 60 * 1000;

type AdminRow = {

  id: string;
  username: string;
  password_hash: string;
  totp_secret: string;
  totp_last_step: number;
  key_alg: KeyAlg;
  key_spki: string;
  device_name: string;
  invited_by: string | null;
  active: number;
  failed_logins: number;
  locked_until: number;
  created_at: string;

};

const username = z.string().regex(/^[a-z0-9._-]{3,32}$/, "3 a 32 caracteres: minúsculas, dígitos, punto, guion o guion bajo");
const totp = z.string().regex(/^\d{6}$/, "Código TOTP de 6 dígitos");

const enrollSchema = z.strictObject({

  code: z.string().min(20).max(200),
  username,
  password: z.string().min(12).max(256),
  deviceName: z.string().trim().min(1).max(100),
  key: z.strictObject({ alg: z.enum(["Ed25519", "ES256"]), spki: z.string().min(40).max(200) })

});

const loginFailed = () => new ApiError(401, "unauthorized", "Credenciales, código o firma inválidos");

async function adminByUsername(db: D1Database, name: string) {

  return db.prepare("SELECT * FROM admin WHERE username = ?").bind(name).first<AdminRow>();
}

async function consumeEnrollmentCode(env: App["Bindings"], code: string): Promise<string | null> {

  const active = await env.DB.prepare("SELECT COUNT(*) AS n FROM admin WHERE active = 1").first<number>("n");

  if (!active) {

    if (env.ADMIN_SETUP_CODE && (await sameSecret(code.trim(), env.ADMIN_SETUP_CODE.trim()))) return null;
    throw new ApiError(403, "forbidden", "Código de alta inválido");

  }

  const invite = await env.DB.prepare("DELETE FROM admin_invite WHERE code_hash = ? AND expires_at > ? RETURNING created_by").bind(await sha256Hex(normalizeHumanCode(code)), Date.now()).first<string>("created_by");
  
  if (!invite) throw new ApiError(403, "forbidden", "Invitación inválida o vencida");
 
  return invite;
}

export const adminAuth = new Hono<App>();

adminAuth.post("/challenges", async (c) => {

  const input = await readJson(c, z.strictObject({ username }));

  return c.json(await issueChallenge(c.env.DB, "admin", input.username, (await adminByUsername(c.env.DB, input.username)) !== null));
});

adminAuth.post("/enroll", async (c) => {

  const input = await readJson(c, enrollSchema);
  const existing = await adminByUsername(c.env.DB, input.username);

  if (existing?.active) throw new ApiError(409, "conflict", "Ese usuario ya existe");

  const invitedBy = await consumeEnrollmentCode(c.env, input.code);
  const id = crypto.randomUUID();
  const secret = newTotpSecret();

  await c.env.DB.batch([
    c.env.DB.prepare("DELETE FROM admin WHERE username = ? AND active = 0").bind(input.username),
    c.env.DB.prepare("INSERT INTO admin (id, username, password_hash, totp_secret, key_alg, key_spki, device_name, invited_by, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)")
    .bind(id, input.username, await hashPassword(input.password), secret, input.key.alg, input.key.spki, input.deviceName, invitedBy, new Date().toISOString())
  ]);

  await audit(c.env.DB, invitedBy, "admin.enroll", id, { username: input.username, deviceName: input.deviceName });

  const uri = `otpauth://totp/CulinaryAdmin:${encodeURIComponent(input.username)}?secret=${secret}&issuer=CulinaryAdmin&algorithm=SHA1&digits=6&period=30`;
  
  return c.json({ adminId: id, totp: { secret, uri } }, 201);
});


adminAuth.post("/enroll/confirm", async (c) => {

  const request = signedHeaders(c, await rawBody(c));
  const input = parseJson(z.strictObject({ totp }), request.body);
  const admin = await adminByUsername(c.env.DB, request.subject);

  if (!admin || admin.active) throw loginFailed();
  if (!(await verifySigned(c, "admin", request, admin.key_alg, admin.key_spki))) throw loginFailed();

  const step = await verifyTotp(admin.totp_secret, input.totp, Date.now(), admin.totp_last_step);

  if (step === null) throw loginFailed();

  const confirmed = await c.env.DB.prepare("UPDATE admin SET active = 1, totp_last_step = ?1 WHERE id = ?2 AND (invited_by IS NOT NULL OR NOT EXISTS (SELECT 1 FROM admin WHERE active = 1)) RETURNING id").bind(step, admin.id).first();
 
  if (!confirmed) throw new ApiError(403, "forbidden", "El código de alta inicial ya se usó; pide una invitación");
 
  await audit(c.env.DB, admin.id, "admin.confirm", admin.id);

  return c.json({ adminId: admin.id, username: admin.username });
});

adminAuth.post("/login", async (c) => {

  const request = signedHeaders(c, await rawBody(c));
  const input = parseJson(z.strictObject({ password: z.string().max(256), totp }), request.body);
  const admin = await adminByUsername(c.env.DB, request.subject);

  if (!admin?.active) throw loginFailed();
  if (!(await verifySigned(c, "admin", request, admin.key_alg, admin.key_spki))) throw loginFailed();
  if (admin.locked_until > Date.now()) throw new ApiError(429, "rate_limited", "Cuenta bloqueada temporalmente por intentos fallidos");

  const step = (await verifyPassword(input.password, admin.password_hash)) ? await verifyTotp(admin.totp_secret, input.totp, Date.now(), admin.totp_last_step) : null;
 
  if (step === null) {

    const failures = admin.failed_logins + 1;
    const lockedUntil = failures >= MAX_FAILED_LOGINS ? Date.now() + LOCKOUT_MS : 0;
    
    await c.env.DB.prepare("UPDATE admin SET failed_logins = ?, locked_until = ? WHERE id = ?").bind(lockedUntil ? 0 : failures, lockedUntil, admin.id).run();
    await audit(c.env.DB, admin.id, "admin.login_failed", admin.id);
   
    throw loginFailed();

  }

  const token = randomToken();
  const expires = Date.now() + SESSION_TTL_MS;
 
  await c.env.DB.batch([
    c.env.DB.prepare("UPDATE admin SET failed_logins = 0, locked_until = 0, totp_last_step = ? WHERE id = ?").bind(step, admin.id),
    c.env.DB.prepare("INSERT INTO admin_session (token_hash, admin_id, expires_at) VALUES (?, ?, ?)").bind(await sha256Hex(token), admin.id, expires)
  ]);
  
  await audit(c.env.DB, admin.id, "admin.login", admin.id);
 
  return c.json({ token, expiresAt: new Date(expires).toISOString(), admin: { id: admin.id, username: admin.username } });
});

export const requireAdmin: MiddlewareHandler<App> = async (c, next) => {

  const auth = c.req.header("authorization") ?? "";
  
  if (!auth.startsWith("Bearer ")) throw new ApiError(401, "unauthorized", "Inicia sesión en el panel");
 
  const sessionHash = await sha256Hex(auth.slice(7));
  const admin = await c.env.DB.prepare("SELECT a.id, a.username FROM admin_session s JOIN admin a ON a.id = s.admin_id WHERE s.token_hash = ? AND s.expires_at > ? AND a.active = 1").bind(sessionHash, Date.now()).first<{ id: string; username: string }>();
  
  if (!admin) throw new ApiError(401, "unauthorized", "Sesión vencida o inválida");
 
  c.set("admin", admin);
  c.set("sessionHash", sessionHash);
  
  await next();

};

export const adminAccounts = new Hono<App>();

adminAccounts.get("/me", (c) => c.json({ admin: c.var.admin }));

adminAccounts.post("/logout", async (c) => {

  await c.env.DB.prepare("DELETE FROM admin_session WHERE token_hash = ?").bind(c.var.sessionHash).run();
 
  return c.json({ ok: true });
});

adminAccounts.post("/invites", async (c) => {
 
  const code = newHumanCode();
  const expires = Date.now() + INVITE_TTL_MS;
 
  await c.env.DB.prepare("INSERT INTO admin_invite (code_hash, created_by, expires_at) VALUES (?, ?, ?)").bind(await sha256Hex(normalizeHumanCode(code)), c.var.admin.id, expires).run();
  await audit(c.env.DB, c.var.admin.id, "admin.invite", null);
  
  return c.json({ code, expiresAt: new Date(expires).toISOString() }, 201);
});

adminAccounts.get("/admins", async (c) => {

  const { results } = await c.env.DB.prepare("SELECT id, username, device_name, key_alg, active, created_at FROM admin ORDER BY created_at").all<AdminRow>();
  
  return c.json({ admins: results.map((a) => ({ id: a.id, username: a.username, deviceName: a.device_name, keyAlg: a.key_alg, active: a.active === 1, createdAt: a.created_at })) });
});

adminAccounts.delete("/admins/:id", async (c) => {

  const id = c.req.param("id");

  if (id === c.var.admin.id) throw new ApiError(409, "conflict", "No puedes eliminar tu propia cuenta");
 
  const deleted = await c.env.DB.prepare("DELETE FROM admin WHERE id = ? RETURNING id").bind(id).first();
 
  if (!deleted) throw new ApiError(404, "not_found", "Administrador no encontrado");
 
  await audit(c.env.DB, c.var.admin.id, "admin.delete", id);
 
  return c.json({ ok: true });
});