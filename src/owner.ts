import { Hono, type MiddlewareHandler } from "hono";
import { z } from "zod";
import { requireFreshSignature } from "./admin-auth";
import { audit } from "./db";
import { hashHumanCode, hashPassword, issueHumanCode, newTotpSecret, randomToken, sha256Hex, verifyPassword, verifyTotp } from "./crypto";
import { ApiError, bearerHash, parse, parseJson, readJson, type App, type Ctx, type OwnerIdentity } from "./http";
import { branchView, cash, closings, products, rangeSchema, staff, summary, type BranchRow } from "./stats";
import { alerts, customers, goals, kitchen, menu, profit, readSettings, settingsSchema, summaryExtras, team, trend, writeSettings } from "./insights";
import { forecast } from "./forecast";
import { sendToBranches, thread, threads } from "./messages";
import { addTicketMessage, createTicket, ownerTicket, ownerTickets } from "./tickets";

const SESSION_TTL_MS = 30 * 24 * 60 * 60 * 1000;
const INVITE_TTL_MS = 7 * 24 * 60 * 60 * 1000;
const MAX_FAILED_LOGINS = 5;
const LOCKOUT_MS = 15 * 60 * 1000;

type AccountRow = OwnerIdentity & { password_hash: string; totp_secret: string; totp_last_step: number; active: number; locked_until: number };

const email = z.string().trim().toLowerCase().max(254).pipe(z.email());
const password = z.string().min(12).max(256);
const totp = z.string().regex(/^\d{6}$/, "Código TOTP de 6 dígitos");
const loginSchema = z.strictObject({ email, password: z.string().max(256), totp });
const loginFailed = () => new ApiError(401, "unauthorized", "Correo, contraseña o código inválidos");

function accountByEmail(db: D1Database, address: string) {

  return db.prepare("SELECT id, tenant_id AS tenantId, email, role, password_hash, totp_secret, totp_last_step, active, locked_until FROM owner_account WHERE email = ?").bind(address).first<AccountRow>();
}

export const ownerAuth = new Hono<App>();

// The code comes from the provider and already names the business, the person and what they may read.
ownerAuth.post("/enroll", async (c) => {

  const input = await readJson(c, z.strictObject({ code: z.string().min(20).max(200), password }));
  const invite = await c.env.DB.prepare("SELECT tenant_id, email, role, license_ids FROM owner_invite WHERE code_hash = ? AND expires_at > ?").bind(await hashHumanCode(input.code), Date.now()).first<{ tenant_id: string; email: string; role: string; license_ids: string }>();

  if (!invite) throw new ApiError(403, "forbidden", "Código de alta inválido o vencido");
  if ((await accountByEmail(c.env.DB, invite.email))?.active) throw new ApiError(409, "conflict", "Ese correo ya tiene cuenta");

  const id = crypto.randomUUID();
  const secret = newTotpSecret();

  // The code is spent only together with the account it creates.
  await c.env.DB.batch([
    c.env.DB.prepare("DELETE FROM owner_invite WHERE code_hash = ?").bind(await hashHumanCode(input.code)),
    c.env.DB.prepare("DELETE FROM owner_account WHERE email = ? AND active = 0").bind(invite.email),
    c.env.DB.prepare("INSERT INTO owner_account (id, tenant_id, email, role, password_hash, totp_secret, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)").bind(id, invite.tenant_id, invite.email, invite.role, await hashPassword(input.password), secret, new Date().toISOString()),
    ...(JSON.parse(invite.license_ids) as string[]).map((licenseId) => c.env.DB.prepare("INSERT INTO owner_membership (account_id, license_id) VALUES (?, ?)").bind(id, licenseId))
  ]);

  return c.json({ email: invite.email, totp: { secret, uri: `otpauth://totp/Culinary:${encodeURIComponent(invite.email)}?secret=${secret}&issuer=Culinary&algorithm=SHA1&digits=6&period=30` } }, 201);
});

ownerAuth.post("/enroll/confirm", async (c) => {

  const input = await readJson(c, loginSchema);
  const account = await accountByEmail(c.env.DB, input.email);

  if (!account || account.active || !(await verifyPassword(input.password, account.password_hash))) throw loginFailed();

  const step = await verifyTotp(account.totp_secret, input.totp, Date.now(), account.totp_last_step);

  if (step === null) throw loginFailed();

  await c.env.DB.prepare("UPDATE owner_account SET active = 1, totp_last_step = ?1 WHERE id = ?2 AND active = 0").bind(step, account.id).run();

  return c.json({ email: account.email, role: account.role });
});

ownerAuth.post("/login", async (c) => {

  const input = await readJson(c, loginSchema);
  const account = await accountByEmail(c.env.DB, input.email);

  if (!account?.active) {

    // An unknown address costs the same as a known one, so the answer does not tell which it was.
    await hashPassword(input.password);

    throw loginFailed();

  }

  if (account.locked_until > Date.now()) throw new ApiError(429, "rate_limited", "Cuenta bloqueada temporalmente por intentos fallidos");

  const step = (await verifyPassword(input.password, account.password_hash)) ? await verifyTotp(account.totp_secret, input.totp, Date.now(), account.totp_last_step) : null;
  const accepted = step !== null && (await c.env.DB.prepare("UPDATE owner_account SET failed_logins = 0, locked_until = 0, totp_last_step = ?1 WHERE id = ?2 AND totp_last_step < ?1 RETURNING id").bind(step, account.id).first());

  if (!accepted) {

    await c.env.DB.prepare("UPDATE owner_account SET failed_logins = CASE WHEN failed_logins + 1 >= ?1 THEN 0 ELSE failed_logins + 1 END, locked_until = CASE WHEN failed_logins + 1 >= ?1 THEN ?2 ELSE locked_until END WHERE id = ?3").bind(MAX_FAILED_LOGINS, Date.now() + LOCKOUT_MS, account.id).run();

    throw loginFailed();

  }

  const token = randomToken();
  const expires = Date.now() + SESSION_TTL_MS;

  await c.env.DB.prepare("INSERT INTO owner_session (token_hash, account_id, expires_at) VALUES (?, ?, ?)").bind(await sha256Hex(token), account.id, expires).run();

  return c.json({ token, expiresAt: new Date(expires).toISOString() });
});

const requireOwner: MiddlewareHandler<App> = async (c, next) => {

  const sessionHash = await bearerHash(c, "Inicia sesión");
  const account = await c.env.DB.prepare("SELECT a.id, a.tenant_id AS tenantId, a.email, a.role FROM owner_session s JOIN owner_account a ON a.id = s.account_id WHERE s.token_hash = ? AND s.expires_at > ? AND a.active = 1").bind(sessionHash, Date.now()).first<OwnerIdentity>();

  if (!account) throw new ApiError(401, "unauthorized", "Sesión vencida o inválida");

  c.set("owner", account);
  c.set("sessionHash", sessionHash);

  await next();

};

// Every read starts here. A manager also needs the branch to still belong to the business of the account.
async function reachable(c: Ctx): Promise<BranchRow[]> {

  const { id, tenantId, role } = c.var.owner;
  const { results } = await c.env.DB.prepare(`SELECT l.*, h.at AS seen_at, h.branch AS seen_branch, h.live AS seen_live FROM license l LEFT JOIN branch_heartbeat h ON h.license_id = l.id
    WHERE l.tenant_id = ?1 AND l.deleted_at IS NULL AND (?2 = 'owner' OR EXISTS (SELECT 1 FROM owner_membership m WHERE m.account_id = ?3 AND m.license_id = l.id)) ORDER BY l.branch_name`).bind(tenantId, role, id).all<BranchRow>();

  return results;
}

async function selection(c: Ctx) {

  const { branch, ...range } = parse(rangeSchema, c.req.query());
  const branches = await reachable(c);

  if (branch === undefined) return { branches, range };

  const chosen = branches.find((b) => b.id === branch);

  // The same answer for a branch of another business and one that does not exist.
  if (!chosen) throw new ApiError(404, "not_found", "Sucursal no encontrada");

  return { branches: [chosen], range };
}

async function chosenBranches(c: Ctx, branch?: string) {

  const branches = await reachable(c);

  if (branch === undefined) return branches;

  const chosen = branches.find((b) => b.id === branch);

  if (!chosen) throw new ApiError(404, "not_found", "Sucursal no encontrada");

  return [chosen];
}

async function selectionWith(c: Ctx) {

  const { branch, ...range } = parse(rangeSchema, c.req.query());

  return { branches: await chosenBranches(c, branch), range, branch };
}

export const owner = new Hono<App>().use(requireOwner);

owner.get("/me", async (c) => {

  const { id, email: address, role } = c.var.owner;

  return c.json({ account: { id, email: address, role }, branches: (await reachable(c)).map((b) => branchView(b)) });
});

owner.post("/logout", async (c) => {

  await c.env.DB.prepare("DELETE FROM owner_session WHERE token_hash = ?").bind(c.var.sessionHash).run();

  return c.json({ ok: true });
});

owner.get("/stats/summary", async (c) => {

  const { branches, range } = await selection(c);
  const settings = await readSettings(c.env.DB, c.var.owner.tenantId);
  const [base, extras] = await Promise.all([summary(c.env.DB, branches, range), summaryExtras(c.env.DB, branches, range, settings)]);

  return c.json({ ...base, ...extras });
});

for (const [path, read] of Object.entries({ products, staff, cash, closings })) {

  owner.get(`/stats/${path}`, async (c) => {

    const { branches, range } = await selection(c);

    return c.json(await read(c.env.DB, branches, range));

  });

}

// Reads that need more than a period: the owner's settings, the role of who asks, or only the branch.
const byRange = { menu, profit, kitchen, customers } as const;

for (const [path, read] of Object.entries(byRange)) {

  owner.get(`/stats/${path}`, async (c) => {

    const { branches, range, branch } = await selectionWith(c);
    const settings = await readSettings(c.env.DB, c.var.owner.tenantId);

    return c.json(await read(c.env.DB, branches, range, settings, branch));

  });

}

owner.get("/stats/team", async (c) => {

  const { branches, range } = await selectionWith(c);

  return c.json(await team(c.env.DB, branches, range, await readSettings(c.env.DB, c.var.owner.tenantId), c.var.owner.role));
});

owner.get("/stats/trend", async (c) => {

  const by = parse(z.enum(["week", "month", "year"]).default("month"), c.req.query("by"));
  const query = c.req.query();
  const { branch, ...range } = parse(rangeSchema, { from: query.from, to: query.to, ...(query.branch === undefined ? {} : { branch: query.branch }) });

  return c.json(await trend(c.env.DB, await chosenBranches(c, branch), range, by));
});

owner.get("/stats/goals", async (c) => {

  const branch = parse(z.string().max(64).optional(), c.req.query("branch"));

  return c.json(await goals(c.env.DB, await chosenBranches(c, branch), await readSettings(c.env.DB, c.var.owner.tenantId), branch));
});

owner.get("/stats/forecast", async (c) => {

  const branch = parse(z.string().max(64).optional(), c.req.query("branch"));

  return c.json(await forecast(c.env.DB, await chosenBranches(c, branch), await readSettings(c.env.DB, c.var.owner.tenantId)));
});

owner.get("/stats/alerts", async (c) => {

  const branch = parse(z.string().max(64).optional(), c.req.query("branch"));

  return c.json(await alerts(c.env.DB, await chosenBranches(c, branch), await readSettings(c.env.DB, c.var.owner.tenantId), c.var.owner.role));
});

owner.get("/settings", async (c) => c.json({ settings: await readSettings(c.env.DB, c.var.owner.tenantId), canEdit: c.var.owner.role === "owner" }));

// Only the owner changes how the panel reads the business; a manager reads the same settings.
owner.put("/settings", async (c) => {

  if (c.var.owner.role !== "owner") throw new ApiError(403, "forbidden", "Sólo el dueño cambia los ajustes del panel");

  const input = await readJson(c, settingsSchema);
  const own = new Set((await reachable(c)).map((b) => b.id));
  const used = [...input.goals.map((g) => g.licenseId), ...input.fixedCosts.map((f) => f.licenseId), ...input.locations.map((l) => l.licenseId)].filter(Boolean);

  if (!used.every((id) => own.has(id))) throw new ApiError(404, "not_found", "Sucursal no encontrada");

  await writeSettings(c.env.DB, c.var.owner.tenantId, c.var.owner.id, input);

  return c.json({ settings: input, canEdit: true });
});

// The city of a branch for its weather, looked up by name. Only coordinates are kept.
owner.get("/geocode", async (c) => {

  if (c.var.owner.role !== "owner") throw new ApiError(403, "forbidden", "Sólo el dueño cambia los ajustes del panel");

  const q = parse(z.string().trim().min(2).max(100), c.req.query("q"));
  const response = await fetch(`https://geocoding-api.open-meteo.com/v1/search?name=${encodeURIComponent(q)}&count=5&language=es&format=json`).catch(() => null);

  if (!response?.ok) throw new ApiError(503, "server_misconfigured", "No se pudo buscar la ciudad. Intenta de nuevo.");

  const body = await response.json() as { results?: { name: string; admin1?: string; country?: string; latitude: number; longitude: number }[] };

  return c.json({ places: (body.results ?? []).map((p) => ({ label: [p.name, p.admin1, p.country].filter(Boolean).join(", "), lat: p.latitude, lon: p.longitude })) });
});

// Messages: the owner's thread with each branch, and what the person asks the provider's support.
const messageText = z.string().trim().min(1).max(2000);

owner.get("/messages", async (c) => {

  const branches = await reachable(c);

  return c.json({ branches: await threads(c.env.DB, c.var.owner.id, branches.map((b) => b.id)), support: await ownerTickets(c.env.DB, c.var.owner.id) });
});

owner.get("/messages/branches/:licenseId", async (c) => {

  const [chosen] = await chosenBranches(c, c.req.param("licenseId"));

  return c.json({ messages: await thread(c.env.DB, c.var.owner.id, chosen!.id) });
});

// To one branch, to several, or with an empty list to every branch this person reads.
owner.post("/messages/branches", async (c) => {

  const input = await readJson(c, z.strictObject({ licenseIds: z.array(z.string().max(64)).max(100), message: messageText }));
  const own = await reachable(c);
  const ids = input.licenseIds.length ? [...new Set(input.licenseIds)] : own.map((b) => b.id);

  if (!ids.length || !ids.every((id) => own.some((b) => b.id === id))) throw new ApiError(404, "not_found", "Sucursal no encontrada");

  return c.json(await sendToBranches(c.env.DB, c.var.owner, ids, input.message), 201);
});

owner.post("/support", async (c) => {

  const input = await readJson(c, z.strictObject({ licenseId: z.string().max(64).optional(), subject: z.string().trim().min(1).max(150), message: z.string().trim().min(1).max(4000) }));
  const own = await reachable(c);
  // A question about the business as a whole still hangs from one of its branches, so support sees whose it is.
  const about = input.licenseId ? own.find((b) => b.id === input.licenseId) : own[0];

  if (!about) throw new ApiError(404, "not_found", "Sucursal no encontrada");

  return c.json({ ticket: await createTicket(c.env.DB, about.id, input.subject, input.message, c.var.owner.id) }, 201);
});

owner.get("/support/:id", async (c) => c.json({ ticket: await ownerTicket(c.env.DB, c.var.owner.id, c.req.param("id")) }));

owner.post("/support/:id/messages", async (c) => {

  const input = await readJson(c, z.strictObject({ message: z.string().trim().min(1).max(4000) }));

  return c.json({ ticket: await addTicketMessage(c.env.DB, c.req.param("id"), { kind: "owner", accountId: c.var.owner.id }, input.message) }, 201);
});

const inviteSchema = z.strictObject({

  tenantId: z.string().min(1).max(64),
  email,
  role: z.enum(["owner", "manager"]),
  licenseIds: z.array(z.string().max(64)).max(100).default([])

}).refine((i) => (i.role === "manager") === (i.licenseIds.length > 0), { message: "Un gerente lleva sus sucursales y el dueño ninguna", path: ["licenseIds"] });

/** What the provider does for a business: mounted behind requireAdmin. Until there is e-mail, a lost password or phone comes here too. */
export const ownerAdmin = new Hono<App>();

ownerAdmin.post("/owner-invites", async (c) => {

  const input = parseJson(inviteSchema, (await requireFreshSignature(c)).body);
  const { results } = await c.env.DB.prepare("SELECT id FROM license WHERE tenant_id = ? AND deleted_at IS NULL").bind(input.tenantId).all<{ id: string }>();
  const own = new Set(results.map((r) => r.id));

  if (!own.size) throw new ApiError(404, "not_found", "Ese negocio no tiene licencias");
  if (!input.licenseIds.every((id) => own.has(id))) throw new ApiError(404, "not_found", "Una sucursal no es de ese negocio");

  const code = await issueHumanCode();
  const expires = Date.now() + INVITE_TTL_MS;

  await c.env.DB.prepare("INSERT INTO owner_invite (code_hash, tenant_id, email, role, license_ids, created_by, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?)").bind(code.hash, input.tenantId, input.email, input.role, JSON.stringify(input.licenseIds), c.var.admin.id, expires).run();
  await audit(c.env.DB, c.var.admin.id, "owner.invite", input.tenantId, { email: input.email, role: input.role, licenseIds: input.licenseIds });

  return c.json({ code: code.code, expiresAt: new Date(expires).toISOString() }, 201);
});

ownerAdmin.get("/owner-accounts", async (c) => {

  const tenantId = parse(z.string().min(1).max(64), c.req.query("tenantId"));
  const { results } = await c.env.DB.prepare("SELECT a.id, a.email, a.role, a.active, a.created_at, (SELECT json_group_array(m.license_id) FROM owner_membership m WHERE m.account_id = a.id) AS license_ids FROM owner_account a WHERE a.tenant_id = ? ORDER BY a.email").bind(tenantId).all<{ id: string; email: string; role: string; active: number; created_at: string; license_ids: string }>();

  return c.json({ accounts: results.map((a) => ({ id: a.id, email: a.email, role: a.role, active: a.active === 1, createdAt: a.created_at, licenseIds: JSON.parse(a.license_ids) as string[] })) });
});

// Removing the account ends its sessions; a new invitation is how the person comes back, with a new password and authenticator.
ownerAdmin.delete("/owner-accounts/:id", async (c) => {

  await requireFreshSignature(c);

  const removed = await c.env.DB.prepare("DELETE FROM owner_account WHERE id = ? RETURNING email, tenant_id").bind(c.req.param("id")).first<{ email: string; tenant_id: string }>();

  if (!removed) throw new ApiError(404, "not_found", "Cuenta no encontrada");

  await audit(c.env.DB, c.var.admin.id, "owner.delete", removed.tenant_id, { email: removed.email });

  return c.json({ ok: true });
});
