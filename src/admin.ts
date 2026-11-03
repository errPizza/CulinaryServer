import { Hono } from "hono";
import { z } from "zod";
import { requireAdmin } from "./admin-auth";
import { addonsSchema, featuresSchema, limitsSchema, PLANS, termEnd, TIERS, type Plan } from "./catalog";
import { ed25519Spki, issueHumanCode, toBase64Url } from "./crypto";
import { keyFloor, licenseSigner, rootPublic } from "./keys";
import { audit } from "./db";
import { adminFaults, FAULT_STATUSES, reopenFault, resolveFault } from "./faults";
import { ApiError, parse, readJson, uniqueOr409, type App } from "./http";
import { ownerAdmin } from "./owner";
import { features, getLicense, LICENSE_STATUSES, licenseStatus, licenseView, nextExpiry, type LicenseRow } from "./licenses";
import { addTicketMessage, adminTickets, closeTicket, ticketDetail, TICKET_STATUSES } from "./tickets";
import { abortRelease, attachManifest, completeRelease, completeSchema, createRelease, listPublications, listReleases, manifestSchema, publicationSchema, publish, releaseSchema, uploadPart, withdraw } from "./updates";

const slug = (max: number) => z.string().regex(new RegExp(`^[a-z0-9-]{1,${max}}$`), `1 a ${max} caracteres: minúsculas, dígitos o guion`);
const trialDays = z.int().min(1).max(365);
const futureDate = z.iso.datetime({ offset: true }).refine((d) => Date.parse(d) > Date.now(), "Debe ser una fecha futura");

const createSchema = z.strictObject({

  customer: z.string().trim().min(1).max(150),
  branchName: z.string().trim().min(1).max(150),
  siteId: slug(32),
  tenantId: slug(64).optional(),
  plan: z.enum(PLANS),
  tier: z.enum(TIERS),
  addons: addonsSchema.default([]),
  trialDays: trialDays.optional(),
  features: featuresSchema,
  limits: limitsSchema

}).refine((l) => (l.plan === "trial") === (l.trialDays !== undefined), { message: "trialDays va solo con el plan de prueba", path: ["trialDays"] });

const editSchema = z.strictObject({

  customer: z.string().trim().min(1).max(150).optional(),
  branchName: z.string().trim().min(1).max(150).optional(),
  plan: z.enum(PLANS).optional(),
  tier: z.enum(TIERS).optional(),
  addons: addonsSchema.optional(),
  trialDays: trialDays.optional(),
  features: featuresSchema.optional(),
  limits: limitsSchema.optional(),
  expiresAt: futureDate.optional(),
  siteId: slug(32).optional()

});

const listQuery = z.strictObject({

  tenantId: z.string().max(64).optional(),
  status: z.enum(LICENSE_STATUSES).optional()

});

// The panel no longer sees a deleted license; the branch side keeps finding it as revoked.
async function listed(db: D1Database, id: string): Promise<LicenseRow> {

  const row = await getLicense(db, id);

  if (row.deleted_at) throw new ApiError(404, "not_found", "Licencia no encontrada");

  return row;
}

async function editable(db: D1Database, id: string): Promise<LicenseRow> {

  const row = await listed(db, id);

  if (row.revoked_at) throw new ApiError(409, "conflict", "La licencia está revocada");

  return row;
}

export const admin = new Hono<App>().use(requireAdmin).route("/", ownerAdmin);

admin.get("/root-key", async (c) => {

  const root = await rootPublic(c.env);
  const spki = ed25519Spki(root.raw);
  const pem = `-----BEGIN PUBLIC KEY-----\n${btoa(String.fromCharCode(...spki))}\n-----END PUBLIC KEY-----\n`;
  // The license intermediate in use, so the panel can warn before it expires.
  const signer = await licenseSigner(c.env).catch(() => null);
  const license = signer && { kid: signer.kid, generation: signer.intermediate.generation, notBefore: signer.intermediate.nbf, expiresAt: signer.intermediate.exp };

  return c.json({ kid: root.kid, alg: "EdDSA", publicKey: toBase64Url(root.raw), spki: toBase64Url(spki), pem, licenseIntermediate: license, keyFloor: await keyFloor(c.env).then(({ license, release }) => ({ license, release })).catch(() => null) });
});

admin.get("/audit", async (c) => {

  const { before } = parse(z.strictObject({ before: z.coerce.number().int().positive().default(Number.MAX_SAFE_INTEGER) }), c.req.query());
  const { results } = await c.env.DB.prepare("SELECT * FROM audit WHERE id < ? ORDER BY id DESC LIMIT 100").bind(before).all<{ id: number; at: string; admin_id: string | null; action: string; target: string | null; detail: string | null }>();
 
  return c.json({ entries: results.map((e) => ({ id: e.id, at: e.at, adminId: e.admin_id, action: e.action, target: e.target, detail: e.detail ? JSON.parse(e.detail) : null })) });
});

admin.post("/licenses", async (c) => {

  const input = await readJson(c, createSchema);
  const id = crypto.randomUUID();
  const activation = await issueHumanCode();
  const insert = c.env.DB.prepare(`INSERT INTO license (id, tenant_id, site_id, customer, branch_name, plan, tier, addons, trial_days, features, limits, revision, created_at, activation_code_hash) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?) RETURNING *`).bind(id, input.tenantId ?? crypto.randomUUID(), input.siteId, input.customer, input.branchName, input.plan, input.tier, JSON.stringify(input.addons), input.trialDays ?? null, JSON.stringify(input.features), JSON.stringify(input.limits), new Date().toISOString(), activation.hash).first<LicenseRow>();
  const row = await uniqueOr409(insert, "Ese siteId ya tiene licencia");
  
  await audit(c.env.DB, c.var.admin.id, "license.create", id, input);
 
  return c.json({ license: licenseView(row!), activationCode: activation.code }, 201);
});

admin.get("/licenses", async (c) => {

  const { tenantId, status } = parse(listQuery, c.req.query());
  const { results } = await c.env.DB.prepare("SELECT * FROM license WHERE deleted_at IS NULL AND (?1 IS NULL OR tenant_id = ?1) ORDER BY created_at DESC").bind(tenantId ?? null).all<LicenseRow>();

  return c.json({ licenses: results.filter((r) => !status || licenseStatus(r) === status).map(licenseView) });
});

admin.get("/licenses/:id", async (c) => c.json({ license: licenseView(await listed(c.env.DB, c.req.param("id"))) }));

admin.patch("/licenses/:id", async (c) => {

  const input = await readJson(c, editSchema);
  const row = await editable(c.env.DB, c.req.param("id"));
  const plan: Plan = input.plan ?? row.plan;
  const days = plan === "trial" ? (input.trialDays ?? row.trial_days) : null;
 
  if (plan === "trial" && !days) throw new ApiError(400, "bad_request", "trialDays: requerido para el plan de prueba");
  if (plan !== "trial" && input.trialDays !== undefined) throw new ApiError(400, "bad_request", "trialDays: va solo con el plan de prueba");
  if (plan === "permanent" && input.expiresAt) throw new ApiError(400, "bad_request", "expiresAt: la licencia permanente no vence");
  // The signed license carries the siteId and the bound branch checks it against its own, so it changes only while no machine holds it.
  if (input.siteId && input.siteId !== row.site_id && row.binding_kind) throw new ApiError(409, "conflict", "Libera el equipo antes de cambiar el siteId");

  const expiresAt = nextExpiry(row, plan, days, input);

  const update = c.env.DB.prepare("UPDATE license SET site_id = ?, customer = ?, branch_name = ?, plan = ?, tier = ?, addons = ?, trial_days = ?, features = ?, limits = ?, expires_at = ?, revision = revision + 1 WHERE id = ? RETURNING *").bind(

    input.siteId ?? row.site_id,
    input.customer ?? row.customer,
    input.branchName ?? row.branch_name,
    plan,
    input.tier ?? row.tier,
    input.addons ? JSON.stringify(input.addons) : row.addons,
    days,
    input.features ? JSON.stringify(input.features) : row.features,
    input.limits ? JSON.stringify(input.limits) : row.limits,
    expiresAt,
    row.id

  ).first<LicenseRow>();
  const updated = await uniqueOr409(update, "Ese siteId ya tiene licencia");

  await audit(c.env.DB, c.var.admin.id, "license.edit", row.id, input);

  return c.json({ license: licenseView(updated!) });
});

// Hides the license from the panel. It is revoked first, so a branch still using it locks on its next contact, and its
// siteId and mTLS certificate are freed for a new license. The row stays for tickets, publications and the audit.
admin.delete("/licenses/:id", async (c) => {

  const row = await listed(c.env.DB, c.req.param("id"));
  const now = new Date().toISOString();

  await c.env.DB.prepare("UPDATE license SET deleted_at = ?1, revoked_at = COALESCE(revoked_at, ?1), revoke_reason = COALESCE(revoke_reason, 'Eliminada desde el panel'), site_id = 'eliminada-' || id, central_cert_sha256 = NULL, activation_code_hash = NULL, revision = revision + 1 WHERE id = ?2").bind(now, row.id).run();
  await audit(c.env.DB, c.var.admin.id, "license.delete", row.id, { siteId: row.site_id, customer: row.customer, branchName: row.branch_name, status: licenseStatus(row) });

  return c.json({ ok: true });
});

admin.post("/licenses/:id/renew", async (c) => {

  const input = await readJson(c, z.strictObject({ until: futureDate.optional() }));
  const row = await editable(c.env.DB, c.req.param("id"));
  
  if (row.plan === "permanent") throw new ApiError(409, "conflict", "La licencia permanente no vence");
  if (!row.activated_at) throw new ApiError(409, "conflict", "El plazo empieza al activar; aún no hay nada que renovar");
  
  const from = new Date(Math.max(Date.now(), row.expires_at ? Date.parse(row.expires_at) : 0));
  const until = input.until ? new Date(input.until) : termEnd(row.plan, row.trial_days, from)!;
  const updated = await c.env.DB.prepare("UPDATE license SET expires_at = ?, revision = revision + 1 WHERE id = ? RETURNING *").bind(until.toISOString(), row.id).first<LicenseRow>();
 
  await audit(c.env.DB, c.var.admin.id, "license.renew", row.id, { from: row.expires_at, until: until.toISOString() });
  
  return c.json({ license: licenseView(updated!) });
});

admin.post("/licenses/:id/revoke", async (c) => {
 
  const input = await readJson(c, z.strictObject({ reason: z.string().trim().min(1).max(500) }));
  const row = await editable(c.env.DB, c.req.param("id"));
  const updated = await c.env.DB.prepare("UPDATE license SET revoked_at = ?, revoke_reason = ?, activation_code_hash = NULL, revision = revision + 1 WHERE id = ? RETURNING *").bind(new Date().toISOString(), input.reason, row.id).first<LicenseRow>();
  
  await audit(c.env.DB, c.var.admin.id, "license.revoke", row.id, input);
 
  return c.json({ license: licenseView(updated!) });
});

admin.post("/licenses/:id/reset-activation", async (c) => {

  const input = await readJson(c, z.strictObject({ reason: z.string().trim().min(1).max(500) }));
  const row = await editable(c.env.DB, c.req.param("id"));
  const activation = await issueHumanCode();
  const updated = await c.env.DB.prepare(`UPDATE license SET activation_code_hash = ?, released_alg = COALESCE(key_alg, released_alg), released_spki = COALESCE(key_spki, released_spki), key_alg = NULL, key_spki = NULL, binding_kind = NULL, fp_board = NULL, fp_disk = NULL, fp_mac = NULL, central_cert_sha256 = NULL, revision = revision + 1 WHERE id = ? RETURNING *`).bind(activation.hash, row.id).first<LicenseRow>();
 
  await audit(c.env.DB, c.var.admin.id, "license.reset_activation", row.id, { reason: input.reason, binding: row.binding_kind, spki: row.key_spki });

  return c.json({ license: licenseView(updated!), activationCode: activation.code });
});

admin.get("/registry", async (c) => {

  const { results } = await c.env.DB.prepare("SELECT * FROM license WHERE (?1 IS NULL OR tenant_id = ?1) AND revoked_at IS NULL ORDER BY tenant_id, site_id").bind(c.req.query("tenantId") ?? null).all<LicenseRow>();
 
  return c.json({ branches: results.map((r) => ({
      
    tenantId: r.tenant_id,
    tenantName: r.customer,
    branchId: r.id,
    siteId: r.site_id,
    slug: r.site_id,
    branchName: r.branch_name,
    certificateSha256: r.central_cert_sha256,
    licenseStatus: licenseStatus(r),
    features: features(r) }))

  });
});

admin.post("/releases", async (c) => {

  const input = await readJson(c, releaseSchema);
  const release = await createRelease(c.env, input);

  await audit(c.env.DB, c.var.admin.id, "release.create", release.id, input);

  return c.json({ release }, 201);
});

admin.get("/releases", async (c) => c.json({ releases: await listReleases(c.env.DB) }));

admin.put("/releases/:id/parts/:part", async (c) => {

  const part = Number(c.req.param("part"));
  
  if (!Number.isInteger(part) || part < 1 || part > 10_000) throw new ApiError(400, "bad_request", "Número de parte entre 1 y 10000");
 
  return c.json(await uploadPart(c, c.req.param("id"), part));
});

admin.post("/releases/:id/complete", async (c) => {

  const input = await readJson(c, completeSchema);
  const release = await completeRelease(c.env, c.req.param("id"), input.parts);

  await audit(c.env.DB, c.var.admin.id, "release.complete", release.id, { bytes: release.bytes, sha512: release.sha512 });

  return c.json({ release });
});

admin.put("/releases/:id/manifest", async (c) => {

  const input = await readJson(c, manifestSchema);
  const { release, kid } = await attachManifest(c.env, c.req.param("id"), input.manifest);

  await audit(c.env.DB, c.var.admin.id, "release.sign", release.id, { kid, sha512: release.sha512 });

  return c.json({ release });
});

admin.delete("/releases/:id", async (c) => {
 
  await abortRelease(c.env, c.req.param("id"));
  await audit(c.env.DB, c.var.admin.id, "release.abort", c.req.param("id"));
  
  return c.json({ ok: true });
});

admin.post("/publications", async (c) => {
 
  const input = await readJson(c, publicationSchema);
  const publication = await publish(c.env.DB, input);
 
  await audit(c.env.DB, c.var.admin.id, "publication.create", publication.id, input);
  
  return c.json({ publication }, 201);
});

admin.get("/publications", async (c) => c.json({ publications: await listPublications(c.env.DB) }));

admin.post("/publications/:id/withdraw", async (c) => {
 
  await withdraw(c.env.DB, c.req.param("id"));
  await audit(c.env.DB, c.var.admin.id, "publication.withdraw", c.req.param("id"));
  
  return c.json({ ok: true });
});

admin.get("/faults", async (c) => c.json({ faults: await adminFaults(c.env.DB, parse(z.strictObject({ status: z.enum(FAULT_STATUSES).optional() }), c.req.query()).status) }));

admin.post("/faults/:id/resolve", async (c) => {

  const fault = await resolveFault(c.env.DB, c.req.param("id"), c.var.admin.id);

  await audit(c.env.DB, c.var.admin.id, "fault.resolve", fault.id, { what: fault.what, version: fault.version });

  return c.json({ fault });
});

admin.post("/faults/:id/reopen", async (c) => {

  const fault = await reopenFault(c.env.DB, c.req.param("id"));

  await audit(c.env.DB, c.var.admin.id, "fault.reopen", fault.id);

  return c.json({ fault });
});

admin.get("/tickets", async (c) => c.json({ tickets: await adminTickets(c.env.DB, parse(z.strictObject({ status: z.enum(TICKET_STATUSES).optional() }), c.req.query()).status) }));
admin.get("/tickets/:id", async (c) => c.json({ ticket: await ticketDetail(c.env.DB, c.req.param("id")) }));

admin.post("/tickets/:id/messages", async (c) => {
  
  const input = await readJson(c, z.strictObject({ message: z.string().trim().min(1).max(4000) }));
  const ticket = await addTicketMessage(c.env.DB, c.req.param("id"), { kind: "admin", adminId: c.var.admin.id }, input.message);
  
  await audit(c.env.DB, c.var.admin.id, "ticket.reply", ticket.id);
 
  return c.json({ ticket }, 201);
});

admin.post("/tickets/:id/close", async (c) => {
 
  const ticket = await closeTicket(c.env.DB, c.req.param("id"));
  
  await audit(c.env.DB, c.var.admin.id, "ticket.close", ticket.id);
 
  return c.json({ ticket });
});