import { Hono } from "hono";
import { z } from "zod";
import { PLATFORMS, termEnd } from "./catalog";
import { hashHumanCode, publicKeySchema, rootKey, sameSecret } from "./crypto";
import { ApiError, parseJson, readJson, uniqueOr409, type App, type Ctx } from "./http";
import { findLicense, licenseToken, requireUsable, type LicenseRow } from "./licenses";
import { issueChallenge, readSigned, verifySigned } from "./signature";
import { addTicketMessage, branchTickets, createTicket } from "./tickets";
import { checkForUpdate, streamDownload } from "./updates";

const hex64 = z.string().regex(/^[0-9a-f]{64}$/, "SHA-256 en hexadecimal minúsculo");
const fingerprintSchema = z.strictObject({ board: hex64, disk: hex64, mac: hex64 });

const activateSchema = z
  .strictObject({
    activationCode: z.string().min(20).max(40),
    key: publicKeySchema,
    binding: z.discriminatedUnion("kind", [
      z.strictObject({ kind: z.literal("tpm") }),
      z.strictObject({ kind: z.literal("fingerprint"), fingerprint: fingerprintSchema }),
    ]),
  })
  .refine((a) => a.binding.kind !== "tpm" || a.key.alg === "ES256", { message: "Una llave de TPM 2.0 es ES256 (P-256)", path: ["key", "alg"] });

const renewSchema = z.strictObject({ fingerprint: fingerprintSchema.optional() });

const unauthorized = () => new ApiError(401, "unauthorized", "Firma o reto inválido");

type Authenticated = { license: LicenseRow; body: Uint8Array; challenge: string };

/** Every branch call after activation is signed with the key bound at activation, over a fresh challenge. */
async function authenticate(c: Ctx): Promise<Authenticated> {
  const request = await readSigned(c);
  const license = await findLicense(c.env.DB, request.subject);
  if (!license?.key_alg || !license.key_spki) throw unauthorized();
  if (!(await verifySigned(c, "branch", request, license.key_alg, license.key_spki))) throw unauthorized();
  return { license, body: request.body, challenge: request.nonce };
}

/** Without a TPM the stored hashes must still match on two of three parts, so one replaced disk or NIC does not lock the branch. */
function sameHardware(license: LicenseRow, fingerprint: z.infer<typeof fingerprintSchema> | undefined): boolean {
  if (license.binding_kind !== "fingerprint") return true;
  if (!fingerprint) return false;
  const matches = [license.fp_board === fingerprint.board, license.fp_disk === fingerprint.disk, license.fp_mac === fingerprint.mac];
  return matches.filter(Boolean).length >= 2;
}

export const branch = new Hono<App>();

branch.post("/challenges", async (c) => {
  const { licenseId } = await readJson(c, z.strictObject({ licenseId: z.string().min(1).max(64) }));
  return c.json(await issueChallenge(c.env, "branch", licenseId));
});

branch.post("/activate", async (c) => {
  const request = await readSigned(c);
  const input = parseJson(activateSchema, request.body);
  const license = await findLicense(c.env.DB, request.subject);
  const invalid = new ApiError(403, "activation_rejected", "Código de activación inválido o ya usado");
  if (!license?.activation_code_hash) throw invalid;
  if (!(await verifySigned(c, "branch", request, input.key.alg, input.key.spki))) throw unauthorized();
  if (!(await sameSecret(await hashHumanCode(input.activationCode), license.activation_code_hash))) throw invalid;

  // Everything that can refuse runs before the code is spent and the key bound.
  await rootKey(c.env.ROOT_PRIVATE_KEY);
  const at = new Date();
  const expiresAt = license.expires_at ?? termEnd(license.plan, license.trial_days, at)?.toISOString() ?? null;
  await requireUsable(c.env, { ...license, activated_at: at.toISOString(), expires_at: expiresAt }, { challenge: request.nonce });

  const fp = input.binding.kind === "fingerprint" ? input.binding.fingerprint : null;
  const updated = await c.env.DB.prepare(
    `UPDATE license SET activation_code_hash = NULL, activated_at = ?1, validated_at = ?1, expires_at = ?2, key_alg = ?3, key_spki = ?4,
       binding_kind = ?5, fp_board = ?6, fp_disk = ?7, fp_mac = ?8, revision = revision + 1
     WHERE id = ?9 AND activation_code_hash = ?10 AND revoked_at IS NULL RETURNING *`,
  )
    .bind(at.toISOString(), expiresAt, input.key.alg, input.key.spki, input.binding.kind, fp?.board ?? null, fp?.disk ?? null, fp?.mac ?? null, license.id, license.activation_code_hash)
    .first<LicenseRow>();
  if (!updated) throw invalid;
  return c.json({ license: await licenseToken(c.env, updated) });
});

branch.post("/license/renew", async (c) => {
  const { license, body, challenge } = await authenticate(c);
  const input = parseJson(renewSchema, body);
  await requireUsable(c.env, license, { challenge });
  if (!sameHardware(license, input.fingerprint)) throw new ApiError(403, "binding_mismatch", "La licencia está ligada a otro equipo");
  // Guarded again in SQL so a revocation or expiry landing mid-request cannot yield a fresh "active" license.
  const now = new Date().toISOString();
  const renewed = await c.env.DB.prepare("UPDATE license SET validated_at = ?1 WHERE id = ?2 AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at > ?1) RETURNING *")
    .bind(now, license.id)
    .first<LicenseRow>();
  if (!renewed) {
    await requireUsable(c.env, (await findLicense(c.env.DB, license.id))!, { challenge });
    throw new ApiError(409, "conflict", "La licencia cambió durante la renovación; reintenta");
  }
  return c.json({ license: await licenseToken(c.env, renewed) });
});

branch.post("/updates/check", async (c) => {
  const { license, body, challenge } = await authenticate(c);
  const input = parseJson(z.strictObject({ platform: z.enum(PLATFORMS), currentVersion: z.string().max(32) }), body);
  await requireUsable(c.env, license, { challenge });
  return c.json(await checkForUpdate(c.env, license, input.platform, input.currentVersion));
});

branch.get("/downloads/:releaseId", (c) => streamDownload(c, c.req.param("releaseId")));

branch.get("/tickets", async (c) => {
  const { license, challenge } = await authenticate(c);
  await requireUsable(c.env, license, { allowExpired: true, challenge });
  return c.json({ tickets: await branchTickets(c.env.DB, license.id) });
});

branch.post("/tickets", async (c) => {
  const { license, body, challenge } = await authenticate(c);
  const input = parseJson(z.strictObject({ subject: z.string().trim().min(1).max(150), message: z.string().trim().min(1).max(4000) }), body);
  await requireUsable(c.env, license, { allowExpired: true, challenge });
  return c.json({ ticket: await createTicket(c.env.DB, license.id, input.subject, input.message) }, 201);
});

branch.post("/tickets/:id/messages", async (c) => {
  const { license, body, challenge } = await authenticate(c);
  const input = parseJson(z.strictObject({ message: z.string().trim().min(1).max(4000) }), body);
  await requireUsable(c.env, license, { allowExpired: true, challenge });
  return c.json({ ticket: await addTicketMessage(c.env.DB, c.req.param("id"), { kind: "branch", licenseId: license.id }, input.message) }, 201);
});

branch.put("/registry", async (c) => {
  const { license, body, challenge } = await authenticate(c);
  const input = parseJson(z.strictObject({ centralCertificateSha256: hex64 }), body);
  await requireUsable(c.env, license, { challenge });
  const write = c.env.DB.prepare("UPDATE license SET central_cert_sha256 = ? WHERE id = ?").bind(input.centralCertificateSha256, license.id).run();
  await uniqueOr409(write, "Ese certificado ya está registrado por otra sucursal");
  return c.json({ siteId: license.site_id, tenantId: license.tenant_id, centralCertificateSha256: input.centralCertificateSha256 });
});
