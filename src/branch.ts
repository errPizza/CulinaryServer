import { Hono } from "hono";
import { z } from "zod";
import { PLATFORMS, termEnd } from "./catalog";
import { hashHumanCode, publicKeySchema, sameSecret } from "./crypto";
import { keyFloor, licenseSigner } from "./keys";
import { ApiError, parseJson, readJson, uniqueOr409, type App, type Ctx } from "./http";
import { audit } from "./db";
import { faultsSchema, recordFaults } from "./faults";
import { findLicense, licenseToken, requireUsable, statusNotice, type LicenseRow } from "./licenses";
import { consumeChallenge, issueChallenge, readSigned, signedBy, verifySigned } from "./signature";
import { branchReply, branchThread } from "./messages";
import { intakeSchema, pendingFor, registerIntake, requireFiscal, resolveSubmission, resultSchema } from "./fiscal";
import { MAX_STATS_BYTES, recordStats, statsSchema } from "./stats";
import { addTicketMessage, branchTickets, createTicket } from "./tickets";
import { checkForUpdate, latestReleases, streamDownload } from "./updates";

const hex64 = z.string().regex(/^[0-9a-f]{64}$/, "SHA-256 en hexadecimal minúsculo");
const fingerprintSchema = z.strictObject({ board: hex64, disk: hex64, mac: hex64 });

const activateSchema = z.strictObject({

  activationCode: z.string().min(20).max(40),
  siteId: z.string().regex(/^[a-z0-9-]{1,32}$/),
  key: publicKeySchema,
  binding: z.discriminatedUnion("kind", [
    z.strictObject({ kind: z.literal("tpm") }),
    z.strictObject({ kind: z.literal("fingerprint"), fingerprint: fingerprintSchema })
  ])

}).refine((a) => a.binding.kind !== "tpm" || a.key.alg === "ES256", { message: "Una llave de TPM 2.0 es ES256 (P-256)", path: ["key", "alg"] });

const renewSchema = z.strictObject({ fingerprint: fingerprintSchema.optional() });
const unauthorized = () => new ApiError(401, "unauthorized", "Firma o reto inválido");
type Authenticated = { license: LicenseRow; body: Uint8Array; challenge: string };

async function authenticate(c: Ctx, limit?: number): Promise<Authenticated> {

  const request = await readSigned(c, limit);
  const license = await findLicense(c.env.DB, request.subject);

  if (!license || !(license.key_spki || license.released_spki)) throw unauthorized();
  if (!(await consumeChallenge(c.env, "branch", request.subject, request.nonce))) throw unauthorized();
  if (license.key_alg && license.key_spki && await signedBy(c, "branch", request, license.key_alg, license.key_spki)) return { license, body: request.body, challenge: request.nonce };
  // The machine it was released from locks on its next contact instead of selling through the offline grace.
  if (license.released_alg && license.released_spki && await signedBy(c, "branch", request, license.released_alg, license.released_spki)) {

    throw new ApiError(403, "license_transferred", "La licencia pasó a otro equipo", { notice: await statusNotice(c.env, license, request.nonce, "transferred") });

  }

  throw unauthorized();
}

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
  // Checked before anything is written, so a branch with another siteId neither spends the code nor binds its key.
  if (input.siteId !== license.site_id) throw new ApiError(409, "site_mismatch", `La licencia es de la sucursal ${license.site_id}, no de ${input.siteId}`);
  // No software is activated for a business without its tax data; a code issued before the data existed waits for it too.
  requireFiscal(license);

  await licenseSigner(c.env);

  const at = new Date();
  const expiresAt = license.expires_at ?? termEnd(license.plan, license.trial_days, at)?.toISOString() ?? null;

  await requireUsable(c.env, { ...license, activated_at: at.toISOString(), expires_at: expiresAt }, { challenge: request.nonce });

  const fp = input.binding.kind === "fingerprint" ? input.binding.fingerprint : null;
  const updated = await c.env.DB.prepare(`UPDATE license SET activation_code_hash = NULL, activated_at = ?1, validated_at = ?1, expires_at = ?2, key_alg = ?3, key_spki = ?4, binding_kind = ?5, fp_board = ?6, fp_disk = ?7, fp_mac = ?8, revision = revision + 1 WHERE id = ?9 AND activation_code_hash = ?10 AND revoked_at IS NULL RETURNING *`).bind(at.toISOString(), expiresAt, input.key.alg, input.key.spki, input.binding.kind, fp?.board ?? null, fp?.disk ?? null, fp?.mac ?? null, license.id, license.activation_code_hash).first<LicenseRow>();
 
  if (!updated) throw invalid;
 
  return c.json({ license: await licenseToken(c.env, updated), keyFloor: (await keyFloor(c.env)).jws });
});

branch.post("/license/renew", async (c) => {

  const { license, body, challenge } = await authenticate(c);
  const input = parseJson(renewSchema, body);

  await requireUsable(c.env, license, { challenge });
  
  if (!sameHardware(license, input.fingerprint)) throw new ApiError(403, "binding_mismatch", "La licencia está ligada a otro equipo");

  const now = new Date().toISOString();
  // The stored fingerprint follows an accepted change; otherwise two repairs a year apart would add up to a foreign machine.
  const fp = license.binding_kind === "fingerprint" ? input.fingerprint : undefined;
  const changed = fp ? (["board", "disk", "mac"] as const).filter((part) => license[`fp_${part}`] !== fp[part]) : [];
  const renewed = await c.env.DB.prepare("UPDATE license SET validated_at = ?1, fp_board = COALESCE(?3, fp_board), fp_disk = COALESCE(?4, fp_disk), fp_mac = COALESCE(?5, fp_mac) WHERE id = ?2 AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at > ?1) RETURNING *").bind(now, license.id, fp?.board ?? null, fp?.disk ?? null, fp?.mac ?? null).first<LicenseRow>();

  if (!renewed) {

    await requireUsable(c.env, (await findLicense(c.env.DB, license.id))!, { challenge });

    throw new ApiError(409, "conflict", "La licencia cambió durante la renovación; reintenta");

  }

  if (changed.length) await audit(c.env.DB, null, "license.hardware_change", license.id, { parts: changed });

  return c.json({ license: await licenseToken(c.env, renewed), keyFloor: (await keyFloor(c.env)).jws });
});

branch.post("/updates/check", async (c) => {

  const { license, body, challenge } = await authenticate(c);
  const input = parseJson(z.strictObject({ platform: z.enum(PLATFORMS), currentVersion: z.string().max(32) }), body);
  
  await requireUsable(c.env, license, { challenge });
 
  return c.json(await checkForUpdate(c.env, license, input.platform, input.currentVersion));
});

// What the branch announces to its managers. It reveals no package and issues no download permission.
branch.post("/updates/latest", async (c) => {

  const { license, challenge } = await authenticate(c);

  await requireUsable(c.env, license, { challenge });

  return c.json({ releases: await latestReleases(c.env, license) });
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

// The owner's thread, read by the branch's managers in the point of sale. A branch that lost its license still hears from its owner.
branch.get("/owner-messages", async (c) => {

  const { license, challenge } = await authenticate(c);

  await requireUsable(c.env, license, { allowExpired: true, challenge });

  return c.json({ messages: await branchThread(c.env.DB, license.id) });
});

branch.post("/owner-messages", async (c) => {

  const { license, body, challenge } = await authenticate(c);
  const input = parseJson(z.strictObject({ id: z.string().min(1).max(64), name: z.string().trim().min(1).max(80), message: z.string().trim().min(1).max(2000) }), body);

  await requireUsable(c.env, license, { allowExpired: true, challenge });

  return c.json(await branchReply(c.env.DB, license.id, input.id, input.name, input.message), 201);
});

// The key the owner's CSD is sealed to. The request is signed by the license key, so it can only come from the machine that holds it.
branch.put("/fiscal/intake-key", async (c) => {

  const { license, body, challenge } = await authenticate(c);
  const input = parseJson(intakeSchema, body);

  await requireUsable(c.env, license, { challenge });

  return c.json(await registerIntake(c.env.DB, license.id, input.spki));
});

branch.get("/fiscal/submissions", async (c) => {

  const { license, challenge } = await authenticate(c);

  await requireUsable(c.env, license, { challenge });

  return c.json({ submissions: await pendingFor(c.env.DB, license.id) });
});

branch.post("/fiscal/submissions/:id/result", async (c) => {

  const { license, body, challenge } = await authenticate(c);
  const input = parseJson(resultSchema, body);

  await requireUsable(c.env, license, { allowExpired: true, challenge });

  return c.json(await resolveSubmission(c.env.DB, license.id, c.req.param("id"), input));
});

// A branch with an expired license is still a branch that can fail, and is the one most likely to call about it.
branch.post("/faults", async (c) => {

  const { license, body, challenge } = await authenticate(c);
  const input = parseJson(faultsSchema, body);

  await requireUsable(c.env, license, { allowExpired: true, challenge });

  return c.json(await recordFaults(c.env.DB, license.id, input.faults));
});

// Only a usable license publishes; what was already sent stays readable for the owner.
branch.post("/stats", async (c) => {

  const { license, body, challenge } = await authenticate(c, MAX_STATS_BYTES);
  const input = parseJson(statsSchema, body);

  await requireUsable(c.env, license, { challenge });

  return c.json(await recordStats(c.env.DB, license, input));
});

branch.put("/registry", async (c) => {

  const { license, body, challenge } = await authenticate(c);
  const input = parseJson(z.strictObject({ centralCertificateSha256: hex64 }), body);
  
  await requireUsable(c.env, license, { challenge });
  
  const write = c.env.DB.prepare("UPDATE license SET central_cert_sha256 = ? WHERE id = ?").bind(input.centralCertificateSha256, license.id).run();
 
  await uniqueOr409(write, "Ese certificado ya está registrado por otra sucursal");
 
  return c.json({ siteId: license.site_id, tenantId: license.tenant_id, centralCertificateSha256: input.centralCertificateSha256 });
});