import { z } from "zod";
import { fromBase64Url, sha256Hex } from "./crypto";
import { audit } from "./db";
import { ApiError, type OwnerIdentity } from "./http";
import type { LicenseRow } from "./licenses";
import type { Fiscal } from "./sat";

// The CSD travels from the owner's app to the branch inside an envelope this server cannot open: ECDH P-256 with the
// branch's intake key, HKDF-SHA-256 and AES-256-GCM. The branch checks it, loads it into the PAC and discards it; here only
// the result is kept. Nobody can read the files or the password back, not even the owner.

const PENDING_TTL_MS = 24 * 60 * 60 * 1000;
const PER_HOUR = 5;
const b64url = (min: number, max: number) => z.string().regex(/^[A-Za-z0-9_-]+$/).min(min).max(max);

export const intakeSchema = z.strictObject({ spki: b64url(80, 200) });

export const submissionSchema = z.strictObject({

  id: z.uuid(),
  intakeSha256: z.string().regex(/^[0-9a-f]{64}$/),
  envelope: z.strictObject({

    v: z.literal(1),
    epk: b64url(80, 200),
    salt: b64url(43, 43),
    iv: b64url(16, 16),
    ct: b64url(32, 40_000)

  })

});

export const resultSchema = z.discriminatedUnion("status", [

  z.strictObject({

    status: z.literal("loaded"),
    rfc: z.string().regex(/^[A-ZÑ&]{3,4}\d{6}[A-Z\d]{3}$/),
    // 20 digits for a SAT certificate; a test authority may use another serial.
    serial: z.string().regex(/^[0-9A-Za-z]{1,40}$/),
    notBefore: z.iso.datetime({ offset: true }),
    notAfter: z.iso.datetime({ offset: true }),
    message: z.string().trim().max(300).default("Sellos cargados con éxito")

  }),
  z.strictObject({ status: z.literal("rejected"), message: z.string().trim().min(1).max(300) })

]);

type SubmissionRow = { id: string; license_id: string; account_id: string; intake_sha256: string; envelope: string | null; status: "pending" | "loaded" | "rejected" | "expired"; message: string | null; rfc: string | null; serial: string | null; not_before: string | null; not_after: string | null; created_at: string; resolved_at: string | null };
type IntakeRow = { license_id: string; spki: string; created_at: string };

export function licenseFiscal(row: LicenseRow): Fiscal | null {

  return row.fiscal_rfc && row.fiscal_name && row.fiscal_postal_code && row.fiscal_regime ? { rfc: row.fiscal_rfc, name: row.fiscal_name, postalCode: row.fiscal_postal_code, regime: row.fiscal_regime } : null;
}

/** A new activation code or an activation needs the business's tax data; a license already running is not stopped for it. */
export function requireFiscal(row: LicenseRow): void {

  if (!licenseFiscal(row)) throw new ApiError(409, "fiscal_incomplete", "La licencia no tiene los datos fiscales del negocio (RFC, razón social, código postal y régimen). Captúralos antes de activarla.");
}

async function intakeHash(spki: string): Promise<string> {

  return sha256Hex(fromBase64Url(spki));
}

/** The branch's ECDH key. Registering a new one leaves any envelope sealed to the old one unreadable, so those expire. */
export async function registerIntake(db: D1Database, licenseId: string, spki: string): Promise<{ sha256: string }> {

  try {

    await crypto.subtle.importKey("spki", fromBase64Url(spki), { name: "ECDH", namedCurve: "P-256" }, false, []);

  } catch {

    throw new ApiError(400, "bad_request", "spki: llave pública ECDH P-256");

  }

  const at = new Date().toISOString(), sha256 = await intakeHash(spki);

  await db.batch([
    db.prepare("INSERT INTO fiscal_intake (license_id, spki, created_at) VALUES (?1, ?2, ?3) ON CONFLICT (license_id) DO UPDATE SET spki = ?2, created_at = ?3 WHERE spki <> ?2").bind(licenseId, spki, at),
    db.prepare("UPDATE fiscal_submission SET envelope = NULL, status = 'expired', message = 'La sucursal cambió su llave de recepción; vuelve a enviar los sellos', resolved_at = ?1 WHERE license_id = ?2 AND status = 'pending' AND intake_sha256 <> ?3").bind(at, licenseId, sha256)
  ]);

  return { sha256 };
}

/** What the owner sees per branch: whether it can receive, what it holds now, and how the last sending ended. */
export async function fiscalStatus(db: D1Database, row: LicenseRow) {

  const intake = await db.prepare("SELECT * FROM fiscal_intake WHERE license_id = ?").bind(row.id).first<IntakeRow>();
  const loaded = await db.prepare("SELECT * FROM fiscal_submission WHERE license_id = ? AND status = 'loaded' ORDER BY resolved_at DESC LIMIT 1").bind(row.id).first<SubmissionRow>();
  const last = await db.prepare("SELECT * FROM fiscal_submission WHERE license_id = ? ORDER BY created_at DESC LIMIT 1").bind(row.id).first<SubmissionRow>();

  return {

    licenseId: row.id,
    branchName: row.branch_name,
    business: licenseFiscal(row),
    intake: intake ? { spki: intake.spki, sha256: await intakeHash(intake.spki), since: intake.created_at } : null,
    csd: loaded ? { loaded: true, rfc: loaded.rfc, serial: loaded.serial, notBefore: loaded.not_before, notAfter: loaded.not_after, loadedAt: loaded.resolved_at } : { loaded: false },
    last: last ? { id: last.id, status: last.status, message: last.message, at: last.resolved_at ?? last.created_at } : null

  };
}

export async function submitCsd(db: D1Database, account: OwnerIdentity, row: LicenseRow, input: z.infer<typeof submissionSchema>) {

  if (!licenseFiscal(row)) throw new ApiError(409, "fiscal_incomplete", "Tu proveedor aún no registra los datos fiscales de esta sucursal; pídele que los capture");

  const intake = await db.prepare("SELECT * FROM fiscal_intake WHERE license_id = ?").bind(row.id).first<IntakeRow>();

  if (!intake) throw new ApiError(409, "intake_missing", "La sucursal aún no se ha conectado para recibir sellos; enciéndela y espera unos minutos");
  if ((await intakeHash(intake.spki)) !== input.intakeSha256) throw new ApiError(409, "intake_changed", "La sucursal cambió su llave de recepción; vuelve a abrir esta pantalla");

  const lastHour = new Date(Date.now() - 3_600_000).toISOString();
  const recent = await db.prepare("SELECT COUNT(*) AS n FROM fiscal_submission WHERE license_id = ? AND created_at > ?").bind(row.id, lastHour).first<number>("n");

  if ((recent ?? 0) >= PER_HOUR) throw new ApiError(429, "rate_limited", "Demasiados envíos de sellos en la última hora. Espera un poco.");

  const at = new Date().toISOString();

  // One sending at a time: a newer one replaces whatever had not been opened yet.
  const [, inserted] = await db.batch([
    db.prepare("UPDATE fiscal_submission SET envelope = NULL, status = 'expired', message = 'Reemplazado por un envío posterior', resolved_at = ?1 WHERE license_id = ?2 AND status = 'pending'").bind(at, row.id),
    db.prepare("INSERT INTO fiscal_submission (id, license_id, account_id, intake_sha256, envelope, status, created_at) VALUES (?, ?, ?, ?, ?, 'pending', ?) ON CONFLICT (id) DO NOTHING RETURNING id").bind(input.id, row.id, account.id, input.intakeSha256, JSON.stringify(input.envelope), at)
  ]);

  if (!inserted?.results.length) throw new ApiError(409, "conflict", "Ese envío ya existe");
  // Who sent sellos to which branch, never what they contain.
  await audit(db, null, "fiscal.csd.submit", row.id, { account: account.id, email: account.email, submission: input.id });

  return { id: input.id, status: "pending" as const, at };
}

/** The envelopes still waiting for this branch, oldest first, sealed to the key it registered. */
export async function pendingFor(db: D1Database, licenseId: string) {

  const { results } = await db.prepare("SELECT * FROM fiscal_submission WHERE license_id = ? AND status = 'pending' AND envelope IS NOT NULL AND created_at > ? ORDER BY created_at LIMIT 5").bind(licenseId, new Date(Date.now() - PENDING_TTL_MS).toISOString()).all<SubmissionRow>();

  return results.map((r) => ({ id: r.id, intakeSha256: r.intake_sha256, envelope: JSON.parse(r.envelope!) as unknown, at: r.created_at }));
}

/** The branch's verdict. The envelope goes away with it; repeating the same verdict is harmless. */
export async function resolveSubmission(db: D1Database, licenseId: string, id: string, result: z.infer<typeof resultSchema>) {

  const at = new Date().toISOString();
  const loaded = result.status === "loaded" ? result : null;
  const updated = await db.prepare("UPDATE fiscal_submission SET envelope = NULL, status = ?, message = ?, rfc = ?, serial = ?, not_before = ?, not_after = ?, resolved_at = ? WHERE id = ? AND license_id = ? AND status = 'pending' RETURNING id")
    .bind(result.status, result.message, loaded?.rfc ?? null, loaded?.serial ?? null, loaded?.notBefore ?? null, loaded?.notAfter ?? null, at, id, licenseId).first();

  if (updated) {

    await audit(db, null, `fiscal.csd.${result.status}`, licenseId, { submission: id, ...(loaded ? { rfc: loaded.rfc, serial: loaded.serial, notAfter: loaded.notAfter } : { message: result.message }) });

    return { id, status: result.status };

  }

  const row = await db.prepare("SELECT status FROM fiscal_submission WHERE id = ? AND license_id = ?").bind(id, licenseId).first<{ status: string }>();

  if (row?.status === result.status) return { id, status: result.status };
  if (!row) throw new ApiError(404, "not_found", "Envío no encontrado");

  throw new ApiError(409, "conflict", "Ese envío ya se resolvió");
}

export function expireSubmissions(db: D1Database, at: number): D1PreparedStatement {

  return db.prepare("UPDATE fiscal_submission SET envelope = NULL, status = 'expired', message = 'La sucursal no lo recibió en 24 horas', resolved_at = ?1 WHERE status = 'pending' AND created_at < ?2").bind(new Date(at).toISOString(), new Date(at - PENDING_TTL_MS).toISOString());
}
