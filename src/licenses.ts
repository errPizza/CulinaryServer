import { OFFLINE_GRACE_MS, type Limits, type Plan } from "./catalog";
import { rootKey, signJws, type KeyAlg } from "./crypto";
import { ApiError, type Env } from "./http";

export type LicenseRow = {
  id: string;
  tenant_id: string;
  site_id: string;
  customer: string;
  branch_name: string;
  plan: Plan;
  trial_days: number | null;
  features: string;
  limits: string;
  revision: number;
  created_at: string;
  expires_at: string | null;
  revoked_at: string | null;
  revoke_reason: string | null;
  activation_code_hash: string | null;
  activated_at: string | null;
  key_alg: KeyAlg | null;
  key_spki: string | null;
  binding_kind: "tpm" | "fingerprint" | null;
  fp_board: string | null;
  fp_disk: string | null;
  fp_mac: string | null;
  validated_at: string | null;
  central_cert_sha256: string | null;
};

export type LicenseStatus = "pending" | "active" | "expired" | "revoked";

export function licenseStatus(row: LicenseRow, at = Date.now()): LicenseStatus {
  if (row.revoked_at) return "revoked";
  if (!row.activated_at) return "pending";
  if (row.expires_at && Date.parse(row.expires_at) <= at) return "expired";
  return "active";
}

export async function findLicense(db: D1Database, id: string): Promise<LicenseRow | null> {
  return db.prepare("SELECT * FROM license WHERE id = ?").bind(id).first<LicenseRow>();
}

export async function getLicense(db: D1Database, id: string): Promise<LicenseRow> {
  const row = await findLicense(db, id);
  if (!row) throw new ApiError(404, "not_found", "Licencia no encontrada");
  return row;
}

/** What the panel sees. Hardware fingerprints stay server-side. */
export function licenseView(row: LicenseRow) {
  return {
    id: row.id,
    tenantId: row.tenant_id,
    siteId: row.site_id,
    customer: row.customer,
    branchName: row.branch_name,
    plan: row.plan,
    trialDays: row.trial_days,
    features: JSON.parse(row.features) as string[],
    limits: JSON.parse(row.limits) as Limits,
    revision: row.revision,
    status: licenseStatus(row),
    createdAt: row.created_at,
    activatedAt: row.activated_at,
    expiresAt: row.expires_at,
    validatedAt: row.validated_at,
    revokedAt: row.revoked_at,
    revokeReason: row.revoke_reason,
    binding: row.binding_kind ? { kind: row.binding_kind, keyAlg: row.key_alg } : null,
    centralCertificateSha256: row.central_cert_sha256,
  };
}

/** The use license: the branch's own public key, certified by the root together with what was paid for. */
export async function licenseToken(env: Env, row: LicenseRow): Promise<string> {
  const validatedAt = row.validated_at!;
  return signJws(await rootKey(env.ROOT_PRIVATE_KEY), "culinary-license+jws", {
    v: 1,
    licenseId: row.id,
    revision: row.revision,
    tenantId: row.tenant_id,
    siteId: row.site_id,
    customer: row.customer,
    branchName: row.branch_name,
    plan: row.plan,
    status: "active",
    features: JSON.parse(row.features),
    limits: JSON.parse(row.limits),
    activatedAt: row.activated_at,
    expiresAt: row.expires_at,
    validatedAt,
    offlineUntil: new Date(Date.parse(validatedAt) + OFFLINE_GRACE_MS).toISOString(),
    key: { alg: row.key_alg, spki: row.key_spki },
    binding: row.binding_kind,
    iat: new Date().toISOString(),
  });
}

/** Signed so the branch locks itself only on the root's word, not on an unauthenticated error. */
export async function statusNotice(env: Env, row: LicenseRow): Promise<string> {
  return signJws(await rootKey(env.ROOT_PRIVATE_KEY), "culinary-license-status+jws", {
    v: 1,
    licenseId: row.id,
    siteId: row.site_id,
    status: licenseStatus(row),
    plan: row.plan,
    expiresAt: row.expires_at,
    revokedAt: row.revoked_at,
    iat: new Date().toISOString(),
  });
}

/** Throws the branch-facing error for a license that may no longer be used, with its signed notice. */
export async function requireUsable(env: Env, row: LicenseRow, options: { allowExpired?: boolean } = {}): Promise<void> {
  const status = licenseStatus(row);
  if (status === "revoked") throw new ApiError(403, "license_revoked", "Licencia revocada", { notice: await statusNotice(env, row) });
  if (status === "expired" && !options.allowExpired) throw new ApiError(403, "license_expired", "Licencia vencida", { notice: await statusNotice(env, row) });
}
