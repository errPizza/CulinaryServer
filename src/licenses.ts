import { OFFLINE_GRACE_MS, termEnd, TIER_TERMINALS, type Limits, type Plan, type Tier } from "./catalog";
import { type KeyAlg } from "./crypto";
import { audit } from "./db";
import { licenseSigner, signJws } from "./keys";
import { ApiError, type Env } from "./http";

export type LicenseRow = {

  id: string;
  tenant_id: string;
  site_id: string;
  customer: string;
  branch_name: string;
  plan: Plan;
  tier: Tier;
  addons: string;
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
  deleted_at: string | null;

};

export const LICENSE_STATUSES = ["pending", "active", "expired", "revoked"] as const;
export type LicenseStatus = (typeof LICENSE_STATUSES)[number];

export function licenseStatus(row: LicenseRow, at = Date.now()): LicenseStatus {

  if (row.revoked_at) return "revoked";
  if (!row.activated_at) return "pending";
  if (row.expires_at && Date.parse(row.expires_at) <= at) return "expired";
 
  return "active";
}

export const features = (row: LicenseRow) => JSON.parse(row.features) as string[];
export const addons = (row: LicenseRow) => JSON.parse(row.addons) as string[];
// maxTerminals left unset follows the tier, so moving Lite to Pro raises it without editing limits.
export function limits(row: LicenseRow): Required<Limits> {

  const stored = JSON.parse(row.limits) as Limits;

  return { ...stored, maxTerminals: stored.maxTerminals ?? TIER_TERMINALS[row.tier] };
}

export async function findLicense(db: D1Database, id: string): Promise<LicenseRow | null> {
  
  return db.prepare("SELECT * FROM license WHERE id = ?").bind(id).first<LicenseRow>();
}

export async function getLicense(db: D1Database, id: string): Promise<LicenseRow> {
  
  const row = await findLicense(db, id);
  
  if (!row) throw new ApiError(404, "not_found", "Licencia no encontrada");
  
  return row;
}

export function nextExpiry(row: LicenseRow, plan: Plan, trialDays: number | null, input: { plan?: Plan; expiresAt?: string }, at = new Date()): string | null {
  
  if (plan === "permanent") return null;
  if (input.expiresAt) return new Date(input.expiresAt).toISOString();
  if (input.plan && input.plan !== row.plan) return row.activated_at ? (termEnd(plan, trialDays, at)?.toISOString() ?? null) : null;
  
  return row.expires_at;
}

export function licenseView(row: LicenseRow) {
  
  return {

    id: row.id,
    tenantId: row.tenant_id,
    siteId: row.site_id,
    customer: row.customer,
    branchName: row.branch_name,
    plan: row.plan,
    tier: row.tier,
    addons: addons(row),
    trialDays: row.trial_days,
    features: features(row),
    limits: limits(row),
    revision: row.revision,
    status: licenseStatus(row),
    createdAt: row.created_at,
    activatedAt: row.activated_at,
    expiresAt: row.expires_at,
    validatedAt: row.validated_at,
    revokedAt: row.revoked_at,
    revokeReason: row.revoke_reason,
    binding: row.binding_kind ? { kind: row.binding_kind, keyAlg: row.key_alg } : null,
    centralCertificateSha256: row.central_cert_sha256

  };
}

export async function licenseToken(env: Env, row: LicenseRow): Promise<string> {

  if (licenseStatus(row) !== "active") throw new Error(`licenseToken for a ${licenseStatus(row)} license`);
  
  const validatedAt = row.validated_at!;
  
  const token = await signJws(env, "culinary-license+jws", {

    licenseId: row.id,
    revision: row.revision,
    tenantId: row.tenant_id,
    siteId: row.site_id,
    customer: row.customer,
    branchName: row.branch_name,
    plan: row.plan,
    tier: row.tier,
    addons: addons(row),
    status: "active",
    features: features(row),
    limits: limits(row),
    activatedAt: row.activated_at,
    expiresAt: row.expires_at,
    validatedAt,
    offlineUntil: new Date(Date.parse(validatedAt) + OFFLINE_GRACE_MS).toISOString(),
    key: { alg: row.key_alg, spki: row.key_spki },
    binding: row.binding_kind

  });

  await audit(env.DB, null, "license.sign", row.id, { kid: (await licenseSigner(env)).kid, revision: row.revision });

  return token;
}

export async function statusNotice(env: Env, row: LicenseRow, challenge: string): Promise<string> {

  return signJws(env, "culinary-license-status+jws", {

    licenseId: row.id,
    revision: row.revision,
    siteId: row.site_id,
    status: licenseStatus(row),
    plan: row.plan,
    tier: row.tier,
    addons: addons(row),
    expiresAt: row.expires_at,
    revokedAt: row.revoked_at,
    challenge

  });
}

export async function requireUsable(env: Env, row: LicenseRow, options: { challenge: string; allowExpired?: boolean }): Promise<void> {
  
  const status = licenseStatus(row);
  
  if (status === "revoked") throw new ApiError(403, "license_revoked", "Licencia revocada", { notice: await statusNotice(env, row, options.challenge) });
  if (status === "expired" && !options.allowExpired) throw new ApiError(403, "license_expired", "Licencia vencida", { notice: await statusNotice(env, row, options.challenge) });

}