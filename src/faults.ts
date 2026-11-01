import { z } from "zod";
import { ApiError } from "./http";

const MAX_OPEN_FAULTS = 500;

export const FAULT_STATUSES = ["open", "resolved"] as const;

export const faultsSchema = z.strictObject({

  faults: z.array(z.strictObject({

    fingerprint: z.string().regex(/^[0-9a-f]{64}$/),
    source: z.enum(["api", "worker", "client", "web", "kiosk"]),
    severity: z.enum(["error", "critical"]),
    what: z.string().min(1).max(300),
    affected: z.string().max(300),
    detail: z.string().max(8000),
    context: z.record(z.string().max(40), z.string().max(300)),
    version: z.string().max(32),
    platform: z.string().max(32),
    occurrences: z.int().min(1).max(1_000_000),
    firstAt: z.iso.datetime({ offset: true }),
    lastAt: z.iso.datetime({ offset: true })

  })).min(1).max(20)

});

type FaultRow = {

  id: string;
  license_id: string;
  fingerprint: string;
  source: string;
  severity: string;
  what: string;
  affected: string;
  detail: string;
  context: string;
  version: string;
  platform: string;
  occurrences: number;
  first_at: string;
  last_at: string;
  status: (typeof FAULT_STATUSES)[number];
  resolved_at: string | null;
  resolved_by: string | null;

};

type ListedFault = FaultRow & { customer: string; branch_name: string; site_id: string };

function faultView(f: ListedFault) {

  return {

    id: f.id,
    licenseId: f.license_id,
    customer: f.customer,
    branchName: f.branch_name,
    siteId: f.site_id,
    source: f.source,
    severity: f.severity,
    what: f.what,
    affected: f.affected,
    detail: f.detail,
    context: JSON.parse(f.context) as Record<string, string>,
    version: f.version,
    platform: f.platform,
    occurrences: f.occurrences,
    firstAt: f.first_at,
    lastAt: f.last_at,
    status: f.status,
    resolvedAt: f.resolved_at,
    resolvedBy: f.resolved_by

  };
}

/** A fault that comes back after being resolved is open again, with the version that still has it. */
export async function recordFaults(db: D1Database, licenseId: string, faults: z.infer<typeof faultsSchema>["faults"]) {

  const open = (await db.prepare("SELECT COUNT(*) AS n FROM fault WHERE license_id = ? AND status = 'open'").bind(licenseId).first<number>("n")) ?? 0;
  // A branch in a failure loop keeps counting what is already known, but cannot grow the table without limit.
  const room = open < MAX_OPEN_FAULTS ? "" : "AND EXISTS (SELECT 1 FROM fault f WHERE f.license_id = ?2 AND f.fingerprint = ?3)";
  const write = `INSERT INTO fault (id, license_id, fingerprint, source, severity, what, affected, detail, context, version, platform, occurrences, first_at, last_at) SELECT ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14 WHERE 1 ${room}
    ON CONFLICT (license_id, fingerprint) DO UPDATE SET occurrences = occurrences + excluded.occurrences, last_at = max(last_at, excluded.last_at), detail = excluded.detail, context = excluded.context, version = excluded.version, status = 'open', resolved_at = NULL, resolved_by = NULL`;

  await db.batch(faults.map((f) => db.prepare(write).bind(crypto.randomUUID(), licenseId, f.fingerprint, f.source, f.severity, f.what, f.affected, f.detail, JSON.stringify(f.context), f.version, f.platform, f.occurrences, f.firstAt, f.lastAt)));

  return { received: faults.length };
}

const FAULT_SELECT = "SELECT f.*, l.customer, l.branch_name, l.site_id FROM fault f JOIN license l ON l.id = f.license_id";

export async function adminFaults(db: D1Database, status: string | undefined) {

  const { results } = await db.prepare(`${FAULT_SELECT} WHERE ?1 IS NULL OR f.status = ?1 ORDER BY f.last_at DESC LIMIT 200`).bind(status ?? null).all<ListedFault>();

  return results.map(faultView);
}

async function setStatus(db: D1Database, id: string, status: FaultRow["status"], adminId: string | null) {

  const changed = await db.prepare("UPDATE fault SET status = ?1, resolved_at = ?2, resolved_by = ?3 WHERE id = ?4 RETURNING id").bind(status, status === "resolved" ? new Date().toISOString() : null, adminId, id).first();

  if (!changed) throw new ApiError(404, "not_found", "Fallo no encontrado");

  return faultView((await db.prepare(`${FAULT_SELECT} WHERE f.id = ?`).bind(id).first<ListedFault>())!);
}

export const resolveFault = (db: D1Database, id: string, adminId: string) => setStatus(db, id, "resolved", adminId);
export const reopenFault = (db: D1Database, id: string) => setStatus(db, id, "open", null);
