import { z } from "zod";
import { PLATFORMS, VERSION_PATTERN } from "./catalog";
import { randomToken, sha256Hex, toHex } from "./crypto";
import { keyFloor, RELEASE_USES, signJws, verifyChained } from "./keys";
import { ApiError, bearerHash, uniqueOr409, type Ctx, type Env } from "./http";
import { licenseStatus, type LicenseRow } from "./licenses";

const DOWNLOAD_TTL_MS = 60 * 60 * 1000;
const PACKAGE_EXTENSION = { "linux-x64": ".deb", "win-x64": ".exe", "android-arm64": ".apk" } as const satisfies Record<(typeof PLATFORMS)[number], string>;

export const releaseSchema = z.strictObject({

  version: z.string().regex(VERSION_PATTERN, "Versión semántica x.y.z"),
  platform: z.enum(PLATFORMS),
  filename: z.string().regex(/^[A-Za-z0-9][A-Za-z0-9._-]{0,150}\.(exe|deb|apk)$/, "Nombre de paquete .exe, .deb o .apk"),
  notes: z.string().max(4000).default("")

}).refine((r) => r.filename.endsWith(PACKAGE_EXTENSION[r.platform]), { message: "La extensión no corresponde a la plataforma", path: ["filename"] });

export const completeSchema = z.strictObject({

  parts: z.array(z.strictObject({ partNumber: z.int().min(1).max(10_000), etag: z.string().min(1).max(200) })).min(1).max(10_000)

});

export const manifestSchema = z.strictObject({ manifest: z.string().min(40).max(32768) });

export const publicationSchema = z.strictObject({

  releaseId: z.string().min(1).max(64),
  target: z.union([z.literal("all"), z.strictObject({ licenseIds: z.array(z.string().min(1).max(64)).min(1).max(1000) })])

});

type ReleaseRow = {

  id: string;
  version: string;
  platform: string;
  filename: string;
  notes: string;
  // "uploading" with upload_id NULL and a sha512 means: complete in R2, waiting for the offline release signature.
  status: "uploading" | "ready";
  upload_id: string | null;
  bytes: number | null;
  sha512: string | null;
  manifest: string | null;
  created_at: string;

};

const objectKey = (r: Pick<ReleaseRow, "id" | "filename">) => `releases/${r.id}/${r.filename}`;

export function releaseView(r: ReleaseRow) {

  return { id: r.id, version: r.version, platform: r.platform, filename: r.filename, notes: r.notes, status: r.status === "uploading" && r.sha512 ? "signing" : r.status, bytes: r.bytes, sha512: r.sha512, manifest: r.manifest, createdAt: r.created_at };
}

async function getRelease(db: D1Database, id: string): Promise<ReleaseRow> {
  
  const row = await db.prepare("SELECT * FROM release WHERE id = ?").bind(id).first<ReleaseRow>();
 
  if (!row) throw new ApiError(404, "not_found", "Versión no encontrada");
 
  return row;
}

const DUPLICATE_VERSION = "Ya existe esa versión para la plataforma";

export async function createRelease(env: Env, input: z.infer<typeof releaseSchema>) {

  const exists = await env.DB.prepare("SELECT id FROM release WHERE platform = ? AND version = ?").bind(input.platform, input.version).first();

  if (exists) throw new ApiError(409, "conflict", DUPLICATE_VERSION);

  // Branches never go back a version, so publishing one that is not newer than the last ready one only confuses them.
  const { results: ready } = await env.DB.prepare("SELECT version FROM release WHERE platform = ? AND status = 'ready'").bind(input.platform).all<{ version: string }>();
  const highest = ready.reduce<string | null>((best, r) => (!best || newer(r.version, best) ? r.version : best), null);

  if (highest && !newer(input.version, highest)) throw new ApiError(409, "conflict", `La versión ${input.version} no es mayor que la última de ${input.platform} (${highest})`);
  
  const row: ReleaseRow = { id: crypto.randomUUID(), ...input, status: "uploading", upload_id: null, bytes: null, sha512: null, manifest: null, created_at: new Date().toISOString() };
  const upload = await env.PACKAGES.createMultipartUpload(objectKey(row));
 
  row.upload_id = upload.uploadId;
  
  const insert = env.DB.prepare("INSERT INTO release (id, version, platform, filename, notes, status, upload_id, created_at) VALUES (?, ?, ?, ?, ?, 'uploading', ?, ?)").bind(row.id, row.version, row.platform, row.filename, row.notes, row.upload_id, row.created_at).run();
 
  await uniqueOr409(insert, DUPLICATE_VERSION).catch(async (error) => {
    
    await upload.abort();
    throw error;

  });

  return releaseView(row);
}

async function uploading(env: Env, id: string) {
  
  const row = await getRelease(env.DB, id);
 
  if (row.status !== "uploading" || !row.upload_id) throw new ApiError(409, "conflict", "La versión ya no acepta partes");
 
  return { row, upload: env.PACKAGES.resumeMultipartUpload(objectKey(row), row.upload_id) };
}

export async function uploadPart(c: Ctx, id: string, partNumber: number) {
  
  const length = Number(c.req.header("content-length") ?? NaN);
 
  if (!Number.isInteger(length) || length < 1) throw new ApiError(400, "bad_request", "Content-Length requerido");
  if (!c.req.raw.body) throw new ApiError(400, "bad_request", "Parte vacía");
  
  const { upload } = await uploading(c.env, id);
  const part = await upload.uploadPart(partNumber, c.req.raw.body);
 
  return { partNumber: part.partNumber, etag: part.etag };
}

export async function completeRelease(env: Env, id: string, parts: z.infer<typeof completeSchema>["parts"]) {
 
  const { row, upload } = await uploading(env, id);
  
  try {

    await upload.complete(parts);

  } catch (error) {

    if (!(await env.PACKAGES.head(objectKey(row)))) throw new ApiError(409, "conflict", `R2 rechazó las partes: ${String(error)}`);

  }

  const object = await env.PACKAGES.get(objectKey(row));

  if (!object) throw new ApiError(409, "conflict", "El paquete no quedó en R2");
 
  const digest = new crypto.DigestStream("SHA-512");
  
  await object.body.pipeTo(digest);
  
  const sha512 = toHex(new Uint8Array(await digest.digest));
  const signing = await env.DB.prepare("UPDATE release SET upload_id = NULL, bytes = ?, sha512 = ? WHERE id = ? RETURNING *").bind(object.size, sha512, id).first<ReleaseRow>();

  return releaseView(signing!);
}

/** The release manifest comes signed from the provider station; it must describe exactly the bytes in R2. */
export async function attachManifest(env: Env, id: string, manifest: string) {

  const row = await getRelease(env.DB, id);

  if (row.status !== "uploading" || row.upload_id || !row.sha512) throw new ApiError(409, "conflict", "La versión no está esperando su firma");

  const { payload, intermediate } = await verifyChained(env, manifest.trim(), RELEASE_USES[0]);

  if (intermediate.generation < (await keyFloor(env)).release) throw new ApiError(400, "bad_request", "La llave intermedia de paquetes está revocada");

  const expected = { releaseId: row.id, version: row.version, platform: row.platform, filename: row.filename, bytes: row.bytes, sha512: row.sha512 };

  for (const [field, value] of Object.entries(expected)) if (payload[field] !== value) throw new ApiError(400, "bad_request", `La firma no corresponde al paquete (${field})`);

  const ready = await env.DB.prepare("UPDATE release SET status = 'ready', manifest = ? WHERE id = ? AND status = 'uploading' RETURNING *").bind(manifest.trim(), id).first<ReleaseRow>();

  if (!ready) throw new ApiError(409, "conflict", "La versión cambió mientras se firmaba");

  return { release: releaseView(ready), kid: intermediate.kid };
}

export async function abortRelease(env: Env, id: string) {

  const { row, upload } = await uploading(env, id);

  await env.DB.prepare("DELETE FROM release WHERE id = ?").bind(id).run();
  await upload.abort().catch(() => env.PACKAGES.delete(objectKey(row)));

}

export async function listReleases(db: D1Database) {

  const { results } = await db.prepare("SELECT * FROM release ORDER BY created_at DESC LIMIT 200").all<ReleaseRow>();

  return results.map(releaseView);
}

type PublicationRow = { id: string; release_id: string; target_all: number; created_at: string; withdrawn_at: string | null; license_ids: string | null };

function publicationView(p: PublicationRow) {

  return {

    id: p.id,
    releaseId: p.release_id,
    target: p.target_all ? "all" : { licenseIds: JSON.parse(p.license_ids ?? "[]") as string[] },
    createdAt: p.created_at,
    withdrawnAt: p.withdrawn_at

  };
}

const PUBLICATION_SELECT = `SELECT p.*, (SELECT json_group_array(license_id) FROM publication_target t WHERE t.publication_id = p.id) AS license_ids FROM publication p`;

export async function listPublications(db: D1Database) {
 
  const { results } = await db.prepare(`${PUBLICATION_SELECT} ORDER BY p.created_at DESC LIMIT 200`).all<PublicationRow>();
 
  return results.map(publicationView);
}

export async function publish(db: D1Database, input: z.infer<typeof publicationSchema>) {
 
  const release = await getRelease(db, input.releaseId);
  
  if (release.status !== "ready") throw new ApiError(409, "conflict", "Termina de subir el paquete antes de publicarlo");
 
  const licenseIds = input.target === "all" ? [] : [...new Set(input.target.licenseIds)];
  
  if (licenseIds.length > 0) {
    
    const found = await db.prepare("SELECT COUNT(*) AS n FROM license WHERE id IN (SELECT value FROM json_each(?))").bind(JSON.stringify(licenseIds)).first<number>("n");
    
    if (found !== licenseIds.length) throw new ApiError(400, "bad_request", "Alguna licencia destinataria no existe");
  
  }

  const id = crypto.randomUUID();
  
  await db.batch([
    db.prepare("INSERT INTO publication (id, release_id, target_all, created_at) VALUES (?, ?, ?, ?)").bind(id, release.id, input.target === "all" ? 1 : 0, new Date().toISOString()),
    db.prepare("INSERT INTO publication_target (publication_id, license_id) SELECT ?, value FROM json_each(?)").bind(id, JSON.stringify(licenseIds)),
  ]);

  return publicationView((await db.prepare(`${PUBLICATION_SELECT} WHERE p.id = ?`).bind(id).first<PublicationRow>())!);
}

export async function withdraw(db: D1Database, id: string) {
 
  const row = await db.prepare("UPDATE publication SET withdrawn_at = ? WHERE id = ? AND withdrawn_at IS NULL RETURNING id").bind(new Date().toISOString(), id).first();
  
  if (!row) throw new ApiError(404, "not_found", "Publicación no encontrada o ya retirada");

}


function versionKey(version: string): number[] {

  const parts = VERSION_PATTERN.exec(version);

  return parts ? parts.slice(1).map(Number) : [0, 0, 0];
}

function newer(a: string, b: string): boolean {
  
  const [x, y] = [versionKey(a), versionKey(b)];
 
  for (let i = 0; i < 3; i++) if (x[i] !== y[i]) return x[i]! > y[i]!;
  
  return false;
}

const PUBLISHED_TO = `FROM release r JOIN publication p ON p.release_id = r.id WHERE r.status = 'ready' AND p.withdrawn_at IS NULL AND (p.target_all = 1 OR EXISTS (SELECT 1 FROM publication_target t WHERE t.publication_id = p.id AND t.license_id = ?1))`;

/** Newest version published to this license on each platform. */
export async function latestReleases(env: Env, license: LicenseRow) {

  const { results } = await env.DB.prepare(`SELECT DISTINCT r.* ${PUBLISHED_TO}`).bind(license.id).all<ReleaseRow>();
  const latest: Record<string, { version: string; notes: string }> = {};

  for (const r of results) if (!latest[r.platform] || newer(r.version, latest[r.platform]!.version)) latest[r.platform] = { version: r.version, notes: r.notes };

  return latest;
}

export async function checkForUpdate(env: Env, license: LicenseRow, platform: string, currentVersion: string) {

  const { results } = await env.DB.prepare(`SELECT DISTINCT r.* ${PUBLISHED_TO} AND r.platform = ?2`).bind(license.id, platform).all<ReleaseRow>();
  const latest = results.reduce<ReleaseRow | undefined>((best, r) => (newer(r.version, best?.version ?? currentVersion) ? r : best), undefined);
 
  // Nothing newer: say which version is published, so the branch can tell "up to date" from "newer than published".
  if (!latest) return { update: null, latestVersion: results.reduce<string | null>((best, r) => (!best || newer(r.version, best) ? r.version : best), null) };

  const token = randomToken();
  const expires = Date.now() + DOWNLOAD_TTL_MS;
 
  await env.DB.prepare("INSERT INTO download_grant (token_hash, license_id, release_id, expires_at) VALUES (?, ?, ?, ?)").bind(await sha256Hex(token), license.id, latest.id, expires).run();
 
  const update = await signJws(env, "culinary-update+jws", {

    licenseId: license.id,
    siteId: license.site_id,
    releaseId: latest.id,
    version: latest.version,
    platform: latest.platform,
    filename: latest.filename,
    bytes: latest.bytes,
    sha512: latest.sha512,
    notes: latest.notes,
    exp: new Date(expires).toISOString()

  });

  return { update, release: latest.manifest, keyFloor: (await keyFloor(env)).jws, download: { path: `/branch/v1/downloads/${latest.id}`, token, expiresAt: new Date(expires).toISOString() } };
}

export async function streamDownload(c: Ctx, releaseId: string): Promise<Response> {

  const tokenHash = await bearerHash(c, "Permiso de descarga requerido");
  const grant = await c.env.DB.prepare(`SELECT l.*, r.filename AS release_filename FROM download_grant g JOIN license l ON l.id = g.license_id JOIN release r ON r.id = g.release_id WHERE g.token_hash = ? AND g.release_id = ? AND g.expires_at > ?`).bind(tokenHash, releaseId, Date.now()).first<LicenseRow & { release_filename: string }>();
  
  if (!grant || licenseStatus(grant) === "revoked") throw new ApiError(401, "unauthorized", "Permiso de descarga inválido o vencido");

  const object = await c.env.PACKAGES.get(objectKey({ id: releaseId, filename: grant.release_filename }), { range: c.req.raw.headers }).catch(() => {
   
    throw new ApiError(416, "range_not_satisfiable", "Rango inválido; pide un solo rango dentro del archivo");
 
  });

  if (!object) throw new ApiError(404, "not_found", "Paquete no disponible");
  
  const headers = new Headers({

    "content-type": "application/octet-stream",
    "content-disposition": `attachment; filename="${grant.release_filename}"`,
    "accept-ranges": "bytes",
    etag: object.httpEtag

  });

  if (object.range && c.req.header("range")) {

    const r = object.range as { offset?: number; length?: number; suffix?: number };
    const offset = r.suffix !== undefined ? object.size - r.suffix : (r.offset ?? 0);
    const length = r.suffix ?? r.length ?? object.size - offset;
   
    headers.set("content-range", `bytes ${offset}-${offset + length - 1}/${object.size}`);
    headers.set("content-length", String(length));
    
    return new Response(object.body, { status: 206, headers });
  }

  headers.set("content-length", String(object.size));

  return new Response(object.body, { headers });
}