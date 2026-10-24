import { env } from "cloudflare:workers";
import { describe, expect, it } from "vitest";
import { toHex } from "../src/crypto";
import { activatedBranch, call, firstAdmin, json, signedBranch, verifyJws } from "./helpers";

const pkg = new TextEncoder().encode("paquete .deb de prueba ".repeat(100));

async function startRelease(token: string, version: string) {
  const body = { version, platform: "linux-x64", filename: `culinary-${version}.deb`, notes: "Corrige impresión" };
  return (await json(await call("POST", "/admin/v1/releases", { token, body }), 201)).release;
}

async function uploadRelease(token: string, version = "1.4.0") {
  const release = await startRelease(token, version);
  const part = await json(await call("PUT", `/admin/v1/releases/${release.id}/parts/1`, { token, raw: pkg, headers: { "content-length": String(pkg.length) } }), 200);
  return (await json(await call("POST", `/admin/v1/releases/${release.id}/complete`, { token, body: { parts: [part] } }), 200)).release;
}

const publishTo = async (token: string, releaseId: string, target: unknown) =>
  (await json(await call("POST", "/admin/v1/publications", { token, body: { releaseId, target } }), 201)).publication;

const check = (branch: Awaited<ReturnType<typeof activatedBranch>>, currentVersion = "1.3.2") =>
  signedBranch(branch, "POST", "/branch/v1/updates/check", { platform: "linux-x64", currentVersion });

describe("actualizaciones", () => {
  it("firma el paquete con el SHA-512 de lo que quedó en R2", async () => {
    const { token } = await firstAdmin();
    const release = await uploadRelease(token);
    const expected = toHex(new Uint8Array(await crypto.subtle.digest("SHA-512", pkg)));
    expect(release).toMatchObject({ status: "ready", bytes: pkg.length, sha512: expected });
    expect(await verifyJws(release.manifest, "culinary-release+jws")).toMatchObject({ v: 1, version: "1.4.0", sha512: expected, bytes: pkg.length });
  });

  it("rechaza un paquete cuya extensión no corresponde a la plataforma", async () => {
    const { token } = await firstAdmin();
    const body = { version: "1.0.0", platform: "win-x64", filename: "culinary.apk" };
    expect((await call("POST", "/admin/v1/releases", { token, body })).status).toBe(400);
  });

  it("entrega solo a las licencias elegidas, con un token firmado para cada una", async () => {
    const { token } = await firstAdmin();
    const target = await activatedBranch(token);
    const other = await activatedBranch(token);
    const release = await uploadRelease(token);
    await publishTo(token, release.id, { licenseIds: [target.license.id] });

    const offered = await json(await check(target), 200);
    expect(await verifyJws(offered.update, "culinary-update+jws")).toMatchObject({ licenseId: target.license.id, version: "1.4.0", sha512: release.sha512 });
    expect((await json(await check(other), 200)).update).toBeNull();
    expect((await json(await check(target, "1.4.0"), 200)).update).toBeNull();
  });

  it("publicar para todas llega a cualquier licencia y retirar la publicación la apaga", async () => {
    const { token } = await firstAdmin();
    const branch = await activatedBranch(token);
    const release = await uploadRelease(token);
    const publication = await publishTo(token, release.id, "all");
    expect((await json(await check(branch), 200)).update).not.toBeNull();
    await json(await call("POST", `/admin/v1/publications/${publication.id}/withdraw`, { token }), 200);
    expect((await json(await check(branch), 200)).update).toBeNull();
  });

  it("ofrece la versión más nueva publicada", async () => {
    const { token } = await firstAdmin();
    const branch = await activatedBranch(token);
    for (const version of ["1.10.0", "1.9.3", "1.2.0"]) await publishTo(token, (await uploadRelease(token, version)).id, "all");
    const offered = await json(await check(branch), 200);
    expect((await verifyJws(offered.update, "culinary-update+jws")).version).toBe("1.10.0");
  });

  it("descarga con el permiso de la licencia, también por rangos", async () => {
    const { token } = await firstAdmin();
    const branch = await activatedBranch(token);
    await publishTo(token, (await uploadRelease(token)).id, "all");
    const { download } = await json(await check(branch), 200);

    const full = await call("GET", download.path, { token: download.token });
    expect(full.status).toBe(200);
    expect(new Uint8Array(await full.arrayBuffer())).toEqual(pkg);

    const partial = await call("GET", download.path, { token: download.token, headers: { range: "bytes=10-19" } });
    expect(partial.status).toBe(206);
    expect(partial.headers.get("content-range")).toBe(`bytes 10-19/${pkg.length}`);
    expect(new Uint8Array(await partial.arrayBuffer())).toEqual(pkg.slice(10, 20));

    expect((await call("GET", download.path, { token: "inventado" })).status).toBe(401);
    expect((await call("GET", download.path)).status).toBe(401);
  });

  it("una licencia vencida o revocada no recibe actualizaciones", async () => {
    const { token } = await firstAdmin();
    const expired = await activatedBranch(token);
    await env.DB.prepare("UPDATE license SET expires_at = ? WHERE id = ?").bind(new Date(Date.now() - 1000).toISOString(), expired.license.id).run();
    expect((await json(await check(expired), 403)).error.code).toBe("license_expired");

    const revoked = await activatedBranch(token);
    await json(await call("POST", `/admin/v1/licenses/${revoked.license.id}/revoke`, { token, body: { reason: "Falta de pago" } }), 200);
    expect((await json(await check(revoked), 403)).error.code).toBe("license_revoked");
  });

  it("no publica una versión que no terminó de subir y la puede cancelar", async () => {
    const { token } = await firstAdmin();
    const release = await startRelease(token, "2.0.0");
    expect((await call("POST", "/admin/v1/publications", { token, body: { releaseId: release.id, target: "all" } })).status).toBe(409);
    await json(await call("DELETE", `/admin/v1/releases/${release.id}`, { token }), 200);
    await startRelease(token, "2.0.0");
  });

  it("no acepta dos veces la misma versión para la plataforma", async () => {
    const { token } = await firstAdmin();
    await startRelease(token, "3.0.0");
    const body = { version: "3.0.0", platform: "linux-x64", filename: "otro.deb" };
    expect((await json(await call("POST", "/admin/v1/releases", { token, body }), 409)).error.code).toBe("conflict");
  });
});
