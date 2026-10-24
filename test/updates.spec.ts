import { env } from "cloudflare:workers";
import { describe, expect, it } from "vitest";
import { toHex } from "../src/crypto";
import { activate, call, createLicense, firstAdmin, json, newDevice, signed, verifyJws, type Device } from "./helpers";

const pkg = new TextEncoder().encode("paquete .deb de prueba ".repeat(100));

async function branchWithLicense(token: string) {
  const { license, activationCode } = await createLicense(token);
  const device = await newDevice();
  await json(await activate(license.id, activationCode, device), 200);
  return { license, device };
}

async function uploadRelease(token: string, version = "1.4.0") {
  const { release } = await json(await call("POST", "/admin/v1/releases", { token, body: { version, platform: "linux-x64", filename: `culinary-${version}.deb`, notes: "Corrige impresión" } }), 201);
  const part = await json(await call("PUT", `/admin/v1/releases/${release.id}/parts/1`, { token, raw: pkg, headers: { "content-length": String(pkg.length) } }), 200);
  return (await json(await call("POST", `/admin/v1/releases/${release.id}/complete`, { token, body: { parts: [part] } }), 200)).release;
}

const check = (device: Device, licenseId: string, currentVersion = "1.3.2") =>
  signed("branch", device, licenseId, "POST", "/branch/v1/updates/check", { platform: "linux-x64", currentVersion });

describe("actualizaciones", () => {
  it("firma el paquete con el SHA-512 de lo que quedó en R2", async () => {
    const { token } = await firstAdmin();
    const release = await uploadRelease(token);
    const expected = toHex(new Uint8Array(await crypto.subtle.digest("SHA-512", pkg)));
    expect(release).toMatchObject({ status: "ready", bytes: pkg.length, sha512: expected });
    expect(await verifyJws(release.manifest, "culinary-release+jws")).toMatchObject({ version: "1.4.0", sha512: expected, bytes: pkg.length });
  });

  it("entrega solo a las licencias elegidas, con un token firmado para cada una", async () => {
    const { token } = await firstAdmin();
    const target = await branchWithLicense(token);
    const other = await branchWithLicense(token);
    const release = await uploadRelease(token);
    await json(await call("POST", "/admin/v1/publications", { token, body: { releaseId: release.id, target: { licenseIds: [target.license.id] } } }), 201);

    const offered = await json(await check(target.device, target.license.id), 200);
    expect(await verifyJws(offered.update, "culinary-update+jws")).toMatchObject({ licenseId: target.license.id, version: "1.4.0", sha512: release.sha512 });
    expect((await json(await check(other.device, other.license.id), 200)).update).toBeNull();
    expect((await json(await check(target.device, target.license.id, "1.4.0"), 200)).update).toBeNull();
  });

  it("publicar para todas llega a cualquier licencia y retirar la publicación la apaga", async () => {
    const { token } = await firstAdmin();
    const branch = await branchWithLicense(token);
    const release = await uploadRelease(token);
    const { publication } = await json(await call("POST", "/admin/v1/publications", { token, body: { releaseId: release.id, target: "all" } }), 201);
    expect((await json(await check(branch.device, branch.license.id), 200)).update).not.toBeNull();
    await json(await call("POST", `/admin/v1/publications/${publication.id}/withdraw`, { token }), 200);
    expect((await json(await check(branch.device, branch.license.id), 200)).update).toBeNull();
  });

  it("ofrece la versión más nueva publicada", async () => {
    const { token } = await firstAdmin();
    const branch = await branchWithLicense(token);
    for (const version of ["1.10.0", "1.9.3"]) {
      const release = await uploadRelease(token, version);
      await json(await call("POST", "/admin/v1/publications", { token, body: { releaseId: release.id, target: "all" } }), 201);
    }
    const offered = await json(await check(branch.device, branch.license.id), 200);
    expect((await verifyJws(offered.update, "culinary-update+jws")).version).toBe("1.10.0");
  });

  it("descarga con el permiso de la licencia, también por rangos", async () => {
    const { token } = await firstAdmin();
    const branch = await branchWithLicense(token);
    const release = await uploadRelease(token);
    await json(await call("POST", "/admin/v1/publications", { token, body: { releaseId: release.id, target: "all" } }), 201);
    const { download } = await json(await check(branch.device, branch.license.id), 200);

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
    const expired = await branchWithLicense(token);
    await env.DB.prepare("UPDATE license SET expires_at = ? WHERE id = ?").bind(new Date(Date.now() - 1000).toISOString(), expired.license.id).run();
    expect((await json(await check(expired.device, expired.license.id), 403)).error.code).toBe("license_expired");

    const revoked = await branchWithLicense(token);
    await json(await call("POST", `/admin/v1/licenses/${revoked.license.id}/revoke`, { token, body: { reason: "Falta de pago" } }), 200);
    expect((await json(await check(revoked.device, revoked.license.id), 403)).error.code).toBe("license_revoked");
  });

  it("no publica una versión que no terminó de subir", async () => {
    const { token } = await firstAdmin();
    const { release } = await json(await call("POST", "/admin/v1/releases", { token, body: { version: "2.0.0", platform: "linux-x64", filename: "c.deb" } }), 201);
    expect((await call("POST", "/admin/v1/publications", { token, body: { releaseId: release.id, target: "all" } })).status).toBe(409);
    await json(await call("DELETE", `/admin/v1/releases/${release.id}`, { token }), 200);
  });
});
