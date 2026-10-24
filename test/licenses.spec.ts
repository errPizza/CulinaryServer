import { env } from "cloudflare:workers";
import { describe, expect, it } from "vitest";
import { termEnd } from "../src/catalog";
import { activate, call, challenge, createLicense, firstAdmin, fingerprint, json, newDevice, signed, verifyJws } from "./helpers";

const renew = (device: Awaited<ReturnType<typeof newDevice>>, licenseId: string, body: unknown = { fingerprint }) =>
  signed("branch", device, licenseId, "POST", "/branch/v1/license/renew", body);

describe("activación", () => {
  it("liga la licencia a la llave del equipo y entrega la licencia firmada por la raíz", async () => {
    const { token } = await firstAdmin();
    const { license, activationCode } = await createLicense(token);
    const device = await newDevice();
    const { license: jws } = await json(await activate(license.id, activationCode, device), 200);
    const payload = await verifyJws(jws, "culinary-license+jws");
    expect(payload).toMatchObject({
      licenseId: license.id,
      siteId: license.siteId,
      plan: "monthly",
      status: "active",
      features: ["printing", "reservations"],
      limits: { maxUsers: 15, maxTables: 30 },
      key: { alg: "Ed25519", spki: device.spki },
      binding: "fingerprint",
    });
    expect(Date.parse(payload.offlineUntil) - Date.parse(payload.validatedAt)).toBe(3 * 24 * 60 * 60 * 1000);
    expect(payload.expiresAt).toBe(termEnd("monthly", null, new Date(payload.activatedAt))!.toISOString());
  });

  it("acepta la llave ES256 de un TPM", async () => {
    const { token } = await firstAdmin();
    const { license, activationCode } = await createLicense(token);
    const tpm = await newDevice("ES256");
    const { license: jws } = await json(await activate(license.id, activationCode, tpm, { kind: "tpm" }), 200);
    expect((await verifyJws(jws, "culinary-license+jws")).binding).toBe("tpm");
    await json(await renew(tpm, license.id, {}), 200);
  });

  it("no deja activar dos veces con el mismo código", async () => {
    const { token } = await firstAdmin();
    const { license, activationCode } = await createLicense(token);
    await json(await activate(license.id, activationCode, await newDevice()), 200);
    const second = await activate(license.id, activationCode, await newDevice());
    expect((await json(second, 403)).error.code).toBe("activation_rejected");
  });

  it("rechaza un código equivocado y conserva el bueno", async () => {
    const { token } = await firstAdmin();
    const { license, activationCode } = await createLicense(token);
    expect((await activate(license.id, "AAAAA-AAAAA-AAAAA-AAAAA", await newDevice())).status).toBe(403);
    await json(await activate(license.id, activationCode.toLowerCase().replace(/-/g, " "), await newDevice()), 200);
  });

  it("el plazo de prueba empieza al activar con los días elegidos en el panel", async () => {
    const { token } = await firstAdmin();
    const { license, activationCode } = await createLicense(token, { plan: "trial", trialDays: 14 });
    expect(license.expiresAt).toBeNull();
    const payload = await verifyJws((await json(await activate(license.id, activationCode, await newDevice()), 200)).license, "culinary-license+jws");
    expect(Date.parse(payload.expiresAt) - Date.parse(payload.activatedAt)).toBe(14 * 24 * 60 * 60 * 1000);
  });

  it("la licencia permanente no tiene vencimiento", async () => {
    const { token } = await firstAdmin();
    const { license, activationCode } = await createLicense(token, { plan: "permanent" });
    const payload = await verifyJws((await json(await activate(license.id, activationCode, await newDevice()), 200)).license, "culinary-license+jws");
    expect(payload.expiresAt).toBeNull();
  });
});

describe("renovación", () => {
  async function activated() {
    const { token } = await firstAdmin();
    const { license, activationCode } = await createLicense(token);
    const device = await newDevice();
    await json(await activate(license.id, activationCode, device), 200);
    return { token, license, device };
  }

  it("renueva con la firma del equipo ligado y tolera un componente de hardware cambiado", async () => {
    const { license, device } = await activated();
    await json(await renew(device, license.id), 200);
    await json(await renew(device, license.id, { fingerprint: { ...fingerprint, disk: "d".repeat(64) } }), 200);
  });

  it("rechaza la licencia copiada a otro equipo", async () => {
    const { license, device } = await activated();
    const otherHardware = { board: "1".repeat(64), disk: "2".repeat(64), mac: fingerprint.mac };
    expect((await json(await renew(device, license.id, { fingerprint: otherHardware }), 403)).error.code).toBe("binding_mismatch");
    expect((await renew(await newDevice(), license.id)).status).toBe(401);
  });

  it("no acepta un reto dos veces ni un reto de otra licencia", async () => {
    const { token, license, device } = await activated();
    const nonce = await challenge("branch", license.id);
    await json(await signed("branch", device, license.id, "POST", "/branch/v1/license/renew", { fingerprint }, nonce), 200);
    expect((await signed("branch", device, license.id, "POST", "/branch/v1/license/renew", { fingerprint }, nonce)).status).toBe(401);

    const other = await createLicense(token);
    const foreign = await challenge("branch", other.license.id);
    expect((await signed("branch", device, license.id, "POST", "/branch/v1/license/renew", { fingerprint }, foreign)).status).toBe(401);
  });

  it("una licencia vencida no se renueva y recibe el aviso firmado para la pantalla de bloqueo", async () => {
    const { token, license, device } = await activated();
    await env.DB.prepare("UPDATE license SET expires_at = ? WHERE id = ?").bind(new Date(Date.now() - 1000).toISOString(), license.id).run();
    const error = (await json(await renew(device, license.id), 403)).error;
    expect(error.code).toBe("license_expired");
    expect(await verifyJws(error.notice, "culinary-license-status+jws")).toMatchObject({ licenseId: license.id, status: "expired", plan: "monthly" });

    const renewed = await json(await call("POST", `/admin/v1/licenses/${license.id}/renew`, { token, body: {} }), 200);
    expect(renewed.license.status).toBe("active");
    await json(await renew(device, license.id), 200);
  });

  it("una licencia revocada no se renueva", async () => {
    const { token, license, device } = await activated();
    await json(await call("POST", `/admin/v1/licenses/${license.id}/revoke`, { token, body: { reason: "Falta de pago" } }), 200);
    const error = (await json(await renew(device, license.id), 403)).error;
    expect(error.code).toBe("license_revoked");
    expect((await verifyJws(error.notice, "culinary-license-status+jws")).status).toBe("revoked");
    expect((await call("POST", `/admin/v1/licenses/${license.id}/renew`, { token, body: {} })).status).toBe(409);
  });
});

describe("edición desde el panel", () => {
  it("habilitar o quitar funciones sube la revisión que recibe la sucursal", async () => {
    const { token } = await firstAdmin();
    const { license, activationCode } = await createLicense(token);
    const device = await newDevice();
    const first = await verifyJws((await json(await activate(license.id, activationCode, device), 200)).license, "culinary-license+jws");
    await json(await call("PATCH", `/admin/v1/licenses/${license.id}`, { token, body: { features: ["multiBranch", "printing"], limits: { maxUsers: 40, maxTables: 80 } } }), 200);
    const next = await verifyJws((await json(await renew(device, license.id), 200)).license, "culinary-license+jws");
    expect(next.revision).toBeGreaterThan(first.revision);
    expect(next.features).toEqual(["multiBranch", "printing"]);
    expect(next.limits).toEqual({ maxUsers: 40, maxTables: 80 });
  });

  it("rechaza funciones que Culinary Restaurant no conoce", async () => {
    const { token } = await firstAdmin();
    const { license } = await createLicense(token);
    expect((await call("PATCH", `/admin/v1/licenses/${license.id}`, { token, body: { features: ["teletransporte"] } })).status).toBe(400);
  });

  it("renovar suma un periodo desde el vencimiento vigente", async () => {
    const { token } = await firstAdmin();
    const { license, activationCode } = await createLicense(token, { plan: "annual" });
    const payload = await verifyJws((await json(await activate(license.id, activationCode, await newDevice()), 200)).license, "culinary-license+jws");
    const renewed = await json(await call("POST", `/admin/v1/licenses/${license.id}/renew`, { token, body: {} }), 200);
    expect(renewed.license.expiresAt).toBe(termEnd("annual", null, new Date(payload.expiresAt))!.toISOString());
  });

  it("liberar el equipo permite activar en hardware nuevo y deja fuera al anterior", async () => {
    const { token } = await firstAdmin();
    const { license, activationCode } = await createLicense(token);
    const old = await newDevice();
    await json(await activate(license.id, activationCode, old), 200);
    const reset = await json(await call("POST", `/admin/v1/licenses/${license.id}/reset-activation`, { token }), 200);
    const replacement = await newDevice("ES256");
    await json(await activate(license.id, reset.activationCode, replacement, { kind: "tpm" }), 200);
    expect((await renew(old, license.id)).status).toBe(401);
    await json(await renew(replacement, license.id, {}), 200);
  });

  it("no repite siteId y valida los días de prueba", async () => {
    const { token } = await firstAdmin();
    const { license } = await createLicense(token);
    expect((await call("POST", "/admin/v1/licenses", { token, body: { customer: "x", branchName: "y", siteId: license.siteId, plan: "monthly", features: [], limits: { maxUsers: 1, maxTables: 1 } } })).status).toBe(409);
    expect((await call("POST", "/admin/v1/licenses", { token, body: { customer: "x", branchName: "y", siteId: "otra", plan: "trial", features: [], limits: { maxUsers: 1, maxTables: 1 } } })).status).toBe(400);
  });
});

describe("plazos", () => {
  it("el mes se ajusta al último día del mes siguiente", () => {
    expect(termEnd("monthly", null, new Date("2026-01-31T10:00:00Z"))!.toISOString()).toBe("2026-02-28T10:00:00.000Z");
    expect(termEnd("annual", null, new Date("2028-02-29T00:00:00Z"))!.toISOString()).toBe("2029-02-28T00:00:00.000Z");
  });
});
