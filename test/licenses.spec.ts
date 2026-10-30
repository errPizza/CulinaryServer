import { env } from "cloudflare:workers";
import { describe, expect, it } from "vitest";
import { DAY_MS, termEnd } from "../src/catalog";
import { nextExpiry, type LicenseRow } from "../src/licenses";
import { activate, activatedBranch, call, challenge, createLicense, firstAdmin, fingerprint, json, newDevice, signed, verifyJws, type Device } from "./helpers";

const renew = (device: Device, licenseId: string, body: unknown = { fingerprint }, nonce?: string) =>
  signed("branch", device, licenseId, "POST", "/branch/v1/license/renew", { body, nonce });

const expire = (licenseId: string) => env.DB.prepare("UPDATE license SET expires_at = ? WHERE id = ?").bind(new Date(Date.now() - 1000).toISOString(), licenseId).run();

describe("activación", () => {
  it("liga la licencia a la llave del equipo y entrega la licencia firmada por la raíz", async () => {
    const { token } = await firstAdmin();
    const { license, activationCode } = await createLicense(token);
    const device = await newDevice();
    const { license: jws } = await json(await activate(license, activationCode, device), 200);
    const payload = await verifyJws(jws, "culinary-license+jws");
    expect(payload).toMatchObject({
      v: 1,
      licenseId: license.id,
      siteId: license.siteId,
      plan: "monthly",
      tier: "lite",
      addons: [],
      status: "active",
      features: ["printing", "reservations"],
      limits: { maxUsers: 15, maxTables: 30, maxTerminals: 2 },
      key: { alg: "Ed25519", spki: device.spki },
      binding: "fingerprint",
    });
    expect(Date.parse(payload.offlineUntil) - Date.parse(payload.validatedAt)).toBe(7 * DAY_MS);
    expect(payload.expiresAt).toBe(termEnd("monthly", null, new Date(payload.activatedAt))!.toISOString());
  });

  it("acepta la llave ES256 de un TPM y rechaza una Ed25519 declarada como TPM", async () => {
    const { token } = await firstAdmin();
    const { license, activationCode } = await createLicense(token);
    expect((await activate(license, activationCode, await newDevice("Ed25519"), { kind: "tpm" })).status).toBe(400);
    const tpm = await newDevice("ES256");
    const { license: jws } = await json(await activate(license, activationCode, tpm, { kind: "tpm" }), 200);
    expect((await verifyJws(jws, "culinary-license+jws")).binding).toBe("tpm");
    await json(await renew(tpm, license.id, {}), 200);
  });

  it("no deja activar dos veces con el mismo código", async () => {
    const { token } = await firstAdmin();
    const { license, activationCode } = await createLicense(token);
    await json(await activate(license, activationCode, await newDevice()), 200);
    const second = await activate(license, activationCode, await newDevice());
    expect((await json(second, 403)).error.code).toBe("activation_rejected");
  });

  it("rechaza un código equivocado y conserva el bueno", async () => {
    const { token } = await firstAdmin();
    const { license, activationCode } = await createLicense(token);
    expect((await activate(license, "AAAAA-AAAAA-AAAAA-AAAAA", await newDevice())).status).toBe(403);
    await json(await activate(license, activationCode.toLowerCase().replace(/-/g, " "), await newDevice()), 200);
  });

  it("una sucursal con otro siteId no gasta el código ni liga su llave", async () => {
    const { token } = await firstAdmin();
    const { license, activationCode } = await createLicense(token);
    const wrong = await activate(license, activationCode, await newDevice(), undefined, "otra-sucursal");
    expect((await json(wrong, 409)).error.code).toBe("site_mismatch");
    expect((await json(await call("GET", `/admin/v1/licenses/${license.id}`, { token }), 200)).license.status).toBe("pending");
    await json(await activate(license, activationCode, await newDevice()), 200);
  });

  it("una activación rechazada por vencimiento no gasta el código", async () => {
    const { token } = await firstAdmin();
    const { license, activationCode } = await createLicense(token);
    await expire(license.id);
    expect((await json(await activate(license, activationCode, await newDevice()), 403)).error.code).toBe("license_expired");
    const row = await env.DB.prepare("SELECT activation_code_hash, key_spki FROM license WHERE id = ?").bind(license.id).first<Pick<LicenseRow, "activation_code_hash" | "key_spki">>();
    expect(row).toEqual({ activation_code_hash: expect.any(String), key_spki: null });
  });

  it("el plazo de prueba empieza al activar con los días elegidos en el panel", async () => {
    const { token } = await firstAdmin();
    const { license, activationCode } = await createLicense(token, { plan: "trial", trialDays: 14 });
    expect(license.expiresAt).toBeNull();
    const payload = await verifyJws((await json(await activate(license, activationCode, await newDevice()), 200)).license, "culinary-license+jws");
    expect(Date.parse(payload.expiresAt) - Date.parse(payload.activatedAt)).toBe(14 * DAY_MS);
  });

  it("la licencia permanente no tiene vencimiento", async () => {
    const { token } = await firstAdmin();
    const { license, activationCode } = await createLicense(token, { plan: "permanent" });
    const payload = await verifyJws((await json(await activate(license, activationCode, await newDevice()), 200)).license, "culinary-license+jws");
    expect(payload.expiresAt).toBeNull();
  });
});

describe("renovación", () => {
  async function activated() {
    const { token } = await firstAdmin();
    return { token, ...(await activatedBranch(token)) };
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
    await json(await renew(device, license.id, { fingerprint }, nonce), 200);
    expect((await renew(device, license.id, { fingerprint }, nonce)).status).toBe(401);

    const other = await createLicense(token);
    const foreign = await challenge("branch", other.license.id);
    expect((await renew(device, license.id, { fingerprint }, foreign)).status).toBe(401);
  });

  it("pedir muchos retos de una licencia no impide renovarla", async () => {
    const { license, device } = await activated();
    for (let i = 0; i < 30; i++) await challenge("branch", license.id);
    await json(await renew(device, license.id), 200);
  });

  it("una licencia vencida no se renueva y recibe el aviso firmado, ligado a su reto, para la pantalla de bloqueo", async () => {
    const { token, license, device } = await activated();
    await expire(license.id);
    const nonce = await challenge("branch", license.id);
    const error = (await json(await renew(device, license.id, { fingerprint }, nonce), 403)).error;
    expect(error.code).toBe("license_expired");
    expect(await verifyJws(error.notice, "culinary-license-status+jws")).toMatchObject({ licenseId: license.id, status: "expired", plan: "monthly", challenge: nonce, revision: 2 });

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
    const first = await verifyJws((await json(await activate(license, activationCode, device), 200)).license, "culinary-license+jws");
    await json(await call("PATCH", `/admin/v1/licenses/${license.id}`, { token, body: { features: ["multiBranch", "printing"], limits: { maxUsers: 40, maxTables: 80 } } }), 200);
    const next = await verifyJws((await json(await renew(device, license.id), 200)).license, "culinary-license+jws");
    expect(next.revision).toBeGreaterThan(first.revision);
    expect(next.features).toEqual(["multiBranch", "printing"]);
    expect(next.limits).toEqual({ maxUsers: 40, maxTables: 80, maxTerminals: 2 });
  });

  it("pasar de Lite a Pro con add-ons llega firmado y sube las terminales del nivel", async () => {
    const { token } = await firstAdmin();
    const { license, activationCode } = await createLicense(token, { addons: ["mobileOrdering"] });
    expect(license).toMatchObject({ tier: "lite", addons: ["mobileOrdering"], limits: { maxTerminals: 2 } });
    const device = await newDevice();
    await json(await activate(license, activationCode, device), 200);
    await json(await call("PATCH", `/admin/v1/licenses/${license.id}`, { token, body: { tier: "pro", addons: ["webOrdering", "deliveryHub", "webOrdering"] } }), 200);
    const pro = await verifyJws((await json(await renew(device, license.id), 200)).license, "culinary-license+jws");
    expect(pro).toMatchObject({ tier: "pro", addons: ["deliveryHub", "webOrdering"], limits: { maxTerminals: 10 } });
    await json(await call("PATCH", `/admin/v1/licenses/${license.id}`, { token, body: { limits: { maxUsers: 15, maxTables: 30, maxTerminals: 4 } } }), 200);
    expect((await verifyJws((await json(await renew(device, license.id), 200)).license, "culinary-license+jws")).limits.maxTerminals).toBe(4);
    expect((await call("PATCH", `/admin/v1/licenses/${license.id}`, { token, body: { tier: "gold" } })).status).toBe(400);
    expect((await call("PATCH", `/admin/v1/licenses/${license.id}`, { token, body: { addons: ["timbres"] } })).status).toBe(400);
  });

  it("rechaza funciones desconocidas y días de prueba fuera del plan de prueba", async () => {
    const { token } = await firstAdmin();
    const { license } = await createLicense(token);
    expect((await call("PATCH", `/admin/v1/licenses/${license.id}`, { token, body: { features: ["teletransporte"] } })).status).toBe(400);
    expect((await call("PATCH", `/admin/v1/licenses/${license.id}`, { token, body: { trialDays: 10 } })).status).toBe(400);
    expect((await call("GET", "/admin/v1/licenses?status=perdida", { token })).status).toBe(400);
  });

  it("renovar suma un periodo desde el vencimiento vigente", async () => {
    const { token } = await firstAdmin();
    const { license, activationCode } = await createLicense(token, { plan: "annual" });
    const payload = await verifyJws((await json(await activate(license, activationCode, await newDevice()), 200)).license, "culinary-license+jws");
    const renewed = await json(await call("POST", `/admin/v1/licenses/${license.id}/renew`, { token, body: {} }), 200);
    expect(renewed.license.expiresAt).toBe(termEnd("annual", null, new Date(payload.expiresAt))!.toISOString());
  });

  it("liberar el equipo permite activar en hardware nuevo y deja fuera al anterior", async () => {
    const { token } = await firstAdmin();
    const { license, activationCode } = await createLicense(token);
    const old = await newDevice();
    await json(await activate(license, activationCode, old), 200);
    const reset = await json(await call("POST", `/admin/v1/licenses/${license.id}/reset-activation`, { token }), 200);
    const replacement = await newDevice("ES256");
    await json(await activate(license, reset.activationCode, replacement, { kind: "tpm" }), 200);
    expect((await renew(old, license.id)).status).toBe(401);
    await json(await renew(replacement, license.id, {}), 200);
  });

  it("no repite siteId y valida los días de prueba", async () => {
    const { token } = await firstAdmin();
    const { license } = await createLicense(token);
    const base = { customer: "x", branchName: "y", plan: "monthly", tier: "pro", features: [], limits: { maxUsers: 1, maxTables: 1 } };
    expect((await json(await call("POST", "/admin/v1/licenses", { token, body: { ...base, siteId: license.siteId } }), 409)).error.code).toBe("conflict");
    expect((await call("POST", "/admin/v1/licenses", { token, body: { ...base, siteId: "otra", plan: "trial" } })).status).toBe(400);
  });
});

describe("plazos", () => {
  it("el mes se ajusta al último día del mes siguiente", () => {
    expect(termEnd("monthly", null, new Date("2026-01-31T10:00:00Z"))!.toISOString()).toBe("2026-02-28T10:00:00.000Z");
    expect(termEnd("annual", null, new Date("2028-02-29T00:00:00Z"))!.toISOString()).toBe("2029-02-28T00:00:00.000Z");
  });

  it("al editar, la fecha explícita gana y el cambio de plan reinicia el plazo solo si ya se activó", () => {
    const at = new Date("2026-05-10T00:00:00Z");
    const row = { plan: "monthly", activated_at: "2026-01-01T00:00:00.000Z", expires_at: "2026-06-01T00:00:00.000Z" } as LicenseRow;
    expect(nextExpiry(row, "permanent", null, { plan: "permanent" }, at)).toBeNull();
    expect(nextExpiry(row, "monthly", null, { expiresAt: "2027-01-01T00:00:00Z" }, at)).toBe("2027-01-01T00:00:00.000Z");
    expect(nextExpiry(row, "annual", null, { plan: "annual" }, at)).toBe("2027-05-10T00:00:00.000Z");
    expect(nextExpiry({ ...row, activated_at: null, expires_at: null }, "annual", null, { plan: "annual" }, at)).toBeNull();
    expect(nextExpiry(row, "monthly", null, {}, at)).toBe(row.expires_at);
  });
});

describe("siteId y eliminación desde el panel", () => {
  it("cambia el siteId mientras ningún equipo tiene la licencia y la activación usa el nuevo", async () => {
    const { token } = await firstAdmin();
    const { license, activationCode } = await createLicense(token);
    const other = await createLicense(token);
    expect((await json(await call("PATCH", `/admin/v1/licenses/${license.id}`, { token, body: { siteId: other.license.siteId } }), 409)).error.code).toBe("conflict");
    const moved = await json(await call("PATCH", `/admin/v1/licenses/${license.id}`, { token, body: { siteId: "sitio-nuevo" } }), 200);
    expect(moved.license.siteId).toBe("sitio-nuevo");
    expect((await activate(license, activationCode, await newDevice())).status).toBe(409);
    await json(await activate(moved.license, activationCode, await newDevice()), 200);
    expect((await call("PATCH", `/admin/v1/licenses/${license.id}`, { token, body: { siteId: "sitio-otro" } })).status).toBe(409);
    const reset = await json(await call("POST", `/admin/v1/licenses/${license.id}/reset-activation`, { token }), 200);
    expect((await json(await call("PATCH", `/admin/v1/licenses/${license.id}`, { token, body: { siteId: "sitio-otro" } }), 200)).license.siteId).toBe("sitio-otro");
    expect(reset.activationCode).toBeTruthy();
  });

  it("eliminar la quita del panel, bloquea a la sucursal y libera su siteId", async () => {
    const { token } = await firstAdmin();
    const { device, license } = await activatedBranch(token);
    await json(await call("DELETE", `/admin/v1/licenses/${license.id}`, { token }), 200);
    const { licenses } = await json(await call("GET", "/admin/v1/licenses", { token }), 200);
    expect(licenses.some((l: any) => l.id === license.id)).toBe(false);
    expect((await call("GET", `/admin/v1/licenses/${license.id}`, { token })).status).toBe(404);
    expect((await call("DELETE", `/admin/v1/licenses/${license.id}`, { token })).status).toBe(404);
    expect((await json(await renew(device, license.id), 403)).error.code).toBe("license_revoked");
    await createLicense(token, { siteId: license.siteId });
    const { entries } = await json(await call("GET", "/admin/v1/audit", { token }), 200);
    expect(entries.find((e: any) => e.action === "license.delete").detail.siteId).toBe(license.siteId);
  });
});
