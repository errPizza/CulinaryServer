import { env } from "cloudflare:workers";
import { describe, expect, it } from "vitest";
import { toBase64Url, totpCode } from "../src/crypto";
import { activate, activatedBranch, call, createLicense, FISCAL, firstAdmin, json, newDevice, PASSWORD, signedAdmin, signedBranch, step, verifyJws, type AdminSession } from "./helpers";

async function ownerSession(admin: AdminSession, tenantId: string, email: string, role = "owner", licenseIds: string[] = []) {
  const { code } = await json(await signedAdmin(admin, "POST", "/admin/v1/owner-invites", { tenantId, email, role, licenseIds }), 201);
  const enrolled = await json(await call("POST", "/owner/v1/enroll", { body: { code, password: PASSWORD } }), 201);
  const secret = enrolled.totp.secret as string;
  await json(await call("POST", "/owner/v1/enroll/confirm", { body: { email, password: PASSWORD, totp: await totpCode(secret, step()) } }), 200);
  return (await json(await call("POST", "/owner/v1/login", { body: { email, password: PASSWORD, totp: await totpCode(secret, step() + 1) } }), 200)).token as string;
}

const create = (token: string, fiscal: unknown) => call("POST", "/admin/v1/licenses", { token, body: { customer: "x", branchName: "y", siteId: `s-${crypto.randomUUID().slice(0, 8)}`, plan: "monthly", tier: "lite", features: [], limits: { maxUsers: 1, maxTables: 1 }, fiscal } });

async function intakeKey() {
  const pair = (await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"])) as CryptoKeyPair;
  return toBase64Url(new Uint8Array((await crypto.subtle.exportKey("spki", pair.publicKey)) as ArrayBuffer));
}

const envelope = { v: 1, epk: "A".repeat(120), salt: "B".repeat(43), iv: "C".repeat(16), ct: "D".repeat(400) };

describe("datos fiscales de la licencia", () => {
  it("no crea una licencia sin RFC, razón social, código postal y régimen válidos", async () => {
    const { token } = await firstAdmin();
    const issues = async (fiscal: unknown) => (await json(await create(token, fiscal), 400)).error;
    expect((await call("POST", "/admin/v1/licenses", { token, body: { customer: "x", branchName: "y", siteId: "sin-fiscal", plan: "monthly", tier: "lite", features: [], limits: { maxUsers: 1, maxTables: 1 } } })).status).toBe(400);
    for (const fiscal of [
      { ...FISCAL, rfc: "EKU9003173C8" }, // dígito verificador
      { ...FISCAL, rfc: "EKU9013173C9" }, // fecha 90-13-17
      { ...FISCAL, rfc: "XAXX010101000" },
      { ...FISCAL, name: "ESCUELA KEMPER URGATE S.A. DE C.V." },
      { ...FISCAL, name: "Escuela Kemper SA de CV" },
      { ...FISCAL, postalCode: "00123" },
      { ...FISCAL, regime: "999" },
      { ...FISCAL, regime: "612" }, // física en una persona moral
      { ...FISCAL, rfc: "CACX7605101P8", regime: "616" }, // sin obligaciones no factura ventas
    ]) await issues(fiscal);
    // Nothing half-written stays behind.
    expect(await env.DB.prepare("SELECT COUNT(*) AS n FROM license WHERE fiscal_rfc IS NULL").first("n")).toBe(0);
  });

  it("normaliza la razón social a mayúsculas y la firma dentro de la licencia", async () => {
    const { token } = await firstAdmin();
    const { license, activationCode } = await json(await create(token, { ...FISCAL, name: "  escuela   kemper urgate " }), 201);
    expect(license).toMatchObject({ fiscal: { ...FISCAL, name: "ESCUELA KEMPER URGATE" }, fiscalComplete: true });
    const { license: jws } = await json(await activate(license, activationCode, await newDevice()), 200);
    expect((await verifyJws(jws, "culinary-license+jws")).fiscal).toEqual(FISCAL);
  });

  it("una licencia anterior sin datos fiscales sigue validando, pero no se activa ni recibe código nuevo", async () => {
    const admin = await firstAdmin();
    const running = await activatedBranch(admin.token);
    const { license, activationCode } = await createLicense(admin.token);
    await env.DB.prepare("UPDATE license SET fiscal_rfc = NULL WHERE id IN (?, ?)").bind(running.license.id, license.id).run();

    await json(await signedBranch(running, "POST", "/branch/v1/license/renew", { fingerprint: { board: "a".repeat(64), disk: "b".repeat(64), mac: "c".repeat(64) } }), 200);
    expect((await json(await activate(license, activationCode, await newDevice()), 409)).error.code).toBe("fiscal_incomplete");
    expect((await json(await call("POST", `/admin/v1/licenses/${running.license.id}/reset-activation`, { token: admin.token, body: { reason: "cambio de equipo" } }), 409)).error.code).toBe("fiscal_incomplete");

    const { license: fixed } = await json(await call("PATCH", `/admin/v1/licenses/${license.id}`, { token: admin.token, body: { fiscal: FISCAL } }), 200);
    expect(fixed.fiscalComplete).toBe(true);
    await json(await activate(license, activationCode, await newDevice()), 200);
  });
});

describe("sellos del dueño hacia la sucursal", () => {
  async function business() {
    const admin = await firstAdmin();
    const centro = await activatedBranch(admin.token, { tenantId: "grupo-csd", branchName: "Centro" });
    const owner = await ownerSession(admin, "grupo-csd", "dueno@csd.mx");
    const manager = await ownerSession(admin, "grupo-csd", "gerente@csd.mx", "manager", [centro.license.id]);
    return { admin, centro, owner, manager };
  }

  it("sólo el dueño ve y envía sellos; un gerente recibe 403", async () => {
    const { centro, owner, manager } = await business();
    expect((await json(await call("GET", "/owner/v1/fiscal", { token: manager }), 403)).error.code).toBe("forbidden");
    expect((await call("POST", `/owner/v1/fiscal/${centro.license.id}/csd`, { token: manager, body: { id: crypto.randomUUID(), intakeSha256: "0".repeat(64), envelope } })).status).toBe(403);
    const { branches } = await json(await call("GET", "/owner/v1/fiscal", { token: owner }), 200);
    expect(branches).toEqual([expect.objectContaining({ licenseId: centro.license.id, business: FISCAL, intake: null, csd: { loaded: false }, last: null })]);
  });

  it("el sobre viaja a la sucursal que registró la llave y sólo queda el resultado", async () => {
    const { centro, owner } = await business();
    const id = crypto.randomUUID();
    const post = (body: unknown) => call("POST", `/owner/v1/fiscal/${centro.license.id}/csd`, { token: owner, body });

    expect((await json(await post({ id, intakeSha256: "0".repeat(64), envelope }), 409)).error.code).toBe("intake_missing");
    const { sha256 } = await json(await signedBranch(centro, "PUT", "/branch/v1/fiscal/intake-key", { spki: await intakeKey() }), 200);
    expect((await json(await post({ id, intakeSha256: "0".repeat(64), envelope }), 409)).error.code).toBe("intake_changed");
    await json(await post({ id, intakeSha256: sha256, envelope }), 202);

    const { submissions } = await json(await signedBranch(centro, "GET", "/branch/v1/fiscal/submissions"), 200);
    expect(submissions).toEqual([expect.objectContaining({ id, intakeSha256: sha256, envelope })]);

    const verdict = { status: "loaded", rfc: FISCAL.rfc, serial: "30001000000500003416", notBefore: "2023-05-18T11:43:51.000Z", notAfter: "2027-05-18T11:43:51.000Z" };
    for (let i = 0; i < 2; i++) await json(await signedBranch(centro, "POST", `/branch/v1/fiscal/submissions/${id}/result`, verdict), 200);
    expect((await json(await signedBranch(centro, "POST", `/branch/v1/fiscal/submissions/${id}/result`, { status: "rejected", message: "otra" }), 409)).error.code).toBe("conflict");

    const stored = await env.DB.prepare("SELECT envelope, status FROM fiscal_submission WHERE id = ?").bind(id).first();
    expect(stored).toEqual({ envelope: null, status: "loaded" });
    const { branches } = await json(await call("GET", "/owner/v1/fiscal", { token: owner }), 200);
    expect(branches[0].csd).toEqual({ loaded: true, rfc: FISCAL.rfc, serial: verdict.serial, notBefore: verdict.notBefore, notAfter: verdict.notAfter, loadedAt: expect.any(String) });
    expect((await json(await signedBranch(centro, "GET", "/branch/v1/fiscal/submissions"), 200)).submissions).toEqual([]);
    // The panel's audit names who sent what to which branch, never the envelope.
    const { results } = await env.DB.prepare("SELECT action, detail FROM audit WHERE target = ? AND action LIKE 'fiscal.%' ORDER BY id").bind(centro.license.id).all<{ action: string; detail: string }>();
    expect(results.map((r) => r.action)).toEqual(["fiscal.csd.submit", "fiscal.csd.loaded"]);
    expect(JSON.stringify(results)).not.toContain(envelope.ct);
  });

  it("un envío nuevo reemplaza al pendiente y una llave nueva invalida los sobres viejos", async () => {
    const { centro, owner } = await business();
    const first = await json(await signedBranch(centro, "PUT", "/branch/v1/fiscal/intake-key", { spki: await intakeKey() }), 200);
    const a = crypto.randomUUID(), b = crypto.randomUUID();
    await json(await call("POST", `/owner/v1/fiscal/${centro.license.id}/csd`, { token: owner, body: { id: a, intakeSha256: first.sha256, envelope } }), 202);
    await json(await call("POST", `/owner/v1/fiscal/${centro.license.id}/csd`, { token: owner, body: { id: b, intakeSha256: first.sha256, envelope } }), 202);
    expect((await json(await signedBranch(centro, "GET", "/branch/v1/fiscal/submissions"), 200)).submissions.map((s: any) => s.id)).toEqual([b]);

    await json(await signedBranch(centro, "PUT", "/branch/v1/fiscal/intake-key", { spki: await intakeKey() }), 200);
    expect((await json(await signedBranch(centro, "GET", "/branch/v1/fiscal/submissions"), 200)).submissions).toEqual([]);
    const rows = await env.DB.prepare("SELECT status, envelope FROM fiscal_submission WHERE id IN (?, ?) ORDER BY created_at").bind(a, b).all();
    expect(rows.results).toEqual([{ status: "expired", envelope: null }, { status: "expired", envelope: null }]);
  });

  it("un dueño de otro negocio no alcanza la sucursal", async () => {
    const { admin, centro } = await business();
    await activatedBranch(admin.token, { tenantId: "ajeno" });
    const stranger = await ownerSession(admin, "ajeno", "otro@ajeno.mx");
    expect((await call("POST", `/owner/v1/fiscal/${centro.license.id}/csd`, { token: stranger, body: { id: crypto.randomUUID(), intakeSha256: "0".repeat(64), envelope } })).status).toBe(404);
  });
});
