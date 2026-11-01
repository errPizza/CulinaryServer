import { env } from "cloudflare:workers";
import { describe, expect, it } from "vitest";
import { activatedBranch, call, createLicense, firstAdmin, json, newDevice, signed, signedBranch } from "./helpers";

const fault = (overrides: Record<string, unknown> = {}) => ({
  fingerprint: "a".repeat(64), source: "api", severity: "error", what: "POST /api/action: NullReferenceException", affected: "La operación payment.add no se pudo confirmar",
  detail: "at MesaNexo.Api.BranchService.Action()", context: { route: "/api/action", operationId: "op-1" }, version: "0.3.3", platform: "linux-x64", occurrences: 2,
  firstAt: "2026-11-01T10:00:00.1234567+00:00", lastAt: "2026-11-01T10:05:00.1234567+00:00", ...overrides
});

async function setup() {
  const { token } = await firstAdmin();
  return { token, ...(await activatedBranch(token)) };
}

describe("fallos", () => {
  it("llega al panel qué falló, qué afectó y lo necesario para revisarlo", async () => {
    const { token, ...branch } = await setup();
    expect(await json(await signedBranch(branch, "POST", "/branch/v1/faults", { faults: [fault()] }), 200)).toEqual({ received: 1 });
    const { faults } = await json(await call("GET", "/admin/v1/faults?status=open", { token }), 200);
    expect(faults).toEqual([expect.objectContaining({ customer: "Restaurante La Plaza", siteId: branch.license.siteId, what: fault().what, affected: fault().affected, detail: fault().detail, context: fault().context, version: "0.3.3", platform: "linux-x64", occurrences: 2, status: "open" })]);
  });

  it("repetir un fallo lo cuenta, y si vuelve tras resolverlo se abre otra vez", async () => {
    const { token, ...branch } = await setup();
    await json(await signedBranch(branch, "POST", "/branch/v1/faults", { faults: [fault()] }), 200);
    await json(await signedBranch(branch, "POST", "/branch/v1/faults", { faults: [fault({ occurrences: 3, version: "0.3.4", lastAt: "2026-11-01T11:00:00.0000000+00:00" })] }), 200);
    const [counted] = (await json(await call("GET", "/admin/v1/faults", { token }), 200)).faults;
    expect(counted).toMatchObject({ occurrences: 5, version: "0.3.4", lastAt: "2026-11-01T11:00:00.0000000+00:00" });

    expect((await json(await call("POST", `/admin/v1/faults/${counted.id}/resolve`, { token, body: {} }), 200)).fault).toMatchObject({ status: "resolved" });
    expect((await json(await call("GET", "/admin/v1/faults?status=open", { token }), 200)).faults).toEqual([]);

    await json(await signedBranch(branch, "POST", "/branch/v1/faults", { faults: [fault({ occurrences: 1 })] }), 200);
    expect((await json(await call("GET", "/admin/v1/faults?status=open", { token }), 200)).faults).toEqual([expect.objectContaining({ id: counted.id, occurrences: 6, resolvedAt: null })]);
  });

  it("el panel puede reabrir un fallo y queda en la bitácora", async () => {
    const { token, ...branch } = await setup();
    await json(await signedBranch(branch, "POST", "/branch/v1/faults", { faults: [fault()] }), 200);
    const [{ id }] = (await json(await call("GET", "/admin/v1/faults", { token }), 200)).faults;
    await json(await call("POST", `/admin/v1/faults/${id}/resolve`, { token, body: {} }), 200);
    expect((await json(await call("POST", `/admin/v1/faults/${id}/reopen`, { token, body: {} }), 200)).fault).toMatchObject({ status: "open", resolvedBy: null });
    expect((await call("POST", "/admin/v1/faults/no-existe/resolve", { token, body: {} })).status).toBe(404);
    const { entries } = await json(await call("GET", "/admin/v1/audit", { token }), 200);
    expect(entries.map((e: any) => e.action)).toEqual(expect.arrayContaining(["fault.resolve", "fault.reopen"]));
  });

  it("con la licencia vencida el fallo se reporta igual", async () => {
    const { token, ...branch } = await setup();
    await env.DB.prepare("UPDATE license SET expires_at = ? WHERE id = ?").bind(new Date(Date.now() - 1000).toISOString(), branch.license.id).run();
    await json(await signedBranch(branch, "POST", "/branch/v1/faults", { faults: [fault()] }), 200);
    expect((await json(await call("GET", "/admin/v1/faults", { token }), 200)).faults).toHaveLength(1);
  });

  it("al llegar al límite sigue contando lo conocido pero no guarda fallos nuevos", async () => {
    const { token, ...branch } = await setup();
    await json(await signedBranch(branch, "POST", "/branch/v1/faults", { faults: [fault()] }), 200);
    await env.DB.batch(Array.from({ length: 499 }, (_, i) => env.DB.prepare("INSERT INTO fault (id, license_id, fingerprint, source, severity, what, affected, detail, context, version, platform, occurrences, first_at, last_at) VALUES (?, ?, ?, 'api', 'error', 'x', '', '', '{}', '0.3.3', 'linux-x64', 1, '2026-11-01', '2026-11-01')").bind(`relleno-${i}`, branch.license.id, String(i).padStart(64, "0"))));
    await json(await signedBranch(branch, "POST", "/branch/v1/faults", { faults: [fault(), fault({ fingerprint: "b".repeat(64) })] }), 200);
    const row = await env.DB.prepare("SELECT occurrences FROM fault WHERE license_id = ? AND fingerprint = ?").bind(branch.license.id, "a".repeat(64)).first<number>("occurrences");
    const added = await env.DB.prepare("SELECT COUNT(*) AS n FROM fault WHERE license_id = ? AND fingerprint = ?").bind(branch.license.id, "b".repeat(64)).first<number>("n");
    expect([row, added]).toEqual([4, 0]);
  });

  it("rechaza reportes mal formados, de quien no está activado y sin sesión de panel", async () => {
    const { token, ...branch } = await setup();
    expect((await signedBranch(branch, "POST", "/branch/v1/faults", { faults: [fault({ fingerprint: "corto" })] })).status).toBe(400);
    expect((await signedBranch(branch, "POST", "/branch/v1/faults", { faults: [] })).status).toBe(400);
    const { license } = await createLicense(token);
    expect((await signed("branch", await newDevice(), license.id, "POST", "/branch/v1/faults", { body: { faults: [fault()] } })).status).toBe(401);
    expect((await call("GET", "/admin/v1/faults")).status).toBe(401);
  });
});
