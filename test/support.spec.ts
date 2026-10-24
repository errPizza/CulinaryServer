import { env } from "cloudflare:workers";
import { describe, expect, it } from "vitest";
import { activatedBranch, call, createLicense, firstAdmin, json, newDevice, signed, signedBranch } from "./helpers";

async function setup() {
  const { token } = await firstAdmin();
  return { token, ...(await activatedBranch(token, { tenantId: "grupo-plaza" })) };
}

describe("soporte", () => {
  it("la sucursal abre un ticket, el panel responde y la sucursal ve la respuesta", async () => {
    const { token, ...branch } = await setup();
    const { ticket } = await json(await signedBranch(branch, "POST", "/branch/v1/tickets", { subject: "No imprime", message: "La impresora de cocina no responde" }), 201);

    const inbox = await json(await call("GET", "/admin/v1/tickets?status=open", { token }), 200);
    expect(inbox.tickets).toEqual([expect.objectContaining({ id: ticket.id, customer: "Restaurante La Plaza", siteId: branch.license.siteId, status: "open" })]);

    await json(await call("POST", `/admin/v1/tickets/${ticket.id}/messages`, { token, body: { message: "Reinicia el servicio de impresión" } }), 201);
    const { tickets } = await json(await signedBranch(branch, "GET", "/branch/v1/tickets"), 200);
    expect(tickets[0].status).toBe("answered");
    expect(tickets[0].messages.map((m: any) => m.author)).toEqual(["branch", "admin"]);

    await json(await signedBranch(branch, "POST", `/branch/v1/tickets/${ticket.id}/messages`, { message: "Ya funciona" }), 201);
    expect((await json(await call("GET", `/admin/v1/tickets/${ticket.id}`, { token }), 200)).ticket.status).toBe("open");
    expect((await json(await call("POST", `/admin/v1/tickets/${ticket.id}/close`, { token }), 200)).ticket.status).toBe("closed");
  });

  it("con la licencia vencida la sucursal pide la renovación y lee la respuesta", async () => {
    const { token, ...branch } = await setup();
    await env.DB.prepare("UPDATE license SET expires_at = ? WHERE id = ?").bind(new Date(Date.now() - 1000).toISOString(), branch.license.id).run();
    const { ticket } = await json(await signedBranch(branch, "POST", "/branch/v1/tickets", { subject: "Renovación", message: "Se venció" }), 201);
    await json(await call("POST", `/admin/v1/tickets/${ticket.id}/messages`, { token, body: { message: "Listo" } }), 201);
    expect((await json(await signedBranch(branch, "GET", "/branch/v1/tickets"), 200)).tickets[0].messages).toHaveLength(2);
  });

  it("una sucursal no ve ni contesta tickets de otra", async () => {
    const { token, ...branch } = await setup();
    const { ticket } = await json(await signedBranch(branch, "POST", "/branch/v1/tickets", { subject: "Duda", message: "Hola" }), 201);
    const other = await activatedBranch(token);
    expect((await signedBranch(other, "POST", `/branch/v1/tickets/${ticket.id}/messages`, { message: "Intruso" })).status).toBe(404);
    expect((await json(await signedBranch(other, "GET", "/branch/v1/tickets"), 200)).tickets).toEqual([]);
  });

  it("sin activar no hay tickets", async () => {
    const { token } = await setup();
    const { license } = await createLicense(token);
    expect((await signed("branch", await newDevice(), license.id, "POST", "/branch/v1/tickets", { body: { subject: "x", message: "y" } })).status).toBe(401);
  });
});

describe("registro de sucursales para la central", () => {
  it("la sucursal registra la huella de su certificado mTLS y el panel la lista por empresa", async () => {
    const { token, ...branch } = await setup();
    const certificateSha256 = "e".repeat(64);
    await json(await signedBranch(branch, "PUT", "/branch/v1/registry", { centralCertificateSha256: certificateSha256 }), 200);
    const { branches } = await json(await call("GET", "/admin/v1/registry?tenantId=grupo-plaza", { token }), 200);
    expect(branches).toEqual([
      expect.objectContaining({ tenantId: "grupo-plaza", branchId: branch.license.id, siteId: branch.license.siteId, slug: branch.license.siteId, certificateSha256, licenseStatus: "active" }),
    ]);
  });

  it("no deja que dos sucursales registren el mismo certificado", async () => {
    const { token, ...branch } = await setup();
    await json(await signedBranch(branch, "PUT", "/branch/v1/registry", { centralCertificateSha256: "f".repeat(64) }), 200);
    const other = await activatedBranch(token);
    expect((await json(await signedBranch(other, "PUT", "/branch/v1/registry", { centralCertificateSha256: "f".repeat(64) }), 409)).error.code).toBe("conflict");
  });
});
