import { describe, expect, it } from "vitest";
import { activate, call, createLicense, firstAdmin, json, newDevice, signed } from "./helpers";

async function setup() {
  const { token } = await firstAdmin();
  const { license, activationCode } = await createLicense(token, { tenantId: "grupo-plaza" });
  const device = await newDevice();
  await json(await activate(license.id, activationCode, device), 200);
  return { token, license, device };
}

describe("soporte", () => {
  it("la sucursal abre un ticket, el panel responde y la sucursal ve la respuesta", async () => {
    const { token, license, device } = await setup();
    const { ticket } = await json(await signed("branch", device, license.id, "POST", "/branch/v1/tickets", { subject: "No imprime", message: "La impresora de cocina no responde" }), 201);

    const inbox = await json(await call("GET", "/admin/v1/tickets?status=open", { token }), 200);
    expect(inbox.tickets).toEqual([expect.objectContaining({ id: ticket.id, customer: "Restaurante La Plaza", siteId: license.siteId, status: "open" })]);

    await json(await call("POST", `/admin/v1/tickets/${ticket.id}/messages`, { token, body: { message: "Reinicia el servicio de impresión" } }), 201);
    const { tickets } = await json(await signed("branch", device, license.id, "GET", "/branch/v1/tickets"), 200);
    expect(tickets[0].status).toBe("answered");
    expect(tickets[0].messages.map((m: any) => m.author)).toEqual(["branch", "admin"]);

    await json(await signed("branch", device, license.id, "POST", `/branch/v1/tickets/${ticket.id}/messages`, { message: "Ya funciona" }), 201);
    expect((await json(await call("GET", `/admin/v1/tickets/${ticket.id}`, { token }), 200)).ticket.status).toBe("open");
    expect((await json(await call("POST", `/admin/v1/tickets/${ticket.id}/close`, { token }), 200)).ticket.status).toBe("closed");
  });

  it("una sucursal no ve ni contesta tickets de otra", async () => {
    const { token, license, device } = await setup();
    const { ticket } = await json(await signed("branch", device, license.id, "POST", "/branch/v1/tickets", { subject: "Duda", message: "Hola" }), 201);
    const other = await createLicense(token);
    const otherDevice = await newDevice();
    await json(await activate(other.license.id, other.activationCode, otherDevice), 200);
    expect((await signed("branch", otherDevice, other.license.id, "POST", `/branch/v1/tickets/${ticket.id}/messages`, { message: "Intruso" })).status).toBe(404);
    expect((await json(await signed("branch", otherDevice, other.license.id, "GET", "/branch/v1/tickets"), 200)).tickets).toEqual([]);
  });

  it("sin activar no hay tickets", async () => {
    const { token } = await setup();
    const { license } = await createLicense(token);
    expect((await signed("branch", await newDevice(), license.id, "POST", "/branch/v1/tickets", { subject: "x", message: "y" })).status).toBe(401);
  });
});

describe("registro de sucursales para la central", () => {
  it("la sucursal registra la huella de su certificado mTLS y el panel la lista por empresa", async () => {
    const { token, license, device } = await setup();
    const certificateSha256 = "e".repeat(64);
    await json(await signed("branch", device, license.id, "PUT", "/branch/v1/registry", { centralCertificateSha256: certificateSha256 }), 200);
    const { branches } = await json(await call("GET", "/admin/v1/registry?tenantId=grupo-plaza", { token }), 200);
    expect(branches).toEqual([
      expect.objectContaining({ tenantId: "grupo-plaza", branchId: license.id, siteId: license.siteId, slug: license.siteId, certificateSha256, licenseStatus: "active" }),
    ]);
  });

  it("no deja que dos sucursales registren el mismo certificado", async () => {
    const { token, license, device } = await setup();
    await json(await signed("branch", device, license.id, "PUT", "/branch/v1/registry", { centralCertificateSha256: "f".repeat(64) }), 200);
    const other = await createLicense(token);
    const otherDevice = await newDevice();
    await json(await activate(other.license.id, other.activationCode, otherDevice), 200);
    expect((await signed("branch", otherDevice, other.license.id, "PUT", "/branch/v1/registry", { centralCertificateSha256: "f".repeat(64) })).status).toBe(409);
  });
});
