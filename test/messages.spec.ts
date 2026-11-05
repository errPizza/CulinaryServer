import { describe, expect, it } from "vitest";
import { totpCode } from "../src/crypto";
import { activatedBranch, call, firstAdmin, json, PASSWORD, signedAdmin, signedBranch, step, type AdminSession } from "./helpers";

async function ownerSession(admin: AdminSession, tenantId: string, email: string, role = "owner", licenseIds: string[] = []) {
  const { code } = await json(await signedAdmin(admin, "POST", "/admin/v1/owner-invites", { tenantId, email, role, licenseIds }), 201);
  const enrolled = await json(await call("POST", "/owner/v1/enroll", { body: { code, password: PASSWORD } }), 201);
  const secret = enrolled.totp.secret as string;
  await json(await call("POST", "/owner/v1/enroll/confirm", { body: { email, password: PASSWORD, totp: await totpCode(secret, step()) } }), 200);
  return (await json(await call("POST", "/owner/v1/login", { body: { email, password: PASSWORD, totp: await totpCode(secret, step() + 1) } }), 200)).token as string;
}

async function business() {
  const admin = await firstAdmin();
  const centro = await activatedBranch(admin.token, { tenantId: "grupo-plaza", branchName: "Centro", tier: "pro" });
  const norte = await activatedBranch(admin.token, { tenantId: "grupo-plaza", branchName: "Norte", tier: "lite" });
  const owner = await ownerSession(admin, "grupo-plaza", "dueno@plaza.mx");
  return { admin, centro, norte, owner };
}

const send = (token: string, body: unknown) => call("POST", "/owner/v1/messages/branches", { token, body });
const read = async (path: string, token: string) => json(await call("GET", path, { token }), 200);

describe("mensajes con las sucursales", () => {
  it("el dueño escribe a una sucursal, la sucursal lo lee y contesta, y el panel lo marca sin leer", async () => {
    const { centro, norte, owner } = await business();
    await json(await send(owner, { licenseIds: [centro.license.id], message: "Hoy llega el gas a las 5" }), 201);

    const { messages } = await json(await signedBranch(centro, "GET", "/branch/v1/owner-messages"), 200);
    expect(messages).toEqual([expect.objectContaining({ author: "owner", name: "Dueño · dueno@plaza.mx", body: "Hoy llega el gas a las 5", toAll: false })]);
    expect((await json(await signedBranch(norte, "GET", "/branch/v1/owner-messages"), 200)).messages).toEqual([]);

    // Sent twice with the same local id, kept once.
    for (let i = 0; i < 2; i++) await json(await signedBranch(centro, "POST", "/branch/v1/owner-messages", { id: "local-1", name: "Ana (gerente)", message: "Enterado" }), 201);

    const list = await read("/owner/v1/messages", owner);
    expect(list.branches.find((b: any) => b.licenseId === centro.license.id)).toMatchObject({ unread: 1, last: { author: "branch", name: "Ana (gerente)", body: "Enterado" } });
    expect(list.branches.find((b: any) => b.licenseId === norte.license.id)).toMatchObject({ unread: 0, last: null });

    const thread = await read(`/owner/v1/messages/branches/${centro.license.id}`, owner);
    expect(thread.messages.map((m: any) => m.author)).toEqual(["owner", "branch"]);
    expect((await read("/owner/v1/messages", owner)).branches.find((b: any) => b.licenseId === centro.license.id).unread).toBe(0);
  });

  it("un mensaje a todas llega a cada sucursal marcado como general, sin importar el plan", async () => {
    const { centro, norte, owner } = await business();
    expect((await json(await send(owner, { licenseIds: [], message: "Junta el lunes" }), 201)).sent).toBe(2);
    for (const branch of [centro, norte]) {
      expect((await json(await signedBranch(branch, "GET", "/branch/v1/owner-messages"), 200)).messages).toEqual([expect.objectContaining({ body: "Junta el lunes", toAll: true })]);
    }
  });

  it("un gerente sólo escribe a sus sucursales", async () => {
    const { admin, centro, norte } = await business();
    const manager = await ownerSession(admin, "grupo-plaza", "gerente@plaza.mx", "manager", [centro.license.id]);
    expect((await send(manager, { licenseIds: [norte.license.id], message: "Hola" })).status).toBe(404);
    expect((await call("GET", `/owner/v1/messages/branches/${norte.license.id}`, { token: manager })).status).toBe(404);
    expect((await json(await send(manager, { licenseIds: [], message: "Hola" }), 201)).sent).toBe(1);
    expect((await json(await signedBranch(norte, "GET", "/branch/v1/owner-messages"), 200)).messages).toEqual([]);
  });

  it("otra empresa no escribe a estas sucursales", async () => {
    const { admin, centro } = await business();
    await activatedBranch(admin.token, { tenantId: "otra", branchName: "Lejos" });
    const stranger = await ownerSession(admin, "otra", "otro@otra.mx");
    expect((await send(stranger, { licenseIds: [centro.license.id], message: "Hola" })).status).toBe(404);
  });
});

describe("soporte desde el panel", () => {
  it("el dueño pregunta, el soporte contesta en su bandeja y la sucursal no lo ve", async () => {
    const { admin, centro, owner } = await business();
    const { ticket } = await json(await call("POST", "/owner/v1/support", { token: owner, body: { licenseId: centro.license.id, subject: "Factura", message: "¿Cuándo llega mi factura?" } }), 201);
    expect(ticket).toMatchObject({ ownerEmail: "dueno@plaza.mx", messages: [{ author: "owner" }] });

    const inbox = await json(await call("GET", "/admin/v1/tickets?status=open", { token: admin.token }), 200);
    expect(inbox.tickets).toEqual([expect.objectContaining({ id: ticket.id, branchName: "Centro", ownerEmail: "dueno@plaza.mx" })]);
    await json(await call("POST", `/admin/v1/tickets/${ticket.id}/messages`, { token: admin.token, body: { message: "Mañana" } }), 201);

    const { support } = await read("/owner/v1/messages", owner);
    expect(support).toEqual([expect.objectContaining({ id: ticket.id, status: "answered" })]);
    expect(support[0].messages.map((m: any) => m.author)).toEqual(["owner", "admin"]);
    await json(await call("POST", `/owner/v1/support/${ticket.id}/messages`, { token: owner, body: { message: "Gracias" } }), 201);

    expect((await json(await signedBranch(centro, "GET", "/branch/v1/tickets"), 200)).tickets).toEqual([]);
    expect((await signedBranch(centro, "POST", `/branch/v1/tickets/${ticket.id}/messages`, { message: "Intruso" })).status).toBe(404);
  });

  it("sin elegir sucursal queda en la primera, y otra persona no lo lee", async () => {
    const { admin, centro, owner } = await business();
    const { ticket } = await json(await call("POST", "/owner/v1/support", { token: owner, body: { subject: "Duda", message: "Hola" } }), 201);
    expect(ticket.licenseId).toBe(centro.license.id);
    const manager = await ownerSession(admin, "grupo-plaza", "gerente@plaza.mx", "manager", [centro.license.id]);
    expect((await call("GET", `/owner/v1/support/${ticket.id}`, { token: manager })).status).toBe(404);
    expect((await call("POST", `/owner/v1/support/${ticket.id}/messages`, { token: manager, body: { message: "x" } })).status).toBe(404);
    expect((await read("/owner/v1/messages", manager)).support).toEqual([]);
  });
});
