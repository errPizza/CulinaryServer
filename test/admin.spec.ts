import { env } from "cloudflare:workers";
import { describe, expect, it } from "vitest";
import { totpCode } from "../src/crypto";
import { call, challenge, enrollAdmin, firstAdmin, json, newDevice, PASSWORD, signed, signedAdmin, step } from "./helpers";

const login = (session: Awaited<ReturnType<typeof firstAdmin>>, password: string, totp: string, nonce?: string) =>
  signed("admin", session.device, session.username, "POST", "/admin/v1/login", { body: { password, totp }, nonce });

describe("panel de administrador", () => {
  it("da de alta al primer administrador con el código inicial y abre sesión con tres factores", async () => {
    const session = await firstAdmin();
    const me = await json(await call("GET", "/admin/v1/me", { token: session.token }), 200);
    expect(me.admin.username).toBe("proveedor");
  });

  it("no acepta el código inicial cuando ya hay un administrador activo", async () => {
    await firstAdmin();
    const device = await newDevice();
    const response = await call("POST", "/admin/v1/enroll", {
      body: { code: env.ADMIN_SETUP_CODE, username: "intruso", password: "otra contraseña larga", deviceName: "x", key: { alg: device.alg, spki: device.spki } },
    });
    expect((await json(response, 403)).error.code).toBe("forbidden");
  });

  it("no revela si un usuario existe a quien no tiene código de alta", async () => {
    await firstAdmin();
    const device = await newDevice();
    const response = await call("POST", "/admin/v1/enroll", {
      body: { code: "INVENTADO-INVENTADO-123", username: "proveedor", password: "otra contraseña larga", deviceName: "x", key: { alg: device.alg, spki: device.spki } },
    });
    expect((await json(response, 403)).error.code).toBe("forbidden");
  });

  it("agrega administradores solo con invitación firmada por un administrador en sesión", async () => {
    const owner = await firstAdmin();
    expect((await call("POST", "/admin/v1/invites", { token: owner.token })).status).toBe(401);
    const invite = await json(await signedAdmin(owner, "POST", "/admin/v1/invites"), 201);
    const second = await enrollAdmin(invite.code, "soporte");
    const admins = await json(await call("GET", "/admin/v1/admins", { token: second.token }), 200);
    expect(admins.admins.map((a: any) => a.username)).toEqual(["proveedor", "soporte"]);
    const reused = await call("POST", "/admin/v1/enroll", {
      body: { code: invite.code, username: "tercero", password: "otra contraseña larga", deviceName: "x", key: { alg: second.device.alg, spki: second.device.spki } },
    });
    expect(reused.status).toBe(403);
  });

  it("borrar un administrador pide la firma del dispositivo, no solo la sesión", async () => {
    const owner = await firstAdmin();
    const invite = await json(await signedAdmin(owner, "POST", "/admin/v1/invites"), 201);
    const second = await enrollAdmin(invite.code, "soporte");
    const { admins } = await json(await call("GET", "/admin/v1/admins", { token: owner.token }), 200);
    const ownerId = admins.find((a: any) => a.username === "proveedor").id;
    expect((await call("DELETE", `/admin/v1/admins/${ownerId}`, { token: second.token })).status).toBe(401);
    await json(await signedAdmin(second, "DELETE", `/admin/v1/admins/${ownerId}`), 200);
  });

  it("rechaza la contraseña correcta firmada por otro dispositivo", async () => {
    const session = await firstAdmin();
    const stranger = await newDevice();
    const response = await signed("admin", stranger, session.username, "POST", "/admin/v1/login", { body: { password: PASSWORD, totp: await totpCode(session.totpSecret, step() + 1) } });
    expect(response.status).toBe(401);
  });

  it("no deja reutilizar un código TOTP ni un reto ya usado", async () => {
    const session = await firstAdmin();
    expect((await login(session, PASSWORD, await totpCode(session.totpSecret, step() + 1))).status).toBe(401);

    const nonce = await challenge("admin", session.username);
    await login(session, "mal", "000000", nonce);
    expect((await login(session, "mal", "000000", nonce)).status).toBe(401);
  });

  it("un reto de una ruta o de otro sujeto no sirve", async () => {
    const session = await firstAdmin();
    const foreign = await challenge("admin", "otro-usuario");
    expect((await login(session, PASSWORD, "000000", foreign)).status).toBe(401);
    const branchNonce = await challenge("branch", session.username);
    expect((await login(session, PASSWORD, "000000", branchNonce)).status).toBe(401);
  });

  it("pedir muchos retos de un usuario no bloquea su alta ni su inicio de sesión", async () => {
    const device = await newDevice();
    const body = { code: env.ADMIN_SETUP_CODE, username: "proveedor", password: PASSWORD, deviceName: "x", key: { alg: device.alg, spki: device.spki } };
    const { totp } = await json(await call("POST", "/admin/v1/enroll", { body }), 201);
    for (let i = 0; i < 30; i++) await challenge("admin", "proveedor");
    await json(await signed("admin", device, "proveedor", "POST", "/admin/v1/enroll/confirm", { body: { totp: await totpCode(totp.secret, step()) } }), 200);
    for (let i = 0; i < 30; i++) await challenge("admin", "proveedor");
    await json(await signed("admin", device, "proveedor", "POST", "/admin/v1/login", { body: { password: PASSWORD, totp: await totpCode(totp.secret, step() + 1) } }), 200);
  });

  it("bloquea la cuenta tras cinco intentos fallidos con el dispositivo correcto", async () => {
    const session = await firstAdmin();
    for (let i = 0; i < 5; i++) expect((await login(session, "contraseña equivocada", "123456")).status).toBe(401);
    const locked = await login(session, PASSWORD, await totpCode(session.totpSecret, step() + 1));
    expect((await json(locked, 429)).error.code).toBe("rate_limited");
  });

  it("cierra la sesión y deja de aceptar el token", async () => {
    const session = await firstAdmin();
    await json(await call("POST", "/admin/v1/logout", { token: session.token }), 200);
    expect((await call("GET", "/admin/v1/me", { token: session.token })).status).toBe(401);
  });

  it("publica la llave pública raíz que se aprovisiona en las sucursales", async () => {
    const session = await firstAdmin();
    const root = await json(await call("GET", "/admin/v1/root-key", { token: session.token }), 200);
    expect(root.spki).toBe(env.ROOT_PUBLIC_SPKI);
    expect(root.pem).toContain("BEGIN PUBLIC KEY");
  });

  it("registra en la auditoría las acciones del panel", async () => {
    const session = await firstAdmin();
    const { entries } = await json(await call("GET", "/admin/v1/audit", { token: session.token }), 200);
    expect(entries.map((e: any) => e.action)).toEqual(["admin.login", "admin.confirm", "admin.enroll"]);
    expect((await call("GET", "/admin/v1/audit?before=abc", { token: session.token })).status).toBe(400);
  });
});

describe("cualquier otro uso", () => {
  it("responde 404 fuera de las rutas del panel y de la sucursal", async () => {
    expect((await call("GET", "/")).status).toBe(404);
    expect((await call("GET", "/branch/v1/nada")).status).toBe(404);
  });

  it("pide sesión en todas las rutas privadas del panel", async () => {
    for (const path of ["/admin/v1/licenses", "/admin/v1/tickets", "/admin/v1/registry", "/admin/v1/releases", "/admin/v1/admins"]) {
      expect((await call("GET", path)).status).toBe(401);
    }
  });

  it("solo permite CORS desde los orígenes configurados", async () => {
    const allowed = await call("OPTIONS", "/admin/v1/challenges", { headers: { origin: "https://panel.test", "access-control-request-method": "POST" } });
    expect(allowed.headers.get("access-control-allow-origin")).toBe("https://panel.test");
    const other = await call("OPTIONS", "/admin/v1/challenges", { headers: { origin: "https://otro.test", "access-control-request-method": "POST" } });
    expect(other.headers.get("access-control-allow-origin")).toBeNull();
    const branch = await call("OPTIONS", "/branch/v1/challenges", { headers: { origin: "https://panel.test", "access-control-request-method": "POST" } });
    expect(branch.headers.get("access-control-allow-origin")).toBeNull();
  });

  it("rechaza cuerpos grandes y campos desconocidos", async () => {
    const big = await call("POST", "/admin/v1/challenges", { body: { username: "x".repeat(70_000) } });
    expect(big.status).toBe(413);
    const extra = await call("POST", "/admin/v1/challenges", { body: { username: "proveedor", otro: 1 } });
    expect(extra.status).toBe(400);
  });
});
