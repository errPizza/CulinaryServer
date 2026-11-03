import { env } from "cloudflare:workers";
import { describe, expect, it, vi } from "vitest";
import { totpCode } from "../src/crypto";
import { purgeExpired } from "../src/db";
import real from "./fixtures/stats-real.json";
import vector from "./fixtures/stats-vector.json";
import { activatedBranch, call, createLicense, firstAdmin, json, newDevice, PASSWORD, signed, signedAdmin, signedBranch, step, type AdminSession } from "./helpers";

const copy = <T>(value: T): T => JSON.parse(JSON.stringify(value));
const FULL = "from=2026-10-30&to=2026-10-31";

function revised(upload: typeof vector, revision: number, change: (day: any) => void = () => {}) {
  const next = copy(upload);
  for (const day of next.days) { day.revision = revision; change(day); }
  return next;
}

async function invited(admin: AdminSession, body: Record<string, unknown>) {
  return json(await signedAdmin(admin, "POST", "/admin/v1/owner-invites", body), 201);
}

/** The whole path of a person: invitation, password, authenticator, sign-in. */
async function ownerSession(admin: AdminSession, tenantId: string, email: string, role = "owner", licenseIds: string[] = []) {
  const { code } = await invited(admin, { tenantId, email, role, licenseIds });
  const enrolled = await json(await call("POST", "/owner/v1/enroll", { body: { code, password: PASSWORD } }), 201);
  const secret = enrolled.totp.secret as string;
  await json(await call("POST", "/owner/v1/enroll/confirm", { body: { email, password: PASSWORD, totp: await totpCode(secret, step()) } }), 200);
  const { token } = await json(await call("POST", "/owner/v1/login", { body: { email, password: PASSWORD, totp: await totpCode(secret, step() + 1) } }), 200);
  return { token, secret };
}

/** Pro by default, so each query shows everything; the Lite cases say so. */
async function business(tenantId: string, norteTier = "pro") {
  const admin = await firstAdmin();
  const centro = await activatedBranch(admin.token, { tenantId, branchName: "Centro", tier: "pro" });
  const norte = await activatedBranch(admin.token, { tenantId, branchName: "Norte", tier: norteTier });
  return { admin, centro, norte };
}

const read = async (path: string, token: string) => json(await call("GET", path, { token }), 200);

describe("resúmenes de la sucursal", () => {
  it("guarda una subida real de la sucursal", async () => {
    const { admin } = await business("grupo");
    const branch = await activatedBranch(admin.token, { tenantId: "grupo", tier: "pro" });
    const date = real.days[0]!.businessDate;
    expect(await json(await signedBranch(branch, "POST", "/branch/v1/stats", real), 200)).toEqual({ accepted: [date], ignored: [], rejected: [] });
    const { token } = await ownerSession(admin, "grupo", "dueno@ejemplo.mx");
    const { totals } = await read(`/owner/v1/stats/summary?from=${date}&to=${date}&branch=${branch.license.id}`, token);
    expect(totals).toMatchObject({ tickets: 1, net: 3000, averageTicket: 3000 });
  });

  it("una revisión menor o repetida nunca reemplaza lo guardado, en cualquier orden", async () => {
    const { admin, centro } = await business("grupo");
    const path = "/branch/v1/stats";
    expect((await json(await signedBranch(centro, "POST", path, revised(vector, 5)), 200)).accepted).toHaveLength(2);
    expect(await json(await signedBranch(centro, "POST", path, revised(vector, 5)), 200)).toMatchObject({ accepted: [], ignored: ["2026-10-30", "2026-10-31"] });
    const older = revised(vector, 3, (day) => { day.hours = []; day.channels = []; day.staff = []; day.products = []; day.payments = []; });
    expect(await json(await signedBranch(centro, "POST", path, older), 200)).toMatchObject({ accepted: [] });
    const { token } = await ownerSession(admin, "grupo", "dueno@ejemplo.mx");
    expect((await read(`/owner/v1/stats/summary?${FULL}`, token)).totals.net).toBe(85600);
    await json(await signedBranch(centro, "POST", path, revised(vector, 6, (day) => { if (day.businessDate === "2026-10-31") Object.assign(day, { hours: [], channels: [], staff: [], products: [], payments: [] }); })), 200);
    expect((await read(`/owner/v1/stats/summary?${FULL}`, token)).totals.net).toBe(59600);
  });

  it("un día que no cuadra no se publica, abre un fallo y no detiene a los demás", async () => {
    const { admin, centro } = await business("grupo");
    const broken = revised(vector, 1, (day) => { if (day.businessDate === "2026-10-30") day.staff[0].net += 1; });
    expect(await json(await signedBranch(centro, "POST", "/branch/v1/stats", broken), 200)).toEqual({ accepted: ["2026-10-31"], ignored: [], rejected: ["2026-10-30"] });
    const { faults } = await json(await call("GET", "/admin/v1/faults", { token: admin.token }), 200);
    expect(faults).toEqual([expect.objectContaining({ affected: "Panel del propietario", detail: expect.stringContaining("2026-10-30") })]);
  });

  it("rechaza subidas mal formadas, enormes, de quien no está activado y con la licencia vencida", async () => {
    const { admin, centro } = await business("grupo");
    expect((await signedBranch(centro, "POST", "/branch/v1/stats", { ...vector, schema: 2 })).status).toBe(400);
    expect((await signedBranch(centro, "POST", "/branch/v1/stats", { ...vector, cliente: "Mario" })).status).toBe(400);
    expect((await signedBranch(centro, "POST", "/branch/v1/stats", { ...vector, days: Array(11).fill(vector.days[0]) })).status).toBe(400);
    expect((await signedBranch(centro, "POST", "/branch/v1/stats", { ...vector, padding: "x".repeat(2 * 1024 * 1024) })).status).toBe(413);
    const { license } = await createLicense(admin.token, { tenantId: "grupo" });
    expect((await signed("branch", await newDevice(), license.id, "POST", "/branch/v1/stats", { body: vector })).status).toBe(401);
    await json(await signedBranch(centro, "POST", "/branch/v1/stats", vector), 200);
    const { token } = await ownerSession(admin, "grupo", "dueno@ejemplo.mx");
    await env.DB.prepare("UPDATE license SET expires_at = ? WHERE id = ?").bind(new Date(Date.now() - 1000).toISOString(), centro.license.id).run();
    const refused = await json(await signedBranch(centro, "POST", "/branch/v1/stats", revised(vector, 2)), 403);
    expect(refused.error.code).toBe("license_expired");
    expect((await read(`/owner/v1/stats/summary?${FULL}`, token)).totals.net).toBe(85600);
  });

  it("borra el detalle de productos a los 13 meses y el día a los 25", async () => {
    const { centro } = await business("grupo");
    await json(await signedBranch(centro, "POST", "/branch/v1/stats", vector), 200);
    await purgeExpired(env.DB, Date.parse("2027-12-05T00:00:00Z"));
    const products = await env.DB.prepare("SELECT COUNT(*) AS n FROM stats_day WHERE products IS NULL").first<number>("n");
    await purgeExpired(env.DB, Date.parse("2028-12-05T00:00:00Z"));
    const days = await env.DB.prepare("SELECT COUNT(*) AS n FROM stats_day").first<number>("n");
    expect([products, days]).toEqual([2, 0]);
  });
});

describe("consultas del propietario", () => {
  it("cada cifra coincide con el caso calculado a mano", async () => {
    const { admin, centro } = await business("grupo");
    await json(await signedBranch(centro, "POST", "/branch/v1/stats", vector), 200);
    const { token } = await ownerSession(admin, "grupo", "dueno@ejemplo.mx");
    const one = "from=2026-10-30&to=2026-10-30";
    const summary = await read(`/owner/v1/stats/summary?${one}&branch=${centro.license.id}`, token);
    expect(summary.totals).toMatchObject({ tickets: 2, people: 5, gross: 64000, discounts: 4400, net: 59600, averageTicket: 29800, averagePerson: 11920, voidedCount: 1, voidedAmount: 6000 });
    expect(summary.hours).toEqual([{ hour: 1, tickets: 1, net: 20000 }, { hour: 20, tickets: 1, net: 39600 }]);
    expect(summary.channels).toEqual([{ channel: "table", tickets: 2, net: 59600 }]);
    expect(summary.payments).toEqual([{ method: "card", amount: 39600, tips: 5000, count: 1 }, { method: "cash", amount: 40000, tips: 0, count: 2 }]);
    const { products } = await read(`/owner/v1/stats/products?${one}`, token);
    expect(products).toEqual([expect.objectContaining({ name: "Pizza", quantity: 3, revenue: 60000, cost: 21000, estimatedMargin: 39000 }), expect.objectContaining({ name: "Refresco", quantity: 1, revenue: 4000, revenueWithoutCost: 4000, estimatedMargin: 0 })]);
    const { staff } = await read(`/owner/v1/stats/staff?${FULL}`, token);
    expect(staff.map((s: any) => [s.name, s.tickets, s.net, s.tips])).toEqual([["Ana", 2, 59600, 5000], ["Luis", 3, 26000, 0]]);
    expect(staff[0].branchName).toBe("Centro");
    const money = await read(`/owner/v1/stats/cash?${FULL}`, token);
    expect(money).toMatchObject({ cash: { withdrawal: 30000 }, inventory: { waste: 2500 } });
    expect(money.closes).toEqual([expect.objectContaining({ cashId: "c1", blind: true, cashDifference: -100 })]);
  });

  it("el corte conserva sus cifras y muestra lo que explica la reapertura", async () => {
    const { admin, centro } = await business("grupo");
    await json(await signedBranch(centro, "POST", "/branch/v1/stats", vector), 200);
    const { token } = await ownerSession(admin, "grupo", "dueno@ejemplo.mx");
    const { closings } = await read(`/owner/v1/stats/closings?${FULL}`, token);
    const by = Object.fromEntries(closings.map((z: any) => [z.number, z]));
    expect(by[1]).toMatchObject({ net: 79600, panelNet: 59600, reopenedNet: 20000, tickets: 3, panelTickets: 2, reopenedTickets: 1 });
    expect(by[2]).toMatchObject({ net: 26000, panelNet: 26000, reopenedNet: 0 });
  });

  it("el consolidado suma sucursales y calcula el promedio con totales", async () => {
    const { admin, centro, norte } = await business("grupo");
    await json(await signedBranch(centro, "POST", "/branch/v1/stats", vector), 200);
    const other = copy(vector);
    other.days = [{ ...copy(vector.days[1]!), businessDate: "2026-10-30" }];
    const day = other.days[0]! as any;
    Object.assign(day, { hours: [{ ...day.hours[0], tickets: 3, gross: 10001, discounts: 0, net: 10001, deliveryFees: 0 }], channels: [{ channel: "table", tickets: 3, net: 10001 }], staff: [{ staffId: "w9", name: "Eva", tickets: 3, net: 10001, tips: 0 }], products: [{ productId: "x", name: "Taco", category: "Platos", quantity: 3, revenue: 10001, unitCost: null }], payments: [], zReports: [] });
    await json(await signedBranch(norte, "POST", "/branch/v1/stats", other), 200);
    const { token } = await ownerSession(admin, "grupo", "dueno@ejemplo.mx");
    const { totals, branches, partial } = await read("/owner/v1/stats/summary?from=2026-10-30&to=2026-10-30", token);
    expect(totals).toMatchObject({ tickets: 5, net: 69601, averageTicket: 13920 });
    expect(branches.map((b: any) => [b.name, b.net, b.averageTicket])).toEqual([["Centro", 59600, 29800], ["Norte", 10001, 3333]]);
    expect(partial).toEqual([]);
  });

  it("señala la sucursal atrasada o sin datos, y dice qué pasa ahora en cada una", async () => {
    const { admin, centro, norte } = await business("grupo");
    await json(await signedBranch(centro, "POST", "/branch/v1/stats", vector), 200);
    const { token } = await ownerSession(admin, "grupo", "dueno@ejemplo.mx");
    expect((await read(`/owner/v1/stats/summary?${FULL}`, token)).partial).toEqual([norte.license.id]);
    await env.DB.prepare("UPDATE branch_heartbeat SET at = ? WHERE license_id = ?").bind(new Date(Date.now() - 16 * 60_000).toISOString(), centro.license.id).run();
    const { branches } = await read("/owner/v1/me", token);
    expect(branches).toEqual([expect.objectContaining({ name: "Centro", stale: true, timeZone: "America/Mexico_City", lastZ: 2, live: expect.objectContaining({ openAccounts: 0 }) }), expect.objectContaining({ name: "Norte", stale: true, lastSeenAt: null, live: null })]);
  });

  it("dice qué día de negocio vive cada sucursal, según su zona y su corte", async () => {
    const { admin, centro } = await business("grupo");
    await json(await signedBranch(centro, "POST", "/branch/v1/stats", vector), 200);
    const { token } = await ownerSession(admin, "grupo", "dueno@ejemplo.mx");
    const at = (iso: string) => { vi.setSystemTime(new Date(iso)); return read("/owner/v1/me", token); };
    vi.useFakeTimers({ toFake: ["Date"] });
    const [night] = (await at("2026-10-31T09:59:00Z")).branches;
    const [morning] = (await at("2026-10-31T10:00:00Z")).branches;
    vi.useRealTimers();
    expect([night.businessDate, morning.businessDate]).toEqual(["2026-10-30", "2026-10-31"]);
  });

  it("no acepta periodos inválidos", async () => {
    const { admin } = await business("grupo");
    const { token } = await ownerSession(admin, "grupo", "dueno@ejemplo.mx");
    for (const query of ["", "from=2026-10-31&to=2026-10-30", "from=2025-01-01&to=2026-10-30", "from=ayer&to=hoy", `${FULL}&extra=1`]) expect((await call("GET", `/owner/v1/stats/summary?${query}`, { token })).status).toBe(400);
    expect((await call("GET", `/owner/v1/stats/otra?${FULL}`, { token })).status).toBe(404);
  });
});

describe("cuentas y alcance", () => {
  it("una cuenta nunca lee otro negocio", async () => {
    const { admin, centro } = await business("grupo");
    const ajena = await activatedBranch(admin.token, { tenantId: "otro-grupo" });
    await json(await signedBranch(centro, "POST", "/branch/v1/stats", vector), 200);
    await json(await signedBranch(ajena, "POST", "/branch/v1/stats", vector), 200);
    const mine = await ownerSession(admin, "grupo", "dueno@ejemplo.mx");
    const { branches } = await read("/owner/v1/me", mine.token);
    expect(branches.map((b: any) => b.licenseId)).not.toContain(ajena.license.id);
    expect((await read(`/owner/v1/stats/summary?${FULL}`, mine.token)).totals.net).toBe(85600);
    for (const section of ["summary", "products", "staff", "cash", "closings"]) expect((await call("GET", `/owner/v1/stats/${section}?${FULL}&branch=${ajena.license.id}`, { token: mine.token })).status).toBe(404);
  });

  it("un gerente sólo ve sus sucursales, y pierde la que deja de ser del negocio", async () => {
    const { admin, centro, norte } = await business("grupo");
    await json(await signedBranch(centro, "POST", "/branch/v1/stats", vector), 200);
    await json(await signedBranch(norte, "POST", "/branch/v1/stats", vector), 200);
    const { token } = await ownerSession(admin, "grupo", "gerente@ejemplo.mx", "manager", [centro.license.id]);
    expect((await read("/owner/v1/me", token)).branches.map((b: any) => b.licenseId)).toEqual([centro.license.id]);
    expect((await read(`/owner/v1/stats/summary?${FULL}`, token)).totals.net).toBe(85600);
    expect((await call("GET", `/owner/v1/stats/summary?${FULL}&branch=${norte.license.id}`, { token })).status).toBe(404);
    await env.DB.prepare("UPDATE license SET tenant_id = 'vendida' WHERE id = ?").bind(centro.license.id).run();
    expect((await read("/owner/v1/me", token)).branches).toEqual([]);
  });

  it("una licencia eliminada desaparece del panel", async () => {
    const { admin, centro } = await business("grupo");
    await json(await signedBranch(centro, "POST", "/branch/v1/stats", vector), 200);
    const { token } = await ownerSession(admin, "grupo", "dueno@ejemplo.mx");
    await json(await call("DELETE", `/admin/v1/licenses/${centro.license.id}`, { token: admin.token, body: {} }), 200);
    expect((await read(`/owner/v1/stats/summary?${FULL}`, token)).totals.net).toBe(0);
    expect((await call("GET", `/owner/v1/stats/summary?${FULL}&branch=${centro.license.id}`, { token })).status).toBe(404);
  });

  it("sin sesión, con sesión vencida o con la cuenta eliminada no se lee nada", async () => {
    const { admin } = await business("grupo");
    const { token } = await ownerSession(admin, "grupo", "dueno@ejemplo.mx");
    expect((await call("GET", `/owner/v1/stats/summary?${FULL}`)).status).toBe(401);
    expect((await call("GET", "/owner/v1/me", { token: admin.token })).status).toBe(401);
    await env.DB.prepare("UPDATE owner_session SET expires_at = 1").run();
    expect((await call("GET", "/owner/v1/me", { token })).status).toBe(401);
    await env.DB.prepare("UPDATE owner_session SET expires_at = ?").bind(Date.now() + 60_000).run();
    expect((await call("GET", "/owner/v1/me", { token })).status).toBe(200);
    const [account] = (await json(await call("GET", "/admin/v1/owner-accounts?tenantId=grupo", { token: admin.token }), 200)).accounts;
    expect(account).toMatchObject({ email: "dueno@ejemplo.mx", role: "owner", active: true, licenseIds: [] });
    await json(await signedAdmin(admin, "DELETE", `/admin/v1/owner-accounts/${account.id}`), 200);
    expect((await call("GET", "/owner/v1/me", { token })).status).toBe(401);
  });

  it("cerrar sesión la termina", async () => {
    const { admin } = await business("grupo");
    const { token } = await ownerSession(admin, "grupo", "dueno@ejemplo.mx");
    await json(await call("POST", "/owner/v1/logout", { token, body: {} }), 200);
    expect((await call("GET", "/owner/v1/me", { token })).status).toBe(401);
  });

  it("entrar pide contraseña y código, no repite un código y bloquea tras cinco intentos", async () => {
    const { admin } = await business("grupo");
    const { secret } = await ownerSession(admin, "grupo", "dueno@ejemplo.mx");
    const attempt = async (password: string, code: string, email = "dueno@ejemplo.mx") => call("POST", "/owner/v1/login", { body: { email, password, totp: code } });
    const used = await totpCode(secret, step() + 1);
    expect((await attempt(PASSWORD, used)).status).toBe(401);
    expect((await attempt("otra contraseña larga", await totpCode(secret, step()))).status).toBe(401);
    expect((await attempt(PASSWORD, await totpCode(secret, step() + 1), "nadie@ejemplo.mx")).status).toBe(401);
    for (let i = 0; i < 3; i++) expect((await attempt("otra contraseña larga", "000000")).status).toBe(401);
    expect((await attempt(PASSWORD, await totpCode(secret, step() + 1))).status).toBe(429);
  });

  it("una cuenta sin confirmar no entra", async () => {
    const { admin } = await business("grupo");
    const { code } = await invited(admin, { tenantId: "grupo", email: "nuevo@ejemplo.mx", role: "owner" });
    const { totp } = await json(await call("POST", "/owner/v1/enroll", { body: { code, password: PASSWORD } }), 201);
    expect((await call("POST", "/owner/v1/login", { body: { email: "nuevo@ejemplo.mx", password: PASSWORD, totp: await totpCode(totp.secret, step()) } })).status).toBe(401);
  });

  it("el código de alta se usa una vez, vence y no sobrescribe una cuenta activa", async () => {
    const { admin } = await business("grupo");
    const { code } = await invited(admin, { tenantId: "grupo", email: "dueno@ejemplo.mx", role: "owner" });
    await json(await call("POST", "/owner/v1/enroll", { body: { code, password: PASSWORD } }), 201);
    expect((await call("POST", "/owner/v1/enroll", { body: { code, password: PASSWORD } })).status).toBe(403);
    await ownerSession(admin, "grupo", "dueno@ejemplo.mx");
    const again = await invited(admin, { tenantId: "grupo", email: "dueno@ejemplo.mx", role: "owner" });
    expect((await call("POST", "/owner/v1/enroll", { body: { code: again.code, password: PASSWORD } })).status).toBe(409);
    await env.DB.prepare("UPDATE owner_invite SET expires_at = 1").run();
    await env.DB.prepare("DELETE FROM owner_account").run();
    expect((await call("POST", "/owner/v1/enroll", { body: { code: again.code, password: PASSWORD } })).status).toBe(403);
  });

  it("sólo el proveedor invita, con su firma, a sucursales de ese negocio", async () => {
    const { admin, centro } = await business("grupo");
    const ajena = await activatedBranch(admin.token, { tenantId: "otro-grupo" });
    const body = { tenantId: "grupo", email: "g@ejemplo.mx", role: "manager", licenseIds: [centro.license.id] };
    expect((await call("POST", "/admin/v1/owner-invites", { token: admin.token, body })).status).toBe(401);
    expect((await call("POST", "/admin/v1/owner-invites", { body })).status).toBe(401);
    expect((await signedAdmin(admin, "POST", "/admin/v1/owner-invites", { ...body, licenseIds: [ajena.license.id] })).status).toBe(404);
    expect((await signedAdmin(admin, "POST", "/admin/v1/owner-invites", { ...body, licenseIds: [] })).status).toBe(400);
    expect((await signedAdmin(admin, "POST", "/admin/v1/owner-invites", { ...body, role: "owner" })).status).toBe(400);
    expect((await signedAdmin(admin, "POST", "/admin/v1/owner-invites", { ...body, tenantId: "no-existe", licenseIds: [] , role: "owner" })).status).toBe(404);
    await invited(admin, body);
    const { entries } = await json(await call("GET", "/admin/v1/audit", { token: admin.token }), 200);
    expect(entries.map((e: any) => e.action)).toContain("owner.invite");
  });
});

describe("planes Lite y Pro", () => {
  const ONE = "from=2026-10-30&to=2026-10-30";
  const pinned = async <T>(iso: string, run: () => Promise<T>) => {
    vi.useFakeTimers({ toFake: ["Date"] });
    vi.setSystemTime(new Date(iso));
    try { return await run(); } finally { vi.useRealTimers(); }
  };
  /** Centro is Pro and Norte Lite, both with the same days, and Norte reports an ingredient below its minimum. */
  const mixed = async () => {
    const { admin, centro, norte } = await business("grupo", "lite");
    await json(await signedBranch(centro, "POST", "/branch/v1/stats", vector), 200);
    const low = copy(vector);
    low.live.lowStock = [{ ingredientId: "i1", name: "Queso", unit: "g", available: 10, min: 500 }] as any;
    await json(await signedBranch(norte, "POST", "/branch/v1/stats", low), 200);
    const { token } = await ownerSession(admin, "grupo", "dueno@ejemplo.mx");
    return { centro, norte, token };
  };

  // The setup runs on the real clock, because the test keys are valid from now; only the reads move the date.
  it("una sucursal Lite suma ventas y productos, pero no entra en ninguna cifra Pro", async () => {
    const { centro, norte, token } = await mixed();
    await pinned("2026-11-03T18:00:00Z", async () => {
    const all = await read(`/owner/v1/stats/summary?${FULL}`, token);
    const onlyPro = await read(`/owner/v1/stats/summary?${FULL}&branch=${centro.license.id}`, token);
    expect(all).toMatchObject({ lite: [norte.license.id], outOfRange: [] });
    expect(all.totals).toMatchObject({ net: 2 * onlyPro.totals.net, tickets: 2 * onlyPro.totals.tickets, discounts: onlyPro.totals.discounts, voidedCount: onlyPro.totals.voidedCount, gross: onlyPro.totals.gross });
    expect([all.hours, all.channels, all.payments, all.refunds]).toEqual([onlyPro.hours, onlyPro.channels, onlyPro.payments, onlyPro.refunds]);
    expect(all.branches.find((b: any) => b.name === "Norte")).toMatchObject({ net: onlyPro.totals.net, gross: 0, discounts: 0, voidedAmount: 0 });
    const day = await read(`/owner/v1/stats/summary?${ONE}`, token);
    expect(day.hours.reduce((t: number, h: any) => t + h.net, 0)).toBe(day.totals.net);

    const products = (await read(`/owner/v1/stats/products?${ONE}`, token)).products;
    const own = (await read(`/owner/v1/stats/products?${ONE}&branch=${centro.license.id}`, token)).products;
    const pizza = (rows: any[]) => rows.find((p) => p.name === "Pizza");
    expect(pizza(products)).toMatchObject({ quantity: 2 * pizza(own).quantity, cost: pizza(own).cost, estimatedMargin: pizza(own).estimatedMargin, revenueWithoutCost: pizza(own).revenue });
    expect(pizza((await read(`/owner/v1/stats/products?${ONE}&branch=${norte.license.id}`, token)).products)).toMatchObject({ cost: 0, estimatedMargin: 0 });

    const lite = `${FULL}&branch=${norte.license.id}`;
    expect(await read(`/owner/v1/stats/staff?${lite}`, token)).toMatchObject({ staff: [], lite: [norte.license.id] });
    expect(await read(`/owner/v1/stats/cash?${lite}`, token)).toMatchObject({ cash: { income: 0, expense: 0, withdrawal: 0 }, inventory: { waste: 0 }, closes: [] });
    expect((await read(`/owner/v1/stats/closings?${lite}`, token)).closings).toEqual([]);
    expect((await read(`/owner/v1/stats/staff?${FULL}`, token)).staff.every((s: any) => s.licenseId === centro.license.id)).toBe(true);
    expect((await read("/owner/v1/me", token)).branches.find((b: any) => b.name === "Norte").live.lowStock).toEqual([]);
    });
  });

  it("Lite lee su mes en curso o sus últimos siete días; lo anterior queda fuera y el consolidado lo dice", async () => {
    const { centro, norte, token } = await mixed();
    expect(await pinned("2026-11-03T18:00:00Z", async () => (await read(`/owner/v1/stats/summary?${FULL}`, token)).outOfRange)).toEqual([]);
    await pinned("2026-11-10T18:00:00Z", async () => {
    const late = await read(`/owner/v1/stats/summary?${FULL}`, token);
    const pro = await read(`/owner/v1/stats/summary?${FULL}&branch=${centro.license.id}`, token);
    expect(late).toMatchObject({ outOfRange: [norte.license.id], totals: { net: pro.totals.net } });
    expect(late.branches.map((b: any) => b.name)).toEqual(["Centro"]);
    expect((await read(`/owner/v1/stats/products?${FULL}&branch=${norte.license.id}`, token)).products).toEqual([]);
    });
  });
});
