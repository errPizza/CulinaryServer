import { afterEach, describe, expect, it, vi } from "vitest";
import { totpCode } from "../src/crypto";
import { holidays } from "../src/forecast";
import { shiftOf, DEFAULT_SETTINGS } from "../src/insights";
import vector from "./fixtures/stats-vector.json";
import { activatedBranch, call, firstAdmin, json, PASSWORD, signedAdmin, signedBranch, step, type AdminSession } from "./helpers";

const copy = <T>(value: T): T => JSON.parse(JSON.stringify(value));
const shift = (date: string, days: number) => new Date(Date.parse(date) + days * 86_400_000).toISOString().slice(0, 10);
const today = () => new Date(Date.now() - 240 * 60_000).toLocaleDateString("en-CA", { timeZone: "America/Mexico_City" });

async function ownerSession(admin: AdminSession, tenantId: string, email: string, role = "owner", licenseIds: string[] = []) {
  const { code } = await json(await signedAdmin(admin, "POST", "/admin/v1/owner-invites", { tenantId, email, role, licenseIds }), 201);
  const enrolled = await json(await call("POST", "/owner/v1/enroll", { body: { code, password: PASSWORD } }), 201);
  const secret = enrolled.totp.secret as string;
  await json(await call("POST", "/owner/v1/enroll/confirm", { body: { email, password: PASSWORD, totp: await totpCode(secret, step()) } }), 200);
  const { token } = await json(await call("POST", "/owner/v1/login", { body: { email, password: PASSWORD, totp: await totpCode(secret, step() + 1) } }), 200);
  return token as string;
}

async function business(norteTier = "pro") {
  const admin = await firstAdmin();
  const centro = await activatedBranch(admin.token, { tenantId: "grupo", branchName: "Centro", tier: "pro" });
  const norte = await activatedBranch(admin.token, { tenantId: "grupo", branchName: "Norte", tier: norteTier });
  return { admin, centro, norte, token: await ownerSession(admin, "grupo", "dueno@ejemplo.mx") };
}

type Product = { name: string; category?: string; quantity: number; revenue: number; unitCost: number | null };
type Options = { net?: number; tickets?: number; tax?: number; products?: Product[]; tips?: number; waste?: number; insights?: Record<string, unknown> };

/** A business day that meets every identity: the same net by hour, channel, waiter and area. */
function day(businessDate: string, o: Options = {}) {
  const products = (o.products ?? [{ name: "Taco", quantity: o.tickets ?? 1, revenue: o.net ?? 10000, unitCost: null }]).map((p, i) => ({ productId: `p${i}`, category: "Platos", ...p }));
  const net = products.reduce((t, p) => t + p.revenue, 0), tickets = o.tickets ?? 1, tips = o.tips ?? 0;
  return {
    businessDate, revision: 1, complete: true,
    hours: [{ hour: 14, z: 1, tickets, people: tickets * 2, gross: net, discounts: 0, net, tax: o.tax ?? 0, deliveryFees: 0, voidedCount: 0, voidedAmount: 0, comps: 0, staffMeals: 0 }],
    payments: [{ hour: 14, method: "cash", amount: net, tips, count: tickets }], refunds: [], channels: [{ channel: "table", tickets, net }], products,
    staff: [{ staffId: "w1", name: "Ana", tickets, net, tips }], cash: { income: 0, expense: 0, withdrawal: 0 }, cashCloses: [], inventory: { waste: o.waste ?? 0, shortage: 0, surplus: 0 }, zReports: [],
    areas: [{ area: "Terraza", tickets, people: tickets * 2, net }], kinds: [{ kind: "food", quantity: products.reduce((t, p) => t + p.quantity, 0), revenue: net }], team: [], labor: [],
    ...o.insights
  };
}

const upload = (days: unknown[], live: Record<string, unknown> = {}) => ({ ...copy(vector), schema: 2, live: { ...copy(vector.live), ...live }, days });

async function send(branch: Awaited<ReturnType<typeof activatedBranch>>, days: unknown[], live: Record<string, unknown> = {}) {
  for (let i = 0; i < Math.max(days.length, 1); i += 10) {
    const reply = await json(await signedBranch(branch, "POST", "/branch/v1/stats", upload(days.slice(i, i + 10), live)), 200);
    expect(reply.rejected).toEqual([]);
  }
}

const read = async (path: string, token: string) => json(await call("GET", path, { token }), 200);

afterEach(() => { vi.restoreAllMocks(); });

describe("contrato 2", () => {
  it("acepta la subida de la versión anterior y la nueva, y rechaza la que no cuadra por área", async () => {
    const { centro } = await business();
    const old = copy(vector) as any;
    old.schema = 1;
    for (const key of Object.keys(old.live)) if (!["at", "openAccounts", "occupiedTables", "openAmount", "pendingRequests", "cashOpen", "lowStock"].includes(key)) delete old.live[key];
    for (const d of old.days) for (const key of ["areas", "kinds", "team", "labor", "couriers", "kitchen", "returns", "promises", "reviews", "reviewProducts", "expenses", "customers"]) delete d[key];
    expect((await json(await signedBranch(centro, "POST", "/branch/v1/stats", old), 200)).accepted).toHaveLength(2);
    const broken = day("2026-10-20");
    broken.areas[0]!.net += 1;
    expect((await json(await signedBranch(centro, "POST", "/branch/v1/stats", upload([broken])), 200)).rejected).toEqual(["2026-10-20"]);
    const labor = day("2026-10-21", { insights: { team: [{ staffId: "w1", name: "Ana", role: "mesero", people: 2, tables: 1, voids: 0, voidAmount: 0, discounts: 0, discountAmount: 0, rejected: 0, reopens: 0, drawerOpens: 0, minutes: 60, laborCost: 5000 }], labor: [{ hour: 14, minutes: 59, cost: 5000 }] } });
    expect((await json(await signedBranch(centro, "POST", "/branch/v1/stats", upload([labor])), 200)).rejected).toEqual(["2026-10-21"]);
  });

  it("una sucursal Lite no muestra lo vivo que es Pro", async () => {
    const { norte, token } = await business("lite");
    await send(norte, [], { expiring: [{ ingredientId: "i", name: "Leche", unit: "ml", quantity: 1, cost: 100, expiresOn: today(), days: 0, products: [] }], tables: { total: 4, free: 1, occupied: 3, cleaning: 0, reserved: 0 }, customers: { identified: 3, active90: 1, repeat90: 1, averageGapDays: 9, lifetimeAverage: 1000, visitsAverageTenths: 20, vip: 0, vipLapsed: 0 } });
    const { branches } = await read("/owner/v1/me", token);
    const lite = branches.find((b: any) => b.name === "Norte");
    expect(lite.live.tables.occupied).toBe(3);
    expect(lite.live.expiring).toEqual([]);
    expect(lite.live.customers).toBeUndefined();
  });
});

describe("ajustes del dueño", () => {
  it("el dueño los cambia, el gerente sólo los lee y nada apunta a otra empresa", async () => {
    const { admin, centro, token } = await business();
    expect(await read("/owner/v1/settings", token)).toEqual({ settings: DEFAULT_SETTINGS, canEdit: true });
    const next = { ...DEFAULT_SETTINGS, goals: [{ licenseId: centro.license.id, period: "month", amount: 1_000_000 }], foodCostTargetBps: 2800 };
    expect((await json(await call("PUT", "/owner/v1/settings", { token, body: next }), 200)).settings.foodCostTargetBps).toBe(2800);
    expect((await call("PUT", "/owner/v1/settings", { token, body: { ...next, shifts: [{ name: "A", start: 8 }, { name: "B", start: 8 }] } })).status).toBe(400);
    expect((await call("PUT", "/owner/v1/settings", { token, body: { ...next, goals: [{ licenseId: "ajena", period: "day", amount: 1 }] } })).status).toBe(404);
    const manager = await ownerSession(admin, "grupo", "gerente@ejemplo.mx", "manager", [centro.license.id]);
    expect((await read("/owner/v1/settings", manager)).canEdit).toBe(false);
    expect((await call("PUT", "/owner/v1/settings", { token: manager, body: next })).status).toBe(403);
  });

  it("cada hora cae en su turno y el último pasa la medianoche", () => {
    expect([2, 7, 11, 12, 17, 18, 23].map((h) => shiftOf(DEFAULT_SETTINGS.shifts, h).name)).toEqual(["Noche", "Mañana", "Mañana", "Comida", "Comida", "Noche", "Noche"]);
  });
});

describe("lecturas nuevas", () => {
  it("turnos y áreas salen del resumen", async () => {
    const { centro, token } = await business();
    await send(centro, [day("2026-10-20", { net: 30000, tickets: 3 })]);
    const summary = await read(`/owner/v1/stats/summary?from=2026-10-20&to=2026-10-20`, token);
    expect(summary.areas).toEqual([{ area: "Terraza", tickets: 3, people: 6, net: 30000 }]);
    expect(summary.shifts.find((s: any) => s.name === "Comida")).toMatchObject({ start: 12, end: 18, tickets: 3, net: 30000, averageTicket: 10000 });
  });

  it("la ingeniería de menú clasifica con margen por unidad y popularidad, y sugiere precio", async () => {
    const { centro, token } = await business();
    await send(centro, [day("2026-10-20", { products: [
      { name: "Taco", quantity: 50, revenue: 200000, unitCost: 1000 },
      { name: "Torta", quantity: 40, revenue: 160000, unitCost: 2500 },
      { name: "Langosta", quantity: 5, revenue: 100000, unitCost: 6000 },
      { name: "Sopa", quantity: 5, revenue: 15000, unitCost: 2000 },
      { name: "Agua", quantity: 10, revenue: 20000, unitCost: null }
    ] })]);
    const result = await read("/owner/v1/stats/menu?from=2026-10-20&to=2026-10-20", token);
    const classes = Object.fromEntries(result.items.map((i: any) => [i.name, i.class]));
    expect(classes).toEqual({ Taco: "star", Torta: "plowhorse", Langosta: "puzzle", Sopa: "dog" });
    expect(result.uncosted).toEqual([{ name: "Agua", category: "Platos", revenue: 20000 }]);
    // Sopa: 2000 of cost on 3000 of price is 67 %; at a 30 % target it would sell at $67.
    expect(result.items.find((i: any) => i.name === "Sopa")).toMatchObject({ foodCostBps: 6667, suggestedPrice: 6700 });
    expect(result.items.find((i: any) => i.name === "Taco").suggestedPrice).toBeNull();
  });

  it("la rentabilidad resta costo de lo vendido, merma, gastos, horas y gastos fijos", async () => {
    const { centro, token } = await business();
    await json(await call("PUT", "/owner/v1/settings", { token, body: { ...DEFAULT_SETTINGS, fixedCosts: [{ licenseId: centro.license.id, name: "Renta", monthly: 365_000 }, { licenseId: "", name: "Contador", monthly: 36_500 }] } }), 200);
    const team = [{ staffId: "w1", name: "Ana", role: "mesero", people: 2, tables: 1, voids: 0, voidAmount: 0, discounts: 0, discountAmount: 0, rejected: 0, reopens: 0, drawerOpens: 0, minutes: 120, laborCost: 12000 }];
    await send(centro, [day("2026-10-20", { tax: 16000, waste: 500, products: [{ name: "Taco", quantity: 10, revenue: 116000, unitCost: 3000 }], insights: { team, labor: [{ hour: 14, minutes: 120, cost: 12000 }], expenses: [{ account: "Limpieza", amount: 2000, count: 1 }] } })]);
    const all = await read("/owner/v1/stats/profit?from=2026-10-20&to=2026-10-20", token);
    // 116000 - 16000 IVA = 100000; - 30000 recetas - 500 merma - 2000 gastos - 12000 horas - 12000 renta - 1200 contador.
    expect(all).toMatchObject({ sales: 100000, cogs: 30000, waste: 500, expensesTotal: 2000, fixedTotal: 13200, profit: 42300, marginBps: 4230 });
    const one = await read(`/owner/v1/stats/profit?from=2026-10-20&to=2026-10-20&branch=${centro.license.id}`, token);
    expect(one.fixedTotal).toBe(12000);
  });

  it("personal: horas, propinas por horas trabajadas y patrones sólo para el dueño", async () => {
    const { admin, centro, token } = await business();
    const person = (staffId: string, name: string, minutes: number, voids: number) => ({ staffId, name, role: "mesero", people: 2, tables: 1, voids, voidAmount: voids * 100, discounts: 0, discountAmount: 0, rejected: 0, reopens: 0, drawerOpens: 0, minutes, laborCost: minutes * 100 });
    const team = [person("w1", "Ana", 120, 9), person("w2", "Beto", 60, 1), person("w3", "Cata", 60, 0)];
    await send(centro, [day("2026-10-20", { tips: 1000, insights: { team, labor: [{ hour: 14, minutes: 240, cost: 24000 }] } })]);
    const result = await read("/owner/v1/stats/team?from=2026-10-20&to=2026-10-20", token);
    expect(result.tips.shares.map((s: any) => [s.name, s.share])).toEqual([["Ana", 500], ["Beto", 250], ["Cata", 250]]);
    expect(result.labor).toMatchObject({ minutes: 240, cost: 24000, laborBps: 24000 });
    expect(result.anomalies).toEqual([expect.objectContaining({ name: "Ana", metric: "voids", value: 9, usual: 1 })]);
    const manager = await ownerSession(admin, "grupo", "gerente@ejemplo.mx", "manager", [centro.license.id]);
    expect((await read("/owner/v1/stats/team?from=2026-10-20&to=2026-10-20", manager)).anomalies).toEqual([]);
  });

  it("cocina: tiempos por platillo y estación, devoluciones y promesas", async () => {
    const { centro, token } = await business();
    await send(centro, [day("2026-10-20", { products: [{ name: "Taco", quantity: 10, revenue: 30000, unitCost: null }], insights: {
      kitchen: [{ productId: "p0", name: "Taco", station: "Cocina", count: 10, waitSeconds: 600, prepSeconds: 4800, maxSeconds: 900, passCount: 10, passSeconds: 1200 }],
      returns: [{ productId: "p0", name: "Taco", reason: "cold", count: 1 }],
      promises: [{ mode: "pickup", count: 4, late: 1, promisedSeconds: 4 * 900, actualSeconds: 4 * 1000 }]
    } })]);
    const result = await read("/owner/v1/stats/kitchen?from=2026-10-20&to=2026-10-20", token);
    expect(result.dishes[0]).toMatchObject({ name: "Taco", averageSeconds: 540, averagePrep: 480, averageWait: 60, averagePass: 120 });
    expect(result.returns[0]).toMatchObject({ name: "Taco", count: 1, sold: 10, rateBps: 1000 });
    expect(result.reasons).toEqual([{ reason: "cold", label: "Llegó frío", count: 1 }]);
    expect(result.promises[0]).toMatchObject({ mode: "pickup", onTimeBps: 7500, averagePromised: 900, averageActual: 1000 });
  });

  it("clientes: sólo cifras, nunca personas, y la calificación por platillo", async () => {
    const { centro, token } = await business();
    await send(centro, [day("2026-10-20", { tickets: 4, insights: { customers: { tickets: 2, net: 6000, first: 1, repeat: 1 }, reviews: { count: 3, food: 12, service: 9, overall: 12, low: 1 }, reviewProducts: [{ productId: "p0", name: "Taco", count: 3, overall: 12 }] } })], { customers: { identified: 10, active90: 6, repeat90: 3, averageGapDays: 12, lifetimeAverage: 45000, visitsAverageTenths: 34, vip: 1, vipLapsed: 1 } });
    const result = await read("/owner/v1/stats/customers?from=2026-10-20&to=2026-10-20", token);
    expect(result.period).toMatchObject({ identifiedTickets: 2, identifiedBps: 5000, first: 1, repeat: 1 });
    expect(result.known).toMatchObject({ identified: 10, averageGapDays: 12, lifetimeAverage: 45000, vipLapsed: 1 });
    expect(result.reviews).toMatchObject({ count: 3, overallTenths: 40, foodTenths: 40, serviceTenths: 30, low: 1 });
    expect(result.best).toEqual([{ name: "Taco", count: 3, averageTenths: 40 }]);
  });

  it("tendencia por mes contra el año anterior", async () => {
    const { centro, token } = await business();
    await send(centro, [day("2025-10-05", { net: 50000 }), day("2026-10-05", { net: 60000 }), day("2026-09-05", { net: 40000 })]);
    const result = await read("/owner/v1/stats/trend?from=2026-09-01&to=2026-10-31&by=month", token);
    expect(result.periods.map((p: any) => [p.key, p.net, p.lastYearNet, p.growthBps])).toEqual([["2026-09", 40000, 0, null], ["2026-10", 60000, 50000, 2000]]);
  });

  it("metas: avance, ritmo y proyección del mes", async () => {
    const { centro, token } = await business();
    const now = today();
    await send(centro, [day(now, { net: 100000 })]);
    await json(await call("PUT", "/owner/v1/settings", { token, body: { ...DEFAULT_SETTINGS, goals: [{ licenseId: "", period: "day", amount: 50000 }, { licenseId: centro.license.id, period: "month", amount: 100_000_000 }] } }), 200);
    const { goals } = await read("/owner/v1/stats/goals", token);
    expect(goals[0]).toMatchObject({ period: "day", target: 50000, actual: 100000, progressBps: 20000, pace: "reached" });
    expect(goals[1]).toMatchObject({ period: "month", branchName: "Centro", actual: 100000, pace: "behind" });
    const { alerts } = await read("/owner/v1/stats/alerts", token);
    expect(alerts.some((a: any) => a.area === "Metas")).toBe(true);
  });

  it("pronóstico: mismo día de la semana, tendencia, festivos y lluvia de Open-Meteo", async () => {
    const { centro, token } = await business();
    const now = today();
    const days = Array.from({ length: 56 }, (_, i) => day(shift(now, -56 + i), { net: 100000, tickets: 10, products: [{ name: "Taco", quantity: 20, revenue: 100000, unitCost: null }] }));
    await send(centro, days);
    const plain = await read("/owner/v1/stats/forecast", token);
    expect(plain.days).toHaveLength(7);
    expect(plain.trend).toBe(1);
    expect(plain.errorBps).toBe(0);
    const usual = plain.days.find((d: any) => !d.holiday);
    expect(usual).toMatchObject({ base: 100000, net: 100000, tickets: 10, weather: null });
    expect(plain.products[0].days[0].units).toBe(plain.days[0].holiday ? Math.round(20 * plain.days[0].factor) : 20);
    await json(await call("PUT", "/owner/v1/settings", { token, body: { ...DEFAULT_SETTINGS, locations: [{ licenseId: centro.license.id, label: "Monterrey", lat: 25.67, lon: -100.31 }] } }), 200);
    const ahead = Array.from({ length: 7 }, (_, i) => shift(now, i + 1));
    const spy = vi.spyOn(globalThis, "fetch").mockImplementation(async (input) => {
      const url = String(input instanceof Request ? input.url : input);
      if (url.includes("archive-api")) return Response.json({ daily: { time: [], precipitation_sum: [], temperature_2m_max: [] } });
      return Response.json({ daily: { time: ahead, precipitation_sum: ahead.map((_, i) => (i === 0 ? 12 : 0)), precipitation_probability_max: ahead.map((_, i) => (i === 0 ? 90 : 10)), temperature_2m_max: ahead.map(() => 24) } });
    });
    const wet = await read(`/owner/v1/stats/forecast?branch=${centro.license.id}`, token);
    expect(spy).toHaveBeenCalled();
    expect(wet.weather).toMatchObject({ label: "Monterrey", used: true, learned: false, rainFactor: 0.93 });
    expect(wet.days[0].weather).toMatchObject({ rainMm: 12, wet: true, factor: 0.93 });
    expect(wet.days[0].net).toBe(Math.round(100000 * (wet.days[0].holiday?.factor ?? 1) * 0.93));
  });

  it("los festivos de México se calculan cada año", () => {
    const y2027 = holidays(2027);
    expect(y2027.get("2027-03-25")?.name).toBe("Jueves Santo");
    expect(y2027.get("2027-05-10")?.factor).toBe(1.4);
    expect(y2027.get("2027-06-20")?.name).toBe("Día del Padre");
    expect(y2027.get("2027-02-01")?.name).toBe("Día de la Constitución");
  });

  it("alertas: caducidad, costos, clientes frecuentes y sucursales sin contacto", async () => {
    const { centro, token } = await business();
    await send(centro, [], {
      expiring: [{ ingredientId: "i", name: "Leche", unit: "ml", quantity: 1000, cost: 2500, expiresOn: today(), days: 0, products: ["Licuado"] }],
      costAlerts: [{ ingredientId: "a", name: "Aguacate", unit: "g", before: 4_000_000, after: 5_000_000, changeBps: 2500, at: new Date().toISOString(), products: [{ name: "Guacamole", price: 9000, cost: 3500 }] }],
      customers: { identified: 50, active90: 20, repeat90: 10, averageGapDays: 14, lifetimeAverage: 50000, visitsAverageTenths: 30, vip: 5, vipLapsed: 2 }
    });
    const { alerts } = await read("/owner/v1/stats/alerts", token);
    const titles = alerts.map((a: any) => a.title);
    expect(titles).toEqual(expect.arrayContaining(["Leche caduca hoy", "Aguacate subió 25 %", "2 clientes frecuentes no han vuelto", "Sucursal sin contacto"]));
    expect(alerts[0].level).toBe("high");
  });

  it("lo nuevo del plan Pro deja fuera a las sucursales Lite y lo dice", async () => {
    const { norte, token } = await business("lite");
    await send(norte, [day(today(), { products: [{ name: "Taco", quantity: 1, revenue: 10000, unitCost: 1000 }] })]);
    const result = await read(`/owner/v1/stats/menu?from=${today()}&to=${today()}`, token);
    expect(result.items).toEqual([]);
    expect(result.lite).toEqual([norte.license.id]);
    const summary = await read(`/owner/v1/stats/summary?from=${today()}&to=${today()}`, token);
    expect(summary.shifts.reduce((t: number, s: any) => t + s.net, 0)).toBe(10000);
  });
});
