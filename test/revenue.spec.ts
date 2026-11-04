import { env } from "cloudflare:workers";
import { describe, expect, it } from "vitest";
import { DAY_MS } from "../src/catalog";
import { periodPrice, periodsUntil, type Prices } from "../src/revenue";
import { activate, call, createLicense, firstAdmin, json, newDevice } from "./helpers";

const PRICES: Prices = {
  tiers: { lite: { monthly: 89_900, annual: 899_000, permanent: 2_490_000 }, pro: { monthly: 169_000, annual: 1_690_000, permanent: 4_490_000 } },
  addons: { mobileOrdering: 29_000, deliveryHub: 49_000, webOrdering: 39_000 },
  combos: { pyme: 109_900, delivery: 239_000 },
};

const setPrices = (token: string, prices: unknown = PRICES) => call("PUT", "/admin/v1/prices", { token, body: prices });
const charges = () => env.DB.prepare("SELECT * FROM license_charge ORDER BY at").all<any>().then((r) => r.results);

async function activeLicense(token: string, overrides: Record<string, unknown> = {}) {
  const { license, activationCode } = await createLicense(token, overrides);
  await json(await activate(license, activationCode, await newDevice()), 200);
  return license;
}

describe("precios", () => {
  it("guarda los precios, los devuelve y deja rastro en la bitácora", async () => {
    const { token } = await firstAdmin();
    expect(await json(await call("GET", "/admin/v1/prices", { token }), 200)).toEqual({ prices: null, updatedAt: null });
    await json(await setPrices(token), 200);
    const { prices, updatedAt } = await json(await call("GET", "/admin/v1/prices", { token }), 200);
    expect(prices).toEqual(PRICES);
    expect(updatedAt).toBeTruthy();
    const { entries } = await json(await call("GET", "/admin/v1/audit", { token }), 200);
    expect(entries[0].action).toBe("prices.update");
  });

  it("rechaza montos negativos, con decimales o sin todos los niveles", async () => {
    const { token } = await firstAdmin();
    expect((await setPrices(token, { ...PRICES, addons: { ...PRICES.addons, deliveryHub: -1 } })).status).toBe(400);
    expect((await setPrices(token, { ...PRICES, combos: { pyme: 1.5, delivery: 2 } })).status).toBe(400);
    expect((await setPrices(token, { ...PRICES, tiers: { lite: PRICES.tiers.lite } })).status).toBe(400);
  });

  it("pide sesión de administrador", async () => {
    expect((await call("GET", "/admin/v1/revenue")).status).toBe(401);
    expect((await call("PUT", "/admin/v1/prices", { body: PRICES })).status).toBe(401);
  });

  it("calcula el periodo: combo mensual, complementos por año y de por vida sin complementos", () => {
    expect(periodPrice(PRICES, "monthly", "lite", ["mobileOrdering"])).toEqual({ base: 89_900, addons: 20_000 });
    expect(periodPrice(PRICES, "monthly", "pro", ["deliveryHub"])).toEqual({ base: 169_000, addons: 49_000 });
    expect(periodPrice(PRICES, "annual", "lite", ["mobileOrdering"])).toEqual({ base: 899_000, addons: 348_000 });
    expect(periodPrice(PRICES, "permanent", "pro", ["deliveryHub"])).toEqual({ base: 4_490_000, addons: 0 });
    expect(periodPrice(PRICES, "trial", "pro", [])).toBeNull();
  });

  it("cuenta meses enteros al renovar hasta una fecha", () => {
    const from = new Date("2026-11-03T00:00:00Z");
    expect(periodsUntil("monthly", from, new Date(from.getTime() + 92 * DAY_MS))).toBe(3);
    expect(periodsUntil("monthly", from, new Date(from.getTime() + 5 * DAY_MS))).toBe(1);
    expect(periodsUntil("annual", from, new Date(from.getTime() + 730 * DAY_MS))).toBe(2);
  });
});

describe("cobros", () => {
  it("no registra cobros sin precios ni en una prueba", async () => {
    const { token } = await firstAdmin();
    await createLicense(token);
    await setPrices(token);
    await createLicense(token, { plan: "trial", trialDays: 14 });
    expect(await charges()).toEqual([]);
  });

  it("cobra la venta al precio de lista o al monto escrito, y conserva lo cobrado si cambia el precio", async () => {
    const { token } = await firstAdmin();
    await setPrices(token);
    await createLicense(token, { tier: "pro", plan: "annual", addons: ["deliveryHub"] });
    await createLicense(token, { charge: 50_000 });
    await setPrices(token, { ...PRICES, tiers: { ...PRICES.tiers, pro: { ...PRICES.tiers.pro, annual: 1 } } });
    const [annual, typed] = await charges();
    expect(annual).toMatchObject({ kind: "sale", plan: "annual", tier: "pro", base_amount: 1_690_000, addons_amount: 588_000 });
    expect(typed).toMatchObject({ kind: "sale", plan: "monthly", base_amount: 50_000, addons_amount: 0 });
  });

  it("cobra la renovación por periodos y el cambio de plan, pero no un cambio de nivel", async () => {
    const { token } = await firstAdmin();
    await setPrices(token);
    const license = await activeLicense(token);
    await json(await call("POST", `/admin/v1/licenses/${license.id}/renew`, { token, body: {} }), 200);
    const { license: renewed } = await json(await call("GET", `/admin/v1/licenses/${license.id}`, { token }), 200);
    await json(await call("POST", `/admin/v1/licenses/${license.id}/renew`, { token, body: { until: new Date(Date.parse(renewed.expiresAt) + 61 * DAY_MS).toISOString() } }), 200);
    await json(await call("PATCH", `/admin/v1/licenses/${license.id}`, { token, body: { tier: "pro" } }), 200);
    await json(await call("PATCH", `/admin/v1/licenses/${license.id}`, { token, body: { plan: "annual" } }), 200);
    expect((await charges()).map((c: any) => [c.kind, c.periods, c.base_amount])).toEqual([
      ["sale", 1, 89_900],
      ["renewal", 1, 89_900],
      ["renewal", 2, 179_800],
      ["plan_change", 1, 1_690_000],
    ]);
  });
});

describe("ganancias", () => {
  it("suma el recurrente por licencia activa, el mes en curso y lo que vence en 30 días", async () => {
    const { token } = await firstAdmin();
    await setPrices(token);
    const monthly = await activeLicense(token, { customer: "Tacos Los Primos", addons: ["mobileOrdering"] });
    const annual = await activeLicense(token, { customer: "La Parrilla", tier: "pro", plan: "annual" });
    await createLicense(token, { customer: "Sin activar" });
    await activeLicense(token, { customer: "Napoli", tier: "pro", plan: "permanent", addons: ["webOrdering"] });

    const r = await json(await call("GET", "/admin/v1/revenue", { token }), 200);
    expect(r.currency).toBe("MXN");
    expect(r.months).toHaveLength(12);
    expect(r.recurring.mix).toEqual({ liteMonthly: 89_900, liteAnnual: 0, proMonthly: 0, proAnnual: 140_833, addons: 20_000 + 39_000 });
    expect(r.recurring.payingLicenses).toBe(3);
    expect(r.recurring.total).toBe(89_900 + 140_833 + 59_000);
    expect(r.perLicense[monthly.id].monthly).toBe(109_900);
    expect(r.perLicense[annual.id].lastCharge).toMatchObject({ kind: "sale", amount: 1_690_000 });
    expect(r.collected.thisMonth).toBe(109_900 + 89_900 + 1_690_000 + 4_490_000);
    expect(r.months.at(-1)).toMatchObject({ lite: 89_900 * 2, pro: 1_690_000, permanent: 4_490_000, addons: 20_000 });
    expect(r.atRisk.licenses.map((l: any) => l.id)).toEqual([monthly.id]);
    expect(r.atRisk.amount).toBe(109_900);
    expect(r.top.map((t: any) => t.customer)).toEqual(["La Parrilla", "Tacos Los Primos", "Napoli"]);
  });

  it("deja fuera del recurrente lo vencido y lo revocado", async () => {
    const { token } = await firstAdmin();
    await setPrices(token);
    const expired = await activeLicense(token);
    const revoked = await activeLicense(token);
    await env.DB.prepare("UPDATE license SET expires_at = ? WHERE id = ?").bind(new Date(Date.now() - 1000).toISOString(), expired.id).run();
    await json(await call("POST", `/admin/v1/licenses/${revoked.id}/revoke`, { token, body: { reason: "cerró" } }), 200);
    const r = await json(await call("GET", "/admin/v1/revenue", { token }), 200);
    expect(r.recurring.total).toBe(0);
    expect(r.atRisk.licenses).toEqual([]);
    expect(r.collected.thisMonth).toBe(89_900 * 2);
  });
});
