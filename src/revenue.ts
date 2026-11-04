import { z } from "zod";
import { COMBOS, DAY_MS, type Plan, type Tier } from "./catalog";
import { addons, licenseStatus, type LicenseRow } from "./licenses";

// Centavos of MXN without IVA; one million pesos is far above any license.
const money = z.int().min(0).max(100_000_000);
const tierPrices = z.strictObject({ monthly: money, annual: money, permanent: money });

export const pricesSchema = z.strictObject({

  tiers: z.strictObject({ lite: tierPrices, pro: tierPrices }),
  addons: z.strictObject({ mobileOrdering: money, deliveryHub: money, webOrdering: money }),
  combos: z.strictObject({ pyme: money, delivery: money })

});

export type Prices = z.infer<typeof pricesSchema>;
export const chargeSchema = money.optional();

const TIME_ZONE = "America/Mexico_City";
const monthKey = new Intl.DateTimeFormat("en-CA", { timeZone: TIME_ZONE, year: "numeric", month: "2-digit" });
const MONTHS_PER_PERIOD: Record<Exclude<Plan, "trial" | "permanent">, number> = { monthly: 1, annual: 12 };

type Split = { base: number; addons: number };
type ChargeRow = { id: string; license_id: string; at: string; kind: string; plan: Plan; tier: Tier; addons: string; periods: number; base_amount: number; addons_amount: number };

export async function currentPrices(db: D1Database): Promise<{ prices: Prices; at: string } | null> {

  const row = await db.prepare("SELECT at, prices FROM price_list ORDER BY id DESC LIMIT 1").first<{ at: string; prices: string }>();

  return row && { prices: JSON.parse(row.prices) as Prices, at: row.at };
}

const addonsMonthly = (prices: Prices, list: string[]) => list.reduce((sum, a) => sum + (prices.addons[a as keyof Prices["addons"]] ?? 0), 0);

/** What one period of this plan costs at these prices. A trial costs nothing; a lifetime license is one payment for the tier. */
export function periodPrice(prices: Prices, plan: Plan, tier: Tier, list: string[]): Split | null {

  const monthlyAddons = addonsMonthly(prices, list);

  switch (plan) {

    case "trial":

      return null;
    case "permanent":

      return { base: prices.tiers[tier].permanent, addons: 0 };
    case "annual":

      return { base: prices.tiers[tier].annual, addons: monthlyAddons * 12 };
    case "monthly": {

      const combo = COMBOS.find((c) => c.tier === tier && c.addons.length === list.length && c.addons.every((a) => list.includes(a)));

      if (!combo) return { base: prices.tiers[tier].monthly, addons: monthlyAddons };

      const total = prices.combos[combo.id], base = Math.min(prices.tiers[tier].monthly, total);

      return { base, addons: total - base };
    }

  }

}

/** A typed-in amount keeps the tier and add-on proportions of the price list, so the monthly chart still splits it. */
function scaled(split: Split | null, override: number | undefined): Split | null {

  if (override === undefined) return split;
  if (!split || split.base + split.addons === 0) return { base: override, addons: 0 };

  const base = Math.round(override * split.base / (split.base + split.addons));

  return { base, addons: override - base };
}

/** Periods a renewal to a chosen date pays for: whole months or years, at least one. */
export function periodsUntil(plan: Plan, from: Date, until: Date): number {

  if (plan !== "monthly" && plan !== "annual") return 1;

  const days = (until.getTime() - from.getTime()) / DAY_MS;

  return Math.max(1, Math.round(days / (MONTHS_PER_PERIOD[plan] * 30.4375)));
}

/** The statement that records a charge, or null when there is nothing to charge: a trial, or no prices and no amount. */
export async function chargeStatement(db: D1Database, row: LicenseRow, kind: "sale" | "renewal" | "plan_change", adminId: string, options: { periods?: number; amount?: number } = {}): Promise<D1PreparedStatement | null> {

  if (row.plan === "trial") return null;

  const periods = options.periods ?? 1;
  const listed = await currentPrices(db);
  const price = listed && periodPrice(listed.prices, row.plan, row.tier, addons(row));
  const split = scaled(price && { base: price.base * periods, addons: price.addons * periods }, options.amount);

  if (!split) return null;

  return db.prepare("INSERT INTO license_charge (id, license_id, at, kind, plan, tier, addons, periods, base_amount, addons_amount, admin_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)").bind(crypto.randomUUID(), row.id, new Date().toISOString(), kind, row.plan, row.tier, row.addons, periods, split.base, split.addons, adminId);
}

const monthsBack = (count: number, at: Date) => Array.from({ length: count }, (_, i) => {

  const [year, month] = monthKey.format(at).split("-").map(Number) as [number, number];
  const d = new Date(Date.UTC(year, month - 1 - (count - 1 - i), 15));

  return monthKey.format(d);

});

/** Recurring value of a license per month: from its last charge if the plan still matches, otherwise from today's prices. */
function monthlyValue(row: LicenseRow, last: ChargeRow | undefined, prices: Prices | null): Split {

  const list = addons(row);

  if (row.plan === "permanent") return { base: 0, addons: prices ? addonsMonthly(prices, list) : 0 };
  if (row.plan === "trial") return { base: 0, addons: 0 };

  const months = MONTHS_PER_PERIOD[row.plan];

  if (last && last.plan === row.plan && last.tier === row.tier && last.addons === row.addons) return { base: Math.round(last.base_amount / last.periods / months), addons: Math.round(last.addons_amount / last.periods / months) };

  const price = prices && periodPrice(prices, row.plan, row.tier, list);

  return price ? { base: Math.round(price.base / months), addons: Math.round(price.addons / months) } : { base: 0, addons: 0 };
}

export async function revenue(db: D1Database, at = new Date()) {

  const months = monthsBack(12, at);
  const since = new Date(at.getTime() - 400 * DAY_MS).toISOString();
  const [listed, licenses, charges, lastCharges] = await Promise.all([

    currentPrices(db),
    db.prepare("SELECT * FROM license WHERE deleted_at IS NULL").all<LicenseRow>().then((r) => r.results),
    db.prepare("SELECT * FROM license_charge WHERE at >= ? ORDER BY at").bind(since).all<ChargeRow>().then((r) => r.results),
    db.prepare("SELECT c.* FROM license_charge c JOIN (SELECT license_id, MAX(at) AS at FROM license_charge GROUP BY license_id) m ON m.license_id = c.license_id AND m.at = c.at").all<ChargeRow>().then((r) => r.results)

  ]);
  const prices = listed?.prices ?? null;
  const last = new Map(lastCharges.map((c) => [c.license_id, c]));
  const byMonth = new Map(months.map((m) => [m, { month: m, lite: 0, pro: 0, addons: 0, permanent: 0, total: 0 }]));

  for (const c of charges) {

    const bucket = byMonth.get(monthKey.format(new Date(c.at)));

    if (!bucket) continue;
    if (c.plan === "permanent") bucket.permanent += c.base_amount; else bucket[c.tier] += c.base_amount;

    bucket.addons += c.addons_amount;
    bucket.total += c.base_amount + c.addons_amount;

  }

  const mix = { liteMonthly: 0, liteAnnual: 0, proMonthly: 0, proAnnual: 0, addons: 0 };
  const perLicense: Record<string, { monthly: number; lastCharge: { at: string; kind: string; amount: number } | null }> = {};
  const tenants = new Map<string, { tenantId: string; customer: string; branches: number; monthly: number }>();
  const risk: { id: string; customer: string; branchName: string; expiresAt: string; amount: number }[] = [];
  let paying = 0;

  for (const row of licenses) {

    const charge = last.get(row.id);
    const active = licenseStatus(row, at.getTime()) === "active";
    const value = active ? monthlyValue(row, charge, prices) : { base: 0, addons: 0 };
    const monthly = value.base + value.addons;

    perLicense[row.id] = { monthly, lastCharge: charge ? { at: charge.at, kind: charge.kind, amount: charge.base_amount + charge.addons_amount } : null };

    if (!monthly) continue;

    paying++;

    if (row.plan === "monthly" || row.plan === "annual") mix[`${row.tier}${row.plan === "monthly" ? "Monthly" : "Annual"}`] += value.base;

    mix.addons += value.addons;

    const tenant = tenants.get(row.tenant_id) ?? { tenantId: row.tenant_id, customer: row.customer, branches: 0, monthly: 0 };

    tenant.branches++;
    tenant.monthly += monthly;
    tenants.set(row.tenant_id, tenant);

    if (row.expires_at && Date.parse(row.expires_at) - at.getTime() <= 30 * DAY_MS && row.plan !== "permanent") {

      const months = MONTHS_PER_PERIOD[row.plan as "monthly" | "annual"];

      risk.push({ id: row.id, customer: row.customer, branchName: row.branch_name, expiresAt: row.expires_at, amount: monthly * months });

    }

  }

  const total = Object.values(mix).reduce((a, b) => a + b, 0);
  const series = [...byMonth.values()];

  return {

    currency: "MXN",
    timeZone: TIME_ZONE,
    pricesAt: listed?.at ?? null,
    months: series,
    recurring: { total, payingLicenses: paying, perLicense: paying ? Math.round(total / paying) : 0, mix },
    collected: { thisMonth: series.at(-1)!.total, lastMonth: series.at(-2)!.total },
    atRisk: { amount: risk.reduce((a, r) => a + r.amount, 0), licenses: risk.sort((a, b) => a.expiresAt.localeCompare(b.expiresAt)) },
    top: [...tenants.values()].sort((a, b) => b.monthly - a.monthly).slice(0, 5),
    perLicense

  };
}
