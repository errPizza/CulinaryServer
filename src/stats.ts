import { z } from "zod";
import { sha256Hex } from "./crypto";
import { recordFaults } from "./faults";
import { licenseStatus, type LicenseRow } from "./licenses";

const STALE_MS = 15 * 60 * 1000;
const MAX_RANGE_DAYS = 366;

export const MAX_STATS_BYTES = 2 * 1024 * 1024;

const money = z.int();
const count = z.int().min(0);
const hour = z.int().min(0).max(23);
const text = (max: number) => z.string().max(max);
const moment = z.iso.datetime({ offset: true });
const date = z.string().regex(/^\d{4}-\d{2}-\d{2}$/, "Fecha AAAA-MM-DD");

const hourRow = z.strictObject({ hour, z: count, tickets: count, people: count, gross: money, discounts: money, net: money, tax: money, deliveryFees: money, voidedCount: count, voidedAmount: money, comps: count, staffMeals: count });

const daySchema = z.strictObject({

  businessDate: date,
  revision: z.int().min(1),
  complete: z.boolean(),
  hours: z.array(hourRow).max(1000),
  payments: z.array(z.strictObject({ hour, method: text(32), amount: money, tips: money, count })).max(1000),
  refunds: z.array(z.strictObject({ method: text(32), amount: money, count })).max(32),
  channels: z.array(z.strictObject({ channel: text(32), tickets: count, net: money })).max(32),
  products: z.array(z.strictObject({ productId: text(64), name: text(300), category: text(300), quantity: count, revenue: money, unitCost: money.nullable() })).max(5000),
  staff: z.array(z.strictObject({ staffId: text(64), name: text(300), tickets: count, net: money, tips: money })).max(500),
  cash: z.strictObject({ income: money, expense: money, withdrawal: money }),
  cashCloses: z.array(z.strictObject({ cashId: text(64), closedAt: moment, blind: z.boolean(), cashDifference: money, cardDifference: money, transferDifference: money, adjustments: money })).max(100),
  inventory: z.strictObject({ waste: money, shortage: money, surplus: money }),
  zReports: z.array(z.strictObject({ number: count, from: moment, to: moment, tickets: count, people: count, gross: money, discounts: money, net: money, tax: money, payments: money, tips: money, refunds: money, digest: text(64) })).max(100)

});

export const statsSchema = z.strictObject({

  schema: z.literal(1),
  sentAt: moment,
  branch: z.strictObject({ timeZone: text(64), businessDayCutoffMinutes: z.int().min(0).max(720), currency: z.literal("MXN"), appVersion: text(32), lastZ: count }),
  live: z.strictObject({

    at: moment,
    openAccounts: count,
    occupiedTables: count,
    openAmount: money,
    pendingRequests: count,
    cashOpen: z.boolean(),
    lowStock: z.array(z.strictObject({ ingredientId: text(64), name: text(300), unit: text(32), available: money, min: money })).max(100)

  }),
  days: z.array(daySchema).max(10)

});

type Stats = z.infer<typeof statsSchema>;
type Day = Stats["days"][number];

const TOTALS = ["tickets", "people", "gross", "discounts", "net", "tax", "deliveryFees", "voidedCount", "voidedAmount", "comps", "staffMeals"] as const;

type Totals = Record<(typeof TOTALS)[number], number>;

const sum = <T>(rows: readonly T[], read: (row: T) => number) => rows.reduce((total, row) => total + read(row), 0);

/** The identities of docs/METRICAS-PANEL.md that a single day can prove. */
function dayProblem(day: Day): string | null {

  const net = sum(day.hours, (h) => h.net);

  if (net !== sum(day.channels, (c) => c.net) || net !== sum(day.staff, (s) => s.net)) return "ventas distintas por hora, canal y mesero";
  if (sum(day.products, (p) => p.revenue) + sum(day.hours, (h) => h.deliveryFees) !== sum(day.hours, (h) => h.gross)) return "productos más envío distintos de la venta bruta";
  if (day.hours.some((h) => h.gross - h.discounts !== h.net)) return "bruta menos descuentos distinta de ventas";
  if (sum(day.payments, (p) => p.tips) !== sum(day.staff, (s) => s.tips)) return "propinas distintas por pago y por mesero";

  return null;
}

const UPSERT_DAY = `INSERT INTO stats_day (license_id, business_date, revision, complete, received_at, tickets, people, gross, discounts, net, tax, delivery_fees, voided_count, voided_amount, comps, staff_meals, hours, payments, refunds, channels, products, staff, cash, cash_closes, inventory, z_reports)
  VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21, ?22, ?23, ?24, ?25, ?26)
  ON CONFLICT (license_id, business_date) DO UPDATE SET revision = excluded.revision, complete = excluded.complete, received_at = excluded.received_at, tickets = excluded.tickets, people = excluded.people, gross = excluded.gross, discounts = excluded.discounts, net = excluded.net, tax = excluded.tax, delivery_fees = excluded.delivery_fees, voided_count = excluded.voided_count, voided_amount = excluded.voided_amount, comps = excluded.comps, staff_meals = excluded.staff_meals, hours = excluded.hours, payments = excluded.payments, refunds = excluded.refunds, channels = excluded.channels, products = excluded.products, staff = excluded.staff, cash = excluded.cash, cash_closes = excluded.cash_closes, inventory = excluded.inventory, z_reports = excluded.z_reports
  WHERE excluded.revision > stats_day.revision RETURNING business_date`;

function writeDay(db: D1Database, licenseId: string, at: string, d: Day) {

  const figures = TOTALS.map((key) => sum(d.hours, (h) => h[key]));
  const sections = [d.hours, d.payments, d.refunds, d.channels, d.products, d.staff, d.cash, d.cashCloses, d.inventory, d.zReports].map((section) => JSON.stringify(section));

  return db.prepare(UPSERT_DAY).bind(licenseId, d.businessDate, d.revision, d.complete ? 1 : 0, at, ...figures, ...sections);
}

/** Sending again is safe in any order: a day is replaced only by a higher revision. A day that does not add up is not published. */
export async function recordStats(db: D1Database, license: LicenseRow, input: Stats) {

  const at = new Date().toISOString();
  const problems = input.days.flatMap((day) => { const problem = dayProblem(day); return problem ? [{ date: day.businessDate, problem }] : []; });
  const refused = new Set(problems.map((p) => p.date));
  const days = input.days.filter((day) => !refused.has(day.businessDate)).map((day) => day.businessDate);
  const heartbeat = db.prepare("INSERT INTO branch_heartbeat (license_id, at, branch, live) VALUES (?1, ?2, ?3, ?4) ON CONFLICT (license_id) DO UPDATE SET at = excluded.at, branch = excluded.branch, live = excluded.live").bind(license.id, at, JSON.stringify(input.branch), JSON.stringify(input.live));
  const [, ...written] = await db.batch<{ business_date: string }>([heartbeat, ...input.days.filter((day) => !refused.has(day.businessDate)).map((day) => writeDay(db, license.id, at, day))]);
  const accepted = new Set(written.flatMap((w) => w.results.map((r) => r.business_date)));

  if (problems.length) {

    await recordFaults(db, license.id, await Promise.all(problems.map(async ({ date: day, problem }) => ({

      fingerprint: await sha256Hex(`stats|${problem}`),
      source: "worker" as const,
      severity: "error" as const,
      what: "Un día del panel no cuadra y el servidor no lo publicó",
      affected: "Panel del propietario",
      detail: `${day}: ${problem}`,
      context: {},
      version: input.branch.appVersion,
      platform: "server",
      occurrences: 1,
      firstAt: at,
      lastAt: at

    }))));

  }

  return { accepted: days.filter((d) => accepted.has(d)), ignored: days.filter((d) => !accepted.has(d)), rejected: [...refused] };
}

export const rangeSchema = z.strictObject({ from: date, to: date, branch: z.string().max(64).optional() }).refine((r) => r.from <= r.to && Date.parse(r.to) - Date.parse(r.from) <= MAX_RANGE_DAYS * 86_400_000, { message: `Periodo inválido (máximo ${MAX_RANGE_DAYS} días)`, path: ["to"] });

export type Range = { from: string; to: string };
export type BranchRow = LicenseRow & { seen_at: string | null; seen_branch: string | null; seen_live: string | null };

const SUM_TOTALS = "SUM(tickets) AS tickets, SUM(people) AS people, SUM(gross) AS gross, SUM(discounts) AS discounts, SUM(net) AS net, SUM(tax) AS tax, SUM(delivery_fees) AS deliveryFees, SUM(voided_count) AS voidedCount, SUM(voided_amount) AS voidedAmount, SUM(comps) AS comps, SUM(staff_meals) AS staffMeals";
const IN_RANGE = "d.license_id IN (SELECT value FROM json_each(?1)) AND d.business_date BETWEEN ?2 AND ?3";
const scope = (branches: BranchRow[], range: Range) => [JSON.stringify(branches.map((b) => b.id)), range.from, range.to];
const field = (name: string) => `json_extract(j.value, '$.${name}')`;
const added = (...names: string[]) => names.map((n) => `SUM(${field(n)}) AS ${n}`).join(", ");

// The date the branch itself is living: 01:30 on Saturday is still Friday night before its cutoff.
function businessDate(branch: Stats["branch"], at: number) {

  return new Date(at - branch.businessDayCutoffMinutes * 60_000).toLocaleDateString("en-CA", { timeZone: branch.timeZone });
}

const isPro = (row: BranchRow) => row.tier === "pro";

/** The first business day a Lite branch can read: its running month or its last seven days, whichever reaches further back. Older days and every comparison they allow are Pro. */
function liteFrom(row: BranchRow, at: number) {

  const today = row.seen_branch ? businessDate(JSON.parse(row.seen_branch) as Stats["branch"], at) : new Date(at).toISOString().slice(0, 10);
  const week = dayShift(today, -6), month = `${today.slice(0, 8)}01`;

  return week < month ? week : month;
}

/**
 * Who enters each figure. `shown` reaches the Lite figures; `pro` the Pro ones. `lite` names the branches left out of every Pro figure,
 * and `outOfRange` the Lite branches left out entirely because the period starts before what Lite reads.
 */
export function plans(branches: BranchRow[], range: Range, at = Date.now()) {

  const outOfRange = branches.filter((b) => !isPro(b) && range.from < liteFrom(b, at));
  const shown = branches.filter((b) => !outOfRange.includes(b));

  return { shown, pro: branches.filter(isPro), lite: branches.filter((b) => !isPro(b)).map((b) => b.id), outOfRange: outOfRange.map((b) => b.id) };
}

export function branchView(row: BranchRow, at = Date.now()) {

  const branch = row.seen_branch ? JSON.parse(row.seen_branch) as Stats["branch"] : null;
  const live = row.seen_live ? JSON.parse(row.seen_live) as Stats["live"] : null;

  return {

    licenseId: row.id,
    name: row.branch_name,
    tier: row.tier,
    licenseStatus: licenseStatus(row, at),
    lastSeenAt: row.seen_at,
    stale: !row.seen_at || at - Date.parse(row.seen_at) > STALE_MS,
    timeZone: branch?.timeZone ?? null,
    businessDate: branch ? businessDate(branch, at) : null,
    businessDayCutoffMinutes: branch?.businessDayCutoffMinutes ?? null,
    lastZ: branch?.lastZ ?? null,
    appVersion: branch?.appVersion ?? null,
    // Low stock is inventory, a Pro area.
    live: live && !isPro(row) ? { ...live, lowStock: [] } : live

  };
}

// Averages always come from the totals shown: averaging branch averages would weigh a quiet branch like a busy one.
const withAverages = <T extends Totals>(t: T) => ({ ...t, averageTicket: t.tickets ? Math.trunc(t.net / t.tickets) : 0, averagePerson: t.people ? Math.trunc(t.net / t.people) : 0 });
const blank = () => Object.fromEntries(TOTALS.map((k) => [k, 0])) as Totals;

// Cancellations, discounts, courtesies and staff meals are Pro; the gross would give the discounts away.
const PRO_TOTALS = new Set<string>(["gross", "discounts", "voidedCount", "voidedAmount", "comps", "staffMeals"]);

export async function summary(db: D1Database, branches: BranchRow[], range: Range) {

  const who = plans(branches, range);
  const shown = scope(who.shown, range), pro = scope(who.pro, range);
  // A single day's hours are what compares today with yesterday at the same hour; peak hours over a period are Pro.
  const hourly = range.from === range.to ? shown : pro;
  const section = (name: string, key: string, args: string[], ...names: string[]) => db.prepare(`SELECT ${field(key)} AS ${key}, ${added(...names)} FROM stats_day d, json_each(d.${name}) j WHERE ${IN_RANGE} GROUP BY 1 ORDER BY 1`).bind(...args);
  const [perBranch, days, hours, channels, payments, refunds] = await db.batch<Record<string, any>>([
    db.prepare(`SELECT d.license_id AS licenseId, COUNT(*) AS days, SUM(complete = 0) AS openDays, ${SUM_TOTALS} FROM stats_day d WHERE ${IN_RANGE} GROUP BY d.license_id`).bind(...shown),
    db.prepare(`SELECT d.business_date AS businessDate, SUM(tickets) AS tickets, SUM(net) AS net FROM stats_day d WHERE ${IN_RANGE} GROUP BY 1 ORDER BY 1`).bind(...shown),
    section("hours", "hour", hourly, "tickets", "net"),
    section("channels", "channel", pro, "tickets", "net"),
    section("payments", "method", pro, "amount", "tips", "count"),
    section("refunds", "method", pro, "amount", "count")
  ]);
  const found = new Map(perBranch!.results.map((r) => [r.licenseId as string, r]));
  const totals = blank();
  const rows = who.shown.map((b) => {

    const figures = found.get(b.id);
    const own = blank();

    for (const key of TOTALS) { own[key] = PRO_TOTALS.has(key) && !isPro(b) ? 0 : figures?.[key] ?? 0; totals[key] += own[key]; }

    return { ...branchView(b), hasData: figures !== undefined, openDays: figures?.openDays ?? 0, ...withAverages(own) };

  }).sort((a, b) => Number(b.hasData) - Number(a.hasData) || b.net - a.net);

  return { ...range, lite: who.lite, outOfRange: who.outOfRange, totals: withAverages(totals), partial: rows.filter((b) => b.stale || !b.hasData).map((b) => b.licenseId), branches: rows, days: days!.results, hours: hours!.results, channels: channels!.results, payments: payments!.results, refunds: refunds!.results };
}

/** Product ids belong to each branch, so across branches a product is its name and category. Margin counts only what has a recipe, and only in Pro branches. */
export async function products(db: D1Database, branches: BranchRow[], range: Range) {

  const who = plans(branches, range);
  const costed = `${field("unitCost")} IS NOT NULL AND d.license_id IN (SELECT value FROM json_each(?4))`;
  const { results } = await db.prepare(`SELECT ${field("name")} AS name, ${field("category")} AS category, ${added("quantity", "revenue")}, SUM(CASE WHEN ${costed} THEN ${field("quantity")} * ${field("unitCost")} END) AS cost, SUM(CASE WHEN ${costed} THEN 0 ELSE ${field("revenue")} END) AS revenueWithoutCost FROM stats_day d, json_each(d.products) j WHERE ${IN_RANGE} GROUP BY 1, 2 ORDER BY revenue DESC`).bind(...scope(who.shown, range), JSON.stringify(who.pro.map((b) => b.id))).all<{ name: string; category: string; quantity: number; revenue: number; cost: number | null; revenueWithoutCost: number }>();

  return { ...range, lite: who.lite, outOfRange: who.outOfRange, products: results.map((p) => ({ ...p, cost: p.cost ?? 0, estimatedMargin: p.revenue - p.revenueWithoutCost - (p.cost ?? 0) })) };
}

// Staff, cash and closings are Pro areas whole: a Lite branch never enters them.
const proOnly = (branches: BranchRow[], range: Range) => { const { pro, lite, outOfRange } = plans(branches, range); return { pro, marks: { lite, outOfRange } }; };

export async function staff(db: D1Database, branches: BranchRow[], range: Range) {

  const { pro, marks } = proOnly(branches, range);
  const names = new Map(pro.map((b) => [b.id, b.branch_name]));
  const { results } = await db.prepare(`SELECT d.license_id AS licenseId, ${field("staffId")} AS staffId, MAX(${field("name")}) AS name, ${added("tickets", "net", "tips")} FROM stats_day d, json_each(d.staff) j WHERE ${IN_RANGE} GROUP BY 1, 2 ORDER BY net DESC`).bind(...scope(pro, range)).all<{ licenseId: string }>();

  return { ...range, ...marks, staff: results.map((s) => ({ ...s, branchName: names.get(s.licenseId) })) };
}

export async function cash(db: D1Database, every: BranchRow[], range: Range) {

  const { pro: branches, marks } = proOnly(every, range);

  const part = (column: string, name: string) => `SUM(json_extract(d.${column}, '$.${name}')) AS ${name}`;
  const [moved, closes] = await db.batch<Record<string, any>>([
    db.prepare(`SELECT ${part("cash", "income")}, ${part("cash", "expense")}, ${part("cash", "withdrawal")}, ${part("inventory", "waste")}, ${part("inventory", "shortage")}, ${part("inventory", "surplus")} FROM stats_day d WHERE ${IN_RANGE}`).bind(...scope(branches, range)),
    db.prepare(`SELECT d.license_id AS licenseId, d.business_date AS businessDate, ${field("cashId")} AS cashId, ${field("closedAt")} AS closedAt, ${field("blind")} AS blind, ${field("cashDifference")} AS cashDifference, ${field("cardDifference")} AS cardDifference, ${field("transferDifference")} AS transferDifference, ${field("adjustments")} AS adjustments FROM stats_day d, json_each(d.cash_closes) j WHERE ${IN_RANGE} ORDER BY 4 DESC LIMIT 500`).bind(...scope(branches, range))
  ]);
  const row = moved!.results[0] ?? {};

  return { ...range, ...marks, cash: { income: row.income ?? 0, expense: row.expense ?? 0, withdrawal: row.withdrawal ?? 0 }, inventory: { waste: row.waste ?? 0, shortage: row.shortage ?? 0, surplus: row.surplus ?? 0 }, closes: closes!.results.map((c) => ({ ...c, blind: c.blind === 1 })) };
}

const dayShift = (value: string, days: number) => new Date(Date.parse(value) + days * 86_400_000).toISOString().slice(0, 10);

/** Each close beside what the panel counts for it. A difference means an account was reopened after that close. */
export async function closings(db: D1Database, every: BranchRow[], range: Range) {

  const { pro: branches, marks } = proOnly(every, range);
  const { results } = await db.prepare(`SELECT d.license_id AS licenseId, d.business_date AS businessDate, j.value AS report FROM stats_day d, json_each(d.z_reports) j WHERE ${IN_RANGE} ORDER BY 2 DESC LIMIT 500`).bind(...scope(branches, range)).all<{ licenseId: string; businessDate: string; report: string }>();

  if (!results.length) return { ...range, ...marks, closings: [] };

  const reports = results.map((r) => ({ ...r, z: JSON.parse(r.report) as Day["zReports"][number] }));
  // The sales of a close happen between its from and to, so the business days around them hold all its hours.
  const around = { from: dayShift(reports.map((r) => r.z.from.slice(0, 10)).sort()[0]!, -2), to: dayShift(reports.map((r) => r.z.to.slice(0, 10)).sort().at(-1)!, 2) };
  const { results: counted } = await db.prepare(`SELECT d.license_id AS licenseId, ${field("z")} AS z, ${added("tickets", "net")} FROM stats_day d, json_each(d.hours) j WHERE ${IN_RANGE} GROUP BY 1, 2`).bind(...scope(branches, around)).all<{ licenseId: string; z: number; tickets: number; net: number }>();
  const panel = new Map(counted.map((c) => [`${c.licenseId}|${c.z}`, c]));
  const names = new Map(branches.map((b) => [b.id, b.branch_name]));

  return { ...range, ...marks, closings: reports.map(({ licenseId, businessDate, z }) => {

    const own = panel.get(`${licenseId}|${z.number}`);

    return { licenseId, branchName: names.get(licenseId), businessDate, ...z, panelTickets: own?.tickets ?? 0, panelNet: own?.net ?? 0, reopenedTickets: z.tickets - (own?.tickets ?? 0), reopenedNet: z.net - (own?.net ?? 0) };

  }) };
}
