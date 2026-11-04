import { z } from "zod";
import { added, businessDate, dayShift, field, IN_RANGE, plans, proOnly, scope, type BranchRow, type Range, type Stats } from "./stats";

// What the owner decides for the panel. Nothing here reaches a branch: shifts, goals, fixed costs and targets only
// change how the panel reads what the branches sent.
const money = z.int().min(0).max(100_000_000_000);
const license = z.string().max(64);
const bps = z.int().min(100).max(9000);

export const settingsSchema = z.strictObject({

  shifts: z.array(z.strictObject({ name: z.string().trim().min(1).max(40), start: z.int().min(0).max(23) })).min(1).max(6).refine((s) => new Set(s.map((x) => x.start)).size === s.length, { message: "Dos turnos no pueden empezar a la misma hora" }),
  goals: z.array(z.strictObject({ licenseId: license, period: z.enum(["day", "month", "year"]), amount: money.min(1) })).max(100),
  fixedCosts: z.array(z.strictObject({ licenseId: license, name: z.string().trim().min(1).max(80), monthly: money })).max(100),
  foodCostTargetBps: bps,
  laborTargetBps: bps,
  countClockLabor: z.boolean(),
  locations: z.array(z.strictObject({ licenseId: license.min(1), label: z.string().trim().min(1).max(120), lat: z.number().min(-90).max(90), lon: z.number().min(-180).max(180) })).max(100)

});

export type Settings = z.infer<typeof settingsSchema>;

export const DEFAULT_SETTINGS: Settings = {

  shifts: [{ name: "Mañana", start: 7 }, { name: "Comida", start: 12 }, { name: "Noche", start: 18 }],
  goals: [],
  fixedCosts: [],
  foodCostTargetBps: 3000,
  laborTargetBps: 3000,
  countClockLabor: true,
  locations: []

};

export async function readSettings(db: D1Database, tenantId: string): Promise<Settings> {

  const row = await db.prepare("SELECT value FROM owner_setting WHERE tenant_id = ?").bind(tenantId).first<{ value: string }>();
  const saved = row ? settingsSchema.partial().safeParse(JSON.parse(row.value)) : null;

  return { ...DEFAULT_SETTINGS, ...(saved?.success ? saved.data : {}) };
}

export async function writeSettings(db: D1Database, tenantId: string, accountId: string, settings: Settings) {

  await db.prepare("INSERT INTO owner_setting (tenant_id, value, updated_at, updated_by) VALUES (?1, ?2, ?3, ?4) ON CONFLICT (tenant_id) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at, updated_by = excluded.updated_by").bind(tenantId, JSON.stringify(settings), new Date().toISOString(), accountId).run();
}

const sum = <T>(rows: readonly T[], read: (row: T) => number) => rows.reduce((total, row) => total + read(row), 0);
const ratioBps = (part: number, whole: number) => whole ? Math.round(part * 10_000 / whole) : 0;
const each = (section: string) => `json_each(d.insights, '$.${section}') j`;
const ids = (branches: BranchRow[]) => JSON.stringify(branches.map((b) => b.id));
const names = (branches: BranchRow[]) => new Map(branches.map((b) => [b.id, b.branch_name]));
const all = async <T>(statement: D1PreparedStatement) => (await statement.all<T>()).results;
const median = (values: number[]) => { if (!values.length) return 0; const sorted = [...values].sort((a, b) => a - b); const mid = Math.floor(sorted.length / 2); return sorted.length % 2 ? sorted[mid]! : (sorted[mid - 1]! + sorted[mid]!) / 2; };
const live = (b: BranchRow) => (b.seen_live ? JSON.parse(b.seen_live) as Stats["live"] : null);
const todayOf = (branches: BranchRow[], at = Date.now()) => { const seen = branches.find((b) => b.seen_branch); return seen ? businessDate(JSON.parse(seen.seen_branch!) as Stats["branch"], at) : new Date(at).toISOString().slice(0, 10); };
const daysBetween = (range: Range) => Math.round((Date.parse(range.to) - Date.parse(range.from)) / 86_400_000) + 1;
const weekday = (date: string) => new Date(`${date}T12:00:00Z`).getUTCDay();

/** The hour each shift covers: from its start to the next start, and the last one wraps past midnight. */
export function shiftOf(shifts: Settings["shifts"], hour: number) {

  const sorted = [...shifts].sort((a, b) => a.start - b.start);

  return [...sorted].reverse().find((s) => s.start <= hour) ?? sorted.at(-1)!;
}

/** Areas and shifts split the sales everyone can read, so Lite reaches them too. */
export async function summaryExtras(db: D1Database, branches: BranchRow[], range: Range, settings: Settings) {

  const who = plans(branches, range);
  const args = scope(who.shown, range);
  const [areas, hours] = await db.batch<Record<string, any>>([
    db.prepare(`SELECT ${field("area")} AS area, ${added("tickets", "people", "net")} FROM stats_day d, ${each("areas")} WHERE ${IN_RANGE} GROUP BY 1 ORDER BY net DESC`).bind(...args),
    db.prepare(`SELECT ${field("hour")} AS hour, ${added("tickets", "people", "net")} FROM stats_day d, json_each(d.hours) j WHERE ${IN_RANGE} GROUP BY 1`).bind(...args)
  ]);
  const sorted = [...settings.shifts].sort((a, b) => a.start - b.start);
  const shifts = sorted.map((s, i) => ({ name: s.name, start: s.start, end: sorted[(i + 1) % sorted.length]!.start, tickets: 0, people: 0, net: 0 }));

  for (const h of hours!.results) { const s = shifts.find((x) => x.name === shiftOf(settings.shifts, h.hour).name)!; s.tickets += h.tickets; s.people += h.people; s.net += h.net; }

  return { areas: areas!.results, shifts: shifts.map((s) => ({ ...s, averageTicket: s.tickets ? Math.trunc(s.net / s.tickets) : 0 })) };
}

const periodKey = (date: string, by: "week" | "month" | "year") => {

  if (by === "year") return date.slice(0, 4);
  if (by === "month") return date.slice(0, 7);

  const day = (weekday(date) + 6) % 7;

  return dayShift(date, -day);
};
const lastYear = (date: string) => `${Number(date.slice(0, 4)) - 1}${date.slice(4)}`.replace(/-02-29$/, "-02-28");

/** Days, weeks, months or years, each beside the same stretch a year before. Comparisons are Pro. */
export async function trend(db: D1Database, branches: BranchRow[], range: Range, by: "week" | "month" | "year") {

  const { pro, marks } = proOnly(branches, range);
  const earlier = { from: lastYear(range.from), to: lastYear(range.to) };
  const query = (r: Range) => db.prepare(`SELECT d.business_date AS businessDate, SUM(tickets) AS tickets, SUM(people) AS people, SUM(net) AS net FROM stats_day d WHERE ${IN_RANGE} GROUP BY 1 ORDER BY 1`).bind(...scope(pro, r));
  const [now, before] = await db.batch<{ businessDate: string; tickets: number; people: number; net: number }>([query(range), query(earlier)]);
  const periods = new Map<string, { key: string; from: string; to: string; tickets: number; people: number; net: number; lastYearNet: number; lastYearTickets: number; days: number }>();

  for (const d of now!.results) {

    const key = periodKey(d.businessDate, by);
    const p = periods.get(key) ?? { key, from: d.businessDate, to: d.businessDate, tickets: 0, people: 0, net: 0, lastYearNet: 0, lastYearTickets: 0, days: 0 };

    p.tickets += d.tickets; p.people += d.people; p.net += d.net; p.days += 1; p.to = d.businessDate;
    periods.set(key, p);

  }
  // A day a year before belongs to the period of the date it compares with.
  for (const d of before!.results) {

    const key = periodKey(`${Number(d.businessDate.slice(0, 4)) + 1}${d.businessDate.slice(4)}`, by);
    const p = periods.get(key);

    if (p) { p.lastYearNet += d.net; p.lastYearTickets += d.tickets; }

  }

  const rows = [...periods.values()].sort((a, b) => a.key.localeCompare(b.key)).map((p) => ({ ...p, averageTicket: p.tickets ? Math.trunc(p.net / p.tickets) : 0, growthBps: p.lastYearNet ? ratioBps(p.net - p.lastYearNet, p.lastYearNet) : null }));

  return { ...range, ...marks, by, periods: rows, total: sum(rows, (r) => r.net), lastYearTotal: sum(rows, (r) => r.lastYearNet), hasLastYear: before!.results.length > 0 };
}

/** Each goal against what is sold so far, and the pace that would reach it by the end of its period. */
export async function goals(db: D1Database, branches: BranchRow[], settings: Settings, chosen?: string, at = Date.now()) {

  const today = todayOf(branches, at);
  const mine = settings.goals.filter((g) => chosen ? g.licenseId === chosen : true).filter((g) => !g.licenseId || branches.some((b) => b.id === g.licenseId));
  const own = names(branches);
  const out = [];

  for (const g of mine) {

    const from = g.period === "day" ? today : g.period === "month" ? `${today.slice(0, 7)}-01` : `${today.slice(0, 4)}-01-01`;
    const end = g.period === "day" ? today : g.period === "month" ? dayShift(`${dayShift(`${today.slice(0, 7)}-28`, 4).slice(0, 7)}-01`, -1) : `${today.slice(0, 4)}-12-31`;
    const range = { from, to: today };
    const who = plans(branches.filter((b) => !g.licenseId || b.id === g.licenseId), range, at);
    const row = await db.prepare(`SELECT SUM(net) AS net, SUM(tickets) AS tickets FROM stats_day d WHERE ${IN_RANGE}`).bind(...scope(who.shown, range)).first<{ net: number | null; tickets: number | null }>();
    const actual = row?.net ?? 0;
    const elapsed = daysBetween(range), length = daysBetween({ from, to: end });
    const expected = Math.round(g.amount * elapsed / length);

    out.push({ licenseId: g.licenseId, branchName: g.licenseId ? own.get(g.licenseId) ?? null : null, period: g.period, from, to: end, target: g.amount, actual, tickets: row?.tickets ?? 0, progressBps: ratioBps(actual, g.amount), expected, projected: Math.round(actual * length / elapsed), pace: g.period === "day" ? actual >= g.amount ? "reached" : "open" : actual >= expected ? "ahead" : actual >= expected * 0.9 ? "close" : "behind", outOfRange: who.outOfRange });

  }

  return { today, goals: out };
}

type MenuRow = { name: string; category: string; quantity: number; revenue: number; cost: number | null; revenueWithoutCost: number };
const CLASS_ADVICE = { star: "Cuídalo: mantén receta, porción y lugar en la carta.", plowhorse: "Se vende mucho y deja poco: sube el precio poco a poco o baja el costo de la receta.", puzzle: "Deja buen margen pero se pide poco: recomiéndalo, muévelo a un lugar visible o renómbralo.", dog: "Se pide poco y deja poco: considera quitarlo o rediseñarlo." } as const;

/**
 * Menu engineering after Kasavana and Smith: popular when its share of units reaches 70 % of an even share; profitable
 * when its margin per unit reaches the average of the menu. Only dishes with a recipe for every unit sold enter it.
 */
export async function menu(db: D1Database, branches: BranchRow[], range: Range, settings: Settings) {

  const { pro, marks } = proOnly(branches, range);
  const args = scope(pro, range);
  const [products, kinds, days, hours] = await db.batch<Record<string, any>>([
    db.prepare(`SELECT ${field("name")} AS name, ${field("category")} AS category, ${added("quantity", "revenue")}, SUM(CASE WHEN ${field("unitCost")} IS NOT NULL THEN ${field("quantity")} * ${field("unitCost")} END) AS cost, SUM(CASE WHEN ${field("unitCost")} IS NULL THEN ${field("revenue")} ELSE 0 END) AS revenueWithoutCost FROM stats_day d, json_each(d.products) j WHERE ${IN_RANGE} GROUP BY 1, 2 ORDER BY revenue DESC`).bind(...args),
    db.prepare(`SELECT ${field("kind")} AS kind, ${added("quantity", "revenue")} FROM stats_day d, ${each("kinds")} WHERE ${IN_RANGE} GROUP BY 1 ORDER BY revenue DESC`).bind(...args),
    db.prepare(`SELECT d.business_date AS businessDate, SUM(net) AS net FROM stats_day d WHERE ${IN_RANGE} GROUP BY 1`).bind(...args),
    db.prepare(`SELECT ${field("hour")} AS hour, ${added("net")} FROM stats_day d, json_each(d.hours) j WHERE ${IN_RANGE} GROUP BY 1`).bind(...args)
  ]);
  const rows = products!.results as MenuRow[];
  const costed = rows.filter((p) => p.quantity > 0 && p.revenueWithoutCost === 0 && p.cost !== null);
  const units = sum(costed, (p) => p.quantity), margin = sum(costed, (p) => p.revenue - (p.cost ?? 0));
  const popular = costed.length ? 0.7 / costed.length : 0, averageMargin = units ? Math.trunc(margin / units) : 0;
  const target = settings.foodCostTargetBps;
  const items = costed.map((p) => {

    const unitMargin = Math.trunc((p.revenue - p.cost!) / p.quantity), share = p.quantity / units;
    const high = share >= popular, rich = unitMargin >= averageMargin;
    const kind = high && rich ? "star" : high ? "plowhorse" : rich ? "puzzle" : "dog";
    const foodCostBps = ratioBps(p.cost!, p.revenue), unitCost = p.cost! / p.quantity, price = Math.trunc(p.revenue / p.quantity);
    // The lowest whole peso that brings the dish back to the target food cost. A suggestion: the branch sets prices.
    const suggestedPrice = foodCostBps > target ? Math.ceil(unitCost * 10_000 / target / 100) * 100 : null;

    return { name: p.name, category: p.category, quantity: p.quantity, revenue: p.revenue, cost: p.cost!, unitMargin, shareBps: Math.round(share * 10_000), foodCostBps, price, suggestedPrice, class: kind, advice: CLASS_ADVICE[kind] };

  });
  // Demand by weekday and hour, to say when a promotion fills a slow stretch and when a discount gives money away.
  const byWeekday = Array.from({ length: 7 }, (_, day) => { const own = days!.results.filter((d) => weekday(d.businessDate) === day); return { weekday: day, days: own.length, average: own.length ? Math.trunc(sum(own, (d) => d.net) / own.length) : 0 }; });
  const withDays = byWeekday.filter((w) => w.days > 0), overall = withDays.length ? sum(withDays, (w) => w.average) / withDays.length : 0;
  const slow = withDays.filter((w) => w.average < overall * 0.8).map((w) => ({ ...w, belowBps: ratioBps(overall - w.average, overall) }));
  const hourAverage = hours!.results.length ? sum(hours!.results, (h) => h.net) / hours!.results.length : 0;
  const peaks = hours!.results.filter((h) => h.net > hourAverage * 1.5).map((h) => ({ hour: h.hour, net: h.net, aboveBps: ratioBps(h.net - hourAverage, hourAverage) })).sort((a, b) => b.net - a.net);
  const own = names(pro);
  const snapshot = pro.flatMap((b) => { const l = live(b); return l ? [{ b, l }] : []; });

  return {

    ...range, ...marks, foodCostTargetBps: target,
    kinds: kinds!.results, items, thresholds: { popularShareBps: Math.round(popular * 10_000), averageMargin },
    uncosted: rows.filter((p) => p.revenueWithoutCost > 0).map((p) => ({ name: p.name, category: p.category, revenue: p.revenueWithoutCost })),
    totals: { revenue: sum(rows, (p) => p.revenue), costedRevenue: sum(costed, (p) => p.revenue), cost: sum(costed, (p) => p.cost!), foodCostBps: ratioBps(sum(costed, (p) => p.cost!), sum(costed, (p) => p.revenue)) },
    weekdays: byWeekday, slowDays: slow, peakHours: peaks,
    costAlerts: snapshot.flatMap(({ b, l }) => (l.costAlerts ?? []).map((a) => ({ ...a, licenseId: b.id, branchName: own.get(b.id) }))),
    expiring: snapshot.flatMap(({ b, l }) => (l.expiring ?? []).map((e) => ({ ...e, licenseId: b.id, branchName: own.get(b.id) }))).sort((a, b) => a.days - b.days)

  };
}

/** What is left of the sales once the cost of what was sold, waste, expenses, labour and fixed costs are paid. */
export async function profit(db: D1Database, branches: BranchRow[], range: Range, settings: Settings, chosen?: string) {

  const { pro, marks } = proOnly(branches, range);
  const args = scope(pro, range);
  const [totals, products, expenses, labor] = await db.batch<Record<string, any>>([
    db.prepare(`SELECT SUM(net) AS net, SUM(tax) AS tax, SUM(json_extract(d.inventory, '$.waste')) AS waste, SUM(json_extract(d.inventory, '$.shortage')) AS shortage, SUM(json_extract(d.inventory, '$.surplus')) AS surplus FROM stats_day d WHERE ${IN_RANGE}`).bind(...args),
    db.prepare(`SELECT SUM(CASE WHEN ${field("unitCost")} IS NOT NULL THEN ${field("quantity")} * ${field("unitCost")} ELSE 0 END) AS cost, SUM(CASE WHEN ${field("unitCost")} IS NULL THEN ${field("revenue")} ELSE 0 END) AS revenueWithoutCost, SUM(${field("revenue")}) AS revenue FROM stats_day d, json_each(d.products) j WHERE ${IN_RANGE}`).bind(...args),
    db.prepare(`SELECT ${field("account")} AS account, ${added("amount", "count")} FROM stats_day d, ${each("expenses")} WHERE ${IN_RANGE} GROUP BY 1 ORDER BY amount DESC`).bind(...args),
    db.prepare(`SELECT ${added("minutes", "cost")} FROM stats_day d, ${each("labor")} WHERE ${IN_RANGE}`).bind(...args)
  ]);
  const t = totals!.results[0] ?? {}, p = products!.results[0] ?? {}, l = labor!.results[0] ?? {};
  const sales = (t.net ?? 0) - (t.tax ?? 0);
  const inScope = new Set(pro.map((b) => b.id));
  // A cost of the whole business counts only when the whole business is in view.
  const fixed = settings.fixedCosts.filter((f) => f.licenseId ? inScope.has(f.licenseId) : !chosen).map((f) => ({ ...f, amount: Math.round(f.monthly * 12 * daysBetween(range) / 365) }));
  const spent = sum(expenses!.results, (e) => e.amount);
  const laborCost = settings.countClockLabor ? l.cost ?? 0 : 0;
  const waste = (t.waste ?? 0) + (t.shortage ?? 0) - (t.surplus ?? 0);
  const cogs = p.cost ?? 0;
  const result = sales - cogs - waste - spent - laborCost - sum(fixed, (f) => f.amount);

  return {

    ...range, ...marks,
    net: t.net ?? 0, tax: t.tax ?? 0, sales, cogs, revenueWithoutCost: p.revenueWithoutCost ?? 0, waste,
    expenses: expenses!.results, expensesTotal: spent,
    labor: { minutes: l.minutes ?? 0, cost: l.cost ?? 0, counted: settings.countClockLabor },
    fixed, fixedTotal: sum(fixed, (f) => f.amount),
    profit: result, marginBps: ratioBps(result, sales), foodCostBps: ratioBps(cogs, (p.revenue ?? 0) - (p.revenueWithoutCost ?? 0)), laborBps: ratioBps(l.cost ?? 0, sales)

  };
}

const ANOMALY_KEYS = ["voids", "discounts", "rejected", "reopens", "drawerOpens"] as const;
const ANOMALY_LABEL: Record<(typeof ANOMALY_KEYS)[number], string> = { voids: "cancelaciones", discounts: "descuentos y cortesías", rejected: "solicitudes rechazadas", reopens: "cuentas reabiertas", drawerOpens: "aperturas de cajón sin venta" };

/** Each person's sales beside their hours; labour beside the sales of each hour; and patterns worth a look. */
export async function team(db: D1Database, branches: BranchRow[], range: Range, settings: Settings, role: "owner" | "manager", at = Date.now()) {

  const { pro, marks } = proOnly(branches, range);
  const args = scope(pro, range);
  const history = { from: dayShift(todayOf(pro, at), -56), to: dayShift(todayOf(pro, at), -1) };
  const [staff, people, labor, hours, couriers, pastHours, pastLabor] = await db.batch<Record<string, any>>([
    db.prepare(`SELECT d.license_id AS licenseId, ${field("staffId")} AS staffId, MAX(${field("name")}) AS name, ${added("tickets", "net", "tips")} FROM stats_day d, json_each(d.staff) j WHERE ${IN_RANGE} GROUP BY 1, 2`).bind(...args),
    db.prepare(`SELECT d.license_id AS licenseId, ${field("staffId")} AS staffId, MAX(${field("name")}) AS name, MAX(${field("role")}) AS role, ${added("people", "tables", "voids", "voidAmount", "discounts", "discountAmount", "rejected", "reopens", "drawerOpens", "minutes", "laborCost")} FROM stats_day d, ${each("team")} WHERE ${IN_RANGE} GROUP BY 1, 2`).bind(...args),
    db.prepare(`SELECT ${field("hour")} AS hour, ${added("minutes", "cost")} FROM stats_day d, ${each("labor")} WHERE ${IN_RANGE} GROUP BY 1`).bind(...args),
    db.prepare(`SELECT ${field("hour")} AS hour, ${added("net")} FROM stats_day d, json_each(d.hours) j WHERE ${IN_RANGE} GROUP BY 1`).bind(...args),
    db.prepare(`SELECT d.license_id AS licenseId, ${field("courierId")} AS courierId, MAX(${field("name")}) AS name, ${added("deliveries", "net")} FROM stats_day d, ${each("couriers")} WHERE ${IN_RANGE} GROUP BY 1, 2 ORDER BY net DESC`).bind(...args),
    db.prepare(`SELECT d.business_date AS businessDate, ${field("hour")} AS hour, ${added("net")} FROM stats_day d, json_each(d.hours) j WHERE ${IN_RANGE} GROUP BY 1, 2`).bind(...scope(pro, history)),
    db.prepare(`SELECT d.business_date AS businessDate, ${field("hour")} AS hour, ${added("minutes", "cost")} FROM stats_day d, ${each("labor")} WHERE ${IN_RANGE} GROUP BY 1, 2`).bind(...scope(pro, history))
  ]);
  const own = names(pro);
  const key = (r: { licenseId: string; staffId: string }) => `${r.licenseId}|${r.staffId}`;
  const merged = new Map<string, any>();

  for (const r of [...staff!.results, ...people!.results]) merged.set(key(r as any), { tickets: 0, net: 0, tips: 0, people: 0, tables: 0, voids: 0, voidAmount: 0, discounts: 0, discountAmount: 0, rejected: 0, reopens: 0, drawerOpens: 0, minutes: 0, laborCost: 0, role: "", ...merged.get(key(r as any)), ...Object.fromEntries(Object.entries(r).filter(([, v]) => v !== null)), branchName: own.get(r.licenseId) });

  const rows = [...merged.values()].map((r) => ({ ...r, averageTicket: r.tickets ? Math.trunc(r.net / r.tickets) : 0, salesPerHour: r.minutes ? Math.trunc(r.net * 60 / r.minutes) : null })).sort((a, b) => b.net - a.net);
  const tips = sum(rows, (r) => r.tips), minutes = sum(rows, (r) => r.minutes);
  // Tips by hours worked, by largest remainder so the shares add up to the cent.
  const pool = rows.filter((r) => r.minutes > 0).map((r) => ({ licenseId: r.licenseId, staffId: r.staffId, name: r.name, branchName: r.branchName, minutes: r.minutes, exact: minutes ? tips * r.minutes / minutes : 0 }));
  let left = tips - sum(pool, (p) => Math.floor(p.exact));
  const shares = pool.map((p) => ({ ...p, share: Math.floor(p.exact) })).sort((a, b) => (b.exact - Math.floor(b.exact)) - (a.exact - Math.floor(a.exact)));

  for (const s of shares) { if (left <= 0) break; s.share += 1; left -= 1; }

  const net = sum(hours!.results, (h) => h.net), laborCost = sum(labor!.results, (h) => h.cost);
  const byHour = Array.from({ length: 24 }, (_, hour) => ({ hour, net: hours!.results.find((h) => h.hour === hour)?.net ?? 0, minutes: labor!.results.find((h) => h.hour === hour)?.minutes ?? 0, cost: labor!.results.find((h) => h.hour === hour)?.cost ?? 0 })).filter((h) => h.net || h.minutes).map((h) => ({ ...h, laborBps: ratioBps(h.cost, h.net) }));
  // Patterns are compared with the colleagues of the same branch: a count at least twice the usual and three or more.
  const anomalies = role !== "owner" ? [] : pro.flatMap((b) => {

    const mates = rows.filter((r) => r.licenseId === b.id);

    return ANOMALY_KEYS.flatMap((metric) => {

      const usual = median(mates.map((r) => r[metric] as number));

      return mates.filter((r) => r[metric] >= 3 && r[metric] >= 2 * Math.max(usual, 1)).map((r) => ({ licenseId: b.id, branchName: own.get(b.id), staffId: r.staffId, name: r.name, metric, label: ANOMALY_LABEL[metric], value: r[metric] as number, usual, amount: metric === "voids" ? r.voidAmount : metric === "discounts" ? r.discountAmount : 0 }));

    });

  }).sort((a, b) => b.value / Math.max(b.usual, 1) - a.value / Math.max(a.usual, 1));
  // A suggested crew per weekday and hour: the average sales of the last eight weeks at the labour target, with the
  // average wage those weeks paid.
  const wage = sum(pastLabor!.results, (l) => l.minutes) ? sum(pastLabor!.results, (l) => l.cost) * 60 / sum(pastLabor!.results, (l) => l.minutes) : 0;
  const weeks = 8;
  const cells = new Map<string, { weekday: number; hour: number; net: number; minutes: number }>();

  for (const h of pastHours!.results) { const k = `${weekday(h.businessDate)}|${h.hour}`; const c = cells.get(k) ?? { weekday: weekday(h.businessDate), hour: h.hour, net: 0, minutes: 0 }; c.net += h.net; cells.set(k, c); }
  for (const h of pastLabor!.results) { const k = `${weekday(h.businessDate)}|${h.hour}`; const c = cells.get(k) ?? { weekday: weekday(h.businessDate), hour: h.hour, net: 0, minutes: 0 }; c.minutes += h.minutes; cells.set(k, c); }

  const schedule = wage > 0 ? [...cells.values()].map((c) => ({ weekday: c.weekday, hour: c.hour, expectedNet: Math.round(c.net / weeks), currentPeople: Math.round(c.minutes / 60 / weeks * 10) / 10, suggestedPeople: Math.max(c.net > 0 ? 1 : 0, Math.floor(c.net / weeks * settings.laborTargetBps / 10_000 / wage)) })).sort((a, b) => a.weekday - b.weekday || a.hour - b.hour) : [];
  const snapshot = pro.flatMap((b) => { const l = live(b); return l && !(at - Date.parse(b.seen_at ?? "") > 15 * 60_000) ? [l] : []; });
  const months = new Map<string, { month: string; hires: number; exits: number; headcount: number }>();

  for (const l of pro.flatMap((b) => live(b)?.roster?.months ?? [])) { const m = months.get(l.month) ?? { month: l.month, hires: 0, exits: 0, headcount: 0 }; m.hires += l.hires; m.exits += l.exits; m.headcount += l.headcount; months.set(l.month, m); }

  const roster = [...months.values()].sort((a, b) => a.month.localeCompare(b.month));
  const averageHeadcount = roster.length ? sum(roster, (m) => m.headcount) / roster.length : 0;

  return {

    ...range, ...marks, laborTargetBps: settings.laborTargetBps,
    staff: rows, couriers: couriers!.results.map((c) => ({ ...c, branchName: own.get(c.licenseId) })),
    labor: { minutes, cost: laborCost, net, laborBps: ratioBps(laborCost, net), byHour, now: { people: sum(snapshot, (l) => l.onClock?.people ?? 0), hourlyCost: sum(snapshot, (l) => l.onClock?.hourlyCost ?? 0) } },
    tips: { total: tips, minutes, shares: shares.sort((a, b) => b.share - a.share).map(({ exact: _, ...s }) => s) },
    anomalies, schedule, averageWage: Math.round(wage),
    roster: { active: sum(pro, (b) => live(b)?.roster?.active ?? 0), months: roster, hires: sum(roster, (m) => m.hires), exits: sum(roster, (m) => m.exits), turnoverBps: averageHeadcount ? ratioBps(sum(roster, (m) => m.exits), averageHeadcount) : 0 }

  };
}

const REASONS: Record<string, string> = { cold: "Llegó frío", doneness: "Término equivocado", foreign: "Cabello u objeto", taste: "Sabor", wrong: "No era lo pedido", late: "Tardó demasiado", other: "Otro" };

/** How long each dish takes, where the kitchen slows down, what comes back and how often a promise is kept. */
export async function kitchen(db: D1Database, branches: BranchRow[], range: Range) {

  const { pro, marks } = proOnly(branches, range);
  const args = scope(pro, range);
  const [dishes, returns, sold, promises] = await db.batch<Record<string, any>>([
    db.prepare(`SELECT ${field("name")} AS name, MAX(${field("station")}) AS station, ${added("count", "waitSeconds", "prepSeconds", "passCount", "passSeconds")}, MAX(${field("maxSeconds")}) AS maxSeconds FROM stats_day d, ${each("kitchen")} WHERE ${IN_RANGE} GROUP BY 1`).bind(...args),
    db.prepare(`SELECT ${field("name")} AS name, ${field("reason")} AS reason, ${added("count")} FROM stats_day d, ${each("returns")} WHERE ${IN_RANGE} GROUP BY 1, 2 ORDER BY count DESC`).bind(...args),
    db.prepare(`SELECT ${field("name")} AS name, ${added("quantity")} FROM stats_day d, json_each(d.products) j WHERE ${IN_RANGE} GROUP BY 1`).bind(...args),
    db.prepare(`SELECT ${field("mode")} AS mode, ${added("count", "late", "promisedSeconds", "actualSeconds")} FROM stats_day d, ${each("promises")} WHERE ${IN_RANGE} GROUP BY 1`).bind(...args)
  ]);
  type Dish = { name: string; station: string; count: number; waitSeconds: number; prepSeconds: number; passCount: number; passSeconds: number; maxSeconds: number };
  const rows = (dishes!.results as Dish[]).map((d) => ({ ...d, averageSeconds: Math.round((d.waitSeconds + d.prepSeconds) / d.count), averagePrep: Math.round(d.prepSeconds / d.count), averageWait: Math.round(d.waitSeconds / d.count), averagePass: d.passCount ? Math.round(d.passSeconds / d.passCount) : null })).sort((a, b) => b.averageSeconds - a.averageSeconds);
  const stations = [...rows.reduce((all, d) => { const s = all.get(d.station) ?? { station: d.station, count: 0, seconds: 0, maxSeconds: 0 }; s.count += d.count; s.seconds += d.waitSeconds + d.prepSeconds; s.maxSeconds = Math.max(s.maxSeconds, d.maxSeconds); return all.set(d.station, s); }, new Map<string, { station: string; count: number; seconds: number; maxSeconds: number }>()).values()].map((s) => ({ ...s, averageSeconds: Math.round(s.seconds / s.count) })).sort((a, b) => b.averageSeconds - a.averageSeconds);
  const quantity = new Map(sold!.results.map((s) => [s.name as string, s.quantity as number]));
  const byDish = [...returns!.results.reduce((all, r) => { const d = all.get(r.name) ?? { name: r.name, count: 0, reasons: [] as { reason: string; label: string; count: number }[] }; d.count += r.count; d.reasons.push({ reason: r.reason, label: REASONS[r.reason] ?? r.reason, count: r.count }); return all.set(r.name, d); }, new Map<string, { name: string; count: number; reasons: { reason: string; label: string; count: number }[] }>()).values()].map((d) => ({ ...d, sold: quantity.get(d.name) ?? 0, rateBps: ratioBps(d.count, quantity.get(d.name) ?? 0) })).sort((a, b) => b.count - a.count);
  const reasons = Object.keys(REASONS).map((reason) => ({ reason, label: REASONS[reason], count: sum(returns!.results.filter((r) => r.reason === reason), (r) => r.count) })).filter((r) => r.count > 0);
  const prepared = sum(rows, (d) => d.count), returned = sum(byDish, (d) => d.count);

  return {

    ...range, ...marks,
    totals: { dishes: prepared, averageSeconds: prepared ? Math.round(sum(rows, (d) => d.waitSeconds + d.prepSeconds) / prepared) : 0, returns: returned, returnBps: ratioBps(returned, sum(sold!.results, (s) => s.quantity)) },
    dishes: rows, stations, returns: byDish, reasons,
    promises: promises!.results.map((p) => ({ ...p, onTimeBps: ratioBps(p.count - p.late, p.count), averagePromised: Math.round(p.promisedSeconds / p.count), averageActual: Math.round(p.actualSeconds / p.count) }))

  };
}

/** Guests the branches know, only as counts: how many return, how often and what they are worth; and how they rate. */
export async function customers(db: D1Database, branches: BranchRow[], range: Range) {

  const { pro, marks } = proOnly(branches, range);
  const args = scope(pro, range);
  const path = (section: string, name: string) => `SUM(json_extract(d.insights, '$.${section}.${name}')) AS ${section}_${name}`;
  const [figures, dishes] = await db.batch<Record<string, any>>([
    db.prepare(`SELECT SUM(tickets) AS tickets, SUM(net) AS net, ${["tickets", "net", "first", "repeat"].map((n) => path("customers", n)).join(", ")}, ${["count", "food", "service", "overall", "low"].map((n) => path("reviews", n)).join(", ")} FROM stats_day d WHERE ${IN_RANGE}`).bind(...args),
    db.prepare(`SELECT ${field("name")} AS name, ${added("count", "overall")} FROM stats_day d, ${each("reviewProducts")} WHERE ${IN_RANGE} GROUP BY 1`).bind(...args)
  ]);
  const f = figures!.results[0] ?? {};
  const known = pro.flatMap((b) => live(b)?.customers ? [live(b)!.customers!] : []);
  const identified = sum(known, (c) => c.identified);
  const reviews = f.reviews_count ?? 0;
  const rated = dishes!.results.filter((d) => d.count >= 3).map((d) => ({ name: d.name, count: d.count, averageTenths: Math.round(d.overall * 10 / d.count) }));

  return {

    ...range, ...marks,
    period: { tickets: f.tickets ?? 0, net: f.net ?? 0, identifiedTickets: f.customers_tickets ?? 0, identifiedNet: f.customers_net ?? 0, first: f.customers_first ?? 0, repeat: f.customers_repeat ?? 0, identifiedBps: ratioBps(f.customers_tickets ?? 0, f.tickets ?? 0), averageIdentified: f.customers_tickets ? Math.trunc(f.customers_net / f.customers_tickets) : 0 },
    // Averages across branches weigh each branch by the guests it knows.
    known: { identified, active90: sum(known, (c) => c.active90), repeat90: sum(known, (c) => c.repeat90), averageGapDays: identified ? Math.round(sum(known, (c) => c.averageGapDays * c.identified) / identified) : 0, lifetimeAverage: identified ? Math.round(sum(known, (c) => c.lifetimeAverage * c.identified) / identified) : 0, visitsAverageTenths: identified ? Math.round(sum(known, (c) => c.visitsAverageTenths * c.identified) / identified) : 0, vip: sum(known, (c) => c.vip), vipLapsed: sum(known, (c) => c.vipLapsed), lapsedDays: 21 },
    reviews: { count: reviews, foodTenths: reviews ? Math.round(f.reviews_food * 10 / reviews) : 0, serviceTenths: reviews ? Math.round(f.reviews_service * 10 / reviews) : 0, overallTenths: reviews ? Math.round(f.reviews_overall * 10 / reviews) : 0, low: f.reviews_low ?? 0 },
    best: [...rated].sort((a, b) => b.averageTenths - a.averageTenths || b.count - a.count).slice(0, 5),
    worst: [...rated].sort((a, b) => a.averageTenths - b.averageTenths || b.count - a.count).slice(0, 5)

  };
}

/** One list of what needs the owner today, most urgent first. Each alert names its branch. */
export async function alerts(db: D1Database, branches: BranchRow[], settings: Settings, role: "owner" | "manager", at = Date.now()) {

  const today = todayOf(branches, at);
  const range = { from: today, to: today };
  const month = { from: `${today.slice(0, 7)}-01`, to: today };
  const { pro } = proOnly(branches, range);
  const own = names(branches);
  const out: { level: "high" | "medium" | "info"; area: string; title: string; detail: string; licenseId: string | null; branchName: string | null }[] = [];
  const add = (level: "high" | "medium" | "info", area: string, title: string, detail: string, licenseId: string | null = null) => out.push({ level, area, title, detail, licenseId, branchName: licenseId ? own.get(licenseId) ?? null : null });
  const pesos = (cents: number) => `$${(cents / 100).toLocaleString("es-MX", { minimumFractionDigits: 2, maximumFractionDigits: 2 })}`;

  for (const b of branches) if (!b.seen_at || at - Date.parse(b.seen_at) > 15 * 60_000) add("medium", "Sucursales", "Sucursal sin contacto", b.seen_at ? `No envía datos desde ${new Date(b.seen_at).toLocaleString("es-MX", { timeZone: "America/Mexico_City" })}. Sus cifras pueden estar incompletas.` : "Nunca ha enviado datos.", b.id);

  for (const b of pro) {

    const l = live(b);

    if (!l) continue;
    for (const e of l.expiring ?? []) add(e.days <= 0 ? "high" : e.days <= 1 ? "medium" : "info", "Inventario", e.days < 0 ? `${e.name} ya caducó` : e.days === 0 ? `${e.name} caduca hoy` : `${e.name} caduca en ${e.days} ${e.days === 1 ? "día" : "días"}`, `${pesos(e.cost)} en existencia.${e.products.length ? ` Promociona ${e.products.join(", ")}.` : ""}`, b.id);
    for (const c of l.costAlerts ?? []) add(c.changeBps >= 2500 ? "high" : "medium", "Costos", `${c.name} subió ${(c.changeBps / 100).toFixed(0)} %`, c.products.length ? `Afecta a ${c.products.map((p) => p.name).join(", ")}. Revisa su precio en Productos.` : "Ningún platillo con receta lo usa.", b.id);
    if (l.customers && l.customers.vipLapsed > 0) add("medium", "Clientes", `${l.customers.vipLapsed} ${l.customers.vipLapsed === 1 ? "cliente frecuente no ha vuelto" : "clientes frecuentes no han vuelto"}`, "Llevan más de 21 días sin visitar la sucursal. Búscalos desde el módulo de clientes de la sucursal.", b.id);

  }
  if (pro.length) {

    const [labor, sales, promised, reviews] = await db.batch<Record<string, any>>([
      db.prepare(`SELECT d.license_id AS licenseId, ${added("cost")} FROM stats_day d, ${each("labor")} WHERE ${IN_RANGE} GROUP BY 1`).bind(...scope(pro, range)),
      db.prepare(`SELECT d.license_id AS licenseId, SUM(net) AS net FROM stats_day d WHERE ${IN_RANGE} GROUP BY 1`).bind(...scope(pro, range)),
      db.prepare(`SELECT d.license_id AS licenseId, ${added("count", "late")} FROM stats_day d, ${each("promises")} WHERE ${IN_RANGE} GROUP BY 1`).bind(...scope(pro, range)),
      db.prepare(`SELECT d.license_id AS licenseId, SUM(json_extract(d.insights, '$.reviews.low')) AS low FROM stats_day d WHERE ${IN_RANGE} GROUP BY 1`).bind(...scope(pro, range))
    ]);

    for (const l of labor!.results) {

      const net = sales!.results.find((s) => s.licenseId === l.licenseId)?.net ?? 0;

      if (l.cost > 0 && ratioBps(l.cost, net) > settings.laborTargetBps) add(net ? "medium" : "info", "Personal", `Costo laboral de hoy en ${net ? (ratioBps(l.cost, net) / 100).toFixed(0) : "—"} %`, `${pesos(l.cost)} en horas trabajadas contra ${pesos(net)} vendidos; tu meta es ${settings.laborTargetBps / 100} %. Considera mandar a descansar a quien no haga falta.`, l.licenseId);

    }
    for (const p of promised!.results) if (p.count >= 3 && p.late / p.count > 0.2) add("medium", "Cocina", `${p.late} de ${p.count} pedidos salieron tarde hoy`, "Revisa los tiempos por platillo en Cocina.", p.licenseId);
    for (const r of reviews!.results) if (r.low > 0) add("info", "Clientes", `${r.low} ${r.low === 1 ? "calificación baja" : "calificaciones bajas"} hoy`, "Calificaciones de 1 o 2 estrellas. Revisa qué se sirvió en Clientes.", r.licenseId);

    if (role === "owner") {

      const found = await team(db, pro, month, settings, role, at);

      for (const a of found.anomalies) add("medium", "Personal", `${a.name}: ${a.value} ${a.label} este mes`, `Lo usual en su sucursal es ${a.usual}. Es para revisar con el gerente, no una acusación.`, a.licenseId);

    }

  }
  for (const g of (await goals(db, branches, settings, undefined, at)).goals) if (g.period !== "day" && g.pace === "behind") add("info", "Metas", `Meta ${g.period === "month" ? "del mes" : "del año"}${g.branchName ? ` de ${g.branchName}` : ""} atrasada`, `Llevas ${pesos(g.actual)} de ${pesos(g.target)}; a este ritmo cerrarías en ${pesos(g.projected)}.`, g.licenseId || null);

  const order = { high: 0, medium: 1, info: 2 };

  return { today, alerts: out.sort((a, b) => order[a.level] - order[b.level]) };
}

