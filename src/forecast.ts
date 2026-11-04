import { businessDate, dayShift, field, IN_RANGE, proOnly, scope, type BranchRow, type Stats } from "./stats";
import type { Settings } from "./insights";

// The sales of the next seven days, from what each branch sold on the same weekday. Every factor is shown with the
// figure, so the owner sees why a day is higher or lower. No figure here is sent to a branch.
const HISTORY_DAYS = 56;
const HORIZON = 7;
const RAIN_MM = 5;

const weekday = (date: string) => new Date(`${date}T12:00:00Z`).getUTCDay();
const nth = (year: number, month: number, day: number, n: number) => { const first = new Date(Date.UTC(year, month - 1, 1)).getUTCDay(); return `${year}-${String(month).padStart(2, "0")}-${String(1 + ((day - first + 7) % 7) + (n - 1) * 7).padStart(2, "0")}`; };

// Easter Sunday by the anonymous Gregorian algorithm; Holy Thursday and Friday hang from it.
function easter(year: number) {

  const a = year % 19, b = Math.floor(year / 100), c = year % 100, d = Math.floor(b / 4), e = b % 4, f = Math.floor((b + 8) / 25), g = Math.floor((b - f + 1) / 3), h = (19 * a + b - d - g + 15) % 30, i = Math.floor(c / 4), k = c % 4, l = (32 + 2 * e + 2 * i - h - k) % 7, m = Math.floor((a + 11 * h + 22 * l) / 451), month = Math.floor((h + l - 7 * m + 114) / 31), day = ((h + l - 7 * m + 114) % 31) + 1;

  return `${year}-${String(month).padStart(2, "0")}-${String(day).padStart(2, "0")}`;
}

/** Dates that move restaurant sales in Mexico, with the effect used until the branch has its own year before. */
export function holidays(year: number): Map<string, { name: string; factor: number }> {

  const e = easter(year);
  const list: [string, string, number][] = [
    [`${year}-01-01`, "Año Nuevo", 0.75], [nth(year, 2, 1, 1), "Día de la Constitución", 1.05], [`${year}-02-14`, "Día del Amor y la Amistad", 1.25],
    [nth(year, 3, 1, 3), "Natalicio de Benito Juárez", 1.05], [dayShift(e, -3), "Jueves Santo", 0.9], [dayShift(e, -2), "Viernes Santo", 0.9],
    [`${year}-05-01`, "Día del Trabajo", 1.05], [`${year}-05-10`, "Día de las Madres", 1.4], [nth(year, 6, 0, 3), "Día del Padre", 1.2],
    [`${year}-09-15`, "Noche Mexicana", 1.2], [`${year}-09-16`, "Día de la Independencia", 1.05], [`${year}-11-02`, "Día de Muertos", 1.0],
    [nth(year, 11, 1, 3), "Revolución Mexicana", 1.05], [`${year}-12-12`, "Día de la Virgen de Guadalupe", 1.0], [`${year}-12-24`, "Nochebuena", 0.8],
    [`${year}-12-25`, "Navidad", 0.7], [`${year}-12-31`, "Fin de año", 0.8]
  ];

  return new Map(list.map(([date, name, factor]) => [date, { name, factor }]));
}

const holidayOf = (date: string) => holidays(Number(date.slice(0, 4))).get(date) ?? null;
const clamp = (value: number, low: number, high: number) => Math.min(high, Math.max(low, value));

type Weather = { date: string; rainMm: number; rainChance: number; maxC: number };

/** Open-Meteo, without a key. Any failure leaves the forecast without weather instead of failing it. */
async function weather(lat: number, lon: number, from: string, to: string, past: boolean): Promise<Weather[]> {

  const host = past ? "https://archive-api.open-meteo.com/v1/archive" : "https://api.open-meteo.com/v1/forecast";
  const daily = past ? "precipitation_sum,temperature_2m_max" : "precipitation_sum,precipitation_probability_max,temperature_2m_max";
  const url = `${host}?latitude=${lat.toFixed(4)}&longitude=${lon.toFixed(4)}&daily=${daily}&timezone=auto&start_date=${from}&end_date=${to}`;

  try {

    const response = await fetch(url, { cf: { cacheTtl: 3 * 3600, cacheEverything: true } } as RequestInit);

    if (!response.ok) return [];

    const body = await response.json() as { daily?: { time: string[]; precipitation_sum: (number | null)[]; precipitation_probability_max?: (number | null)[]; temperature_2m_max: (number | null)[] } };
    const d = body.daily;

    return d ? d.time.map((date, i) => ({ date, rainMm: d.precipitation_sum[i] ?? 0, rainChance: d.precipitation_probability_max?.[i] ?? ((d.precipitation_sum[i] ?? 0) >= RAIN_MM ? 100 : 0), maxC: d.temperature_2m_max[i] ?? 0 })) : [];

  } catch { return []; }
}

const average = (values: number[]) => values.length ? values.reduce((a, b) => a + b, 0) / values.length : 0;

/** Same weekday of the last eight weeks, the newest weighing most. */
function baseline(history: Map<string, number>, date: string, open?: Map<string, number>) {

  let total = 0, weights = 0, weeks = 0;

  for (let w = 1; w <= HISTORY_DAYS / 7; w++) {

    // A product absent from a day the branch sold is a day it sold none of.
    const value = history.get(dayShift(date, -7 * w)) ?? (open?.has(dayShift(date, -7 * w)) ? 0 : undefined);

    if (value === undefined) continue;
    // A holiday of the past is not a usual day of its weekday.
    if (holidayOf(dayShift(date, -7 * w))) continue;

    const weight = HISTORY_DAYS / 7 + 1 - w;

    total += value * weight; weights += weight; weeks += 1;

  }

  return { value: weights ? total / weights : 0, weeks };
}

export async function forecast(db: D1Database, branches: BranchRow[], settings: Settings, at = Date.now()) {

  const seen = branches.find((b) => b.seen_branch);
  const today = seen ? businessDate(JSON.parse(seen.seen_branch!) as Stats["branch"], at) : new Date(at).toISOString().slice(0, 10);
  const range = { from: dayShift(today, -HISTORY_DAYS - 371), to: dayShift(today, -1) };
  const recent = { from: dayShift(today, -HISTORY_DAYS), to: dayShift(today, -1) };
  const { pro, marks } = proOnly(branches, recent);
  const [daysResult, productsResult] = await db.batch<Record<string, any>>([
    db.prepare(`SELECT d.license_id AS licenseId, d.business_date AS businessDate, tickets, net FROM stats_day d WHERE ${IN_RANGE}`).bind(...scope(pro, range)),
    db.prepare(`SELECT d.business_date AS businessDate, ${field("name")} AS name, SUM(${field("quantity")}) AS quantity FROM stats_day d, json_each(d.products) j WHERE ${IN_RANGE} GROUP BY 1, 2`).bind(...scope(pro, recent))
  ]);
  const net = new Map<string, number>(), tickets = new Map<string, number>();

  for (const d of daysResult!.results) { net.set(d.businessDate, (net.get(d.businessDate) ?? 0) + d.net); tickets.set(d.businessDate, (tickets.get(d.businessDate) ?? 0) + d.tickets); }

  // The last four weeks against the four before them, softened and bounded: a trend, not a jump.
  const window = (from: number, to: number) => { let total = 0; for (let i = from; i <= to; i++) total += net.get(dayShift(today, -i)) ?? 0; return total; };
  const last = window(1, 28), before = window(29, 56);
  const trend = before > 0 && last > 0 ? clamp(Math.sqrt(last / before), 0.85, 1.15) : 1;
  // Rain: what this business sold on rainy days against its usual, once there are enough rainy days to say so.
  const place = settings.locations.find((l) => pro.length === 1 ? l.licenseId === pro[0]!.id : true) ?? null;
  const ahead = Array.from({ length: HORIZON }, (_, i) => dayShift(today, i + 1));
  const [coming, past]: [Weather[], Weather[]] = place && pro.length === 1 ? await Promise.all([weather(place.lat, place.lon, ahead[0]!, ahead.at(-1)!, false), weather(place.lat, place.lon, recent.from, dayShift(today, -6), true)]) : [[], []];
  const rainy = past.filter((w) => w.rainMm >= RAIN_MM && net.has(w.date)).map((w) => net.get(w.date)! / Math.max(1, baseline(net, w.date).value));
  const rainFactor = rainy.length >= 3 ? clamp(average(rainy), 0.7, 1.15) : 0.93;
  const learnedRain = rainy.length >= 3;
  // A holiday of this year against the same holiday a year before, when the branch was already open.
  const holidayFactor = (date: string) => {

    const h = holidayOf(date);

    if (!h) return null;

    const year = Number(date.slice(0, 4)) - 1;
    const then = [...holidays(year)].find(([, x]) => x.name === h.name)?.[0];
    const sold = then ? net.get(then) : undefined;
    const usual = then ? baseline(net, then) : { value: 0, weeks: 0 };

    return { name: h.name, factor: sold !== undefined && usual.weeks >= 3 && usual.value > 0 ? clamp(sold / usual.value, 0.5, 2) : h.factor, learned: sold !== undefined && usual.weeks >= 3 };
  };
  // How far the same method missed on the last fourteen days it can be checked against.
  const misses: number[] = [];

  for (let i = 1; i <= 14; i++) {

    const date = dayShift(today, -i), actual = net.get(date), base = baseline(net, date);

    if (actual === undefined || base.weeks < 3 || actual <= 0) continue;
    misses.push(Math.abs(actual - base.value * trend * (holidayFactor(date)?.factor ?? 1)) / actual);

  }

  const errorBps = misses.length ? Math.round(average(misses) * 10_000) : null;
  const days = ahead.map((date) => {

    const base = baseline(net, date), baseTickets = baseline(tickets, date);
    const h = holidayFactor(date), w = coming.find((x) => x.date === date) ?? null;
    const wet = w !== null && (w.rainMm >= RAIN_MM || w.rainChance >= 70);
    const factor = trend * (h?.factor ?? 1) * (wet ? rainFactor : 1);
    const value = Math.round(base.value * factor), spread = errorBps === null ? 0.25 : clamp(errorBps / 10_000, 0.05, 0.5);

    return { date, weekday: weekday(date), weeks: base.weeks, base: Math.round(base.value), net: value, tickets: Math.round(baseTickets.value * factor), low: Math.round(value * (1 - spread)), high: Math.round(value * (1 + spread)), trend: Math.round(trend * 1000) / 1000, holiday: h, weather: w ? { ...w, wet, factor: wet ? Math.round(rainFactor * 1000) / 1000 : 1 } : null, factor: Math.round(factor * 1000) / 1000 };

  });
  // Units of the ten best sellers of the last four weeks, by the same weekday and factors: what to prepare.
  const units = new Map<string, Map<string, number>>();

  for (const p of productsResult!.results) { const own = units.get(p.name) ?? new Map<string, number>(); own.set(p.businessDate, p.quantity); units.set(p.name, own); }

  const top = [...units].map(([name, byDate]) => ({ name, recent: [...byDate].filter(([d]) => d >= dayShift(today, -28)).reduce((t, [, q]) => t + q, 0), byDate })).sort((a, b) => b.recent - a.recent).slice(0, 10);

  return {

    ...marks, today, trend: Math.round(trend * 1000) / 1000, errorBps, historyDays: net.size,
    weather: place ? { label: place.label, used: pro.length === 1, rainFactor: Math.round(rainFactor * 1000) / 1000, learned: learnedRain } : null,
    days,
    products: top.map((p) => ({ name: p.name, days: days.map((d) => { const b = baseline(p.byDate, d.date, net); return { date: d.date, units: Math.round(b.value * d.factor) }; }) }))

  };
}
