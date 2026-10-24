import { z } from "zod";

// Must match Restaurant.Modules in MesaNexo.Core; the branch rejects names it does not know.
export const FEATURES = ["reservations", "reviews", "customerRequests", "printing", "courses", "promotions", "multiBranch"] as const;

export const PLANS = ["trial", "monthly", "annual", "permanent"] as const;
export type Plan = (typeof PLANS)[number];

export const PLATFORMS = ["linux-x64", "win-x64", "android-arm64"] as const;

export const DAY_MS = 24 * 60 * 60 * 1000;
export const OFFLINE_GRACE_MS = 3 * DAY_MS;

export const VERSION_PATTERN = /^(\d{1,5})\.(\d{1,5})\.(\d{1,5})$/;

export const limitsSchema = z.strictObject({
  maxUsers: z.int().min(1).max(10_000),
  maxTables: z.int().min(1).max(10_000),
});
export type Limits = z.infer<typeof limitsSchema>;

export const featuresSchema = z.array(z.enum(FEATURES)).max(FEATURES.length).transform((list) => [...new Set(list)].sort());

/** Calendar months in UTC, clamped to the last day: 31 Jan + 1 month is 28 or 29 Feb. */
function addMonths(from: Date, months: number): Date {
  const end = new Date(from);
  end.setUTCDate(1);
  end.setUTCMonth(end.getUTCMonth() + months);
  const lastDay = new Date(Date.UTC(end.getUTCFullYear(), end.getUTCMonth() + 1, 0)).getUTCDate();
  end.setUTCDate(Math.min(from.getUTCDate(), lastDay));
  return end;
}

export function termEnd(plan: Plan, trialDays: number | null, from: Date): Date | null {
  switch (plan) {
    case "permanent":
      return null;
    case "trial":
      return new Date(from.getTime() + (trialDays ?? 0) * DAY_MS);
    case "monthly":
      return addMonths(from, 1);
    case "annual":
      return addMonths(from, 12);
  }
}
