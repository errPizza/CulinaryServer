import { z } from "zod";

export const FEATURES = ["reservations", "reviews", "customerRequests", "printing", "courses", "promotions", "multiBranch"] as const;
export const PLANS = ["trial", "monthly", "annual", "permanent"] as const;
export type Plan = (typeof PLANS)[number];
// Commercial level, independent of the billing period above. Each brings a default terminal allowance.
export const TIERS = ["lite", "pro"] as const;
export type Tier = (typeof TIERS)[number];
export const TIER_TERMINALS: Record<Tier, number> = { lite: 2, pro: 10 };
// Paid add-ons on top of either tier. Fiscal stamps are billed per use, not licensed.
export const ADDONS = ["mobileOrdering", "deliveryHub", "webOrdering"] as const;
// Sold together at their own monthly price. Keep in step with COMBOS in CulinaryAdmin src/api.ts.
export const COMBOS = [{ id: "pyme", tier: "lite", addons: ["mobileOrdering"] }, { id: "delivery", tier: "pro", addons: ["deliveryHub", "webOrdering"] }] as const;
export const addonsSchema = z.array(z.enum(ADDONS)).max(ADDONS.length).transform((list) => [...new Set(list)].sort());
export const PLATFORMS = ["linux-x64", "win-x64", "android-arm64"] as const;
export const DAY_MS = 24 * 60 * 60 * 1000;
export const OFFLINE_GRACE_MS = 7 * DAY_MS;
export const VERSION_PATTERN = /^(\d{1,5})\.(\d{1,5})\.(\d{1,5})$/;

export const limitsSchema = z.strictObject({

  maxUsers: z.int().min(1).max(10_000),
  maxTables: z.int().min(1).max(10_000),
  maxTerminals: z.int().min(1).max(1_000).optional()

});

export type Limits = z.infer<typeof limitsSchema>;
export const featuresSchema = z.array(z.enum(FEATURES)).max(FEATURES.length).transform((list) => [...new Set(list)].sort());

function addMonths(from: Date, months: number): Date {

  const end = new Date(from);
  
  end.setUTCDate(1);
  end.setUTCMonth(end.getUTCMonth() + months);
  
  const lastDay = new Date(Date.UTC(end.getUTCFullYear(), end.getUTCMonth() + 1, 0)).getUTCDate();
  
  end.setUTCDate(Math.min(from.getUTCDate(), lastDay));
 
  return end;
}

export function termEnd(plan: Plan, trialDays: number | null, from: Date): Date | null { switch (plan) {

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