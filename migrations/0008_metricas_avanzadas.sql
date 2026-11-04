-- Schema 2 of a branch's upload: kitchen times, returns, the time clock, areas, kinds of product, couriers, reviews,
-- expenses and known guests, kept together as one JSON object per day. A schema 1 day holds '{}'.
ALTER TABLE stats_day ADD COLUMN insights TEXT NOT NULL DEFAULT '{}';

-- What the owner decides for the panel: shifts, goals, fixed costs, targets and where each branch is. One row per
-- business; only an owner changes it.
CREATE TABLE owner_setting (
  tenant_id TEXT PRIMARY KEY,
  value TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  updated_by TEXT NOT NULL
);
