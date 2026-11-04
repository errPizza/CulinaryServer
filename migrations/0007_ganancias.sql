-- License prices the provider sets in the panel, in centavos of MXN without IVA. Each change is a new row; the newest applies.
CREATE TABLE price_list (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  at TEXT NOT NULL,
  admin_id TEXT,
  prices TEXT NOT NULL
);

-- What each license was charged when it was sold, renewed or moved to another plan. The amount is frozen at that
-- moment, so a later price change never rewrites what was already collected.
CREATE TABLE license_charge (
  id TEXT PRIMARY KEY,
  license_id TEXT NOT NULL REFERENCES license(id),
  at TEXT NOT NULL,
  kind TEXT NOT NULL,
  plan TEXT NOT NULL,
  tier TEXT NOT NULL,
  addons TEXT NOT NULL,
  periods INTEGER NOT NULL,
  base_amount INTEGER NOT NULL,
  addons_amount INTEGER NOT NULL,
  admin_id TEXT
);
CREATE INDEX license_charge_at ON license_charge (at);
CREATE INDEX license_charge_license ON license_charge (license_id, at);
