-- One row per branch and business day, replaced whole by a higher revision. A send rewrites only its days' rows; the
-- sections stay as JSON and the panel adds them up with json_each. products empties after 13 months, the rest after 25.
CREATE TABLE stats_day (
  license_id TEXT NOT NULL REFERENCES license(id),
  business_date TEXT NOT NULL,
  revision INTEGER NOT NULL,
  complete INTEGER NOT NULL,
  received_at TEXT NOT NULL,
  tickets INTEGER NOT NULL,
  people INTEGER NOT NULL,
  gross INTEGER NOT NULL,
  discounts INTEGER NOT NULL,
  net INTEGER NOT NULL,
  tax INTEGER NOT NULL,
  delivery_fees INTEGER NOT NULL,
  voided_count INTEGER NOT NULL,
  voided_amount INTEGER NOT NULL,
  comps INTEGER NOT NULL,
  staff_meals INTEGER NOT NULL,
  hours TEXT NOT NULL,
  payments TEXT NOT NULL,
  refunds TEXT NOT NULL,
  channels TEXT NOT NULL,
  products TEXT,
  staff TEXT NOT NULL,
  cash TEXT NOT NULL,
  cash_closes TEXT NOT NULL,
  inventory TEXT NOT NULL,
  z_reports TEXT NOT NULL,
  PRIMARY KEY (license_id, business_date)
);
CREATE INDEX stats_day_date ON stats_day (business_date);

-- What each branch says about itself right now; only the newest counts.
CREATE TABLE branch_heartbeat (
  license_id TEXT PRIMARY KEY REFERENCES license(id),
  at TEXT NOT NULL,
  branch TEXT NOT NULL,
  live TEXT NOT NULL
);

-- People of a business: an owner reads every branch of the tenant, a manager only those in owner_membership.
CREATE TABLE owner_account (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  email TEXT NOT NULL UNIQUE,
  role TEXT NOT NULL CHECK (role IN ('owner', 'manager')),
  password_hash TEXT NOT NULL,
  totp_secret TEXT NOT NULL,
  totp_last_step INTEGER NOT NULL DEFAULT 0,
  active INTEGER NOT NULL DEFAULT 0,
  failed_logins INTEGER NOT NULL DEFAULT 0,
  locked_until INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL
);
CREATE INDEX owner_account_tenant ON owner_account (tenant_id);

CREATE TABLE owner_membership (
  account_id TEXT NOT NULL REFERENCES owner_account(id) ON DELETE CASCADE,
  license_id TEXT NOT NULL REFERENCES license(id),
  PRIMARY KEY (account_id, license_id)
);

CREATE TABLE owner_session (
  token_hash TEXT PRIMARY KEY,
  account_id TEXT NOT NULL REFERENCES owner_account(id) ON DELETE CASCADE,
  expires_at INTEGER NOT NULL
);

CREATE TABLE owner_invite (
  code_hash TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  email TEXT NOT NULL,
  role TEXT NOT NULL,
  license_ids TEXT NOT NULL,
  created_by TEXT NOT NULL REFERENCES admin(id) ON DELETE CASCADE,
  expires_at INTEGER NOT NULL
);
