-- The business behind each license, as its Constancia de Situación Fiscal states it. Required for every new license and for
-- every new activation code; a license activated before this migration keeps working and the panel shows it incomplete.
ALTER TABLE license ADD COLUMN fiscal_rfc TEXT;
ALTER TABLE license ADD COLUMN fiscal_name TEXT;
ALTER TABLE license ADD COLUMN fiscal_postal_code TEXT;
ALTER TABLE license ADD COLUMN fiscal_regime TEXT;

-- The public key each branch receives its CSD with. The branch registers it with a request signed by its license key, so the
-- owner's app encrypts to the machine that holds the license and this server only carries ciphertext.
CREATE TABLE fiscal_intake (
  license_id TEXT PRIMARY KEY REFERENCES license(id),
  spki TEXT NOT NULL,
  created_at TEXT NOT NULL
);

-- A CSD on its way from the owner to the branch. The envelope is dropped as soon as the branch answers or the day ends; what
-- stays is who sent it and what the branch found: RFC, serial number and validity, never the files or the password.
CREATE TABLE fiscal_submission (
  id TEXT PRIMARY KEY,
  license_id TEXT NOT NULL REFERENCES license(id),
  account_id TEXT NOT NULL,
  intake_sha256 TEXT NOT NULL,
  envelope TEXT,
  status TEXT NOT NULL CHECK (status IN ('pending', 'loaded', 'rejected', 'expired')),
  message TEXT,
  rfc TEXT,
  serial TEXT,
  not_before TEXT,
  not_after TEXT,
  created_at TEXT NOT NULL,
  resolved_at TEXT
);
CREATE INDEX fiscal_submission_license ON fiscal_submission (license_id, created_at);
