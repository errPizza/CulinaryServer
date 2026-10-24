CREATE TABLE license (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  site_id TEXT NOT NULL UNIQUE,
  customer TEXT NOT NULL,
  branch_name TEXT NOT NULL,
  plan TEXT NOT NULL CHECK (plan IN ('trial', 'monthly', 'annual', 'permanent')),
  trial_days INTEGER,
  features TEXT NOT NULL,
  limits TEXT NOT NULL,
  revision INTEGER NOT NULL,
  created_at TEXT NOT NULL,
  expires_at TEXT,
  revoked_at TEXT,
  revoke_reason TEXT,
  activation_code_hash TEXT,
  activated_at TEXT,
  key_alg TEXT,
  key_spki TEXT,
  binding_kind TEXT CHECK (binding_kind IN ('tpm', 'fingerprint')),
  fp_board TEXT,
  fp_disk TEXT,
  fp_mac TEXT,
  validated_at TEXT,
  central_cert_sha256 TEXT UNIQUE
);
CREATE INDEX license_tenant ON license (tenant_id);

-- Short-lived security rows store expiry as INTEGER milliseconds; business rows use ISO 8601 TEXT.
CREATE TABLE used_challenge (
  nonce TEXT PRIMARY KEY,
  expires_at INTEGER NOT NULL
);

CREATE TABLE admin (
  id TEXT PRIMARY KEY,
  username TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  totp_secret TEXT NOT NULL,
  totp_last_step INTEGER NOT NULL DEFAULT 0,
  key_alg TEXT NOT NULL,
  key_spki TEXT NOT NULL,
  device_name TEXT NOT NULL,
  invited_by TEXT,
  active INTEGER NOT NULL DEFAULT 0,
  failed_logins INTEGER NOT NULL DEFAULT 0,
  locked_until INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL
);

CREATE TABLE admin_invite (
  code_hash TEXT PRIMARY KEY,
  created_by TEXT NOT NULL REFERENCES admin (id) ON DELETE CASCADE,
  expires_at INTEGER NOT NULL
);

CREATE TABLE admin_session (
  token_hash TEXT PRIMARY KEY,
  admin_id TEXT NOT NULL REFERENCES admin (id) ON DELETE CASCADE,
  expires_at INTEGER NOT NULL
);

CREATE TABLE audit (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  at TEXT NOT NULL,
  admin_id TEXT,
  action TEXT NOT NULL,
  target TEXT,
  detail TEXT
);

CREATE TABLE release (
  id TEXT PRIMARY KEY,
  version TEXT NOT NULL,
  platform TEXT NOT NULL,
  filename TEXT NOT NULL,
  notes TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('uploading', 'ready')),
  upload_id TEXT,
  bytes INTEGER,
  sha512 TEXT,
  manifest TEXT,
  created_at TEXT NOT NULL,
  UNIQUE (platform, version)
);

CREATE TABLE publication (
  id TEXT PRIMARY KEY,
  release_id TEXT NOT NULL REFERENCES release (id),
  target_all INTEGER NOT NULL,
  created_at TEXT NOT NULL,
  withdrawn_at TEXT
);

CREATE TABLE publication_target (
  publication_id TEXT NOT NULL REFERENCES publication (id),
  license_id TEXT NOT NULL REFERENCES license (id),
  PRIMARY KEY (publication_id, license_id)
);

CREATE TABLE download_grant (
  token_hash TEXT PRIMARY KEY,
  license_id TEXT NOT NULL REFERENCES license (id),
  release_id TEXT NOT NULL REFERENCES release (id),
  expires_at INTEGER NOT NULL
);

CREATE TABLE ticket (
  id TEXT PRIMARY KEY,
  license_id TEXT NOT NULL REFERENCES license (id),
  subject TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('open', 'answered', 'closed')),
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE INDEX ticket_license ON ticket (license_id, updated_at);
CREATE INDEX ticket_status ON ticket (status, updated_at);

CREATE TABLE ticket_message (
  id TEXT PRIMARY KEY,
  ticket_id TEXT NOT NULL REFERENCES ticket (id),
  author TEXT NOT NULL CHECK (author IN ('branch', 'admin')),
  admin_id TEXT,
  body TEXT NOT NULL,
  created_at TEXT NOT NULL
);
CREATE INDEX ticket_message_ticket ON ticket_message (ticket_id, created_at);
