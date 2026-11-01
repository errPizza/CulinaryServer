-- What failed at each branch. One row per distinct fault of a license; repeats only count and reopen it.
CREATE TABLE fault (
  id TEXT PRIMARY KEY,
  license_id TEXT NOT NULL REFERENCES license(id),
  fingerprint TEXT NOT NULL,
  source TEXT NOT NULL,
  severity TEXT NOT NULL,
  what TEXT NOT NULL,
  affected TEXT NOT NULL,
  detail TEXT NOT NULL,
  context TEXT NOT NULL,
  version TEXT NOT NULL,
  platform TEXT NOT NULL,
  occurrences INTEGER NOT NULL,
  first_at TEXT NOT NULL,
  last_at TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'open',
  resolved_at TEXT,
  resolved_by TEXT,
  UNIQUE (license_id, fingerprint)
);
CREATE INDEX fault_status ON fault (status, last_at);
