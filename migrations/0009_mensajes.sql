-- The owner's conversation with each branch: one thread per branch, written by the panel and by the branch's managers.
-- A message to every branch is one row per branch with the same broadcast id.
CREATE TABLE owner_message (
  id TEXT PRIMARY KEY,
  license_id TEXT NOT NULL REFERENCES license(id),
  author TEXT NOT NULL CHECK (author IN ('owner', 'branch')),
  account_id TEXT,
  author_name TEXT NOT NULL,
  body TEXT NOT NULL,
  broadcast_id TEXT,
  created_at TEXT NOT NULL
);
CREATE INDEX owner_message_license ON owner_message (license_id, created_at);
CREATE INDEX owner_message_account ON owner_message (account_id, created_at);

-- Up to where each person of the panel read each branch's thread.
CREATE TABLE owner_message_read (
  account_id TEXT NOT NULL REFERENCES owner_account(id) ON DELETE CASCADE,
  license_id TEXT NOT NULL REFERENCES license(id),
  read_at TEXT NOT NULL,
  PRIMARY KEY (account_id, license_id)
);

-- A support ticket opened from the panel names the person who wrote it, and the branch does not see it.
ALTER TABLE ticket ADD COLUMN owner_account_id TEXT;
CREATE INDEX ticket_owner ON ticket (owner_account_id, updated_at);
