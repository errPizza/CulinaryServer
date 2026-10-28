-- A deleted license leaves the panel but keeps its row: tickets, publications and the audit still point to it.
ALTER TABLE license ADD COLUMN deleted_at TEXT;
