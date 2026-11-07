-- Integrations each license includes, as a JSON array (see INTEGRATIONS in src/catalog.ts). NULL marks a license created
-- before the list existed: the branch keeps every integration for it, so nobody loses what they already use.
ALTER TABLE license ADD COLUMN integrations TEXT;
