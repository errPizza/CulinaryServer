import { env } from "cloudflare:workers";
import { beforeEach, expect } from "vitest";
import { migrate } from "../src/db";

// Storage is shared by the tests of one file, so each test starts from empty tables (children first).
const TABLES = ["owner_message_read", "owner_message", "owner_setting", "owner_session", "owner_membership", "owner_invite", "owner_account", "branch_heartbeat", "stats_day", "ticket_message", "ticket", "download_grant", "fault", "license_charge", "price_list", "publication_target", "publication", "release", "audit", "admin_session", "admin_invite", "admin", "used_challenge", "license"];

beforeEach(async () => {
  await migrate(env.DB);
  const { results } = await env.DB.prepare("SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%' AND name NOT IN ('d1_migrations', '_cf_KV', '_cf_METADATA')").all<{ name: string }>();
  expect(results.map((t) => t.name).sort(), "TABLES debe cubrir todo el esquema").toEqual([...TABLES].sort());
  await env.DB.batch(TABLES.map((t) => env.DB.prepare(`DELETE FROM ${t}`)));
});
