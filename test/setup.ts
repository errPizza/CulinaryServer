import { env } from "cloudflare:workers";
import { beforeEach } from "vitest";
import { migrate } from "../src/db";

// Storage is shared by the tests of one file, so each test starts from empty tables.
const TABLES = ["ticket_message", "ticket", "download_grant", "publication_target", "publication", "release", "audit", "admin_session", "admin_invite", "admin", "challenge", "license"];

beforeEach(async () => {
  await migrate(env.DB);
  await env.DB.batch(TABLES.map((t) => env.DB.prepare(`DELETE FROM ${t}`)));
});
