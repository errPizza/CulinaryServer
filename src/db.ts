import initial from "../migrations/0001_inicial.sql";
import { DAY_MS } from "./catalog";

const MIGRATIONS: [name: string, sql: string][] = [["0001_inicial.sql", initial]];

// Same table and names as `wrangler d1 migrations`, so both can be used on the same database.
const TRACKING = "CREATE TABLE IF NOT EXISTS d1_migrations (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT UNIQUE, applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL)";

let ready: Promise<void> | undefined;

/** The Worker migrates its own database, so a Git deploy from Cloudflare needs no manual migration step. */
export function migrate(db: D1Database): Promise<void> {
  ready ??= applyPending(db).catch((error) => {
    ready = undefined;
    throw error;
  });
  return ready;
}

async function applied(db: D1Database): Promise<Set<string>> {
  await db.prepare(TRACKING).run();
  const { results } = await db.prepare("SELECT name FROM d1_migrations").all<{ name: string }>();
  return new Set(results.map((r) => r.name));
}

async function applyPending(db: D1Database): Promise<void> {
  const done = await applied(db);
  for (const [name, sql] of MIGRATIONS) {
    if (done.has(name)) continue;
    // Splits on a semicolon that ends a line; a migration with triggers (BEGIN ... END;) would need a real parser.
    const statements = sql.split(/;\s*$/m).map((s) => s.trim()).filter(Boolean).map((s) => db.prepare(s));
    try {
      await db.batch([...statements, db.prepare("INSERT INTO d1_migrations (name) VALUES (?)").bind(name)]);
    } catch (error) {
      // Another isolate may have won the race; the batch is a transaction, so nothing half-applied remains.
      if (!(await applied(db)).has(name)) throw error;
    }
  }
}

/** Daily cleanup of rows that only exist until a deadline, including enrollments never confirmed within a day. */
export async function purgeExpired(db: D1Database, at: number): Promise<void> {
  await db.batch([
    db.prepare("DELETE FROM used_challenge WHERE expires_at < ?").bind(at),
    db.prepare("DELETE FROM admin_session WHERE expires_at < ?").bind(at),
    db.prepare("DELETE FROM admin_invite WHERE expires_at < ?").bind(at),
    db.prepare("DELETE FROM download_grant WHERE expires_at < ?").bind(at),
    db.prepare("DELETE FROM admin WHERE active = 0 AND created_at < ?").bind(new Date(at - DAY_MS).toISOString()),
  ]);
}

export async function audit(db: D1Database, adminId: string | null, action: string, target: string | null, detail: unknown = null): Promise<void> {
  await db
    .prepare("INSERT INTO audit (at, admin_id, action, target, detail) VALUES (?, ?, ?, ?, ?)")
    .bind(new Date().toISOString(), adminId, action, target, detail === null ? null : JSON.stringify(detail))
    .run();
}
