import initial from "../migrations/0001_inicial.sql";

const MIGRATIONS: [name: string, sql: string][] = [["0001_inicial.sql", initial]];

// Same table and names as `wrangler d1 migrations`, so both can be used on the same database.
const TRACKING = "CREATE TABLE IF NOT EXISTS d1_migrations (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT UNIQUE, applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL)";

let ready: Promise<void> | undefined;

/**
 * The Worker migrates its own database because Git deploys from Cloudflare create D1 without writing
 * its ID back to the repo, which leaves `wrangler d1 migrations apply` nothing to target.
 */
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
    const statements = sql.split(/;\s*$/m).map((s) => s.trim()).filter(Boolean).map((s) => db.prepare(s));
    try {
      await db.batch([...statements, db.prepare("INSERT INTO d1_migrations (name) VALUES (?)").bind(name)]);
    } catch (error) {
      // Another isolate may have won the race; the batch is a transaction, so nothing half-applied remains.
      if (!(await applied(db)).has(name)) throw error;
    }
  }
}

export async function audit(db: D1Database, adminId: string | null, action: string, target: string | null, detail: unknown = null): Promise<void> {
  await db
    .prepare("INSERT INTO audit (at, admin_id, action, target, detail) VALUES (?, ?, ?, ?, ?)")
    .bind(new Date().toISOString(), adminId, action, target, detail === null ? null : JSON.stringify(detail))
    .run();
}
