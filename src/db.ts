import initial from "../migrations/0001_inicial.sql";
import tiers from "../migrations/0002_nivel_y_addons.sql";
import deleted from "../migrations/0003_licencia_eliminada.sql";
import released from "../migrations/0004_llave_liberada.sql";
import faults from "../migrations/0005_fallos.sql";
import ownerPanel from "../migrations/0006_panel_propietario.sql";
import revenue from "../migrations/0007_ganancias.sql";
import insights from "../migrations/0008_metricas_avanzadas.sql";
import { DAY_MS } from "./catalog";

const MIGRATIONS: [name: string, sql: string][] = [["0001_inicial.sql", initial], ["0002_nivel_y_addons.sql", tiers], ["0003_licencia_eliminada.sql", deleted], ["0004_llave_liberada.sql", released], ["0005_fallos.sql", faults], ["0006_panel_propietario.sql", ownerPanel], ["0007_ganancias.sql", revenue], ["0008_metricas_avanzadas.sql", insights]];
const TRACKING = "CREATE TABLE IF NOT EXISTS d1_migrations (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT UNIQUE, applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL)";
let ready: Promise<void> | undefined;

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

      if (!(await applied(db)).has(name)) throw error;

    }

  }

}

export async function purgeExpired(db: D1Database, at: number): Promise<void> {

  await db.batch([
    db.prepare("DELETE FROM used_challenge WHERE expires_at < ?").bind(at),
    db.prepare("DELETE FROM admin_session WHERE expires_at < ?").bind(at),
    db.prepare("DELETE FROM admin_invite WHERE expires_at < ?").bind(at),
    db.prepare("DELETE FROM download_grant WHERE expires_at < ?").bind(at),
    db.prepare("DELETE FROM fault WHERE status = 'resolved' AND resolved_at < ?").bind(new Date(at - 90 * DAY_MS).toISOString()),
    db.prepare("DELETE FROM owner_session WHERE expires_at < ?").bind(at),
    db.prepare("DELETE FROM owner_invite WHERE expires_at < ?").bind(at),
    db.prepare("DELETE FROM owner_account WHERE active = 0 AND created_at < ?").bind(new Date(at - DAY_MS).toISOString()),
    db.prepare("UPDATE stats_day SET products = NULL WHERE business_date < ? AND products IS NOT NULL").bind(new Date(at - 396 * DAY_MS).toISOString().slice(0, 10)),
    db.prepare("DELETE FROM stats_day WHERE business_date < ?").bind(new Date(at - 762 * DAY_MS).toISOString().slice(0, 10)),
    db.prepare("DELETE FROM admin WHERE active = 0 AND created_at < ?").bind(new Date(at - DAY_MS).toISOString())
  ]);

}

export async function audit(db: D1Database, adminId: string | null, action: string, target: string | null, detail: unknown = null): Promise<void> {

  await db.prepare("INSERT INTO audit (at, admin_id, action, target, detail) VALUES (?, ?, ?, ?, ?)").bind(new Date().toISOString(), adminId, action, target, detail === null ? null : JSON.stringify(detail)).run();

}