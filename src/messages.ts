import { ApiError, type OwnerIdentity } from "./http";

// The owner's thread with each branch. The panel writes to one, several or every branch at once; the branch's managers
// read it in the point of sale and answer from there.

const THREAD_LIMIT = 200;
const BRANCH_READ_LIMIT = 100;
const PER_HOUR = 60;

type Row = { id: string; license_id: string; author: "owner" | "branch"; account_id: string | null; author_name: string; body: string; broadcast_id: string | null; created_at: string };

const view = (m: Row) => ({ id: m.id, licenseId: m.license_id, author: m.author, name: m.author_name, body: m.body, toAll: m.broadcast_id !== null, createdAt: m.created_at });

/** How the branch sees who wrote: the role and the address, so a manager knows whom to answer. */
export const ownerName = (account: OwnerIdentity) => `${account.role === "owner" ? "Dueño" : "Gerente"} · ${account.email}`;

/** One line per branch: its last message and how many of the branch's are still unread by this person. */
export async function threads(db: D1Database, accountId: string, licenseIds: string[]) {

  if (!licenseIds.length) return [];

  const { results } = await db.prepare(`SELECT m.*, (SELECT COUNT(*) FROM owner_message u WHERE u.license_id = m.license_id AND u.author = 'branch' AND u.created_at > COALESCE((SELECT read_at FROM owner_message_read r WHERE r.account_id = ?2 AND r.license_id = m.license_id), '')) AS unread
    FROM owner_message m WHERE m.license_id IN (SELECT value FROM json_each(?1)) AND m.created_at = (SELECT MAX(created_at) FROM owner_message x WHERE x.license_id = m.license_id) GROUP BY m.license_id`).bind(JSON.stringify(licenseIds), accountId).all<Row & { unread: number }>();
  const last = new Map(results.map((r) => [r.license_id, r]));

  return licenseIds.map((licenseId) => {

    const row = last.get(licenseId);

    return { licenseId, last: row ? view(row) : null, unread: row?.unread ?? 0 };

  });
}

/** The thread, oldest first, and it counts as read up to now for this person. */
export async function thread(db: D1Database, accountId: string, licenseId: string) {

  const { results } = await db.prepare("SELECT * FROM (SELECT * FROM owner_message WHERE license_id = ? ORDER BY created_at DESC, id DESC LIMIT ?) ORDER BY created_at, id").bind(licenseId, THREAD_LIMIT).all<Row>();

  await db.prepare("INSERT INTO owner_message_read (account_id, license_id, read_at) VALUES (?1, ?2, ?3) ON CONFLICT (account_id, license_id) DO UPDATE SET read_at = ?3").bind(accountId, licenseId, new Date().toISOString()).run();

  return results.map(view);
}

/** To one branch or to several at once; with more than one, every copy carries the same broadcast id. */
export async function sendToBranches(db: D1Database, account: OwnerIdentity, licenseIds: string[], body: string) {

  const lastHour = new Date(Date.now() - 3_600_000).toISOString();
  const sent = await db.prepare("SELECT COUNT(DISTINCT COALESCE(broadcast_id, id)) AS n FROM owner_message WHERE account_id = ? AND created_at > ?").bind(account.id, lastHour).first<number>("n");

  if ((sent ?? 0) >= PER_HOUR) throw new ApiError(429, "rate_limited", "Enviaste muchos mensajes en la última hora. Espera un poco.");

  const at = new Date().toISOString(), broadcast = licenseIds.length > 1 ? crypto.randomUUID() : null, name = ownerName(account);

  await db.batch(licenseIds.map((licenseId) => db.prepare("INSERT INTO owner_message (id, license_id, author, account_id, author_name, body, broadcast_id, created_at) VALUES (?, ?, 'owner', ?, ?, ?, ?, ?)").bind(crypto.randomUUID(), licenseId, account.id, name, body, broadcast, at)));
  // Writing to a branch means its thread was read up to here.
  await db.batch(licenseIds.map((licenseId) => db.prepare("INSERT INTO owner_message_read (account_id, license_id, read_at) VALUES (?1, ?2, ?3) ON CONFLICT (account_id, license_id) DO UPDATE SET read_at = ?3").bind(account.id, licenseId, at)));

  return { sent: licenseIds.length, at };
}

/** What the branch keeps in its point of sale: the newest messages of its own thread. */
export async function branchThread(db: D1Database, licenseId: string) {

  const { results } = await db.prepare("SELECT * FROM (SELECT * FROM owner_message WHERE license_id = ? ORDER BY created_at DESC, id DESC LIMIT ?) ORDER BY created_at, id").bind(licenseId, BRANCH_READ_LIMIT).all<Row>();

  return results.map(view);
}

/** A manager's answer from the point of sale. The id is the branch's own, so sending it twice keeps one copy. */
export async function branchReply(db: D1Database, licenseId: string, id: string, name: string, body: string) {

  const at = new Date().toISOString();
  const key = `${licenseId}:${id}`;

  await db.prepare("INSERT INTO owner_message (id, license_id, author, account_id, author_name, body, broadcast_id, created_at) VALUES (?, ?, 'branch', NULL, ?, ?, NULL, ?) ON CONFLICT (id) DO NOTHING").bind(key, licenseId, name, body, at).run();

  return { id: key };
}
