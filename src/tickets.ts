import { ApiError } from "./http";

const MAX_OPEN_TICKETS = 20;
const MAX_MESSAGES = 100;

type TicketRow = { id: string; license_id: string; subject: string; status: "open" | "answered" | "closed"; created_at: string; updated_at: string };
type MessageRow = { id: string; ticket_id: string; author: "branch" | "admin"; admin_id: string | null; body: string; created_at: string };

export type Author = { kind: "branch"; licenseId: string } | { kind: "admin"; adminId: string };

function ticketView(ticket: TicketRow, messages: MessageRow[]) {
  return {
    id: ticket.id,
    licenseId: ticket.license_id,
    subject: ticket.subject,
    status: ticket.status,
    createdAt: ticket.created_at,
    updatedAt: ticket.updated_at,
    messages: messages.map((m) => ({ id: m.id, author: m.author, adminId: m.admin_id, body: m.body, createdAt: m.created_at })),
  };
}

async function messagesOf(db: D1Database, ticketIds: string[]): Promise<Map<string, MessageRow[]>> {
  const byTicket = new Map<string, MessageRow[]>(ticketIds.map((id) => [id, []]));
  if (ticketIds.length === 0) return byTicket;
  const { results } = await db
    .prepare(`SELECT * FROM ticket_message WHERE ticket_id IN (SELECT value FROM json_each(?)) ORDER BY created_at, id`)
    .bind(JSON.stringify(ticketIds))
    .all<MessageRow>();
  for (const message of results) byTicket.get(message.ticket_id)!.push(message);
  return byTicket;
}

export async function ticketDetail(db: D1Database, id: string) {
  const ticket = await db.prepare("SELECT * FROM ticket WHERE id = ?").bind(id).first<TicketRow>();
  if (!ticket) throw new ApiError(404, "not_found", "Ticket no encontrado");
  return ticketView(ticket, (await messagesOf(db, [id])).get(id)!);
}

export async function createTicket(db: D1Database, licenseId: string, subject: string, body: string) {
  const open = await db.prepare("SELECT COUNT(*) AS n FROM ticket WHERE license_id = ? AND status <> 'closed'").bind(licenseId).first<number>("n");
  if ((open ?? 0) >= MAX_OPEN_TICKETS) throw new ApiError(429, "rate_limited", "Demasiados tickets abiertos; espera respuesta o cierra alguno");
  const id = crypto.randomUUID();
  const at = new Date().toISOString();
  await db.batch([
    db.prepare("INSERT INTO ticket (id, license_id, subject, status, created_at, updated_at) VALUES (?, ?, ?, 'open', ?, ?)").bind(id, licenseId, subject, at, at),
    db.prepare("INSERT INTO ticket_message (id, ticket_id, author, admin_id, body, created_at) VALUES (?, ?, 'branch', NULL, ?, ?)").bind(crypto.randomUUID(), id, body, at),
  ]);
  return ticketDetail(db, id);
}

/** A branch reply reopens the ticket; an admin reply marks it answered. */
export async function addTicketMessage(db: D1Database, ticketId: string, author: Author, body: string) {
  const ticket = await db.prepare("SELECT * FROM ticket WHERE id = ?").bind(ticketId).first<TicketRow>();
  if (!ticket || (author.kind === "branch" && ticket.license_id !== author.licenseId)) throw new ApiError(404, "not_found", "Ticket no encontrado");
  const count = await db.prepare("SELECT COUNT(*) AS n FROM ticket_message WHERE ticket_id = ?").bind(ticketId).first<number>("n");
  if ((count ?? 0) >= MAX_MESSAGES) throw new ApiError(409, "conflict", "El ticket llegó al máximo de mensajes; abre otro");
  const at = new Date().toISOString();
  await db.batch([
    db.prepare("INSERT INTO ticket_message (id, ticket_id, author, admin_id, body, created_at) VALUES (?, ?, ?, ?, ?, ?)").bind(
      crypto.randomUUID(),
      ticketId,
      author.kind,
      author.kind === "admin" ? author.adminId : null,
      body,
      at,
    ),
    db.prepare("UPDATE ticket SET status = ?, updated_at = ? WHERE id = ?").bind(author.kind === "admin" ? "answered" : "open", at, ticketId),
  ]);
  return ticketDetail(db, ticketId);
}

export async function closeTicket(db: D1Database, ticketId: string) {
  const closed = await db.prepare("UPDATE ticket SET status = 'closed', updated_at = ? WHERE id = ? RETURNING id").bind(new Date().toISOString(), ticketId).first();
  if (!closed) throw new ApiError(404, "not_found", "Ticket no encontrado");
  return ticketDetail(db, ticketId);
}

export async function branchTickets(db: D1Database, licenseId: string) {
  const { results } = await db.prepare("SELECT * FROM ticket WHERE license_id = ? ORDER BY updated_at DESC LIMIT 50").bind(licenseId).all<TicketRow>();
  const messages = await messagesOf(db, results.map((t) => t.id));
  return results.map((t) => ticketView(t, messages.get(t.id)!));
}

/** Panel inbox: newest activity first, without message bodies. */
export async function adminTickets(db: D1Database, status: string | undefined) {
  const { results } = await db
    .prepare(
      `SELECT t.id, t.license_id, t.subject, t.status, t.created_at, t.updated_at, l.customer, l.branch_name, l.site_id
       FROM ticket t JOIN license l ON l.id = t.license_id
       WHERE ?1 IS NULL OR t.status = ?1 ORDER BY t.updated_at DESC LIMIT 200`,
    )
    .bind(status ?? null)
    .all<TicketRow & { customer: string; branch_name: string; site_id: string }>();
  return results.map((t) => ({
    id: t.id,
    licenseId: t.license_id,
    customer: t.customer,
    branchName: t.branch_name,
    siteId: t.site_id,
    subject: t.subject,
    status: t.status,
    createdAt: t.created_at,
    updatedAt: t.updated_at,
  }));
}
