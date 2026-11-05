import { ApiError } from "./http";

const MAX_OPEN_TICKETS = 20;
const MAX_MESSAGES = 100;

export const TICKET_STATUSES = ["open", "answered", "closed"] as const;

type TicketRow = { id: string; license_id: string; subject: string; status: (typeof TICKET_STATUSES)[number]; created_at: string; updated_at: string; owner_account_id: string | null; owner_email?: string | null };
type MessageRow = { id: string; ticket_id: string; author: "branch" | "admin"; admin_id: string | null; body: string; created_at: string };

// A person of the owner's panel writes as the business; the table keeps 'branch' and the ticket names who it was.
export type Author = { kind: "branch"; licenseId: string } | { kind: "admin"; adminId: string } | { kind: "owner"; accountId: string };

function ticketView(ticket: TicketRow, messages: MessageRow[]) {

  const fromOwner = ticket.owner_account_id !== null;

  return {

    id: ticket.id,
    licenseId: ticket.license_id,
    subject: ticket.subject,
    status: ticket.status,
    createdAt: ticket.created_at,
    updatedAt: ticket.updated_at,
    ...(fromOwner ? { ownerEmail: ticket.owner_email ?? null } : {}),
    messages: messages.map((m) => ({ id: m.id, author: fromOwner && m.author === "branch" ? "owner" : m.author, adminId: m.admin_id, body: m.body, createdAt: m.created_at }))
  };
}

async function messagesOf(db: D1Database, ticketIds: string[]): Promise<Map<string, MessageRow[]>> {

  const byTicket = new Map<string, MessageRow[]>(ticketIds.map((id) => [id, []]));

  if (ticketIds.length === 0) return byTicket;

  const { results } = await db.prepare(`SELECT * FROM ticket_message WHERE ticket_id IN (SELECT value FROM json_each(?)) ORDER BY created_at, id`).bind(JSON.stringify(ticketIds)).all<MessageRow>();

  for (const message of results) byTicket.get(message.ticket_id)!.push(message);

  return byTicket;
}

const WITH_OWNER = "SELECT t.*, a.email AS owner_email FROM ticket t LEFT JOIN owner_account a ON a.id = t.owner_account_id";

export async function ticketDetail(db: D1Database, id: string) {

  const ticket = await db.prepare(`${WITH_OWNER} WHERE t.id = ?`).bind(id).first<TicketRow>();

  if (!ticket) throw new ApiError(404, "not_found", "Ticket no encontrado");

  return ticketView(ticket, (await messagesOf(db, [id])).get(id)!);
}

export async function createTicket(db: D1Database, licenseId: string, subject: string, body: string, ownerAccountId: string | null = null) {

  const open = ownerAccountId
    ? await db.prepare("SELECT COUNT(*) AS n FROM ticket WHERE owner_account_id = ? AND status <> 'closed'").bind(ownerAccountId).first<number>("n")
    : await db.prepare("SELECT COUNT(*) AS n FROM ticket WHERE license_id = ? AND owner_account_id IS NULL AND status <> 'closed'").bind(licenseId).first<number>("n");

  if ((open ?? 0) >= MAX_OPEN_TICKETS) throw new ApiError(429, "rate_limited", "Demasiados tickets abiertos; espera respuesta o cierra alguno");

  const id = crypto.randomUUID();
  const at = new Date().toISOString();

  await db.batch([
    db.prepare("INSERT INTO ticket (id, license_id, subject, status, created_at, updated_at, owner_account_id) VALUES (?, ?, ?, 'open', ?, ?, ?)").bind(id, licenseId, subject, at, at, ownerAccountId),
    db.prepare("INSERT INTO ticket_message (id, ticket_id, author, admin_id, body, created_at) VALUES (?, ?, 'branch', NULL, ?, ?)").bind(crypto.randomUUID(), id, body, at),
  ]);

  return ticketDetail(db, id);
}

function writes(ticket: TicketRow, author: Author) {

  if (author.kind === "branch") return ticket.license_id === author.licenseId && ticket.owner_account_id === null;
  if (author.kind === "owner") return ticket.owner_account_id === author.accountId;

  return true;
}

export async function addTicketMessage(db: D1Database, ticketId: string, author: Author, body: string) {

  const ticket = await db.prepare("SELECT * FROM ticket WHERE id = ?").bind(ticketId).first<TicketRow>();

  if (!ticket || !writes(ticket, author)) throw new ApiError(404, "not_found", "Ticket no encontrado");

  const count = await db.prepare("SELECT COUNT(*) AS n FROM ticket_message WHERE ticket_id = ?").bind(ticketId).first<number>("n");

  if ((count ?? 0) >= MAX_MESSAGES) throw new ApiError(409, "conflict", "El ticket llegó al máximo de mensajes; abre otro");

  const at = new Date().toISOString();

  await db.batch([
    db.prepare("INSERT INTO ticket_message (id, ticket_id, author, admin_id, body, created_at) VALUES (?, ?, ?, ?, ?, ?)").bind(crypto.randomUUID(), ticketId, author.kind === "admin" ? "admin" : "branch", author.kind === "admin" ? author.adminId : null, body, at),
    db.prepare("UPDATE ticket SET status = ?, updated_at = ? WHERE id = ?").bind(author.kind === "admin" ? "answered" : "open", at, ticketId)
  ]);

  return ticketDetail(db, ticketId);
}

export async function closeTicket(db: D1Database, ticketId: string) {

  const closed = await db.prepare("UPDATE ticket SET status = 'closed', updated_at = ? WHERE id = ? RETURNING id").bind(new Date().toISOString(), ticketId).first();

  if (!closed) throw new ApiError(404, "not_found", "Ticket no encontrado");

  return ticketDetail(db, ticketId);
}

export async function branchTickets(db: D1Database, licenseId: string) {

  const { results } = await db.prepare("SELECT * FROM ticket WHERE license_id = ? AND owner_account_id IS NULL ORDER BY updated_at DESC LIMIT 50").bind(licenseId).all<TicketRow>();
  const messages = await messagesOf(db, results.map((t) => t.id));

  return results.map((t) => ticketView(t, messages.get(t.id)!));
}

/** What one person of the panel asked the provider; each person sees only their own. */
export async function ownerTickets(db: D1Database, accountId: string) {

  const { results } = await db.prepare(`${WITH_OWNER} WHERE t.owner_account_id = ? ORDER BY t.updated_at DESC LIMIT 50`).bind(accountId).all<TicketRow>();
  const messages = await messagesOf(db, results.map((t) => t.id));

  return results.map((t) => ticketView(t, messages.get(t.id)!));
}

export async function ownerTicket(db: D1Database, accountId: string, id: string) {

  const ticket = await ticketDetail(db, id);
  const row = await db.prepare("SELECT owner_account_id FROM ticket WHERE id = ?").bind(id).first<string | null>("owner_account_id");

  if (row !== accountId) throw new ApiError(404, "not_found", "Ticket no encontrado");

  return ticket;
}

export async function adminTickets(db: D1Database, status: string | undefined) {

  const { results } = await db.prepare(`SELECT t.id, t.license_id, t.subject, t.status, t.created_at, t.updated_at, t.owner_account_id, a.email AS owner_email, l.customer, l.branch_name, l.site_id FROM ticket t JOIN license l ON l.id = t.license_id LEFT JOIN owner_account a ON a.id = t.owner_account_id WHERE ?1 IS NULL OR t.status = ?1 ORDER BY t.updated_at DESC LIMIT 200`).bind(status ?? null).all<TicketRow & { customer: string; branch_name: string; site_id: string }>();

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
    ...(t.owner_account_id ? { ownerEmail: t.owner_email ?? null } : {})

  }));
}
