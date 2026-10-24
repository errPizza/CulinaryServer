import { fromBase64Url, importPublicKey, randomToken, sha256Hex, utf8, verifySignature, type KeyAlg } from "./crypto";
import { ApiError, type Ctx } from "./http";

export type Scope = "branch" | "admin";

const CHALLENGE_TTL_MS = 2 * 60 * 1000;
const MAX_OPEN_CHALLENGES = 10;

/**
 * Only subjects that exist get a stored challenge. Unknown ones receive an identical-looking nonce
 * that can never be consumed, so the endpoint does not reveal which usernames or licenses exist.
 */
export async function issueChallenge(db: D1Database, scope: Scope, subject: string, exists: boolean): Promise<{ nonce: string; expiresAt: string }> {
  const nonce = randomToken();
  const expires = Date.now() + CHALLENGE_TTL_MS;
  if (exists) {
    await db.prepare("DELETE FROM challenge WHERE scope = ? AND subject = ? AND expires_at < ?").bind(scope, subject, Date.now()).run();
    const open = await db.prepare("SELECT COUNT(*) AS n FROM challenge WHERE scope = ? AND subject = ?").bind(scope, subject).first<number>("n");
    if ((open ?? 0) >= MAX_OPEN_CHALLENGES) throw new ApiError(429, "rate_limited", "Demasiados retos pendientes; espera dos minutos");
    await db.prepare("INSERT INTO challenge (nonce, scope, subject, expires_at) VALUES (?, ?, ?, ?)").bind(nonce, scope, subject, expires).run();
  }
  return { nonce, expiresAt: new Date(expires).toISOString() };
}

export type SignedRequest = { subject: string; nonce: string; signature: Uint8Array<ArrayBuffer>; body: Uint8Array };

export function signedHeaders(c: Ctx, body: Uint8Array): SignedRequest {
  const subject = c.req.header("x-culinary-subject") ?? "";
  const nonce = c.req.header("x-culinary-challenge") ?? "";
  const signature = c.req.header("x-culinary-signature") ?? "";
  if (!subject || !nonce || !signature) throw new ApiError(401, "unauthorized", "Faltan las cabeceras de firma");
  return { subject, nonce, signature: fromBase64Url(signature), body };
}

export async function signingInput(scope: Scope, method: string, path: string, subject: string, nonce: string, body: Uint8Array): Promise<Uint8Array<ArrayBuffer>> {
  return utf8(["culinary-request-v1", scope, method.toUpperCase(), path, subject, nonce, await sha256Hex(body)].join("\n"));
}

/**
 * The challenge is consumed before the signature is checked, so each nonce allows exactly one attempt.
 * Callers map `false` to their own error to keep responses uniform.
 */
export async function verifySigned(c: Ctx, scope: Scope, request: SignedRequest, alg: KeyAlg, spki: string): Promise<boolean> {
  const consumed = await c.env.DB.prepare("DELETE FROM challenge WHERE nonce = ? AND scope = ? AND subject = ? AND expires_at >= ? RETURNING nonce")
    .bind(request.nonce, scope, request.subject, Date.now())
    .first();
  if (!consumed) return false;
  const url = new URL(c.req.url);
  const input = await signingInput(scope, c.req.method, url.pathname + url.search, request.subject, request.nonce, request.body);
  return verifySignature(alg, await importPublicKey(alg, spki), request.signature, input);
}
