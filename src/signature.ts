import { fromBase64Url, importPublicKey, randomBytes, sha256, sha256Hex, toBase64Url, utf8, verifySignature, type KeyAlg } from "./crypto";
import { ApiError, rawBody, type Ctx, type Env } from "./http";

export type Scope = "branch" | "admin";

const CHALLENGE_TTL_MS = 2 * 60 * 1000;

let macCache: { secret: string; key: Promise<CryptoKey> } | undefined;

function challengeKey(secret: string | undefined): Promise<CryptoKey> {
  if (!secret) throw new ApiError(503, "server_misconfigured", "Falta el secreto ROOT_PRIVATE_KEY");
  if (macCache?.secret !== secret) {
    const key = sha256(`culinary-challenge-v1|${secret}`).then((raw) => crypto.subtle.importKey("raw", raw, { name: "HMAC", hash: "SHA-256" }, false, ["sign", "verify"]));
    macCache = { secret, key };
  }
  return macCache.key;
}

function macInput(scope: Scope, subject: string, expires: number, random: Uint8Array): Uint8Array<ArrayBuffer> {
  return utf8(`${scope}\n${subject}\n${expires}\n${toBase64Url(random)}`);
}

/**
 * Stateless: the nonce is expiry + random + HMAC over scope and subject, so issuing one writes nothing.
 * Nobody can exhaust another subject's challenges, and every subject, real or not, gets the same answer.
 */
export async function issueChallenge(env: Env, scope: Scope, subject: string): Promise<{ nonce: string; expiresAt: string }> {
  const expires = Date.now() + CHALLENGE_TTL_MS;
  const random = randomBytes(16);
  const mac = new Uint8Array(await crypto.subtle.sign("HMAC", await challengeKey(env.ROOT_PRIVATE_KEY), macInput(scope, subject, expires, random)));
  const head = new DataView(new ArrayBuffer(8));
  head.setFloat64(0, expires);
  return { nonce: toBase64Url(new Uint8Array([...new Uint8Array(head.buffer), ...random, ...mac])), expiresAt: new Date(expires).toISOString() };
}

/** Valid, unexpired, issued for this scope and subject, and recorded as used for the first time. */
async function consumeChallenge(env: Env, scope: Scope, subject: string, nonce: string): Promise<boolean> {
  const bytes = fromBase64Url(nonce);
  if (bytes.length !== 56) return false;
  const expires = new DataView(bytes.buffer).getFloat64(0);
  if (!(expires >= Date.now())) return false;
  const valid = await crypto.subtle.verify("HMAC", await challengeKey(env.ROOT_PRIVATE_KEY), bytes.slice(24), macInput(scope, subject, expires, bytes.slice(8, 24)));
  if (!valid) return false;
  const used = await env.DB.prepare("INSERT INTO used_challenge (nonce, expires_at) VALUES (?, ?) ON CONFLICT DO NOTHING RETURNING nonce").bind(nonce, expires).first();
  return used !== null;
}

export type SignedRequest = { subject: string; nonce: string; signature: Uint8Array<ArrayBuffer>; body: Uint8Array };

export async function readSigned(c: Ctx): Promise<SignedRequest> {
  const body = await rawBody(c);
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
  if (!(await consumeChallenge(c.env, scope, request.subject, request.nonce))) return false;
  const url = new URL(c.req.url);
  const input = await signingInput(scope, c.req.method, url.pathname + url.search, request.subject, request.nonce, request.body);
  return verifySignature(alg, await importPublicKey(alg, spki), request.signature, input);
}
