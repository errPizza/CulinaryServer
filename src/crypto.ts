import { ApiError } from "./http";

const encoder = new TextEncoder();

export type KeyAlg = "Ed25519" | "ES256";

export function utf8(text: string): Uint8Array<ArrayBuffer> {
  return encoder.encode(text) as Uint8Array<ArrayBuffer>;
}

export function toBase64Url(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function fromBase64Url(text: string): Uint8Array<ArrayBuffer> {
  if (!/^[A-Za-z0-9_-]*$/.test(text)) throw new ApiError(400, "bad_request", "Base64url inválido");
  const padded = text.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - (text.length % 4)) % 4);
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

export function toHex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

export async function sha256(data: Uint8Array | string): Promise<Uint8Array<ArrayBuffer>> {
  const bytes = typeof data === "string" ? utf8(data) : data;
  return new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
}

export async function sha256Hex(data: Uint8Array | string): Promise<string> {
  return toHex(await sha256(data));
}

export function randomBytes(length: number): Uint8Array<ArrayBuffer> {
  return crypto.getRandomValues(new Uint8Array(length));
}

export function randomToken(): string {
  return toBase64Url(randomBytes(32));
}

const BASE32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

function base32(bytes: Uint8Array): string {
  let bits = 0;
  let value = 0;
  let out = "";
  for (const byte of bytes) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      out += BASE32[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) out += BASE32[(value << (5 - bits)) & 31];
  return out;
}

function fromBase32(text: string): Uint8Array<ArrayBuffer> {
  let bits = 0;
  let value = 0;
  const out: number[] = [];
  for (const char of text) {
    const index = BASE32.indexOf(char);
    if (index < 0) throw new Error("base32 inválido");
    value = (value << 5) | index;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 255);
      bits -= 8;
    }
  }
  return new Uint8Array(out);
}

/** Codes people type at a till: 20 base32 characters (100 bits) in groups of five. */
export function newHumanCode(): string {
  return base32(randomBytes(13)).slice(0, 20).match(/.{5}/g)!.join("-");
}

export function normalizeHumanCode(code: string): string {
  return code.toUpperCase().replace(/[\s-]/g, "");
}

export async function sameSecret(a: string, b: string): Promise<boolean> {
  return crypto.subtle.timingSafeEqual(await sha256(a), await sha256(b));
}

export async function importPublicKey(alg: KeyAlg, spki: string): Promise<CryptoKey> {
  const params = alg === "Ed25519" ? { name: "Ed25519" } : { name: "ECDSA", namedCurve: "P-256" };
  try {
    return await crypto.subtle.importKey("spki", fromBase64Url(spki), params, false, ["verify"]);
  } catch {
    throw new ApiError(400, "bad_request", `Llave pública ${alg} inválida`);
  }
}

/** ES256 signatures are IEEE P1363 (r || s, 64 bytes), not DER. */
export async function verifySignature(alg: KeyAlg, key: CryptoKey, signature: Uint8Array<ArrayBuffer>, data: Uint8Array<ArrayBuffer>): Promise<boolean> {
  if (signature.length !== 64) return false;
  const params = alg === "Ed25519" ? { name: "Ed25519" } : { name: "ECDSA", hash: "SHA-256" };
  return crypto.subtle.verify(params, key, signature, data);
}

export type RootKey = { privateKey: CryptoKey; publicRaw: Uint8Array<ArrayBuffer>; kid: string };

let rootCache: { secret: string; key: Promise<RootKey> } | undefined;

/** Accepts the PKCS#8 key as PEM, base64 or base64url (what scripts/generate-secrets.mjs prints). */
export function rootKey(secret: string | undefined): Promise<RootKey> {
  if (!secret) throw new ApiError(503, "server_misconfigured", "Falta el secreto ROOT_PRIVATE_KEY");
  if (rootCache?.secret !== secret) rootCache = { secret, key: loadRootKey(secret) };
  return rootCache.key;
}

async function loadRootKey(secret: string): Promise<RootKey> {
  const body = secret.replace(/-----[^-]+-----/g, "").replace(/\s/g, "").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  const privateKey = await crypto.subtle.importKey("pkcs8", fromBase64Url(body), { name: "Ed25519" }, true, ["sign"]);
  const jwk = (await crypto.subtle.exportKey("jwk", privateKey)) as JsonWebKey;
  const publicRaw = fromBase64Url(jwk.x!);
  return { privateKey, publicRaw, kid: toBase64Url(await sha256(publicRaw)).slice(0, 16) };
}

/** SubjectPublicKeyInfo DER for an Ed25519 key: fixed 12-byte prefix plus the 32 raw bytes. */
export function ed25519Spki(raw: Uint8Array): Uint8Array<ArrayBuffer> {
  const prefix = [0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00];
  return new Uint8Array([...prefix, ...raw]);
}

/** Compact JWS (RFC 7515) with EdDSA (RFC 8037). `typ` tells documents apart so one cannot pass for another. */
export async function signJws(root: RootKey, typ: string, payload: unknown): Promise<string> {
  const header = toBase64Url(utf8(JSON.stringify({ alg: "EdDSA", typ, kid: root.kid })));
  const body = toBase64Url(utf8(JSON.stringify(payload)));
  const signature = await crypto.subtle.sign({ name: "Ed25519" }, root.privateKey, utf8(`${header}.${body}`));
  return `${header}.${body}.${toBase64Url(new Uint8Array(signature))}`;
}

// Kept at 100,000 to stay within Workers CPU limits; TOTP and the device signature carry the rest of the login.
const PBKDF2_ITERATIONS = 100_000;

async function pbkdf2(password: string, salt: Uint8Array<ArrayBuffer>, iterations: number): Promise<Uint8Array<ArrayBuffer>> {
  const key = await crypto.subtle.importKey("raw", utf8(password), "PBKDF2", false, ["deriveBits"]);
  return new Uint8Array(await crypto.subtle.deriveBits({ name: "PBKDF2", hash: "SHA-256", salt, iterations }, key, 256));
}

export async function hashPassword(password: string): Promise<string> {
  const salt = randomBytes(16);
  return `pbkdf2-sha256$${PBKDF2_ITERATIONS}$${toBase64Url(salt)}$${toBase64Url(await pbkdf2(password, salt, PBKDF2_ITERATIONS))}`;
}

export async function verifyPassword(password: string, stored: string): Promise<boolean> {
  const [scheme, iterations, salt, hash] = stored.split("$");
  if (scheme !== "pbkdf2-sha256" || !iterations || !salt || !hash) return false;
  const actual = await pbkdf2(password, fromBase64Url(salt), Number(iterations));
  return crypto.subtle.timingSafeEqual(actual, fromBase64Url(hash));
}

export function newTotpSecret(): string {
  return base32(randomBytes(20));
}

async function hotp(secret: string, counter: number): Promise<string> {
  const key = await crypto.subtle.importKey("raw", fromBase32(secret), { name: "HMAC", hash: "SHA-1" }, false, ["sign"]);
  const message = new DataView(new ArrayBuffer(8));
  message.setUint32(0, Math.floor(counter / 2 ** 32));
  message.setUint32(4, counter >>> 0);
  const mac = new Uint8Array(await crypto.subtle.sign("HMAC", key, message.buffer));
  const offset = mac[19]! & 15;
  const code = (((mac[offset]! & 127) << 24) | (mac[offset + 1]! << 16) | (mac[offset + 2]! << 8) | mac[offset + 3]!) % 1_000_000;
  return code.toString().padStart(6, "0");
}

export function totpCode(secret: string, step: number): Promise<string> {
  return hotp(secret, step);
}

/** RFC 6238 with 30-second steps and one step of clock drift. Returns the matched step, or null. */
export async function verifyTotp(secret: string, code: string, nowMs: number, lastStep: number): Promise<number | null> {
  if (!/^\d{6}$/.test(code)) return null;
  const current = Math.floor(nowMs / 30_000);
  for (const step of [current - 1, current, current + 1]) {
    if (step > lastStep && (await sameSecret(await hotp(secret, step), code))) return step;
  }
  return null;
}
