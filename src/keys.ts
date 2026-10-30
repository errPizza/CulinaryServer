import { fromBase64Url, sha256, toBase64Url, utf8 } from "./crypto";
import { ApiError, type Env } from "./http";

// The root signs offline: only intermediates and the key floor. Each intermediate may sign only its own document
// types, so the license key that lives in this Worker cannot authorize a package.
export const INTERMEDIATE = "culinary-intermediate+jws";
export const KEY_FLOOR = "culinary-key-floor+jws";
export const LICENSE_USES = ["culinary-license+jws", "culinary-license-status+jws", "culinary-update+jws"] as const;
export const RELEASE_USES = ["culinary-release+jws"] as const;

export type Intermediate = { kid: string; key: string; uses: string[]; generation: number; nbf: string; exp: string };
type Signer = { privateKey: CryptoKey; kid: string; chain: string; intermediate: Intermediate };

const kidOf = async (raw: Uint8Array) => toBase64Url(await sha256(raw)).slice(0, 16);
const misconfigured = (message: string) => new ApiError(503, "server_misconfigured", message);

function keyBytes(text: string): Uint8Array<ArrayBuffer> {

  return fromBase64Url(text.replace(/-----[^-]+-----/g, "").replace(/\s/g, "").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, ""));
}

function decode(part: string): Record<string, any> {

  try { return JSON.parse(new TextDecoder().decode(fromBase64Url(part))); } catch { throw new ApiError(400, "bad_request", "Documento firmado ilegible"); }
}

let rootCache: { spki: string; root: Promise<{ key: CryptoKey; kid: string }> } | undefined;

export function rootPublic(env: Env): Promise<{ key: CryptoKey; kid: string; raw: Uint8Array<ArrayBuffer> }> {

  const spki = env.ROOT_PUBLIC_SPKI;

  if (!spki) throw misconfigured("Falta ROOT_PUBLIC_SPKI");
  if (rootCache?.spki !== spki) {

    const bytes = keyBytes(spki);
    rootCache = { spki, root: crypto.subtle.importKey("spki", bytes, { name: "Ed25519" }, false, ["verify"]).then(async (key) => ({ key, kid: await kidOf(bytes.slice(12)), raw: bytes.slice(12) })) };

  }

  return rootCache.root as Promise<{ key: CryptoKey; kid: string; raw: Uint8Array<ArrayBuffer> }>;
}

async function verifyWith(key: CryptoKey, jws: string): Promise<{ header: Record<string, any>; payload: Record<string, any> }> {

  const parts = jws.split(".");

  if (parts.length !== 3 || jws.length > 32768) throw new ApiError(400, "bad_request", "Documento firmado inválido");

  const [header, payload] = [decode(parts[0]!), decode(parts[1]!)];
  const valid = await crypto.subtle.verify({ name: "Ed25519" }, key, fromBase64Url(parts[2]!), utf8(`${parts[0]}.${parts[1]}`));

  if (!valid || header.alg !== "EdDSA" || payload.v !== 1) throw new ApiError(400, "bad_request", "Firma inválida");

  return { header, payload };
}

/** A document the root signed itself: intermediates and the key floor. */
export async function verifyRoot(env: Env, jws: string, typ: string): Promise<Record<string, any>> {

  const root = await rootPublic(env);
  const { header, payload } = await verifyWith(root.key, jws);

  if (header.typ !== typ || header.kid !== root.kid) throw new ApiError(400, "bad_request", "El documento no lo firmó la raíz");

  return payload;
}

/** Parses an intermediate certificate and checks that the root issued it for `typ`. */
export async function verifyIntermediate(env: Env, chain: string, typ: string): Promise<Intermediate> {

  const cert = (await verifyRoot(env, chain, INTERMEDIATE)) as Intermediate;

  if (!Array.isArray(cert.uses) || !cert.uses.includes(typ)) throw new ApiError(400, "bad_request", "La llave intermedia no puede firmar este tipo de documento");
  if (cert.kid !== (await kidOf(keyBytes(cert.key)))) throw new ApiError(400, "bad_request", "Llave intermedia inconsistente");

  return cert;
}

/** A document signed by an intermediate, carried in the `chain` header, within the intermediate's validity. */
export async function verifyChained(env: Env, jws: string, typ: string): Promise<{ payload: Record<string, any>; intermediate: Intermediate }> {

  const header = decode(jws.split(".")[0] ?? "");

  if (header.typ !== typ || typeof header.chain !== "string") throw new ApiError(400, "bad_request", "El documento no es del tipo esperado");

  const intermediate = await verifyIntermediate(env, header.chain, typ);
  const key = await crypto.subtle.importKey("raw", keyBytes(intermediate.key), { name: "Ed25519" }, false, ["verify"]);
  const { payload } = await verifyWith(key, jws);
  const iat = Date.parse(payload.iat);

  if (header.kid !== intermediate.kid || !(iat >= Date.parse(intermediate.nbf) && iat <= Date.parse(intermediate.exp))) throw new ApiError(400, "bad_request", "Firmado fuera de la vigencia de la llave intermedia");

  return { payload, intermediate };
}

let signerCache: { key: string; chain: string; signer: Promise<Signer> } | undefined;

async function loadSigner(env: Env, secret: string, chain: string): Promise<Signer> {

  const privateKey = await crypto.subtle.importKey("pkcs8", keyBytes(secret), { name: "Ed25519" }, true, ["sign"]).catch(() => { throw misconfigured("LICENSE_SIGNING_KEY no es una llave Ed25519 PKCS#8"); });
  const jwk = (await crypto.subtle.exportKey("jwk", privateKey)) as JsonWebKey;
  const intermediate = await verifyIntermediate(env, chain, LICENSE_USES[0]).catch(() => { throw misconfigured("LICENSE_SIGNING_CHAIN no es una intermedia de licencias firmada por la raíz"); });

  if (intermediate.key !== jwk.x || LICENSE_USES.some((typ) => !intermediate.uses.includes(typ))) throw misconfigured("LICENSE_SIGNING_KEY no corresponde a LICENSE_SIGNING_CHAIN");

  return { privateKey, kid: intermediate.kid, chain, intermediate };
}

/** The license intermediate, refused once expired or below the key floor so a rotation cannot be forgotten. */
export async function licenseSigner(env: Env): Promise<Signer> {

  const { LICENSE_SIGNING_KEY: key, LICENSE_SIGNING_CHAIN: chain } = env;

  if (!key || !chain) throw misconfigured("Faltan los secretos LICENSE_SIGNING_KEY y LICENSE_SIGNING_CHAIN");
  if (signerCache?.key !== key || signerCache.chain !== chain) {

    const signer = loadSigner(env, key, chain.trim());
    signerCache = { key, chain, signer };
    signer.catch(() => { if (signerCache?.signer === signer) signerCache = undefined; });

  }

  const signer = await signerCache.signer;
  const now = Date.now();

  if (now < Date.parse(signer.intermediate.nbf) || now > Date.parse(signer.intermediate.exp)) throw misconfigured("La llave intermedia de licencias venció o aún no es válida; firma una nueva con la raíz");
  if (signer.intermediate.generation < (await keyFloor(env)).license) throw misconfigured("La llave intermedia de licencias está revocada por el piso de llaves");

  return signer;
}

export async function signJws(env: Env, typ: (typeof LICENSE_USES)[number], payload: Record<string, unknown>): Promise<string> {

  const signer = await licenseSigner(env);
  const header = toBase64Url(utf8(JSON.stringify({ alg: "EdDSA", typ, kid: signer.kid, chain: signer.chain })));
  const body = toBase64Url(utf8(JSON.stringify({ v: 1, ...payload, iat: new Date().toISOString() })));
  const signature = await crypto.subtle.sign({ name: "Ed25519" }, signer.privateKey, utf8(`${header}.${body}`));

  return `${header}.${body}.${toBase64Url(new Uint8Array(signature))}`;
}

/** Lowest valid generation per use; raised by the root to revoke a compromised intermediate. */
export async function keyFloor(env: Env): Promise<{ license: number; release: number; jws: string | null }> {

  if (!env.KEY_FLOOR) return { license: 0, release: 0, jws: null };

  const floor = await verifyRoot(env, env.KEY_FLOOR.trim(), KEY_FLOOR).catch(() => { throw misconfigured("KEY_FLOOR no es un piso de llaves firmado por la raíz"); });

  return { license: Number(floor.license) || 0, release: Number(floor.release) || 0, jws: env.KEY_FLOOR.trim() };
}
