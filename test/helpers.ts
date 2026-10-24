import { env, exports } from "cloudflare:workers";
import { expect } from "vitest";
import { fromBase64Url, toBase64Url, totpCode, utf8, type KeyAlg } from "../src/crypto";
import { signingInput, type Scope } from "../src/signature";

export type Device = { alg: KeyAlg; spki: string; privateKey: CryptoKey };

export async function newDevice(alg: KeyAlg = "Ed25519"): Promise<Device> {
  const params = alg === "Ed25519" ? { name: "Ed25519" } : { name: "ECDSA", namedCurve: "P-256" };
  const pair = (await crypto.subtle.generateKey(params, true, ["sign", "verify"])) as CryptoKeyPair;
  const spki = (await crypto.subtle.exportKey("spki", pair.publicKey)) as ArrayBuffer;
  return { alg, spki: toBase64Url(new Uint8Array(spki)), privateKey: pair.privateKey };
}

type CallOptions = { body?: unknown; raw?: BodyInit; headers?: Record<string, string>; token?: string };

export function call(method: string, path: string, options: CallOptions = {}): Promise<Response> {
  const headers = new Headers(options.headers);
  if (options.token) headers.set("authorization", `Bearer ${options.token}`);
  let body = options.raw ?? null;
  if (options.body !== undefined) {
    body = JSON.stringify(options.body);
    headers.set("content-type", "application/json");
  }
  return exports.default.fetch(new Request(`https://culinary.test${path}`, { method, headers, body }));
}

export async function json<T = any>(response: Response, status: number): Promise<T> {
  const text = await response.text();
  expect(response.status, text).toBe(status);
  return JSON.parse(text) as T;
}

export async function challenge(scope: Scope, subject: string): Promise<string> {
  const body = scope === "branch" ? { licenseId: subject } : { username: subject };
  return (await json(await call("POST", `/${scope}/v1/challenges`, { body }), 200)).nonce;
}

/** Signs exactly like the branch or the panel: fresh challenge, then the canonical input over the raw body. */
export async function signed(scope: Scope, device: Device, subject: string, method: string, path: string, body?: unknown, nonce?: string): Promise<Response> {
  nonce ??= await challenge(scope, subject);
  const bytes = body === undefined ? new Uint8Array() : utf8(JSON.stringify(body));
  const input = await signingInput(scope, method, path, subject, nonce, bytes);
  const params = device.alg === "Ed25519" ? { name: "Ed25519" } : { name: "ECDSA", hash: "SHA-256" };
  const signature = new Uint8Array(await crypto.subtle.sign(params, device.privateKey, input));
  const headers: Record<string, string> = {
    "x-culinary-subject": subject,
    "x-culinary-challenge": nonce,
    "x-culinary-signature": toBase64Url(signature),
  };
  if (body !== undefined) headers["content-type"] = "application/json";
  return call(method, path, { raw: body === undefined ? undefined : bytes, headers });
}

/** Verifies a compact JWS against the root public key the branch has embedded, and returns its payload. */
export async function verifyJws(jws: string, typ: string): Promise<any> {
  const [header, payload, signature] = jws.split(".");
  const key = await crypto.subtle.importKey("spki", fromBase64Url(env.ROOT_PUBLIC_SPKI), { name: "Ed25519" }, false, ["verify"]);
  expect(await crypto.subtle.verify({ name: "Ed25519" }, key, fromBase64Url(signature!), utf8(`${header}.${payload}`))).toBe(true);
  const decoded = JSON.parse(new TextDecoder().decode(fromBase64Url(header!)));
  expect(decoded).toMatchObject({ alg: "EdDSA", typ });
  return JSON.parse(new TextDecoder().decode(fromBase64Url(payload!)));
}

export const step = () => Math.floor(Date.now() / 30_000);

export type AdminSession = { token: string; username: string; device: Device; totpSecret: string };

/** Enrolls and confirms an admin, then logs in with the next TOTP step (the confirm step cannot be replayed). */
export async function enrollAdmin(code: string, username: string, password = "contraseña muy larga 123"): Promise<AdminSession> {
  const device = await newDevice();
  const enrolled = await json(await call("POST", "/admin/v1/enroll", { body: { code, username, password, deviceName: "Laptop de pruebas", key: { alg: device.alg, spki: device.spki } } }), 201);
  const secret = enrolled.totp.secret as string;
  await json(await signed("admin", device, username, "POST", "/admin/v1/enroll/confirm", { totp: await totpCode(secret, step()) }), 200);
  const login = await json(await signed("admin", device, username, "POST", "/admin/v1/login", { password, totp: await totpCode(secret, step() + 1) }), 200);
  return { token: login.token, username, device, totpSecret: secret };
}

export function firstAdmin(): Promise<AdminSession> {
  return enrollAdmin(env.ADMIN_SETUP_CODE, "proveedor");
}

export const fingerprint = { board: "a".repeat(64), disk: "b".repeat(64), mac: "c".repeat(64) };

export async function createLicense(token: string, overrides: Record<string, unknown> = {}) {
  const body = {
    customer: "Restaurante La Plaza",
    branchName: "Centro",
    siteId: `sitio-${crypto.randomUUID().slice(0, 8)}`,
    plan: "monthly",
    features: ["printing", "reservations"],
    limits: { maxUsers: 15, maxTables: 30 },
    ...overrides,
  };
  return json<{ license: any; activationCode: string }>(await call("POST", "/admin/v1/licenses", { token, body }), 201);
}

export async function activate(licenseId: string, activationCode: string, device: Device, binding: unknown = { kind: "fingerprint", fingerprint }) {
  return signed("branch", device, licenseId, "POST", "/branch/v1/activate", { activationCode, key: { alg: device.alg, spki: device.spki }, binding });
}
