import { createHash, createPrivateKey, createPublicKey, sign } from "node:crypto";
import { readFileSync } from "node:fs";

// Same JWS shape the Worker and Culinary Restaurant use: EdDSA over "header.body", payload version 1 with iat.
export const INTERMEDIATE = "culinary-intermediate+jws";
export const KEY_FLOOR = "culinary-key-floor+jws";
export const USES = {
  license: ["culinary-license+jws", "culinary-license-status+jws", "culinary-update+jws"],
  release: ["culinary-release+jws"],
};

const b64 = (data) => Buffer.from(data).toString("base64url");

export function arg(name, fallback) {

  const i = process.argv.indexOf(`--${name}`);
  if (i >= 0 && process.argv[i + 1]) return process.argv[i + 1];
  if (fallback === undefined) { console.error(`Falta --${name}`); process.exit(2); }
  return fallback;
}

/** A private key file as written by these scripts: PKCS#8 DER in base64url (PEM is accepted too). */
export function readPrivate(path) {

  const text = readFileSync(path, "utf8").trim();
  const key = text.includes("BEGIN") ? createPrivateKey(text) : createPrivateKey({ key: Buffer.from(text, "base64url"), format: "der", type: "pkcs8" });
  const raw = createPublicKey(key).export({ type: "spki", format: "der" }).subarray(12);
  return { key, raw, kid: createHash("sha256").update(raw).digest("base64url").slice(0, 16) };
}

export function signJws(signer, typ, payload, extraHeader = {}) {

  const header = b64(JSON.stringify({ alg: "EdDSA", typ, kid: signer.kid, ...extraHeader }));
  const body = b64(JSON.stringify({ v: 1, ...payload, iat: new Date().toISOString() }));
  return `${header}.${body}.${b64(sign(null, Buffer.from(`${header}.${body}`), signer.key))}`;
}

export function decode(jws) {

  const [header, body] = jws.trim().split(".");
  return { header: JSON.parse(Buffer.from(header, "base64url")), payload: JSON.parse(Buffer.from(body, "base64url")) };
}
