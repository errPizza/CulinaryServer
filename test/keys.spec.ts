import { env as testEnv } from "cloudflare:workers";
import { describe, expect, it } from "vitest";
import { toBase64Url } from "../src/crypto";
import { INTERMEDIATE, KEY_FLOOR, keyFloor, LICENSE_USES, licenseSigner } from "../src/keys";
import type { Env } from "../src/http";
import { stationSign } from "./helpers";

const env = testEnv as unknown as Env & typeof testEnv;

async function newIntermediate(overrides: Record<string, unknown> = {}) {
  const pair = (await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"])) as CryptoKeyPair;
  const raw = new Uint8Array((await crypto.subtle.exportKey("raw", pair.publicKey)) as ArrayBuffer);
  const kid = toBase64Url(new Uint8Array(await crypto.subtle.digest("SHA-256", raw))).slice(0, 16);
  const now = Date.now();
  const chain = await stationSign(env.TEST_ROOT_KEY, INTERMEDIATE, { kid, key: toBase64Url(raw), uses: [...LICENSE_USES], generation: 1, nbf: new Date(now - 60_000).toISOString(), exp: new Date(now + 86400000).toISOString(), ...overrides });
  return { LICENSE_SIGNING_KEY: toBase64Url(new Uint8Array((await crypto.subtle.exportKey("pkcs8", pair.privateKey)) as ArrayBuffer)), LICENSE_SIGNING_CHAIN: chain };
}

describe("llaves de firma", () => {
  it("firma licencias con la intermedia de licencias", async () => {
    const signer = await licenseSigner(env);
    expect(signer.intermediate.uses).toEqual([...LICENSE_USES]);
  });

  it("no firma con una intermedia vencida, de otro uso o que no corresponde a su llave", async () => {
    await expect(licenseSigner({ ...env, ...(await newIntermediate({ exp: new Date(Date.now() - 1000).toISOString() })) })).rejects.toThrow(/venció/);
    await expect(licenseSigner({ ...env, ...(await newIntermediate({ uses: ["culinary-release+jws"] })) })).rejects.toThrow(/intermedia de licencias/);
    await expect(licenseSigner({ ...env, LICENSE_SIGNING_KEY: (await newIntermediate()).LICENSE_SIGNING_KEY })).rejects.toThrow(/no corresponde/);
  });

  it("un certificado intermedio que no firmó la raíz no sirve", async () => {
    const forged = await newIntermediate();
    const signedBySelf = await stationSign(forged.LICENSE_SIGNING_KEY, INTERMEDIATE, JSON.parse(atob(forged.LICENSE_SIGNING_CHAIN.split(".")[1]!.replace(/-/g, "+").replace(/_/g, "/"))));
    await expect(licenseSigner({ ...env, LICENSE_SIGNING_CHAIN: signedBySelf, LICENSE_SIGNING_KEY: forged.LICENSE_SIGNING_KEY })).rejects.toThrow(/firmada por la raíz/);
  });

  it("el piso de llaves firmado por la raíz revoca generaciones anteriores", async () => {
    const floor = await stationSign(env.TEST_ROOT_KEY, KEY_FLOOR, { license: 2, release: 1 });
    expect(await keyFloor({ ...env, KEY_FLOOR: floor })).toMatchObject({ license: 2, release: 1, jws: floor });
    await expect(licenseSigner({ ...env, KEY_FLOOR: floor })).rejects.toThrow(/revocada/);
    const forged = await stationSign(env.TEST_RELEASE_KEY, KEY_FLOOR, { license: 0, release: 0 });
    await expect(keyFloor({ ...env, KEY_FLOOR: forged })).rejects.toThrow(/firmado por la raíz/);
  });
});
