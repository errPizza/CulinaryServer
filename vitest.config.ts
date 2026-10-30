import { createHash, generateKeyPairSync, type KeyObject, type KeyPairKeyObjectResult } from "node:crypto";
import { cloudflareTest } from "@cloudflare/vitest-plugin";
import { defineConfig } from "vitest/config";
// @ts-expect-error plain ESM script shared with the offline signing tools
import { INTERMEDIATE, signJws, USES } from "./scripts/lib/jws.mjs";

// A test chain built like the offline station does: root → license and release intermediates.
const pkcs8 = (key: KeyObject) => key.export({ type: "pkcs8", format: "der" }).toString("base64url");
const spki = (key: KeyObject) => key.export({ type: "spki", format: "der" }).toString("base64url");
const signer = (pair: KeyPairKeyObjectResult) => {
  const raw = pair.publicKey.export({ type: "spki", format: "der" }).subarray(12);
  return { key: pair.privateKey, raw, kid: createHash("sha256").update(raw).digest("base64url").slice(0, 16) };
};
const root = generateKeyPairSync("ed25519");
const intermediate = (use: "license" | "release", generation: number) => {
  const pair = generateKeyPairSync("ed25519");
  const s = signer(pair);
  const now = Date.now();
  const chain = signJws(signer(root), INTERMEDIATE, { kid: s.kid, key: s.raw.toString("base64url"), uses: USES[use], generation, nbf: new Date(now - 60_000).toISOString(), exp: new Date(now + 30 * 86400000).toISOString() });
  return { key: pkcs8(pair.privateKey), chain };
};
const license = intermediate("license", 1);
const release = intermediate("release", 1);

export default defineConfig({
  test: { setupFiles: ["./test/setup.ts"] },
  plugins: [
    cloudflareTest({
      wrangler: { configPath: "./wrangler.jsonc" },
      miniflare: {
        bindings: {
          ROOT_PUBLIC_SPKI: spki(root.publicKey),
          LICENSE_SIGNING_KEY: license.key,
          LICENSE_SIGNING_CHAIN: license.chain,
          CHALLENGE_KEY: "llave-de-retos-solo-para-pruebas-0123456789",
          ADMIN_SETUP_CODE: "codigo-de-alta-solo-para-pruebas-0123456789",
          ADMIN_ORIGINS: "https://panel.test",
          // Only for tests: what the offline station holds.
          TEST_ROOT_KEY: pkcs8(root.privateKey),
          TEST_RELEASE_KEY: release.key,
          TEST_RELEASE_CHAIN: release.chain,
        },
      },
    }),
  ],
});
