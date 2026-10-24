import { generateKeyPairSync } from "node:crypto";
import { cloudflareTest } from "@cloudflare/vitest-plugin";
import { defineConfig } from "vitest/config";

const root = generateKeyPairSync("ed25519");

export default defineConfig({
  test: { setupFiles: ["./test/setup.ts"] },
  plugins: [
    cloudflareTest({
      wrangler: { configPath: "./wrangler.jsonc" },
      miniflare: {
        bindings: {
          ROOT_PRIVATE_KEY: root.privateKey.export({ type: "pkcs8", format: "der" }).toString("base64url"),
          ROOT_PUBLIC_SPKI: root.publicKey.export({ type: "spki", format: "der" }).toString("base64url"),
          ADMIN_SETUP_CODE: "codigo-de-alta-solo-para-pruebas-0123456789",
          ADMIN_ORIGINS: "https://panel.test",
        },
      },
    }),
  ],
});
