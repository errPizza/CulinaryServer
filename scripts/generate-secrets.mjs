// Run once on a trusted, preferably offline, machine. Creates whatever is missing in secrets/ and never overwrites:
// rotating the root obliges reprovisioning every branch.
import { createHash, createPublicKey, generateKeyPairSync, randomBytes } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";

const dir = join(process.cwd(), "secrets");
const path = (name) => join(dir, name);
mkdirSync(dir, { recursive: true });

if (!existsSync(path("root-private.txt"))) {

  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  writeFileSync(path("root-private.txt"), privateKey.export({ type: "pkcs8", format: "der" }).toString("base64url") + "\n", { mode: 0o600 });
  writeFileSync(path("root-public.pem"), publicKey.export({ type: "spki", format: "pem" }));
  console.log("Llave raíz creada.");

}

for (const [name, label] of [["challenge-key.txt", "llave de retos"], ["admin-setup-code.txt", "código de alta del primer administrador"]]) {

  if (existsSync(path(name))) continue;
  writeFileSync(path(name), randomBytes(32).toString("base64url") + "\n", { mode: 0o600 });
  console.log(`Creado ${name} (${label}).`);

}

const spki = createPublicKey(readFileSync(path("root-public.pem"), "utf8")).export({ type: "spki", format: "der" });
const kid = createHash("sha256").update(spki.subarray(12)).digest("base64url").slice(0, 16);

console.log(`
Raíz kid ${kid}. Pública para Culinary Restaurant: secrets/root-public.pem
1. Variable pública del Worker (wrangler.jsonc, vars): ROOT_PUBLIC_SPKI = ${spki.toString("base64url")}
2. Secretos del Worker:
   npx wrangler secret put CHALLENGE_KEY      (contenido de secrets/challenge-key.txt)
   npx wrangler secret put ADMIN_SETUP_CODE   (contenido de secrets/admin-setup-code.txt)
3. Intermedias: node scripts/sign-intermediate.mjs --use license --generation 1
                node scripts/sign-intermediate.mjs --use release --generation 1
4. Guarda secrets/root-private.txt fuera de línea y bórralo de este equipo. El Worker ya no la necesita.`);
