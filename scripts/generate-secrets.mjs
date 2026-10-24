// Run once per deployment: creates the root Ed25519 key and the panel's setup code.
// The private key leaves this machine only as the ROOT_PRIVATE_KEY secret.
import { createHash, generateKeyPairSync, randomBytes } from "node:crypto";
import { existsSync, mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";

const dir = join(process.cwd(), "secrets");
const privatePath = join(dir, "root-private.txt");
if (existsSync(privatePath)) {
  console.error(`Ya existe ${privatePath}. Rotar la raíz obliga a reaprovisionar todas las sucursales; bórralo a mano solo si es lo que quieres.`);
  process.exit(1);
}

const { publicKey, privateKey } = generateKeyPairSync("ed25519");
const pkcs8 = privateKey.export({ type: "pkcs8", format: "der" }).toString("base64url");
const spki = publicKey.export({ type: "spki", format: "der" });
const raw = spki.subarray(12);
const kid = createHash("sha256").update(raw).digest("base64url").slice(0, 16);
const pem = publicKey.export({ type: "spki", format: "pem" });
const setupCode = randomBytes(32).toString("base64url");

mkdirSync(dir, { recursive: true });
writeFileSync(privatePath, pkcs8 + "\n", { mode: 0o600 });
writeFileSync(join(dir, "admin-setup-code.txt"), setupCode + "\n", { mode: 0o600 });
writeFileSync(join(dir, "root-public.pem"), pem);

console.log(`Llave raíz creada (kid ${kid}).

Pública, para Culinary Restaurant (secrets/root-public.pem):
${pem}
Pública en bruto (base64url): ${raw.toString("base64url")}

Sube los secretos al Worker:
  npx wrangler secret put ROOT_PRIVATE_KEY   (pega el contenido de secrets/root-private.txt)
  npx wrangler secret put ADMIN_SETUP_CODE   (pega el contenido de secrets/admin-setup-code.txt)

Después guarda secrets/root-private.txt fuera de línea y bórralo de este equipo.`);
