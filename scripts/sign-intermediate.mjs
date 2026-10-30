// Run on the offline station: the root signs a new intermediate key for licenses (Worker) or releases (station).
// node scripts/sign-intermediate.mjs --use license --generation 1 [--days 400] [--root secrets/root-private.txt]
import { generateKeyPairSync } from "node:crypto";
import { existsSync, mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { arg, INTERMEDIATE, readPrivate, signJws, USES } from "./lib/jws.mjs";

const use = arg("use");
const generation = Number(arg("generation"));
const days = Number(arg("days", "400"));

if (!USES[use]) { console.error("--use debe ser license o release"); process.exit(2); }
if (!Number.isInteger(generation) || generation < 1) { console.error("--generation debe ser un entero desde 1"); process.exit(2); }
if (!(days >= 1 && days <= 800)) { console.error("--days entre 1 y 800"); process.exit(2); }

const root = readPrivate(arg("root", join("secrets", "root-private.txt")));
const dir = join(process.cwd(), "secrets");
const keyPath = join(dir, `${use}-g${generation}-private.txt`);
const chainPath = join(dir, `${use}-g${generation}-chain.txt`);

if (existsSync(keyPath)) { console.error(`Ya existe ${keyPath}; usa otra generación.`); process.exit(1); }

const { privateKey } = generateKeyPairSync("ed25519");
const pkcs8 = privateKey.export({ type: "pkcs8", format: "der" }).toString("base64url");
mkdirSync(dir, { recursive: true });
writeFileSync(keyPath, pkcs8 + "\n", { mode: 0o600 });

const intermediate = readPrivate(keyPath);
const now = Date.now();
const chain = signJws(root, INTERMEDIATE, {
  kid: intermediate.kid,
  key: intermediate.raw.toString("base64url"),
  uses: USES[use],
  generation,
  nbf: new Date(now - 5 * 60 * 1000).toISOString(),
  exp: new Date(now + days * 86400000).toISOString(),
});
writeFileSync(chainPath, chain + "\n");

console.log(`Intermedia de ${use === "license" ? "licencias" : "paquetes"} generación ${generation} (kid ${intermediate.kid}), vence en ${days} días.
  Llave privada: ${keyPath}
  Certificado:   ${chainPath}`);
if (use === "license") console.log(`Súbela al Worker como secretos:
  npx wrangler secret put LICENSE_SIGNING_KEY    (contenido de ${keyPath})
  npx wrangler secret put LICENSE_SIGNING_CHAIN  (contenido de ${chainPath})
Después borra ${keyPath} de este equipo.`);
else console.log("Guárdala en la estación de firma de paquetes; no la subas al Worker.");
