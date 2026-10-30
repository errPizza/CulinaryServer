// Run on the release station with the exact file uploaded from CulinaryAdmin. Prints the manifest to paste in the panel.
// node scripts/sign-release.mjs --file Culinary-0.4.0.exe --release-id <id> --version 0.4.0 --platform win-x64
//   [--key secrets/release-g1-private.txt] [--chain secrets/release-g1-chain.txt]
import { createHash } from "node:crypto";
import { readFileSync, statSync } from "node:fs";
import { basename, join } from "node:path";
import { arg, decode, readPrivate, signJws } from "./lib/jws.mjs";

const file = arg("file");
const key = readPrivate(arg("key", join("secrets", "release-g1-private.txt")));
const chain = readFileSync(arg("chain", join("secrets", "release-g1-chain.txt")), "utf8").trim();
const cert = decode(chain).payload;

if (cert.kid !== key.kid || !cert.uses?.includes("culinary-release+jws")) { console.error("La llave no corresponde al certificado de paquetes."); process.exit(1); }
if (Date.now() > Date.parse(cert.exp)) { console.error("La intermedia de paquetes venció; firma una nueva con la raíz."); process.exit(1); }

const manifest = signJws(key, "culinary-release+jws", {
  releaseId: arg("release-id"),
  version: arg("version"),
  platform: arg("platform"),
  filename: basename(file),
  bytes: statSync(file).size,
  sha512: createHash("sha512").update(readFileSync(file)).digest("hex"),
}, { chain });

console.log(manifest);
