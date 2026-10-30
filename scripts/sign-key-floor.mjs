// Run on the offline station to revoke intermediates: generations below the floor stop being accepted.
// node scripts/sign-key-floor.mjs --license 2 --release 1 [--root secrets/root-private.txt]
import { join } from "node:path";
import { arg, KEY_FLOOR, readPrivate, signJws } from "./lib/jws.mjs";

const floor = { license: Number(arg("license")), release: Number(arg("release")) };

if (!Object.values(floor).every((n) => Number.isInteger(n) && n >= 0)) { console.error("--license y --release deben ser enteros desde 0"); process.exit(2); }

const jws = signJws(readPrivate(arg("root", join("secrets", "root-private.txt"))), KEY_FLOOR, floor);

console.log(`${jws}

Súbelo al Worker: npx wrangler secret put KEY_FLOOR (pega la línea anterior).
Las sucursales lo guardan al renovar la licencia; una generación menor deja de valer.`);
