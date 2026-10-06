/**
 * Checks Kosha's crypto against the specifications it claims to
 * implement, rather than against itself.
 *
 * The scrypt core in static/js/crypto.js is hand-written (WebCrypto
 * has no native scrypt), and it was rewritten once for speed — a
 * change that is invisible if it is subtly wrong and catastrophic if
 * it ships. These are RFC 7914's own published vectors, so a passing
 * run means the implementation agrees with the standard, not merely
 * with yesterday's build.
 *
 * Run:  node tests/test_crypto.mjs
 */

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import nodeCrypto from "node:crypto";
import vm from "node:vm";

const here = dirname(fileURLToPath(import.meta.url));
const src = readFileSync(join(here, "..", "static", "js", "crypto.js"), "utf8");

// crypto.js is a plain browser script, not a module. Evaluating it in a
// context with the globals it expects gets it under test without
// adding a build step or a module wrapper the browser does not use.
const ctx = { crypto: globalThis.crypto, TextEncoder, TextDecoder, console, btoa, atob, performance };
ctx.self = ctx;
vm.createContext(ctx);
vm.runInContext(src + "\n;globalThis.__KOSHA = KoshaCrypto;", ctx);
const K = ctx.__KOSHA;

const hex = (b) => Buffer.from(b).toString("hex");
const utf8 = (s) => new TextEncoder().encode(s);

let passed = 0;
let failed = 0;
function check(name, ok, detail = "") {
  if (ok) {
    passed++;
    console.log(`  ok   ${name}`);
  } else {
    failed++;
    console.log(`  FAIL ${name}${detail ? "\n       " + detail : ""}`);
  }
}

// -- RFC 7914 §12 -----------------------------------------------------

console.log("RFC 7914 scrypt vectors");
const vectors = [
  {
    P: "", S: "", N: 16, r: 1, p: 1, len: 64,
    want: `77 d6 57 62 38 65 7b 20 3b 19 ca 42 c1 8a 04 97
           f1 6b 48 44 e3 07 4a e8 df df fa 3f ed e2 14 42
           fc d0 06 9d ed 09 48 f8 32 6a 75 3a 0f c8 1f 17
           e8 d3 e0 fb 2e 0d 36 28 cf 35 e2 0c 38 d1 89 06`,
  },
  {
    P: "password", S: "NaCl", N: 1024, r: 8, p: 16, len: 64,
    want: `fd ba be 1c 9d 34 72 00 78 56 e7 19 0d 01 e9 fe
           7c 6a d7 cb c8 23 78 30 e7 73 76 63 4b 37 31 62
           2e af 30 d9 2e 22 a3 88 6f f1 09 27 9d 98 30 da
           c7 27 af b9 4a 83 ee 6d 83 60 cb df a2 cc 06 40`,
  },
  {
    P: "pleaseletmein", S: "SodiumChloride", N: 16384, r: 8, p: 1, len: 64,
    want: `70 23 bd cb 3a fd 73 48 46 1c 06 cd 81 fd 38 eb
           fd a8 fb ba 90 4f 8e 3e a9 b5 43 f6 54 5d a1 f2
           d5 43 29 55 61 3f 0f cf 62 d4 97 05 24 2a 9a f9
           e6 1e 85 dc 0d 65 1e 40 df cf 01 7b 45 57 58 87`,
  },
];

for (const v of vectors) {
  const want = v.want.replace(/\s+/g, "");
  const got = hex(await K.scrypt(utf8(v.P), utf8(v.S), v.N, v.r, v.p, v.len));
  check(`scrypt(N=${v.N}, r=${v.r}, p=${v.p})`, got === want, `want ${want}\n       got  ${got}`);
}

// A non-power-of-two N would silently corrupt the mask in romix, so it
// must be refused rather than quietly producing a wrong key.
let rejected = false;
try {
  await K.scrypt(utf8("x"), utf8("y"), 1000, 8, 1, 32);
} catch {
  rejected = true;
}
check("scrypt rejects a non-power-of-two N", rejected);

// -- PBKDF2, against Node's own implementation ------------------------

console.log("\nPBKDF2-HMAC-SHA256");
for (const [pw, salt, iters, len] of [
  ["password", "salt", 1, 32],
  ["password", "salt", 4096, 40],
  ["", "", 2, 64],
]) {
  const mine = hex(await K.pbkdf2(utf8(pw), utf8(salt), iters, len));
  const theirs = nodeCrypto.pbkdf2Sync(pw, salt, iters, len, "sha256").toString("hex");
  check(`pbkdf2("${pw}", "${salt}", ${iters}, ${len})`, mine === theirs, `want ${theirs}\n       got  ${mine}`);
}

// -- The split-key property -------------------------------------------

console.log("\nSplit-key derivation");
const salt = K.randomBytes(16);
const a = await K.deriveSplitKeys("correct horse battery staple", salt, 1024);
const b = await K.deriveSplitKeys("correct horse battery staple", salt, 1024);
const c = await K.deriveSplitKeys("a different password", salt, 1024);

check("the same password and salt give the same keys", hex(a.authKey) === hex(b.authKey) && hex(a.encKey) === hex(b.encKey));
check("auth and enc halves are different keys", hex(a.authKey) !== hex(a.encKey));
check("a different password gives different keys", hex(a.authKey) !== hex(c.authKey));
check("both halves are 32 bytes", a.authKey.length === 32 && a.encKey.length === 32);

// -- AES-256-GCM -------------------------------------------------------

console.log("\nAES-256-GCM");
const key = K.randomBytes(32);
const aad = utf8("blob-id-1");
const ct = await K.encrypt(key, utf8("the quick brown fox"), aad);
check("round trip", K.fromUtf8(await K.decrypt(key, ct, aad)) === "the quick brown fox");
check("nonce is prepended and unique", ct.length === 12 + 19 + 16 && hex(ct.slice(0, 12)) !== hex((await K.encrypt(key, utf8("x"), aad)).slice(0, 12)));

for (const [name, mutate] of [
  ["a flipped ciphertext bit is rejected", (x) => { const y = x.slice(); y[20] ^= 1; return [key, y, aad]; }],
  ["the wrong AAD is rejected", (x) => [key, x, utf8("blob-id-2")]],
  ["the wrong key is rejected", (x) => [K.randomBytes(32), x, aad]],
  ["a truncated ciphertext is rejected", (x) => [key, x.slice(0, x.length - 2), aad]],
]) {
  let threw = false;
  try {
    await K.decrypt(...mutate(ct));
  } catch {
    threw = true;
  }
  check(name, threw);
}

// -- Vault keys --------------------------------------------------------

console.log("\nVault key separation");
const master = K.generateMasterKey();
const dbKey = await K.vaultDbKey(master);
const fileKey = await K.blobKey(master);
check("master key is 32 random bytes", master.length === 32);
check("the database and file keys differ", hex(dbKey) !== hex(fileKey));
check("neither subkey is the master key", hex(dbKey) !== hex(master) && hex(fileKey) !== hex(master));
check("the fingerprint is stable", (await K.vaultFingerprint(master)) === (await K.vaultFingerprint(master)));
check("different masters give different fingerprints", (await K.vaultFingerprint(master)) !== (await K.vaultFingerprint(K.generateMasterKey())));

// -- Base64 ------------------------------------------------------------

console.log("\nByte helpers");
const big = K.randomBytes(200000); // past the fromCharCode argument limit
check("base64 round-trips a large buffer", hex(K.base64ToBytes(K.bytesToBase64(big))) === hex(big));
check("hex round-trips", hex(K.hexToBytes(K.bytesToHex(big))) === hex(big));

console.log(`\n${passed} passed, ${failed} failed`);
process.exit(failed ? 1 : 0);
