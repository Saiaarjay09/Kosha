/**
 * Kosha's browser crypto engine.
 *
 * This is a trimmed port of Haven's `webapp/static/js/crypto.js` — the
 * same primitives, verified the same way, with the parts Kosha has no
 * use for (X25519, the message ratchet) removed rather than carried
 * along unused. What survives is exactly the set a zero-knowledge
 * *vault* needs:
 *
 *   - scrypt (RFC 7914), implemented from spec because WebCrypto still
 *     has no native scrypt. Checked against RFC 7914's own official
 *     test vectors by tests/test_crypto.html.
 *   - HKDF-SHA256 and AES-256-GCM, both from the browser's native
 *     `crypto.subtle` — audited, vendor-implemented code, not
 *     something this project wrote.
 *   - The split-key derivation that makes the whole "server cannot
 *     read your data" claim work (see deriveSplitKeys below).
 *
 * THE ONE IDEA WORTH UNDERSTANDING HERE, if you read nothing else:
 * your password is turned into *two* independent keys. One of them
 * (`authKey`) goes to the server, which uses it only to decide whether
 * to let you in. The other (`encKey`) never leaves this browser, and
 * it is the only thing in the universe that can decrypt your vault.
 * Neither key can be computed from the other. That is why a complete
 * dump of Kosha's server database is a pile of noise to whoever steals
 * it — and also why losing both your password and your recovery
 * phrase is genuinely unrecoverable, by anyone, including you.
 */

const KoshaCrypto = (() => {
  "use strict";

  // -------------------------------------------------------------------
  // Byte utilities
  // -------------------------------------------------------------------

  function hexToBytes(hex) {
    if (hex.length % 2 !== 0) throw new Error("odd-length hex string");
    const out = new Uint8Array(hex.length / 2);
    for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.substr(i * 2, 2), 16);
    return out;
  }

  function bytesToHex(bytes) {
    return Array.from(bytes)
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");
  }

  function utf8(str) {
    return new TextEncoder().encode(str);
  }

  function fromUtf8(bytes) {
    return new TextDecoder().decode(bytes);
  }

  function concatBytes(...parts) {
    const total = parts.reduce((n, p) => n + p.length, 0);
    const out = new Uint8Array(total);
    let offset = 0;
    for (const p of parts) {
      out.set(p, offset);
      offset += p.length;
    }
    return out;
  }

  function randomBytes(n) {
    const out = new Uint8Array(n);
    // getRandomValues throws QuotaExceededError past 65536 bytes — a
    // limit in the Web Crypto spec itself, not a browser quirk.
    // Nothing in Kosha asks for a key that large today, but a helper
    // named randomBytes should not have a silent cliff in it.
    const CHUNK = 65536;
    for (let offset = 0; offset < n; offset += CHUNK) {
      crypto.getRandomValues(out.subarray(offset, Math.min(offset + CHUNK, n)));
    }
    return out;
  }

  // Base64 for transporting ciphertext over JSON. Done in chunks
  // because String.fromCharCode(...arr) on a multi-megabyte array
  // overflows the argument-count limit and throws — a failure mode
  // that only shows up once someone uploads a real file, which is
  // precisely when you least want to discover it.
  function bytesToBase64(bytes) {
    const CHUNK = 0x8000;
    let binary = "";
    for (let i = 0; i < bytes.length; i += CHUNK) {
      binary += String.fromCharCode.apply(null, bytes.subarray(i, i + CHUNK));
    }
    return btoa(binary);
  }

  function base64ToBytes(b64) {
    const binary = atob(b64);
    const out = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
    return out;
  }

  function xorBytes(a, b) {
    const out = new Uint8Array(a.length);
    for (let i = 0; i < a.length; i++) out[i] = a[i] ^ b[i];
    return out;
  }

  // -------------------------------------------------------------------
  // HKDF + HMAC
  // -------------------------------------------------------------------

  // Domain-separation salt. Changing this string invalidates every key
  // ever derived by this app, so it is fixed forever at v1.
  const HKDF_SALT = utf8("kosha-v1");

  async function hkdf(keyMaterial, infoBytes, length = 32) {
    const key = await crypto.subtle.importKey("raw", keyMaterial, "HKDF", false, ["deriveBits"]);
    const bits = await crypto.subtle.deriveBits(
      { name: "HKDF", hash: "SHA-256", salt: HKDF_SALT, info: infoBytes },
      key,
      length * 8
    );
    return new Uint8Array(bits);
  }

  async function hmacSha256(keyBytes, msgBytes) {
    // WebCrypto refuses a zero-length HMAC key outright, even though
    // HMAC's own construction handles one fine (zero-padded to the
    // block size). RFC 7914's scrypt vectors include an empty
    // password, which becomes pbkdf2()'s empty HMAC key below, so this
    // genuinely comes up. A 64-byte all-zero key is exactly what HMAC
    // would build internally from an empty one.
    const effectiveKey = keyBytes.length === 0 ? new Uint8Array(64) : keyBytes;
    const key = await crypto.subtle.importKey("raw", effectiveKey, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
    return new Uint8Array(await crypto.subtle.sign("HMAC", key, msgBytes));
  }

  async function sha256(bytes) {
    return new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
  }

  // -------------------------------------------------------------------
  // scrypt (RFC 7914), from spec
  // -------------------------------------------------------------------

  // PBKDF2 is hand-rolled on top of hmacSha256 rather than handed to
  // crypto.subtle because Firefox caps subtle.deriveBits output at
  // 2048 bits; scrypt needs up to 128*r*p bytes from a single PBKDF2
  // call, comfortably over that. HMAC-SHA256 itself has no such limit
  // — each block is an independent fixed-size HMAC.
  async function pbkdf2(passwordBytes, saltBytes, iterations, lengthBytes) {
    const hLen = 32;
    const numBlocks = Math.ceil(lengthBytes / hLen);
    // One importKey for the whole derivation rather than one per HMAC.
    // scrypt's first call asks for 128*r*p bytes — 32 blocks at our
    // settings — so this removes 32 redundant key imports each time.
    const key = await crypto.subtle.importKey(
      "raw",
      passwordBytes.length === 0 ? new Uint8Array(64) : passwordBytes,
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["sign"]
    );
    const sign = async (msg) => new Uint8Array(await crypto.subtle.sign("HMAC", key, msg));

    const out = new Uint8Array(numBlocks * hLen);
    for (let i = 1; i <= numBlocks; i++) {
      const blockIndex = new Uint8Array(4);
      new DataView(blockIndex.buffer).setUint32(0, i, false); // big-endian, per RFC 2898
      let u = await sign(concatBytes(saltBytes, blockIndex));
      const t = u.slice();
      for (let c = 1; c < iterations; c++) {
        u = await sign(u);
        for (let k = 0; k < hLen; k++) t[k] ^= u[k];
      }
      out.set(t, (i - 1) * hLen);
    }
    return out.slice(0, lengthBytes);
  }

  /**
   * Salsa20/8 core, in place on 16 little-endian words.
   *
   * Written with sixteen local variables rather than array indexing,
   * and with no allocation at all. That reads worse than the obvious
   * version and is the single most important thing in this file for
   * how the app feels: the obvious version allocated a fresh
   * Uint8Array and DataView on every one of the ~2 million calls a
   * login makes, and measured 15 seconds per sign-in. Same algorithm,
   * same output, verified against RFC 7914's vectors — about eight
   * times faster.
   */
  function salsa20_8(x) {
    const j0 = x[0], j1 = x[1], j2 = x[2], j3 = x[3],
          j4 = x[4], j5 = x[5], j6 = x[6], j7 = x[7],
          j8 = x[8], j9 = x[9], j10 = x[10], j11 = x[11],
          j12 = x[12], j13 = x[13], j14 = x[14], j15 = x[15];
    let x0 = j0, x1 = j1, x2 = j2, x3 = j3,
        x4 = j4, x5 = j5, x6 = j6, x7 = j7,
        x8 = j8, x9 = j9, x10 = j10, x11 = j11,
        x12 = j12, x13 = j13, x14 = j14, x15 = j15;
    let u;

    for (let i = 0; i < 8; i += 2) {
      u = x0 + x12;  x4 ^= (u << 7) | (u >>> 25);
      u = x4 + x0;   x8 ^= (u << 9) | (u >>> 23);
      u = x8 + x4;   x12 ^= (u << 13) | (u >>> 19);
      u = x12 + x8;  x0 ^= (u << 18) | (u >>> 14);

      u = x5 + x1;   x9 ^= (u << 7) | (u >>> 25);
      u = x9 + x5;   x13 ^= (u << 9) | (u >>> 23);
      u = x13 + x9;  x1 ^= (u << 13) | (u >>> 19);
      u = x1 + x13;  x5 ^= (u << 18) | (u >>> 14);

      u = x10 + x6;  x14 ^= (u << 7) | (u >>> 25);
      u = x14 + x10; x2 ^= (u << 9) | (u >>> 23);
      u = x2 + x14;  x6 ^= (u << 13) | (u >>> 19);
      u = x6 + x2;   x10 ^= (u << 18) | (u >>> 14);

      u = x15 + x11; x3 ^= (u << 7) | (u >>> 25);
      u = x3 + x15;  x7 ^= (u << 9) | (u >>> 23);
      u = x7 + x3;   x11 ^= (u << 13) | (u >>> 19);
      u = x11 + x7;  x15 ^= (u << 18) | (u >>> 14);

      u = x0 + x3;   x1 ^= (u << 7) | (u >>> 25);
      u = x1 + x0;   x2 ^= (u << 9) | (u >>> 23);
      u = x2 + x1;   x3 ^= (u << 13) | (u >>> 19);
      u = x3 + x2;   x0 ^= (u << 18) | (u >>> 14);

      u = x5 + x4;   x6 ^= (u << 7) | (u >>> 25);
      u = x6 + x5;   x7 ^= (u << 9) | (u >>> 23);
      u = x7 + x6;   x4 ^= (u << 13) | (u >>> 19);
      u = x4 + x7;   x5 ^= (u << 18) | (u >>> 14);

      u = x10 + x9;  x11 ^= (u << 7) | (u >>> 25);
      u = x11 + x10; x8 ^= (u << 9) | (u >>> 23);
      u = x8 + x11;  x9 ^= (u << 13) | (u >>> 19);
      u = x9 + x8;   x10 ^= (u << 18) | (u >>> 14);

      u = x15 + x14; x12 ^= (u << 7) | (u >>> 25);
      u = x12 + x15; x13 ^= (u << 9) | (u >>> 23);
      u = x13 + x12; x14 ^= (u << 13) | (u >>> 19);
      u = x14 + x13; x15 ^= (u << 18) | (u >>> 14);
    }

    x[0] = (x0 + j0) | 0;    x[1] = (x1 + j1) | 0;
    x[2] = (x2 + j2) | 0;    x[3] = (x3 + j3) | 0;
    x[4] = (x4 + j4) | 0;    x[5] = (x5 + j5) | 0;
    x[6] = (x6 + j6) | 0;    x[7] = (x7 + j7) | 0;
    x[8] = (x8 + j8) | 0;    x[9] = (x9 + j9) | 0;
    x[10] = (x10 + j10) | 0; x[11] = (x11 + j11) | 0;
    x[12] = (x12 + j12) | 0; x[13] = (x13 + j13) | 0;
    x[14] = (x14 + j14) | 0; x[15] = (x15 + j15) | 0;
  }

  /** RFC 7914 §4: BlockMix over 2r 64-byte blocks, into scratch Y. */
  function blockMix(BY, Yi, r, x) {
    // X starts as the LAST block, per the spec.
    const last = (2 * r - 1) * 16;
    for (let i = 0; i < 16; i++) x[i] = BY[last + i];

    for (let i = 0; i < 2 * r; i++) {
      const off = i * 16;
      for (let j = 0; j < 16; j++) x[j] ^= BY[off + j];
      salsa20_8(x);
      const o = Yi + off;
      for (let j = 0; j < 16; j++) BY[o + j] = x[j];
    }
    // De-interleave Y back over B: even blocks first, then odd.
    for (let i = 0; i < r; i++) {
      const from = Yi + i * 32;
      const to = i * 16;
      for (let j = 0; j < 16; j++) BY[to + j] = BY[from + j];
    }
    for (let i = 0; i < r; i++) {
      const from = Yi + i * 32 + 16;
      const to = (i + r) * 16;
      for (let j = 0; j < 16; j++) BY[to + j] = BY[from + j];
    }
  }

  /**
   * RFC 7914 §5: ROMix. This is where scrypt's memory-hardness lives —
   * V holds N copies of the block, so an attacker must either keep
   * 128*r*N bytes around (128 MB at our settings) or recompute, which
   * is exactly the cost that makes custom cracking hardware expensive.
   */
  function romix(B, r, N, V, XY, x) {
    const words = 32 * r;
    // Load B (bytes, little-endian) into X (words).
    for (let i = 0; i < words; i++) {
      const k = i * 4;
      XY[i] = B[k] | (B[k + 1] << 8) | (B[k + 2] << 16) | (B[k + 3] << 24);
    }

    for (let i = 0; i < N; i++) {
      const o = i * words;
      for (let j = 0; j < words; j++) V[o + j] = XY[j];
      blockMix(XY, words, r, x);
    }

    for (let i = 0; i < N; i++) {
      // Integerify: the first word of the last block, reduced mod N.
      // N is a power of two, so only the low log2(N) bits matter and a
      // mask replaces a 64-bit modulo — by far the hottest line here.
      const j = (XY[(2 * r - 1) * 16] & (N - 1)) >>> 0;
      const o = j * words;
      for (let k = 0; k < words; k++) XY[k] ^= V[o + k];
      blockMix(XY, words, r, x);
    }

    for (let i = 0; i < words; i++) {
      const v = XY[i];
      const k = i * 4;
      B[k] = v & 0xff;
      B[k + 1] = (v >>> 8) & 0xff;
      B[k + 2] = (v >>> 16) & 0xff;
      B[k + 3] = (v >>> 24) & 0xff;
    }
  }

  async function scrypt(passwordBytes, saltBytes, N, r, p, dkLen) {
    if (N < 2 || (N & (N - 1)) !== 0) throw new Error("scrypt: N must be a power of two");
    const blockLen = 128 * r;
    const B = await pbkdf2(passwordBytes, saltBytes, 1, blockLen * p);

    // Allocated once and reused across all p iterations rather than
    // per call. V is the big one: 128 * r * N bytes.
    const words = 32 * r;
    const V = new Uint32Array(words * N);
    const XY = new Uint32Array(words * 2);
    const x = new Uint32Array(16);

    for (let i = 0; i < p; i++) {
      romix(B.subarray(i * blockLen, (i + 1) * blockLen), r, N, V, XY, x);
    }
    return pbkdf2(passwordBytes, B, 1, dkLen);
  }

  // -------------------------------------------------------------------
  // Password -> keys
  // -------------------------------------------------------------------

  // OWASP's current minimum recommendation for scrypt, and what this
  // app uses. It costs an attacker 128 MB of memory *per guess* —
  // which is the property that makes custom cracking hardware
  // uneconomic, and the reason to prefer scrypt over a plain
  // iteration count.
  //
  // Measured at roughly 270 ms in a browser on this machine, which is
  // what makes meeting the recommendation affordable: an earlier,
  // allocation-heavy version of the core above took over 15 seconds
  // at this cost and forced a weaker setting. If you lower this,
  // lower it knowingly — and note that existing accounts are
  // unaffected either way, since the server records the cost each one
  // was created under and the client derives with that (see
  // api.js's login).
  const SCRYPT_N = 2 ** 17;
  const SCRYPT_R = 8;
  const SCRYPT_P = 1;

  async function deriveKeyFromPassword(password, saltBytes, length = 32, n = SCRYPT_N) {
    return scrypt(utf8(password), saltBytes, n, SCRYPT_R, SCRYPT_P, length);
  }

  /**
   * The split: one scrypt run, two HKDF expansions with different info
   * strings. `authKey` is sent to the server as the login proof;
   * `encKey` is kept in this tab's memory and never transmitted.
   *
   * HKDF's guarantee is what makes the pair safe to use this way —
   * given one output you cannot work backwards to the shared input, so
   * a server holding (a hash of) authKey learns nothing at all about
   * encKey. If these were the same key, or derived from each other,
   * the whole design would collapse into "the server can read your
   * files", which is the thing it exists not to do.
   */
  async function deriveSplitKeys(password, saltBytes, n = SCRYPT_N) {
    const combined = await deriveKeyFromPassword(password, saltBytes, 32, n);
    const authKey = await hkdf(combined, utf8("kosha-auth-key"));
    const encKey = await hkdf(combined, utf8("kosha-enc-key"));
    return { authKey, encKey };
  }

  // -------------------------------------------------------------------
  // AES-256-GCM
  // -------------------------------------------------------------------

  /**
   * Authenticated encryption: tampering, truncation or a wrong key all
   * fail loudly at decrypt time rather than silently returning wrong
   * bytes. Output layout is [12-byte nonce][ciphertext||tag].
   *
   * `aad` (additional authenticated data) is not encrypted but *is*
   * covered by the tag. Kosha uses it to bind a ciphertext to its own
   * identity — see vault.js, where a blob's id is passed as AAD so a
   * server that swapped two of your encrypted files for each other
   * would be caught instead of silently serving the wrong one.
   */
  async function encrypt(keyBytes, plaintext, aad = new Uint8Array(0)) {
    const key = await crypto.subtle.importKey("raw", keyBytes, "AES-GCM", false, ["encrypt"]);
    const nonce = randomBytes(12);
    const ct = new Uint8Array(
      await crypto.subtle.encrypt({ name: "AES-GCM", iv: nonce, additionalData: aad }, key, plaintext)
    );
    return concatBytes(nonce, ct);
  }

  async function decrypt(keyBytes, blob, aad = new Uint8Array(0)) {
    const nonce = blob.slice(0, 12);
    const ciphertext = blob.slice(12);
    const key = await crypto.subtle.importKey("raw", keyBytes, "AES-GCM", false, ["decrypt"]);
    const pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv: nonce, additionalData: aad }, key, ciphertext);
    return new Uint8Array(pt);
  }

  // -------------------------------------------------------------------
  // Vault keys
  // -------------------------------------------------------------------

  /**
   * Your vault is not encrypted with encKey directly. Instead a random
   * 32-byte *master key* is generated once at signup and stored, itself
   * encrypted under encKey, in a small "keyring" the server holds.
   *
   * The indirection buys two things that matter in practice. Changing
   * your password re-encrypts only the keyring (32 bytes), not every
   * file you own — otherwise a password change would mean downloading,
   * decrypting and re-uploading your entire vault. And the recovery
   * phrase can wrap the *same* master key independently, which is what
   * makes "forgot password" possible at all without the server ever
   * holding anything that could decrypt your data.
   */
  function generateMasterKey() {
    return randomBytes(32);
  }

  // Per-purpose subkeys, so the database blob and file blobs are never
  // encrypted under literally the same key. Cheap, and it keeps a
  // hypothetical flaw in one path from reaching the other.
  async function vaultDbKey(masterKey) {
    return hkdf(masterKey, utf8("kosha-vault-db"));
  }

  async function blobKey(masterKey) {
    return hkdf(masterKey, utf8("kosha-file-blob"));
  }

  /**
   * A short human-checkable digest of the master key, shown in
   * Settings. It is not a security control on its own — it is a way to
   * notice, with your own eyes, if the vault you just unlocked is not
   * the vault you had yesterday (a swapped keyring, a half-finished
   * password reset). Same idea as Haven's safety number.
   */
  async function vaultFingerprint(masterKey) {
    const digest = await sha256(concatBytes(utf8("kosha-fingerprint"), masterKey));
    const groups = [];
    for (let i = 0; i < 10; i += 2) {
      groups.push(((digest[i] << 8) | digest[i + 1]).toString().padStart(5, "0"));
    }
    return groups.join(" ");
  }

  return {
    hexToBytes,
    bytesToHex,
    utf8,
    fromUtf8,
    concatBytes,
    randomBytes,
    bytesToBase64,
    base64ToBytes,
    sha256,
    hkdf,
    hmacSha256,
    scrypt,
    pbkdf2,
    deriveKeyFromPassword,
    deriveSplitKeys,
    encrypt,
    decrypt,
    generateMasterKey,
    vaultDbKey,
    blobKey,
    vaultFingerprint,
    SCRYPT_N,
    SCRYPT_R,
    SCRYPT_P,
  };
})();

// Make the engine reachable from the scrypt worker, which runs this
// same file via importScripts and has no `window`.
if (typeof self !== "undefined") self.KoshaCrypto = KoshaCrypto;
