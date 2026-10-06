/**
 * Everything that talks to the server, in one file.
 *
 * Worth noticing how little is here, and how dull it is. Signup,
 * login, recovery, and four verbs for moving opaque bytes. There is no
 * `search`, no `listFiles`, no `runQuery` — the server could not
 * implement them. Your folder tree, your filenames and your rows live
 * inside an encrypted SQLite file that only this browser can open, so
 * every operation that needs to *understand* your data happens on this
 * side of the wire. This file just posts ciphertext.
 */

const KoshaAPI = (() => {
  "use strict";
  const C = KoshaCrypto;

  // Same origin as the page. The server hosts both (see
  // server/server.py), so there is no URL for anyone to configure
  // wrongly and no cross-origin request to get blocked.
  const BASE = "";

  // Kept in memory for the tab's lifetime only. Deliberately NOT in
  // localStorage: a token there survives the tab closing, which means
  // an unattended laptop stays logged in, and it is readable by any
  // script that manages to run on this origin. Closing the tab should
  // end the session, and here it does.
  let token = null;
  let session = null; // { username, masterKey, encKey }

  class ApiError extends Error {
    constructor(message, status) {
      super(message);
      this.status = status;
    }
  }

  async function request(path, { method = "GET", json, body, headers = {}, raw = false } = {}) {
    const opts = { method, headers: { ...headers } };
    if (token) opts.headers["Authorization"] = `Bearer ${token}`;
    if (json !== undefined) {
      opts.headers["Content-Type"] = "application/json";
      opts.body = JSON.stringify(json);
    } else if (body !== undefined) {
      opts.headers["Content-Type"] = "application/octet-stream";
      opts.body = body;
    }

    let res;
    try {
      res = await fetch(BASE + path, opts);
    } catch (e) {
      // A network-level failure, not an HTTP error. On a Tailnet this
      // overwhelmingly means the machine hosting Kosha is asleep or
      // off the tailnet, so say that rather than "Failed to fetch".
      throw new ApiError("Can't reach the Kosha server. Is the machine hosting it awake and on your tailnet?", 0);
    }

    if (!res.ok) {
      let detail = `${res.status} ${res.statusText}`;
      try {
        const data = await res.json();
        if (data && data.detail) {
          detail = typeof data.detail === "string" ? data.detail : JSON.stringify(data.detail);
        }
      } catch {
        /* a non-JSON error body; the status line above will do */
      }
      throw new ApiError(detail, res.status);
    }

    if (raw) return res;
    if (res.status === 204) return null;
    return res.json();
  }

  // -------------------------------------------------------------------
  // Account creation and sign-in
  // -------------------------------------------------------------------

  let wordlist = null;
  async function loadWordlist() {
    if (!wordlist) wordlist = await fetch("js/wordlist.json").then((r) => r.json());
    return wordlist;
  }

  /**
   * Twelve words from the BIP39 English list. The list is used for its
   * transcription safety — no two words share a four-letter prefix, so
   * a phrase written down in a hurry and read back later is unlikely
   * to be ambiguous — not for BIP39's mnemonic checksum math, which
   * plays no part here.
   */
  async function generateRecoveryPhrase(numWords = 12) {
    const words = await loadWordlist();
    // Rejection sampling rather than `% words.length`: 2048 divides
    // 65536 exactly, so the modulo would in fact be unbiased here, but
    // relying on that coincidence would quietly break the day someone
    // swaps in a wordlist of a different size.
    const out = [];
    while (out.length < numWords) {
      const buf = crypto.getRandomValues(new Uint16Array(numWords));
      for (const v of buf) {
        if (out.length === numWords) break;
        if (v < 65536 - (65536 % words.length)) out.push(words[v % words.length]);
      }
    }
    return out.join(" ");
  }

  function normalizePhrase(phrase) {
    return phrase.trim().toLowerCase().split(/\s+/).join(" ");
  }

  /**
   * Create an account.
   *
   * The sequence matters, so here it is in full:
   *   1. Two random salts, one for the password and one for the phrase.
   *   2. scrypt each secret into an auth/enc key pair (in a Worker, so
   *      the page keeps animating).
   *   3. Generate ONE random 32-byte master key — this, and nothing
   *      derived from a human-chosen password, is what actually
   *      encrypts the vault.
   *   4. Wrap that master key twice: once under the password's enc
   *      key, once under the phrase's. Either can open it; neither
   *      wrapper reveals it.
   *   5. Send the server the salts, the two auth keys, and the two
   *      wrapped copies. It receives nothing that can unwrap either.
   */
  async function signup(username, password, onProgress = () => {}) {
    const passwordSalt = C.randomBytes(16);
    const recoverySalt = C.randomBytes(16);
    const phrase = await generateRecoveryPhrase();

    onProgress("Deriving your key (this is the slow part, on purpose)…");
    const [pw, rec] = await Promise.all([
      KoshaScrypt.deriveSplitKeys(password, passwordSalt, C.SCRYPT_N),
      KoshaScrypt.deriveSplitKeys(normalizePhrase(phrase), recoverySalt, C.SCRYPT_N),
    ]);

    onProgress("Creating your vault key…");
    const masterKey = C.generateMasterKey();
    const [wrappedPw, wrappedRec] = await Promise.all([
      C.encrypt(pw.encKey, masterKey, C.utf8("kosha-keyring")),
      C.encrypt(rec.encKey, masterKey, C.utf8("kosha-keyring")),
    ]);

    onProgress("Registering…");
    const res = await request("/api/signup", {
      method: "POST",
      json: {
        username,
        password_salt: C.bytesToHex(passwordSalt),
        password_kdf_n: C.SCRYPT_N,
        auth_key: C.bytesToHex(pw.authKey),
        recovery_salt: C.bytesToHex(recoverySalt),
        recovery_kdf_n: C.SCRYPT_N,
        recovery_key: C.bytesToHex(rec.authKey),
        keyring_password: C.bytesToBase64(wrappedPw),
        keyring_recovery: C.bytesToBase64(wrappedRec),
      },
    });

    token = res.token;
    session = { username: res.username, masterKey, encKey: pw.encKey };
    return { ...res, recoveryPhrase: phrase, masterKey };
  }

  async function login(username, password, onProgress = () => {}) {
    onProgress("Looking up your account…");
    // The cost this account was created under, not today's constant —
    // so raising SCRYPT_N later does not lock anyone out of an
    // existing account.
    const { password_salt, password_kdf_n } = await request(
      `/api/login-salt?username=${encodeURIComponent(username)}`
    );

    onProgress("Deriving your key…");
    const { authKey, encKey } = await KoshaScrypt.deriveSplitKeys(
      password,
      C.hexToBytes(password_salt),
      password_kdf_n
    );

    onProgress("Signing in…");
    const res = await request("/api/login", {
      method: "POST",
      json: { username, auth_key: C.bytesToHex(authKey) },
    });
    token = res.token;

    onProgress("Unlocking your vault…");
    let masterKey;
    try {
      masterKey = await C.decrypt(encKey, C.base64ToBytes(res.keyring_password), C.utf8("kosha-keyring"));
    } catch {
      // The server already accepted the auth half, so the password was
      // right. Reaching here means the stored wrapper does not match
      // that password — a half-completed password change, or a
      // tampered record. Either way it is not a wrong-password error
      // and saying so would send the user down the wrong path.
      throw new ApiError(
        "Your password was accepted but your vault key could not be unwrapped. " +
          "If you recently changed your password, use your recovery phrase to reset it.",
        500
      );
    }
    session = { username: res.username, masterKey, encKey };
    return { ...res, masterKey };
  }

  /** Reset a forgotten password with the 12-word phrase. */
  async function recover(username, phrase, newPassword, onProgress = () => {}) {
    const normalized = normalizePhrase(phrase);
    onProgress("Checking your recovery phrase…");
    const { recovery_salt, recovery_kdf_n } = await request(
      `/api/recovery-salt?username=${encodeURIComponent(username)}`
    );
    const rec = await KoshaScrypt.deriveSplitKeys(normalized, C.hexToBytes(recovery_salt), recovery_kdf_n);

    const { keyring_recovery } = await request(
      `/api/recovery-keyring?username=${encodeURIComponent(username)}&recovery_key=${C.bytesToHex(rec.authKey)}`
    );

    onProgress("Unlocking your vault key…");
    let masterKey;
    try {
      masterKey = await C.decrypt(rec.encKey, C.base64ToBytes(keyring_recovery), C.utf8("kosha-keyring"));
    } catch {
      throw new ApiError("That recovery phrase does not match this account.", 401);
    }

    onProgress("Setting your new password…");
    const salt = C.randomBytes(16);
    const pw = await KoshaScrypt.deriveSplitKeys(newPassword, salt, C.SCRYPT_N);
    const wrapped = await C.encrypt(pw.encKey, masterKey, C.utf8("kosha-keyring"));

    const res = await request("/api/recover", {
      method: "POST",
      json: {
        username,
        recovery_key: C.bytesToHex(rec.authKey),
        password_salt: C.bytesToHex(salt),
        password_kdf_n: C.SCRYPT_N,
        auth_key: C.bytesToHex(pw.authKey),
        keyring_password: C.bytesToBase64(wrapped),
      },
    });
    token = res.token;
    session = { username: res.username, masterKey, encKey: pw.encKey };
    return { ...res, masterKey };
  }

  /**
   * Change the password of a signed-in account. The master key is
   * untouched — only its password wrapper is replaced — so this costs
   * one scrypt run and 60 bytes of upload no matter how large the
   * vault is.
   */
  async function changePassword(currentPassword, newPassword) {
    if (!session) throw new ApiError("Not signed in.", 401);
    const { password_salt, password_kdf_n } = await request(
      `/api/login-salt?username=${encodeURIComponent(session.username)}`
    );
    const current = await KoshaScrypt.deriveSplitKeys(
      currentPassword,
      C.hexToBytes(password_salt),
      password_kdf_n
    );
    const salt = C.randomBytes(16);
    const next = await KoshaScrypt.deriveSplitKeys(newPassword, salt, C.SCRYPT_N);
    const wrapped = await C.encrypt(next.encKey, session.masterKey, C.utf8("kosha-keyring"));

    const res = await request("/api/change-password", {
      method: "POST",
      json: {
        current_auth_key: C.bytesToHex(current.authKey),
        password_salt: C.bytesToHex(salt),
        password_kdf_n: C.SCRYPT_N,
        auth_key: C.bytesToHex(next.authKey),
        keyring_password: C.bytesToBase64(wrapped),
      },
    });
    token = res.token; // the old one was revoked server-side
    session.encKey = next.encKey;
    return res;
  }

  /** Issue a new recovery phrase, invalidating the old one. */
  async function rotateRecoveryPhrase(currentPassword) {
    if (!session) throw new ApiError("Not signed in.", 401);
    const { password_salt, password_kdf_n } = await request(
      `/api/login-salt?username=${encodeURIComponent(session.username)}`
    );
    const current = await KoshaScrypt.deriveSplitKeys(
      currentPassword,
      C.hexToBytes(password_salt),
      password_kdf_n
    );
    const phrase = await generateRecoveryPhrase();
    const salt = C.randomBytes(16);
    const rec = await KoshaScrypt.deriveSplitKeys(normalizePhrase(phrase), salt, C.SCRYPT_N);
    const wrapped = await C.encrypt(rec.encKey, session.masterKey, C.utf8("kosha-keyring"));

    await request("/api/rotate-recovery", {
      method: "POST",
      json: {
        current_auth_key: C.bytesToHex(current.authKey),
        recovery_salt: C.bytesToHex(salt),
        recovery_kdf_n: C.SCRYPT_N,
        recovery_key: C.bytesToHex(rec.authKey),
        keyring_recovery: C.bytesToBase64(wrapped),
      },
    });
    return phrase;
  }

  async function logout() {
    try {
      await request("/api/logout", { method: "POST" });
    } catch {
      /* already gone server-side; the local clear below is what matters */
    }
    token = null;
    session = null;
  }

  // -------------------------------------------------------------------
  // Opaque-byte endpoints
  // -------------------------------------------------------------------

  async function fetchVault() {
    const res = await request("/api/vault", { raw: true });
    const version = parseInt(res.headers.get("X-Kosha-Version") || "0", 10);
    if (res.status === 204) return { blob: null, version };
    return { blob: new Uint8Array(await res.arrayBuffer()), version };
  }

  async function pushVault(ciphertext, expectedVersion) {
    return request("/api/vault", {
      method: "PUT",
      body: ciphertext,
      headers: { "X-Kosha-Version": String(expectedVersion) },
    });
  }

  async function putBlob(ciphertext) {
    return request("/api/blob", { method: "POST", body: ciphertext });
  }

  async function getBlob(blobId) {
    const res = await request(`/api/blob/${blobId}`, { raw: true });
    return new Uint8Array(await res.arrayBuffer());
  }

  async function deleteBlob(blobId) {
    return request(`/api/blob/${blobId}`, { method: "DELETE" });
  }

  async function collectGarbage(keepIds) {
    return request("/api/blob/gc", { method: "POST", json: { keep: keepIds } });
  }

  async function usage() {
    return request("/api/usage");
  }

  async function deleteAccount() {
    if (!session) throw new ApiError("Not signed in.", 401);
    return request(`/api/account?confirm=${encodeURIComponent(session.username)}`, { method: "DELETE" });
  }

  return {
    ApiError,
    get session() {
      return session;
    },
    get signedIn() {
      return !!session;
    },
    signup,
    login,
    recover,
    logout,
    changePassword,
    rotateRecoveryPhrase,
    generateRecoveryPhrase,
    normalizePhrase,
    fetchVault,
    pushVault,
    putBlob,
    getBlob,
    deleteBlob,
    collectGarbage,
    usage,
    deleteAccount,
  };
})();
