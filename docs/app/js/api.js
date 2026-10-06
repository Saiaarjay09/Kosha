/**
 * Everything that stores or retrieves bytes, and the account flows
 * built on top of it.
 *
 * Kosha runs in two deployments from one codebase:
 *
 *   SERVER mode — a Python process on your own machine (reachable over
 *     Tailscale). The encrypted vault lives there, so every device you
 *     sign in from sees the same data. Needs that machine to be awake.
 *
 *   LOCAL mode — no server at all. The identical ciphertext goes into
 *     this browser's IndexedDB instead, which is what lets the whole
 *     app be served from a static host like GitHub Pages and keep
 *     working with every machine you own switched off. The cost is
 *     that the vault lives on this one device and does not sync.
 *
 * The mode is detected, not configured: the page asks its own origin
 * for `api/health`, and if nothing answers it stores locally. A static
 * host has no such endpoint, so Pages lands in local mode by itself
 * and a Tailscale deployment lands in server mode by itself.
 *
 * What does NOT change between them is everything that matters: the
 * key derivation, the encryption, and the fact that nothing but
 * ciphertext is ever written anywhere. The backends differ only in
 * where the ciphertext comes to rest.
 */

const KoshaAPI = (() => {
  "use strict";
  const C = KoshaCrypto;

  // Kept in memory for the tab's lifetime only. Deliberately NOT in
  // localStorage: a token there survives the tab closing, which means
  // an unattended laptop stays signed in, and it is readable by any
  // script that manages to run on this origin.
  let token = null;
  let session = null; // { username, masterKey, encKey }
  let mode = null; // "server" | "local"

  class ApiError extends Error {
    constructor(message, status) {
      super(message);
      this.status = status;
    }
  }

  // -------------------------------------------------------------------
  // Which backend, and where
  // -------------------------------------------------------------------

  /**
   * Resolve a path against the directory this page was served from,
   * rather than against the origin root.
   *
   * This is what lets Kosha live under a path prefix — the Tailscale
   * deployment serves it at `/kosha` alongside other apps on the same
   * hostname, and a hardcoded `/api/...` would punch straight out of
   * that prefix and hit the wrong app.
   */
  function url(path) {
    return new URL(path, document.baseURI).toString();
  }

  async function detectMode() {
    if (mode) return mode;
    // An explicit override, mostly so the hosted deployment can be
    // tested in local mode without standing up a static host.
    const forced = new URLSearchParams(location.search).get("mode");
    if (forced === "local" || forced === "server") return (mode = forced);

    try {
      const res = await fetch(url("api/health"), { cache: "no-store" });
      // A static host typically answers a missing path with its 404
      // page — a 200 with HTML in it would be a false positive, so the
      // body is checked, not just the status.
      if (res.ok) {
        const data = await res.json();
        if (data && data.service === "kosha") return (mode = "server");
      }
    } catch {
      /* nothing listening: local it is */
    }
    return (mode = "local");
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
      res = await fetch(url(path), opts);
    } catch {
      throw new ApiError("Can't reach the Kosha server. Is the machine hosting it awake and on your tailnet?", 0);
    }

    if (!res.ok) {
      let detail = `${res.status} ${res.statusText}`;
      try {
        const data = await res.json();
        if (data && data.detail) detail = typeof data.detail === "string" ? data.detail : JSON.stringify(data.detail);
      } catch {
        /* a non-JSON error body; the status line will do */
      }
      throw new ApiError(detail, res.status);
    }

    if (raw) return res;
    if (res.status === 204) return null;
    return res.json();
  }

  // -------------------------------------------------------------------
  // Recovery phrases
  // -------------------------------------------------------------------

  let wordlist = null;
  async function loadWordlist() {
    if (!wordlist) wordlist = await fetch(url("js/wordlist.json")).then((r) => r.json());
    return wordlist;
  }

  /**
   * Twelve words from the BIP39 English list, chosen for its
   * transcription safety — no two words share a four-letter prefix, so
   * a phrase written down in a hurry reads back unambiguously. BIP39's
   * checksum math plays no part here.
   */
  async function generateRecoveryPhrase(numWords = 12) {
    const words = await loadWordlist();
    // Rejection sampling rather than `% words.length`. With 2048 words
    // the modulo would in fact be unbiased, but relying on that
    // coincidence would break silently if the wordlist ever changed.
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

  const KEYRING_AAD = () => C.utf8("kosha-keyring");

  // -------------------------------------------------------------------
  // Signup
  // -------------------------------------------------------------------

  /**
   * Create a vault.
   *
   *   1. Two random salts — one for the password, one for the phrase.
   *   2. scrypt each secret into an auth/enc key pair, in a Worker so
   *      the page keeps animating.
   *   3. Generate ONE random 32-byte master key. This, and nothing
   *      derived from a human-chosen password, is what encrypts your
   *      data.
   *   4. Wrap that master key twice — once under the password's enc
   *      key, once under the phrase's. Either opens it; neither
   *      wrapper reveals it.
   *   5. Store the salts and the two wrapped copies. In server mode the
   *      auth halves go too, as login proofs. In local mode they are
   *      not even computed into anything stored: there is no server to
   *      prove anything to, and AES-GCM failing to unwrap the keyring
   *      is already a complete and un-bypassable password check.
   */
  async function signup(username, password, onProgress = () => {}) {
    await detectMode();
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
      C.encrypt(pw.encKey, masterKey, KEYRING_AAD()),
      C.encrypt(rec.encKey, masterKey, KEYRING_AAD()),
    ]);

    const record = {
      username,
      password_salt: C.bytesToHex(passwordSalt),
      password_kdf_n: C.SCRYPT_N,
      recovery_salt: C.bytesToHex(recoverySalt),
      recovery_kdf_n: C.SCRYPT_N,
      keyring_password: C.bytesToBase64(wrappedPw),
      keyring_recovery: C.bytesToBase64(wrappedRec),
    };

    if (mode === "local") {
      onProgress("Setting up local storage…");
      if (!/^[A-Za-z][A-Za-z0-9_]{2,23}$/.test(username)) {
        throw new ApiError("Username must start with a letter and be 3-24 letters, numbers or underscores.", 400);
      }
      await KoshaLocalStore.createAccount(record);
      await KoshaLocalStore.requestPersistence();
      session = { username, masterKey, encKey: pw.encKey };
      return { username, recoveryPhrase: phrase, masterKey, vault_version: 0 };
    }

    onProgress("Registering…");
    const res = await request("api/signup", {
      method: "POST",
      json: { ...record, auth_key: C.bytesToHex(pw.authKey), recovery_key: C.bytesToHex(rec.authKey) },
    });
    token = res.token;
    session = { username: res.username, masterKey, encKey: pw.encKey };
    return { ...res, recoveryPhrase: phrase, masterKey };
  }

  // -------------------------------------------------------------------
  // Login
  // -------------------------------------------------------------------

  async function login(username, password, onProgress = () => {}) {
    await detectMode();
    onProgress("Looking up your vault…");

    if (mode === "local") {
      const account = await KoshaLocalStore.getAccount(username);
      if (!account) throw new ApiError("There is no vault on this device with that name.", 404);

      onProgress("Deriving your key…");
      const { encKey } = await KoshaScrypt.deriveSplitKeys(
        password,
        C.hexToBytes(account.password_salt),
        account.password_kdf_n
      );

      onProgress("Unlocking your vault…");
      let masterKey;
      try {
        masterKey = await C.decrypt(encKey, C.base64ToBytes(account.keyring_password), KEYRING_AAD());
      } catch {
        // With no server to check a proof against, this failure IS the
        // password check — and a strictly better one, since there is no
        // stored hash to attack separately.
        throw new ApiError("Wrong password.", 401);
      }
      await KoshaLocalStore.requestPersistence();
      session = { username: account.display_name || username, masterKey, encKey };
      return { username: session.username, masterKey, vault_version: (await KoshaLocalStore.getVault(username)).version };
    }

    // The cost this account was created under, not today's constant, so
    // raising SCRYPT_N later never locks anyone out.
    const { password_salt, password_kdf_n } = await request(`api/login-salt?username=${encodeURIComponent(username)}`);

    onProgress("Deriving your key…");
    const { authKey, encKey } = await KoshaScrypt.deriveSplitKeys(password, C.hexToBytes(password_salt), password_kdf_n);

    onProgress("Signing in…");
    const res = await request("api/login", { method: "POST", json: { username, auth_key: C.bytesToHex(authKey) } });
    token = res.token;

    onProgress("Unlocking your vault…");
    let masterKey;
    try {
      masterKey = await C.decrypt(encKey, C.base64ToBytes(res.keyring_password), KEYRING_AAD());
    } catch {
      // The server already accepted the auth half, so the password was
      // right. Reaching here means the stored wrapper does not match it
      // — a half-finished password change, or a tampered record. Not a
      // wrong-password error, and saying so would send the user down
      // the wrong path.
      throw new ApiError(
        "Your password was accepted but your vault key could not be unwrapped. " +
          "If you recently changed your password, use your recovery phrase to reset it.",
        500
      );
    }
    session = { username: res.username, masterKey, encKey };
    return { ...res, masterKey };
  }

  // -------------------------------------------------------------------
  // Recovery and key rotation
  // -------------------------------------------------------------------

  async function recover(username, phrase, newPassword, onProgress = () => {}) {
    await detectMode();
    const normalized = normalizePhrase(phrase);
    onProgress("Checking your recovery phrase…");

    let recSalt, recN, wrappedRecovery;
    if (mode === "local") {
      const account = await KoshaLocalStore.getAccount(username);
      if (!account) throw new ApiError("There is no vault on this device with that name.", 404);
      ({ recovery_salt: recSalt, recovery_kdf_n: recN, keyring_recovery: wrappedRecovery } = account);
    } else {
      const salts = await request(`api/recovery-salt?username=${encodeURIComponent(username)}`);
      recSalt = salts.recovery_salt;
      recN = salts.recovery_kdf_n;
    }

    const rec = await KoshaScrypt.deriveSplitKeys(normalized, C.hexToBytes(recSalt), recN);

    if (mode !== "local") {
      ({ keyring_recovery: wrappedRecovery } = await request(
        `api/recovery-keyring?username=${encodeURIComponent(username)}&recovery_key=${C.bytesToHex(rec.authKey)}`
      ));
    }

    onProgress("Unlocking your vault key…");
    let masterKey;
    try {
      masterKey = await C.decrypt(rec.encKey, C.base64ToBytes(wrappedRecovery), KEYRING_AAD());
    } catch {
      throw new ApiError("That recovery phrase does not match this vault.", 401);
    }

    onProgress("Setting your new password…");
    const salt = C.randomBytes(16);
    const pw = await KoshaScrypt.deriveSplitKeys(newPassword, salt, C.SCRYPT_N);
    const wrapped = await C.encrypt(pw.encKey, masterKey, KEYRING_AAD());

    if (mode === "local") {
      await KoshaLocalStore.updateAccount(username, {
        password_salt: C.bytesToHex(salt),
        password_kdf_n: C.SCRYPT_N,
        keyring_password: C.bytesToBase64(wrapped),
      });
      const account = await KoshaLocalStore.getAccount(username);
      session = { username: account.display_name || username, masterKey, encKey: pw.encKey };
      return { username: session.username, masterKey };
    }

    const res = await request("api/recover", {
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
   * Change the password. The master key is untouched — only its
   * wrapper is replaced — so this costs one key derivation and 60
   * bytes of storage no matter how large the vault is.
   */
  async function changePassword(currentPassword, newPassword) {
    if (!session) throw new ApiError("Not signed in.", 401);
    const username = session.username;

    if (mode === "local") {
      const account = await KoshaLocalStore.getAccount(username);
      const current = await KoshaScrypt.deriveSplitKeys(
        currentPassword,
        C.hexToBytes(account.password_salt),
        account.password_kdf_n
      );
      try {
        await C.decrypt(current.encKey, C.base64ToBytes(account.keyring_password), KEYRING_AAD());
      } catch {
        throw new ApiError("Current password is wrong.", 401);
      }
      const salt = C.randomBytes(16);
      const next = await KoshaScrypt.deriveSplitKeys(newPassword, salt, C.SCRYPT_N);
      const wrapped = await C.encrypt(next.encKey, session.masterKey, KEYRING_AAD());
      await KoshaLocalStore.updateAccount(username, {
        password_salt: C.bytesToHex(salt),
        password_kdf_n: C.SCRYPT_N,
        keyring_password: C.bytesToBase64(wrapped),
      });
      session.encKey = next.encKey;
      return { ok: true };
    }

    const { password_salt, password_kdf_n } = await request(`api/login-salt?username=${encodeURIComponent(username)}`);
    const current = await KoshaScrypt.deriveSplitKeys(currentPassword, C.hexToBytes(password_salt), password_kdf_n);
    const salt = C.randomBytes(16);
    const next = await KoshaScrypt.deriveSplitKeys(newPassword, salt, C.SCRYPT_N);
    const wrapped = await C.encrypt(next.encKey, session.masterKey, KEYRING_AAD());

    const res = await request("api/change-password", {
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

  /** Issue a new recovery phrase, retiring the old one. */
  async function rotateRecoveryPhrase(currentPassword) {
    if (!session) throw new ApiError("Not signed in.", 401);
    const username = session.username;
    const phrase = await generateRecoveryPhrase();
    const salt = C.randomBytes(16);
    const rec = await KoshaScrypt.deriveSplitKeys(normalizePhrase(phrase), salt, C.SCRYPT_N);
    const wrapped = await C.encrypt(rec.encKey, session.masterKey, KEYRING_AAD());

    if (mode === "local") {
      const account = await KoshaLocalStore.getAccount(username);
      const current = await KoshaScrypt.deriveSplitKeys(
        currentPassword,
        C.hexToBytes(account.password_salt),
        account.password_kdf_n
      );
      try {
        await C.decrypt(current.encKey, C.base64ToBytes(account.keyring_password), KEYRING_AAD());
      } catch {
        throw new ApiError("Current password is wrong.", 401);
      }
      await KoshaLocalStore.updateAccount(username, {
        recovery_salt: C.bytesToHex(salt),
        recovery_kdf_n: C.SCRYPT_N,
        keyring_recovery: C.bytesToBase64(wrapped),
      });
      return phrase;
    }

    const { password_salt, password_kdf_n } = await request(`api/login-salt?username=${encodeURIComponent(username)}`);
    const current = await KoshaScrypt.deriveSplitKeys(currentPassword, C.hexToBytes(password_salt), password_kdf_n);
    await request("api/rotate-recovery", {
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
    if (mode === "server") {
      try {
        await request("api/logout", { method: "POST" });
      } catch {
        /* already gone server-side; the local clear below is what matters */
      }
    }
    token = null;
    session = null;
  }

  // -------------------------------------------------------------------
  // Opaque bytes
  // -------------------------------------------------------------------

  async function fetchVault() {
    if (mode === "local") return KoshaLocalStore.getVault(session.username);
    const res = await request("api/vault", { raw: true });
    const version = parseInt(res.headers.get("X-Kosha-Version") || "0", 10);
    if (res.status === 204) return { blob: null, version };
    return { blob: new Uint8Array(await res.arrayBuffer()), version };
  }

  async function pushVault(ciphertext, expectedVersion) {
    if (mode === "local") return KoshaLocalStore.putVault(session.username, ciphertext, expectedVersion);
    return request("api/vault", {
      method: "PUT",
      body: ciphertext,
      headers: { "X-Kosha-Version": String(expectedVersion) },
    });
  }

  async function putBlob(ciphertext) {
    if (mode === "local") return KoshaLocalStore.putBlob(session.username, ciphertext);
    return request("api/blob", { method: "POST", body: ciphertext });
  }

  async function getBlob(blobId) {
    if (mode === "local") return KoshaLocalStore.getBlob(session.username, blobId);
    const res = await request(`api/blob/${blobId}`, { raw: true });
    return new Uint8Array(await res.arrayBuffer());
  }

  async function deleteBlob(blobId) {
    if (mode === "local") return KoshaLocalStore.deleteBlob(session.username, blobId);
    return request(`api/blob/${blobId}`, { method: "DELETE" });
  }

  async function collectGarbage(keepIds) {
    if (mode === "local") return KoshaLocalStore.collectGarbage(session.username, keepIds);
    return request("api/blob/gc", { method: "POST", json: { keep: keepIds } });
  }

  async function usage() {
    if (mode === "local") return KoshaLocalStore.usage(session.username);
    return request("api/usage");
  }

  async function deleteAccount() {
    if (!session) throw new ApiError("Not signed in.", 401);
    if (mode === "local") return KoshaLocalStore.deleteAccount(session.username);
    return request(`api/account?confirm=${encodeURIComponent(session.username)}`, { method: "DELETE" });
  }

  // -------------------------------------------------------------------
  // Moving a vault between devices and deployments
  // -------------------------------------------------------------------

  /**
   * Export everything belonging to the signed-in vault as one file of
   * already-encrypted bytes.
   *
   * In local mode this is the only backup that exists, and the only way
   * to get the vault onto another device. In server mode it is a
   * portable copy you can import into a local one — which is what makes
   * "use it on the Pages site when my Mac is off" actually workable.
   */
  async function exportVault() {
    if (!session) throw new ApiError("Not signed in.", 401);
    if (mode === "local") return KoshaLocalStore.exportAccount(session.username);

    // Server mode: reassemble the same bundle from the API. The vault
    // database knows which blobs it references; anything else on the
    // server is garbage awaiting collection and is not worth copying.
    const account = await request(`api/login-salt?username=${encodeURIComponent(session.username)}`);
    const recovery = await request(`api/recovery-salt?username=${encodeURIComponent(session.username)}`);
    const keyring = await request("api/keyring");
    const { blob, version } = await fetchVault();
    // The vault database knows which blobs it references; anything
    // else on the server is garbage awaiting collection and copying it
    // would only bloat the file.
    const blobs = [];
    for (const id of KoshaVault.referencedBlobIds()) {
      const data = await getBlob(id);
      blobs.push({ id, size: data.length, data: C.bytesToBase64(data) });
    }
    return {
      format: "kosha-vault",
      version: 1,
      exported_at: new Date().toISOString(),
      account: {
        username: session.username,
        password_salt: account.password_salt,
        password_kdf_n: account.password_kdf_n,
        recovery_salt: recovery.recovery_salt,
        recovery_kdf_n: recovery.recovery_kdf_n,
        keyring_password: keyring.keyring_password,
        keyring_recovery: keyring.keyring_recovery,
      },
      vault: blob ? C.bytesToBase64(blob) : null,
      vault_version: version,
      blobs,
    };
  }

  /** Import a vault bundle into this browser's local storage. */
  async function importVault(bundle, opts) {
    await detectMode();
    return KoshaLocalStore.importAccount(bundle, opts);
  }

  async function listLocalVaults() {
    try {
      return await KoshaLocalStore.listAccounts();
    } catch {
      return [];
    }
  }

  return {
    ApiError,
    detectMode,
    get mode() {
      return mode;
    },
    get isLocal() {
      return mode === "local";
    },
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
    exportVault,
    importVault,
    listLocalVaults,
  };
})();
