/**
 * The browser-only storage backend.
 *
 * Kosha has always done its real work in the browser — the crypto, the
 * SQL, the conversions. The server was never more than a place to put
 * bytes it could not read. This file replaces that place with
 * IndexedDB, which means the whole app can run from a static host like
 * GitHub Pages with no server at all, and keeps working when the
 * machine that used to host it is switched off.
 *
 * It stores exactly the same ciphertext the server would have stored,
 * produced by exactly the same code. Nothing here touches a key or a
 * plaintext; swapping backends does not change the encryption, only
 * where the encrypted bytes come to rest.
 *
 * WHAT YOU GAIN: it works offline, it works with every other machine
 * you own turned off, and the ciphertext never crosses a network at
 * all — there is no server to compromise, which removes the one real
 * caveat the hosted version has to admit to.
 *
 * WHAT YOU GIVE UP, and this is not a small thing: the data lives in
 * *this browser on this device*. It does not sync. Open Kosha on your
 * phone and you get a separate, empty vault. Clear your browser's site
 * data and it is gone, the same way clearing site data loses anything
 * else a site stored. That is why Settings offers an encrypted export
 * file — it is the only way to move a local vault to another device or
 * to get it back after a wipe, and the app says so plainly rather than
 * letting someone find out the hard way.
 *
 * One more honest note about the browser: Safari evicts IndexedDB for
 * sites you have not visited in seven days, and every browser may
 * evict under storage pressure. `requestPersistence` below asks for
 * exemption from that, which browsers grant to sites the user
 * engages with. It is a request, not a guarantee. Export regularly.
 */

const KoshaLocalStore = (() => {
  "use strict";

  const DB_NAME = "kosha";
  const DB_VERSION = 1;
  let dbPromise = null;

  function open() {
    if (dbPromise) return dbPromise;
    dbPromise = new Promise((resolve, reject) => {
      const req = indexedDB.open(DB_NAME, DB_VERSION);
      req.onupgradeneeded = () => {
        const db = req.result;
        // accounts: one record per username. Holds salts, KDF costs and
        // the wrapped master keys — the same fields the server's
        // accounts table holds, minus the auth hash (see verify()).
        if (!db.objectStoreNames.contains("accounts")) {
          db.createObjectStore("accounts", { keyPath: "username" });
        }
        // vaults: the encrypted SQLite database, one per username.
        if (!db.objectStoreNames.contains("vaults")) {
          db.createObjectStore("vaults", { keyPath: "username" });
        }
        // blobs: encrypted file contents, keyed by a random id.
        if (!db.objectStoreNames.contains("blobs")) {
          const store = db.createObjectStore("blobs", { keyPath: "id" });
          store.createIndex("username", "username", { unique: false });
        }
      };
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => reject(new Error("This browser would not open its local database. Private browsing can block it."));
      req.onblocked = () => reject(new Error("Another Kosha tab is open and holding the database. Close it and reload."));
    });
    return dbPromise;
  }

  function tx(storeNames, mode, fn) {
    return open().then(
      (db) =>
        new Promise((resolve, reject) => {
          const t = db.transaction(storeNames, mode);
          let result;
          t.oncomplete = () => resolve(result);
          t.onerror = () => reject(t.error || new Error("The local database rejected that write."));
          t.onabort = () =>
            reject(
              t.error?.name === "QuotaExceededError"
                ? new Error("This browser is out of storage for Kosha. Export your vault, then free some space.")
                : t.error || new Error("The local database aborted that write.")
            );
          const stores = [].concat(storeNames).map((n) => t.objectStore(n));
          result = fn(stores.length === 1 ? stores[0] : stores, t);
          // A request's own result is resolved via oncomplete above, so
          // callers return the value they want rather than the request.
        })
    );
  }

  const request = (req) =>
    new Promise((resolve, reject) => {
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => reject(req.error);
    });

  /**
   * Ask the browser not to evict this data under storage pressure or
   * after a period of not visiting. Granted on engagement; a refusal
   * is not an error, just a fact worth surfacing in Settings.
   */
  async function requestPersistence() {
    try {
      if (navigator.storage?.persist) {
        const already = await navigator.storage.persisted();
        return already || (await navigator.storage.persist());
      }
    } catch {
      /* not supported; treated the same as refused */
    }
    return false;
  }

  async function estimate() {
    try {
      const e = await navigator.storage.estimate();
      return { usage: e.usage ?? null, quota: e.quota ?? null, persisted: await navigator.storage.persisted() };
    } catch {
      return { usage: null, quota: null, persisted: false };
    }
  }

  // -------------------------------------------------------------------
  // Accounts
  // -------------------------------------------------------------------

  const key = (username) => String(username).toLowerCase();

  async function getAccount(username) {
    const db = await open();
    return request(db.transaction("accounts").objectStore("accounts").get(key(username)));
  }

  async function listAccounts() {
    const db = await open();
    const all = await request(db.transaction("accounts").objectStore("accounts").getAll());
    return all.map((a) => a.display_name || a.username);
  }

  async function createAccount(record) {
    const existing = await getAccount(record.username);
    if (existing) throw new Error("There is already a vault on this device with that name.");
    const row = {
      username: key(record.username),
      display_name: record.username,
      password_salt: record.password_salt,
      password_kdf_n: record.password_kdf_n,
      recovery_salt: record.recovery_salt,
      recovery_kdf_n: record.recovery_kdf_n,
      keyring_password: record.keyring_password,
      keyring_recovery: record.keyring_recovery,
      created_at: Math.floor(Date.now() / 1000),
    };
    await tx("accounts", "readwrite", (store) => store.put(row));
    return row;
  }

  async function updateAccount(username, patch) {
    const row = await getAccount(username);
    if (!row) throw new Error("No vault on this device with that name.");
    await tx("accounts", "readwrite", (store) => store.put({ ...row, ...patch }));
  }

  async function deleteAccount(username) {
    const u = key(username);
    const db = await open();
    const ids = await request(db.transaction("blobs").objectStore("blobs").index("username").getAllKeys(u));
    await tx(["accounts", "vaults", "blobs"], "readwrite", ([accounts, vaults, blobs]) => {
      accounts.delete(u);
      vaults.delete(u);
      for (const id of ids) blobs.delete(id);
    });
  }

  // -------------------------------------------------------------------
  // The vault blob
  // -------------------------------------------------------------------

  async function getVault(username) {
    const db = await open();
    const row = await request(db.transaction("vaults").objectStore("vaults").get(key(username)));
    if (!row) return { blob: null, version: 0 };
    return { blob: new Uint8Array(row.blob), version: row.version };
  }

  /**
   * The same compare-and-swap the server does. Two tabs of a local
   * vault is just as real a situation as two tabs of a hosted one, and
   * losing the first tab's work silently would be just as bad.
   */
  async function putVault(username, bytes, expectedVersion) {
    const u = key(username);
    const current = await getVault(u);
    if (current.version !== expectedVersion) {
      const err = new Error(
        `Your vault was changed in another tab (version ${current.version}). ` +
          "Reload before saving again so nothing is lost."
      );
      err.status = 409;
      throw err;
    }
    const version = current.version + 1;
    await tx("vaults", "readwrite", (store) =>
      store.put({ username: u, blob: bytes.slice().buffer, version, updated_at: Math.floor(Date.now() / 1000) })
    );
    return { ok: true, vault_version: version };
  }

  // -------------------------------------------------------------------
  // File blobs
  // -------------------------------------------------------------------

  function randomId() {
    return Array.from(crypto.getRandomValues(new Uint8Array(16)))
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");
  }

  async function putBlob(username, bytes) {
    const id = randomId();
    await tx("blobs", "readwrite", (store) =>
      store.put({ id, username: key(username), blob: bytes.slice().buffer, size: bytes.length, created_at: Math.floor(Date.now() / 1000) })
    );
    return { blob_id: id, size: bytes.length };
  }

  async function getBlob(username, id) {
    const db = await open();
    const row = await request(db.transaction("blobs").objectStore("blobs").get(id));
    if (!row || row.username !== key(username)) {
      const err = new Error("No such file.");
      err.status = 404;
      throw err;
    }
    return new Uint8Array(row.blob);
  }

  async function deleteBlob(username, id) {
    const db = await open();
    const row = await request(db.transaction("blobs").objectStore("blobs").get(id));
    if (!row || row.username !== key(username)) return { deleted: false };
    await tx("blobs", "readwrite", (store) => store.delete(id));
    return { deleted: true };
  }

  async function listBlobs(username) {
    const db = await open();
    return request(db.transaction("blobs").objectStore("blobs").index("username").getAll(key(username)));
  }

  async function collectGarbage(username, keepIds) {
    const keep = new Set(keepIds);
    const rows = await listBlobs(username);
    const doomed = rows.filter((r) => !keep.has(r.id)).map((r) => r.id);
    if (doomed.length) {
      await tx("blobs", "readwrite", (store) => {
        for (const id of doomed) store.delete(id);
      });
    }
    return { removed: doomed.length };
  }

  async function usage(username) {
    const rows = await listBlobs(username);
    const vault = await getVault(username);
    const account = await getAccount(username);
    const space = await estimate();
    return {
      blob_count: rows.length,
      blob_bytes: rows.reduce((n, r) => n + r.size, 0),
      vault_bytes: vault.blob ? vault.blob.length : 0,
      vault_version: vault.version,
      vault_updated_at: null,
      created_at: account?.created_at ?? null,
      quota_bytes: space.quota,
      persisted: space.persisted,
      local: true,
    };
  }

  // -------------------------------------------------------------------
  // Export and import
  // -------------------------------------------------------------------

  /**
   * Everything belonging to one vault, in one file.
   *
   * Every byte in it is already encrypted — this is a copy of the
   * ciphertext, not a decryption of it — so the file is exactly as safe
   * as the password that opens it, and no safer. It is the bridge
   * between a local vault and a hosted one, and the only backup a
   * browser-stored vault has.
   */
  async function exportAccount(username) {
    const account = await getAccount(username);
    if (!account) throw new Error("No vault on this device with that name.");
    const vault = await getVault(username);
    const blobs = await listBlobs(username);
    const b64 = KoshaCrypto.bytesToBase64;
    return {
      format: "kosha-vault",
      version: 1,
      exported_at: new Date().toISOString(),
      account: {
        username: account.display_name || account.username,
        password_salt: account.password_salt,
        password_kdf_n: account.password_kdf_n,
        recovery_salt: account.recovery_salt,
        recovery_kdf_n: account.recovery_kdf_n,
        keyring_password: account.keyring_password,
        keyring_recovery: account.keyring_recovery,
      },
      vault: vault.blob ? b64(vault.blob) : null,
      vault_version: vault.version,
      blobs: blobs.map((r) => ({ id: r.id, size: r.size, data: b64(new Uint8Array(r.blob)) })),
    };
  }

  async function importAccount(bundle, { overwrite = false } = {}) {
    if (!bundle || bundle.format !== "kosha-vault") {
      throw new Error("That is not a Kosha vault file.");
    }
    if (bundle.version !== 1) {
      throw new Error(`That file was written by a newer version of Kosha (format ${bundle.version}).`);
    }
    const name = bundle.account.username;
    const existing = await getAccount(name);
    if (existing && !overwrite) {
      throw new Error(`There is already a vault called "${name}" on this device.`);
    }
    if (existing) await deleteAccount(name);

    const bytes = KoshaCrypto.base64ToBytes;
    await createAccount({ ...bundle.account, username: name });
    const u = key(name);

    if (bundle.vault) {
      await tx("vaults", "readwrite", (store) =>
        store.put({ username: u, blob: bytes(bundle.vault).buffer, version: bundle.vault_version || 1 })
      );
    }
    if (bundle.blobs?.length) {
      await tx("blobs", "readwrite", (store) => {
        for (const b of bundle.blobs) {
          // Ids are preserved deliberately: the vault database that
          // came in the same bundle refers to files by id, and
          // reassigning them would break every one of those references.
          store.put({ id: b.id, username: u, blob: bytes(b.data).buffer, size: b.size, created_at: Math.floor(Date.now() / 1000) });
        }
      });
    }
    return { username: name, blobs: bundle.blobs?.length ?? 0 };
  }

  return {
    requestPersistence,
    estimate,
    getAccount,
    listAccounts,
    createAccount,
    updateAccount,
    deleteAccount,
    getVault,
    putVault,
    putBlob,
    getBlob,
    deleteBlob,
    listBlobs,
    collectGarbage,
    usage,
    exportAccount,
    importAccount,
  };
})();
