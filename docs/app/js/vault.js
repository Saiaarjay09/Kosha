/**
 * The vault: Kosha's own data model, and the sync that keeps it safe
 * on the server without the server understanding any of it.
 *
 * A vault is a single SQLite database living in this tab's memory. It
 * holds two kinds of thing side by side, which is the whole point of
 * the project:
 *
 *   - Kosha's own bookkeeping, in tables prefixed `kosha_` — your
 *     folders, their declared filetype, their ordering rules, and a
 *     row per stored file.
 *   - Your actual tables, created when you import data or write
 *     CREATE TABLE yourself. These are ordinary SQLite tables and
 *     nothing here treats them as special.
 *
 * Because both live in one database, a query can join your data
 * against your filing system — "which CSVs in /invoices have more
 * than a thousand rows" is a SELECT, not a feature someone has to
 * build.
 *
 * File *contents* are not in here. A 40 MB spreadsheet sitting in the
 * vault database would mean re-encrypting and re-uploading 40 MB
 * every time you renamed a folder. Instead each file's bytes are
 * encrypted separately, uploaded once as a blob, and referenced by id
 * — so the vault database stays small and quick to save, and only
 * what actually changed moves over the wire.
 */

const KoshaVault = (() => {
  "use strict";
  const C = KoshaCrypto;
  const E = KoshaEngine;

  const SCHEMA_VERSION = 1;

  const SCHEMA = `
CREATE TABLE IF NOT EXISTS kosha_meta (
  key   TEXT PRIMARY KEY,
  value TEXT
);

-- A folder declares what it holds. That declaration is the contract
-- the rest of the app enforces: anything arriving here is converted
-- to \`filetype\` or refused.
CREATE TABLE IF NOT EXISTS kosha_folders (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  parent_id     INTEGER REFERENCES kosha_folders(id) ON DELETE CASCADE,
  name          TEXT    NOT NULL,
  filetype      TEXT    NOT NULL DEFAULT 'any',
  auto_convert  INTEGER NOT NULL DEFAULT 1,
  strict        INTEGER NOT NULL DEFAULT 1,
  sort_key      TEXT    NOT NULL DEFAULT 'name',
  sort_dir      TEXT    NOT NULL DEFAULT 'asc',
  path_template TEXT    NOT NULL DEFAULT '{name}.{ext}',
  note          TEXT,
  position      INTEGER NOT NULL DEFAULT 0,
  created_at    INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS kosha_files (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  folder_id     INTEGER NOT NULL REFERENCES kosha_folders(id) ON DELETE CASCADE,
  name          TEXT    NOT NULL,
  format        TEXT    NOT NULL,
  original_name TEXT    NOT NULL,
  original_format TEXT  NOT NULL,
  converted     INTEGER NOT NULL DEFAULT 0,
  blob_id       TEXT    NOT NULL,
  size          INTEGER NOT NULL,
  row_count     INTEGER,
  col_count     INTEGER,
  table_name    TEXT,
  stored_path   TEXT    NOT NULL,
  position      INTEGER NOT NULL DEFAULT 0,
  created_at    INTEGER NOT NULL,
  updated_at    INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_files_folder ON kosha_files(folder_id);
CREATE INDEX IF NOT EXISTS idx_files_blob   ON kosha_files(blob_id);

CREATE TABLE IF NOT EXISTS kosha_queries (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  name       TEXT NOT NULL,
  sql        TEXT NOT NULL,
  created_at INTEGER NOT NULL
);
`;

  let db = null;
  let masterKey = null;
  let dbKey = null;
  let fileKey = null;
  let version = 0;
  let dirty = false;
  let saving = null;
  let saveTimer = null;
  const listeners = new Set();

  function now() {
    return Math.floor(Date.now() / 1000);
  }

  function emit(event, detail) {
    for (const fn of listeners) {
      try {
        fn(event, detail);
      } catch (e) {
        console.error("vault listener failed", e);
      }
    }
  }

  function on(fn) {
    listeners.add(fn);
    return () => listeners.delete(fn);
  }

  function requireOpen() {
    if (!db) throw new Error("No vault is open.");
    return db;
  }

  // -------------------------------------------------------------------
  // Opening and saving
  // -------------------------------------------------------------------

  /**
   * Download the encrypted vault, decrypt it, and open it as SQLite.
   * A brand-new account has no vault yet, so one is created with a
   * starter folder — an empty screen with no obvious first move is a
   * bad way to meet a new tool.
   */
  async function open(key, onProgress = () => {}) {
    masterKey = key;
    dbKey = await C.vaultDbKey(masterKey);
    fileKey = await C.blobKey(masterKey);

    onProgress("Starting the database engine…");
    await E.init();

    onProgress("Fetching your vault…");
    const { blob, version: v } = await KoshaAPI.fetchVault();
    version = v;

    if (!blob) {
      onProgress("Creating your vault…");
      db = E.Database.create();
      db.exec(SCHEMA);
      db.run("INSERT OR REPLACE INTO kosha_meta (key, value) VALUES ('schema_version', ?)", [String(SCHEMA_VERSION)]);
      db.run("INSERT OR REPLACE INTO kosha_meta (key, value) VALUES ('created_at', ?)", [String(now())]);
      createFolder({ name: "Inbox", filetype: "any", note: "Anything, unconverted. A good place to start." });
      await save({ immediate: true });
    } else {
      onProgress("Decrypting…");
      let plain;
      try {
        plain = await C.decrypt(dbKey, blob, C.utf8("kosha-vault"));
      } catch {
        // GCM's tag failed. Either the ciphertext was altered in
        // transit or at rest, or this is not the key for this vault.
        // Both are serious and neither should be papered over with a
        // blank database.
        throw new Error(
          "Your vault failed its integrity check. The stored data does not match your key, " +
            "which means it was either corrupted or tampered with. Nothing has been overwritten."
        );
      }
      onProgress("Opening…");
      db = E.Database.open(plain);
      migrate();
    }

    emit("opened", { version });
    return { version };
  }

  /** Bring an older vault up to the current schema. */
  function migrate() {
    db.exec(SCHEMA); // every statement is IF NOT EXISTS
    const row = db.one("SELECT value FROM kosha_meta WHERE key = 'schema_version'");
    const current = row ? parseInt(row.value, 10) : 0;
    if (current < SCHEMA_VERSION) {
      db.run("INSERT OR REPLACE INTO kosha_meta (key, value) VALUES ('schema_version', ?)", [String(SCHEMA_VERSION)]);
    }
  }

  function markDirty() {
    dirty = true;
    emit("dirty", {});
    // Debounced, because a single user action can be a dozen writes
    // (create a folder, insert ten files, update a counter) and each
    // save is a full encrypt-and-upload of the database. Waiting a
    // moment turns that into one upload.
    clearTimeout(saveTimer);
    saveTimer = setTimeout(() => {
      save().catch((e) => emit("save-failed", { error: e }));
    }, 1200);
  }

  /**
   * Encrypt the database and store it, with a compare-and-swap on the
   * version so a second tab cannot silently overwrite this one.
   */
  async function save({ immediate = false } = {}) {
    if (!db) return;
    if (saving) {
      // A save is already in flight. Rather than queue a second one
      // against a version that is about to change, wait for it and
      // then save again if anything is still outstanding.
      await saving;
      if (!dirty && !immediate) return;
    }
    clearTimeout(saveTimer);
    const run = (async () => {
      emit("saving", {});
      const bytes = db.serialize();
      const ciphertext = await C.encrypt(dbKey, bytes, C.utf8("kosha-vault"));
      const res = await KoshaAPI.pushVault(ciphertext, version);
      version = res.vault_version;
      dirty = false;
      emit("saved", { version, bytes: ciphertext.length });
      return res;
    })();
    saving = run.finally(() => {
      saving = null;
    });
    return saving;
  }

  function close() {
    clearTimeout(saveTimer);
    if (db) db.close();
    db = null;
    masterKey = null;
    dbKey = null;
    fileKey = null;
    version = 0;
    dirty = false;
    emit("closed", {});
  }

  // -------------------------------------------------------------------
  // Folders
  // -------------------------------------------------------------------

  function listFolders() {
    const rows = requireOpen().all(
      `SELECT f.*,
              (SELECT COUNT(*) FROM kosha_files WHERE folder_id = f.id) AS file_count,
              (SELECT COALESCE(SUM(size),0) FROM kosha_files WHERE folder_id = f.id) AS total_size
         FROM kosha_folders f
        ORDER BY f.position, f.name`
    );
    // Build the tree in one pass. Any folder whose parent is missing
    // is promoted to the root rather than vanishing from the UI.
    const byId = new Map(rows.map((r) => [r.id, { ...r, children: [] }]));
    const roots = [];
    for (const node of byId.values()) {
      const parent = node.parent_id != null ? byId.get(node.parent_id) : null;
      if (parent) parent.children.push(node);
      else roots.push(node);
    }
    return { roots, flat: [...byId.values()] };
  }

  function getFolder(id) {
    return requireOpen().one("SELECT * FROM kosha_folders WHERE id = ?", [id]);
  }

  function folderPath(id) {
    const parts = [];
    let node = getFolder(id);
    const guard = new Set();
    while (node && !guard.has(node.id)) {
      guard.add(node.id);
      parts.unshift(node.name);
      node = node.parent_id != null ? getFolder(node.parent_id) : null;
    }
    return "/" + parts.join("/");
  }

  function createFolder({
    name,
    parentId = null,
    filetype = "any",
    autoConvert = true,
    strict = true,
    sortKey = "name",
    sortDir = "asc",
    pathTemplate = "{name}.{ext}",
    note = "",
  }) {
    const d = requireOpen();
    const clean = String(name || "").trim();
    if (!clean) throw new Error("A folder needs a name.");
    if (clean.includes("/")) throw new Error("Folder names cannot contain a slash.");
    const clash = d.one(
      "SELECT id FROM kosha_folders WHERE name = ? AND parent_id IS ?",
      [clean, parentId]
    );
    if (clash) throw new Error(`There is already a folder called "${clean}" here.`);
    const position = d.scalar("SELECT COALESCE(MAX(position), 0) + 1 FROM kosha_folders WHERE parent_id IS ?", [parentId]);
    d.run(
      `INSERT INTO kosha_folders (parent_id, name, filetype, auto_convert, strict, sort_key, sort_dir, path_template, note, position, created_at)
       VALUES (?,?,?,?,?,?,?,?,?,?,?)`,
      [parentId, clean, filetype, autoConvert ? 1 : 0, strict ? 1 : 0, sortKey, sortDir, pathTemplate, note, position, now()]
    );
    const id = d.lastInsertId();
    markDirty();
    emit("folders-changed", {});
    return id;
  }

  function updateFolder(id, patch) {
    const d = requireOpen();
    const allowed = {
      name: "name", filetype: "filetype", autoConvert: "auto_convert", strict: "strict",
      sortKey: "sort_key", sortDir: "sort_dir", pathTemplate: "path_template",
      note: "note", parentId: "parent_id", position: "position",
    };
    const sets = [];
    const params = [];
    for (const [k, col] of Object.entries(allowed)) {
      if (!(k in patch)) continue;
      let v = patch[k];
      if (k === "autoConvert" || k === "strict") v = v ? 1 : 0;
      if (k === "name") {
        v = String(v).trim();
        if (!v) throw new Error("A folder needs a name.");
        if (v.includes("/")) throw new Error("Folder names cannot contain a slash.");
      }
      if (k === "parentId" && v != null) {
        // Re-parenting a folder into its own subtree would detach the
        // whole branch from the root and make it unreachable.
        if (v === id || isDescendant(v, id)) throw new Error("A folder cannot be moved inside itself.");
      }
      sets.push(`${col} = ?`);
      params.push(v);
    }
    if (!sets.length) return;
    params.push(id);
    d.run(`UPDATE kosha_folders SET ${sets.join(", ")} WHERE id = ?`, params);
    markDirty();
    emit("folders-changed", {});
  }

  function isDescendant(candidateId, ancestorId) {
    let node = getFolder(candidateId);
    const guard = new Set();
    while (node && node.parent_id != null && !guard.has(node.id)) {
      guard.add(node.id);
      if (node.parent_id === ancestorId) return true;
      node = getFolder(node.parent_id);
    }
    return false;
  }

  /**
   * Delete a folder, everything inside it, and the server-side blobs
   * those files pointed at. The blob deletion happens before the rows
   * are removed — if it were the other way round and the page closed
   * in between, the blobs would be orphaned with nothing left
   * referencing them.
   */
  async function deleteFolder(id) {
    const d = requireOpen();
    const ids = [id, ...collectDescendants(id)];
    const placeholders = ids.map(() => "?").join(",");
    const files = d.all(`SELECT blob_id FROM kosha_files WHERE folder_id IN (${placeholders})`, ids);
    for (const f of files) {
      try {
        await KoshaAPI.deleteBlob(f.blob_id);
      } catch {
        // Leave it; the gc pass will catch anything stranded here.
      }
    }
    d.run(`DELETE FROM kosha_files WHERE folder_id IN (${placeholders})`, ids);
    d.run(`DELETE FROM kosha_folders WHERE id IN (${placeholders})`, ids);
    markDirty();
    emit("folders-changed", {});
    return files.length;
  }

  function collectDescendants(id) {
    const out = [];
    const stack = [id];
    while (stack.length) {
      const current = stack.pop();
      for (const row of requireOpen().all("SELECT id FROM kosha_folders WHERE parent_id = ?", [current])) {
        out.push(row.id);
        stack.push(row.id);
      }
    }
    return out;
  }

  // -------------------------------------------------------------------
  // Where a file gets filed
  // -------------------------------------------------------------------

  /**
   * Resolve a folder's path template into the name a file is stored
   * under. This is the "you define the structure" part: a folder set
   * to `{yyyy}/{mm}/{name}.{ext}` files everything into year and
   * month subpaths automatically, without the user making those
   * folders or remembering the convention.
   */
  function resolvePath(template, { name, ext, format, folderName, index = 1, date = new Date() }) {
    const pad = (n, w = 2) => String(n).padStart(w, "0");
    const tokens = {
      name: name,
      ext: ext,
      format: format,
      folder: folderName,
      yyyy: String(date.getFullYear()),
      yy: pad(date.getFullYear() % 100),
      mm: pad(date.getMonth() + 1),
      dd: pad(date.getDate()),
      hh: pad(date.getHours()),
      min: pad(date.getMinutes()),
      mon: date.toLocaleString("en", { month: "short" }).toLowerCase(),
      n: String(index),
      nnn: pad(index, 3),
      slug: String(name).toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, ""),
    };
    const resolved = String(template).replace(/\{(\w+)\}/g, (match, key) =>
      key in tokens ? tokens[key] : match
    );
    // Collapse doubled and leading separators so a template with an
    // empty token in it ("{folder}/{name}" at the root) does not
    // produce "//file.csv".
    return resolved.replace(/\/{2,}/g, "/").replace(/^\//, "");
  }

  const TEMPLATE_TOKENS = [
    ["{name}", "the file's name, without its extension"],
    ["{ext}", "the extension this folder converts to"],
    ["{format}", "the format's short name"],
    ["{folder}", "this folder's name"],
    ["{slug}", "the name lowercased and hyphenated"],
    ["{yyyy}", "four-digit year"],
    ["{yy}", "two-digit year"],
    ["{mm}", "two-digit month"],
    ["{mon}", "short month name (jan, feb…)"],
    ["{dd}", "two-digit day"],
    ["{hh}", "hour, 24-clock"],
    ["{min}", "minute"],
    ["{n}", "a counter, 1 upward within the folder"],
    ["{nnn}", "the same counter, zero-padded to three digits"],
  ];

  const SORT_KEYS = [
    ["name", "Name"],
    ["added", "When it was added"],
    ["size", "File size"],
    ["rows", "Number of rows"],
    ["format", "Format"],
    ["manual", "The order you arranged them in"],
  ];

  function sortExpression(sortKey, sortDir) {
    const dir = sortDir === "desc" ? "DESC" : "ASC";
    const column =
      {
        name: "name COLLATE NOCASE",
        added: "created_at",
        size: "size",
        rows: "COALESCE(row_count, -1)",
        format: "format",
        manual: "position",
      }[sortKey] || "name COLLATE NOCASE";
    return `${column} ${dir}`;
  }

  // -------------------------------------------------------------------
  // Files
  // -------------------------------------------------------------------

  function listFiles(folderId) {
    const folder = getFolder(folderId);
    if (!folder) return [];
    return requireOpen().all(
      `SELECT * FROM kosha_files WHERE folder_id = ? ORDER BY ${sortExpression(folder.sort_key, folder.sort_dir)}`,
      [folderId]
    );
  }

  function getFile(id) {
    return requireOpen().one("SELECT * FROM kosha_files WHERE id = ?", [id]);
  }

  /** What would happen if this file were added to this folder. */
  function previewAdd(folderId, filename, bytes) {
    const folder = getFolder(folderId);
    if (!folder) throw new Error("That folder no longer exists.");
    const target = folder.auto_convert ? folder.filetype : "any";
    const p = KoshaConvert.plan(filename, bytes, target);
    if (!p.possible && !folder.strict) {
      return {
        ...p,
        action: "store",
        possible: true,
        notes: [
          ...p.notes,
          "This folder is not strict, so the file will be stored in its original format instead of being refused.",
        ],
      };
    }
    return p;
  }

  /**
   * Add a file: convert it to the folder's type, encrypt it, upload
   * it, record it, and — if it is tabular — offer its contents as a
   * SQL table.
   *
   * The order matters. The blob is uploaded *before* the row is
   * written, so a failure half way leaves an unreferenced blob (which
   * the gc pass cleans up) rather than a row pointing at a file that
   * was never stored (which would be a permanent broken entry).
   */
  async function addFile(folderId, filename, bytes, { importAsTable = "auto", onProgress = () => {} } = {}) {
    const d = requireOpen();
    const folder = getFolder(folderId);
    if (!folder) throw new Error("That folder no longer exists.");

    const target = folder.auto_convert ? folder.filetype : "any";
    onProgress("Checking the file…");
    const plan = previewAdd(folderId, filename, bytes);
    if (!plan.possible) throw new Error(plan.notes[0]);

    onProgress(plan.action === "convert" ? `Converting to ${KoshaConvert.FORMATS[target].label}…` : "Reading…");
    const result =
      plan.action === "convert"
        ? await KoshaConvert.convert(filename, bytes, target)
        : {
            bytes,
            format: KoshaConvert.detect(filename, bytes),
            name: filename,
            dataset: null,
            notes: plan.notes,
            converted: false,
          };

    // Only parse for a row count if the file is tabular and we do not
    // already have the parsed dataset from the conversion.
    let dataset = result.dataset;
    if (!dataset && KoshaConvert.familyOf(result.format) === "tabular") {
      try {
        dataset = await KoshaConvert.toDataset(result.name, result.bytes);
      } catch {
        dataset = null; // a malformed table is still storable as a file
      }
    }

    onProgress("Encrypting…");
    const blobId = await (async () => {
      // AAD binds this ciphertext to nothing yet — the id is assigned
      // by the server. So the file key alone authenticates it, and the
      // id-binding check happens on read via the vault's own record.
      const ciphertext = await C.encrypt(fileKey, result.bytes, C.utf8("kosha-file"));
      onProgress("Uploading…");
      const res = await KoshaAPI.putBlob(ciphertext);
      return res.blob_id;
    })();

    const index = d.scalar("SELECT COUNT(*) + 1 FROM kosha_files WHERE folder_id = ?", [folderId]);
    const base = KoshaConvert.baseName(result.name);
    const ext = KoshaConvert.extOf(result.name) || KoshaConvert.FORMATS[result.format]?.ext || "";
    const storedPath = resolvePath(folder.path_template, {
      name: base,
      ext,
      format: result.format,
      folderName: folder.name,
      index,
    });

    const position = d.scalar("SELECT COALESCE(MAX(position), 0) + 1 FROM kosha_files WHERE folder_id = ?", [folderId]);
    const ts = now();
    d.run(
      `INSERT INTO kosha_files (folder_id, name, format, original_name, original_format, converted,
                                blob_id, size, row_count, col_count, table_name, stored_path, position,
                                created_at, updated_at)
       VALUES (?,?,?,?,?,?,?,?,?,?,NULL,?,?,?,?)`,
      [
        folderId,
        result.name,
        result.format,
        filename,
        plan.from,
        result.converted ? 1 : 0,
        blobId,
        result.bytes.length,
        dataset ? dataset.rows.length : null,
        dataset ? dataset.columns.length : null,
        storedPath,
        position,
        ts,
        ts,
      ]
    );
    const fileId = d.lastInsertId();

    let importedTable = null;
    const shouldImport = importAsTable === true || (importAsTable === "auto" && !!dataset && dataset.rows.length > 0);
    if (shouldImport && dataset) {
      onProgress("Building a SQL table…");
      const imported = d.importDataset(base, dataset);
      d.run("UPDATE kosha_files SET table_name = ? WHERE id = ?", [imported.table, fileId]);
      importedTable = imported;
    }

    markDirty();
    emit("files-changed", { folderId });
    return { fileId, blobId, result, dataset, importedTable, notes: result.notes, storedPath };
  }

  /** Decrypt and return a stored file's bytes. */
  async function readFile(fileId) {
    const file = getFile(fileId);
    if (!file) throw new Error("That file is no longer in your vault.");
    const ciphertext = await KoshaAPI.getBlob(file.blob_id);
    try {
      return { file, bytes: await C.decrypt(fileKey, ciphertext, C.utf8("kosha-file")) };
    } catch {
      throw new Error(
        `"${file.name}" failed its integrity check — the stored bytes do not match your key. ` +
          "The file was either corrupted or altered on the server."
      );
    }
  }

  async function deleteFile(fileId, { dropTable = false } = {}) {
    const d = requireOpen();
    const file = getFile(fileId);
    if (!file) return;
    try {
      await KoshaAPI.deleteBlob(file.blob_id);
    } catch {
      /* gc will sweep it */
    }
    if (dropTable && file.table_name) {
      d.run(`DROP TABLE IF EXISTS ${E.quoteIdent(file.table_name)}`);
    }
    d.run("DELETE FROM kosha_files WHERE id = ?", [fileId]);
    markDirty();
    emit("files-changed", { folderId: file.folder_id });
  }

  function renameFile(fileId, newName) {
    const clean = String(newName || "").trim();
    if (!clean) throw new Error("A file needs a name.");
    requireOpen().run("UPDATE kosha_files SET name = ?, updated_at = ? WHERE id = ?", [clean, now(), fileId]);
    markDirty();
    emit("files-changed", {});
  }

  function moveFile(fileId, targetFolderId) {
    const d = requireOpen();
    const position = d.scalar("SELECT COALESCE(MAX(position),0) + 1 FROM kosha_files WHERE folder_id = ?", [targetFolderId]);
    d.run("UPDATE kosha_files SET folder_id = ?, position = ?, updated_at = ? WHERE id = ?", [
      targetFolderId, position, now(), fileId,
    ]);
    markDirty();
    emit("files-changed", {});
  }

  /** Reorder within a manually-sorted folder. */
  function reorderFiles(folderId, orderedIds) {
    const d = requireOpen();
    orderedIds.forEach((id, i) => d.run("UPDATE kosha_files SET position = ? WHERE id = ? AND folder_id = ?", [i + 1, id, folderId]));
    markDirty();
    emit("files-changed", { folderId });
  }

  /**
   * Re-run a folder's rules over everything already in it.
   *
   * Changing a folder's filetype after the fact should mean something,
   * and this is it: every file is fetched, converted, re-uploaded and
   * re-filed under the current template. Files that cannot be
   * converted are reported and left exactly as they were.
   */
  async function reapplyFolderRules(folderId, onProgress = () => {}) {
    const d = requireOpen();
    const folder = getFolder(folderId);
    if (!folder) throw new Error("That folder no longer exists.");
    const files = d.all("SELECT * FROM kosha_files WHERE folder_id = ? ORDER BY position", [folderId]);
    const converted = [];
    const skipped = [];

    for (let i = 0; i < files.length; i++) {
      const file = files[i];
      onProgress(`Re-filing ${i + 1} of ${files.length}: ${file.name}`);
      const target = folder.auto_convert ? folder.filetype : "any";
      let bytes;
      try {
        ({ bytes } = await readFile(file.id));
      } catch (e) {
        skipped.push({ name: file.name, reason: e.message });
        continue;
      }
      const plan = KoshaConvert.plan(file.name, bytes, target);
      const base = KoshaConvert.baseName(file.name);

      let newName = file.name;
      let newFormat = file.format;
      let newBlobId = file.blob_id;
      let newSize = file.size;

      if (plan.possible && plan.action === "convert") {
        try {
          const result = await KoshaConvert.convert(file.name, bytes, target);
          const ciphertext = await C.encrypt(fileKey, result.bytes, C.utf8("kosha-file"));
          const res = await KoshaAPI.putBlob(ciphertext);
          // The old blob goes only after the new one is safely stored.
          try {
            await KoshaAPI.deleteBlob(file.blob_id);
          } catch {
            /* gc will sweep it */
          }
          newName = result.name;
          newFormat = result.format;
          newBlobId = res.blob_id;
          newSize = result.bytes.length;
          converted.push(file.name);
        } catch (e) {
          skipped.push({ name: file.name, reason: e.message });
          continue;
        }
      } else if (!plan.possible && folder.strict) {
        skipped.push({ name: file.name, reason: plan.notes[0] });
        continue;
      }

      const storedPath = resolvePath(folder.path_template, {
        name: KoshaConvert.baseName(newName) || base,
        ext: KoshaConvert.extOf(newName),
        format: newFormat,
        folderName: folder.name,
        index: i + 1,
        date: new Date(file.created_at * 1000),
      });
      d.run(
        `UPDATE kosha_files SET name=?, format=?, blob_id=?, size=?, stored_path=?, updated_at=?,
                                converted = CASE WHEN ? = original_format THEN 0 ELSE 1 END
          WHERE id = ?`,
        [newName, newFormat, newBlobId, newSize, storedPath, now(), newFormat, file.id]
      );
    }

    markDirty();
    emit("files-changed", { folderId });
    return { converted, skipped, total: files.length };
  }

  // -------------------------------------------------------------------
  // Saved queries
  // -------------------------------------------------------------------

  function listQueries() {
    return requireOpen().all("SELECT * FROM kosha_queries ORDER BY created_at DESC");
  }

  function saveQuery(name, sql) {
    requireOpen().run("INSERT INTO kosha_queries (name, sql, created_at) VALUES (?,?,?)", [name, sql, now()]);
    markDirty();
    emit("queries-changed", {});
  }

  function deleteQuery(id) {
    requireOpen().run("DELETE FROM kosha_queries WHERE id = ?", [id]);
    markDirty();
    emit("queries-changed", {});
  }

  // -------------------------------------------------------------------
  // Housekeeping
  // -------------------------------------------------------------------

  /** Every blob id the vault still points at. */
  function referencedBlobIds() {
    return requireOpen().all("SELECT blob_id FROM kosha_files").map((r) => r.blob_id);
  }

  /** Tell the store which blobs are still referenced; it drops the rest. */
  async function collectGarbage() {
    return KoshaAPI.collectGarbage(referencedBlobIds());
  }

  function stats() {
    const d = requireOpen();
    const tables = d.listTables();
    return {
      folders: d.scalar("SELECT COUNT(*) FROM kosha_folders"),
      files: d.scalar("SELECT COUNT(*) FROM kosha_files"),
      fileBytes: d.scalar("SELECT COALESCE(SUM(size),0) FROM kosha_files"),
      tables: tables.length,
      rows: tables.reduce((n, t) => n + (t.rowCount || 0), 0),
      vaultBytes: d.serialize().length,
      version,
    };
  }

  return {
    SCHEMA_VERSION,
    TEMPLATE_TOKENS,
    SORT_KEYS,
    on,
    open,
    save,
    close,
    get db() {
      return db;
    },
    get isOpen() {
      return !!db;
    },
    get isDirty() {
      return dirty;
    },
    get version() {
      return version;
    },
    get masterKey() {
      return masterKey;
    },
    listFolders,
    getFolder,
    folderPath,
    createFolder,
    updateFolder,
    deleteFolder,
    listFiles,
    getFile,
    previewAdd,
    addFile,
    readFile,
    deleteFile,
    renameFile,
    moveFile,
    reorderFiles,
    reapplyFolderRules,
    resolvePath,
    listQueries,
    saveQuery,
    deleteQuery,
    referencedBlobIds,
    collectGarbage,
    stats,
  };
})();
