/**
 * The database engine.
 *
 * This is real SQLite — the actual C library, compiled to WebAssembly,
 * running inside your browser tab. Not a subset, not an imitation, not
 * "SQL-like". Joins, subqueries, CTEs, window functions, views,
 * triggers, indexes, transactions, CHECK constraints, foreign keys,
 * JSON functions, full-text search: if SQLite does it, Kosha does it,
 * because it IS SQLite.
 *
 * Running it here rather than on the server is what makes the
 * encryption honest. A server-side database would have to hold your
 * rows in the clear to index or filter them; there is no getting
 * around that, and every "encrypted cloud database" that offers
 * server-side querying is quietly telling you its server can read your
 * data. Kosha moves the engine to where the key already is.
 *
 * The price, stated plainly: your whole database is in this tab's
 * memory while it is open. That is comfortable into the hundreds of
 * megabytes on a normal laptop and becomes a bad idea somewhere in the
 * low gigabytes. For a personal or small-team store that is the right
 * trade; for a hundred-gigabyte warehouse it is the wrong tool, and
 * you should know that before you load it rather than after.
 */

const KoshaEngine = (() => {
  "use strict";

  let SQL = null; // the initialised sql.js module

  async function init(onProgress = () => {}) {
    if (SQL) return SQL;
    onProgress("Starting the database engine…");
    // initSqlJs is defined by vendor/sql-wasm.js, loaded as a plain
    // <script> in index.html. Both it and the .wasm are served from
    // this origin — no CDN at runtime, which keeps the page working
    // offline and keeps `connect-src 'self'` in the CSP truthful.
    SQL = await initSqlJs({ locateFile: (f) => `vendor/${f}` });
    return SQL;
  }

  /** Column type as SQLite will actually treat it. */
  const TYPES = ["TEXT", "INTEGER", "REAL", "NUMERIC", "BLOB"];

  /**
   * Quote an identifier for safe interpolation.
   *
   * SQLite's parameter binding covers values but NOT identifiers — you
   * cannot write `SELECT * FROM ?`. Table and column names therefore
   * have to be interpolated as text, which is exactly where injection
   * lives. Doubling embedded quotes inside double quotes is SQLite's
   * own escaping rule and makes any name, including one containing a
   * quote or a semicolon, a single inert identifier token.
   */
  function quoteIdent(name) {
    return `"${String(name).replace(/"/g, '""')}"`;
  }

  function quoteLiteral(value) {
    if (value === null || value === undefined) return "NULL";
    if (typeof value === "number") return Number.isFinite(value) ? String(value) : "NULL";
    return `'${String(value).replace(/'/g, "''")}'`;
  }

  /**
   * Turn an arbitrary heading from a spreadsheet into a usable SQL
   * column name. Imported files have headings like "Total (£)" or
   * "2024 Q1" or nothing at all, and all three need to become
   * something you can type in a query without quoting gymnastics.
   */
  function safeColumnName(raw, index, taken = new Set()) {
    let name = String(raw ?? "").trim().toLowerCase();
    name = name.replace(/[^a-z0-9_]+/g, "_").replace(/^_+|_+$/g, "");
    if (!name) name = `column_${index + 1}`;
    if (/^[0-9]/.test(name)) name = `c_${name}`;
    let candidate = name;
    let n = 2;
    while (taken.has(candidate)) candidate = `${name}_${n++}`;
    taken.add(candidate);
    return candidate;
  }

  function safeTableName(raw, taken = new Set()) {
    let name = String(raw ?? "").trim().toLowerCase();
    name = name.replace(/\.[^.]+$/, ""); // drop a file extension
    name = name.replace(/[^a-z0-9_]+/g, "_").replace(/^_+|_+$/g, "");
    if (!name) name = "table";
    if (/^[0-9]/.test(name)) name = `t_${name}`;
    // `kosha_` is this app's own namespace (see vault.js). An imported
    // file called "kosha_files.csv" must not be able to collide with
    // the folder index and quietly destroy it.
    if (name.startsWith("kosha_")) name = `t_${name}`;
    let candidate = name;
    let n = 2;
    while (taken.has(candidate)) candidate = `${name}_${n++}`;
    taken.add(candidate);
    return candidate;
  }

  /**
   * Guess a column's type from its values.
   *
   * Only ever widens: one non-numeric value in ten thousand makes the
   * whole column TEXT. That is deliberate. A column silently typed
   * INTEGER because the first thousand rows looked like numbers will
   * mangle the row where someone wrote "n/a", and a wrong number is a
   * far worse outcome than a number stored as text — which you can
   * still CAST at query time.
   */
  function inferType(values) {
    let sawValue = false;
    let allInt = true;
    let allNum = true;
    for (const v of values) {
      if (v === null || v === undefined || v === "") continue;
      sawValue = true;
      if (typeof v === "number") {
        if (!Number.isInteger(v)) allInt = false;
        continue;
      }
      const s = String(v).trim();
      if (!/^-?\d+$/.test(s)) allInt = false;
      // Rejects "1,234" and "£5" on purpose: a column of formatted
      // currency is text until the user decides how to clean it.
      if (!/^-?(\d+\.?\d*|\.\d+)([eE][+-]?\d+)?$/.test(s)) allNum = false;
      if (!allInt && !allNum) break;
    }
    if (!sawValue) return "TEXT";
    if (allInt) return "INTEGER";
    if (allNum) return "REAL";
    return "TEXT";
  }

  class Database {
    constructor(db) {
      this.db = db;
    }

    static create() {
      const db = new SQL.Database();
      db.run("PRAGMA foreign_keys = ON");
      return new Database(db);
    }

    static open(bytes) {
      const db = new SQL.Database(bytes);
      db.run("PRAGMA foreign_keys = ON");
      return new Database(db);
    }

    /** Raw multi-statement execution. Returns sql.js result sets. */
    exec(sql, params) {
      return this.db.exec(sql, params);
    }

    /** A statement run for its effect, with bound parameters. */
    run(sql, params = []) {
      this.db.run(sql, params);
    }

    /** One row as a plain object, or null. */
    one(sql, params = []) {
      const stmt = this.db.prepare(sql);
      try {
        stmt.bind(params);
        return stmt.step() ? stmt.getAsObject() : null;
      } finally {
        stmt.free();
      }
    }

    /** All rows as plain objects. */
    all(sql, params = []) {
      const stmt = this.db.prepare(sql);
      const out = [];
      try {
        stmt.bind(params);
        while (stmt.step()) out.push(stmt.getAsObject());
      } finally {
        stmt.free();
      }
      return out;
    }

    scalar(sql, params = []) {
      const row = this.one(sql, params);
      return row ? Object.values(row)[0] : null;
    }

    lastInsertId() {
      return this.scalar("SELECT last_insert_rowid()");
    }

    /**
     * Run whatever the user typed in the SQL console.
     *
     * Returns one entry per statement, each either a result grid or a
     * count of rows changed, plus the elapsed time — so the console
     * can show "3 rows updated in 2 ms" for an UPDATE and a table for
     * a SELECT, which is what a beginner needs in order to tell the
     * two apart at all.
     */
    runScript(sql) {
      const started = performance.now();
      const results = [];
      // iterateStatements walks a multi-statement script one statement
      // at a time, which is what lets a script of five statements
      // report five separate outcomes instead of one blurred total.
      for (const s of this.db.iterateStatements(sql)) {
        const columns = s.getColumnNames();
        const rows = [];
        while (s.step()) rows.push(s.get());
        results.push({
          sql: s.getNormalizedSQL ? s.getNormalizedSQL() : "",
          columns,
          rows,
          // getRowsModified is a property of the connection, not the
          // statement, so it is only meaningful immediately after a
          // statement that returned no grid of its own.
          changes: columns.length === 0 ? this.db.getRowsModified() : null,
        });
      }
      return { results, elapsedMs: performance.now() - started };
    }

    /** Every user table, with its row count. `kosha_` tables excluded. */
    listTables(includeInternal = false) {
      const rows = this.all(
        `SELECT name, type, sql FROM sqlite_master
          WHERE type IN ('table','view') AND name NOT LIKE 'sqlite_%'
          ORDER BY type DESC, name`
      );
      return rows
        .filter((r) => includeInternal || !r.name.startsWith("kosha_"))
        .map((r) => {
          let count = null;
          try {
            count = this.scalar(`SELECT COUNT(*) FROM ${quoteIdent(r.name)}`);
          } catch {
            // A view over a table that was since dropped still appears
            // in sqlite_master but cannot be counted. Showing it with
            // an unknown count beats the whole sidebar throwing.
            count = null;
          }
          return { name: r.name, type: r.type, rowCount: count, ddl: r.sql };
        });
    }

    describeTable(name) {
      const cols = this.all(`PRAGMA table_info(${quoteIdent(name)})`);
      const indexes = this.all(`PRAGMA index_list(${quoteIdent(name)})`);
      const fks = this.all(`PRAGMA foreign_key_list(${quoteIdent(name)})`);
      return {
        columns: cols.map((c) => ({
          name: c.name,
          type: c.type || "",
          notNull: !!c.notnull,
          defaultValue: c.dflt_value,
          primaryKey: !!c.pk,
        })),
        indexes: indexes.map((i) => ({ name: i.name, unique: !!i.unique })),
        foreignKeys: fks.map((f) => ({ column: f.from, references: `${f.table}(${f.to})` })),
      };
    }

    /** A page of rows, with optional sort and a simple text filter. */
    page(table, { limit = 100, offset = 0, orderBy = null, desc = false, filter = "" } = {}) {
      const info = this.describeTable(table);
      const names = info.columns.map((c) => c.name);
      let where = "";
      const params = [];
      if (filter) {
        // Match the text against every column, cast to text. Slower
        // than a targeted search, but it is what someone means when
        // they type a word into a box above a table.
        where = " WHERE " + names.map((n) => `CAST(${quoteIdent(n)} AS TEXT) LIKE ?`).join(" OR ");
        for (let i = 0; i < names.length; i++) params.push(`%${filter}%`);
      }
      const order = orderBy && names.includes(orderBy) ? ` ORDER BY ${quoteIdent(orderBy)} ${desc ? "DESC" : "ASC"}` : "";
      const total = this.scalar(`SELECT COUNT(*) FROM ${quoteIdent(table)}${where}`, params);
      const stmt = this.db.prepare(
        `SELECT * FROM ${quoteIdent(table)}${where}${order} LIMIT ${Number(limit)} OFFSET ${Number(offset)}`
      );
      const rows = [];
      try {
        stmt.bind(params);
        while (stmt.step()) rows.push(stmt.get());
      } finally {
        stmt.free();
      }
      return { columns: names, rows, total };
    }

    /**
     * Create a table from a parsed dataset and fill it.
     *
     * The insert runs inside one transaction and one prepared
     * statement. That is not a micro-optimisation: SQLite autocommits
     * every bare INSERT, so a 50,000-row import done naively is 50,000
     * transactions and takes minutes instead of a moment.
     */
    importDataset(tableName, dataset, { replace = false } = {}) {
      const taken = new Set(this.listTables(true).map((t) => t.name));
      if (replace) taken.delete(tableName);
      const table = replace ? tableName : safeTableName(tableName, taken);

      const colTaken = new Set();
      const columns = dataset.columns.map((c, i) => ({
        name: safeColumnName(c, i, colTaken),
        original: String(c ?? ""),
        type: inferType(dataset.rows.map((r) => r[i])),
      }));

      const ddl =
        `CREATE TABLE ${quoteIdent(table)} (\n  ` +
        columns.map((c) => `${quoteIdent(c.name)} ${c.type}`).join(",\n  ") +
        "\n)";

      this.db.run("BEGIN");
      try {
        if (replace) this.db.run(`DROP TABLE IF EXISTS ${quoteIdent(table)}`);
        this.db.run(ddl);
        const placeholders = columns.map(() => "?").join(", ");
        const stmt = this.db.prepare(`INSERT INTO ${quoteIdent(table)} VALUES (${placeholders})`);
        try {
          for (const row of dataset.rows) {
            const bound = columns.map((c, i) => {
              const v = row[i];
              if (v === undefined || v === "") return null;
              if (c.type === "INTEGER" || c.type === "REAL") {
                if (v === null) return null;
                const n = typeof v === "number" ? v : Number(String(v).trim());
                return Number.isFinite(n) ? n : null;
              }
              return v === null ? null : typeof v === "object" ? JSON.stringify(v) : String(v);
            });
            stmt.run(bound);
          }
        } finally {
          stmt.free();
        }
        this.db.run("COMMIT");
      } catch (e) {
        this.db.run("ROLLBACK");
        throw e;
      }
      return { table, columns, rowCount: dataset.rows.length, ddl };
    }

    /** Read a whole table back out in the shape convert.js writes. */
    exportDataset(table, { limit = null } = {}) {
      const sql = `SELECT * FROM ${quoteIdent(table)}${limit ? ` LIMIT ${Number(limit)}` : ""}`;
      const res = this.db.exec(sql);
      if (!res.length) return { columns: this.describeTable(table).columns.map((c) => c.name), rows: [] };
      return { columns: res[0].columns, rows: res[0].values };
    }

    /** The file's bytes, ready to be encrypted and uploaded. */
    serialize() {
      return this.db.export();
    }

    close() {
      this.db.close();
    }
  }

  return { init, Database, TYPES, quoteIdent, quoteLiteral, safeTableName, safeColumnName, inferType };
})();
