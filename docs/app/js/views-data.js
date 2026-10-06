/**
 * The two database views.
 *
 * `Tables` is the browsing half: what tables exist, what is in them,
 * how they are shaped, and a designer for making new ones without
 * writing DDL.
 *
 * `Query` is the SQL console. It is a real console — any statement
 * SQLite accepts runs here — but it is built on the assumption that
 * the person using it may be learning SQL rather than fluent in it.
 * So the query builder does not hide the SQL behind a form; it
 * *writes* the SQL into the editor, where it can be read, changed and
 * eventually written from scratch. A tool that generates queries you
 * never see teaches you nothing and leaves you stuck the first time
 * it cannot express what you want.
 */

const ViewData = (() => {
  "use strict";
  const { el } = UI;

  let selectedTable = null;
  let page = { offset: 0, limit: 50, orderBy: null, desc: false, filter: "" };
  let editorValue = "SELECT 1 + 1 AS answer;";
  let lastRun = null;

  function openTable(name) {
    selectedTable = name;
    page = { offset: 0, limit: 50, orderBy: null, desc: false, filter: "" };
  }

  // ===================================================================
  // Tables
  // ===================================================================

  function renderTables(container) {
    UI.clear(container);
    const db = KoshaVault.db;
    const tables = db.listTables();

    const panel = el("div", { class: "panel" });
    panel.appendChild(
      el("div", { class: "panel-head" }, [
        el("div", { class: "row spread" }, [
          el("div", {}, [
            el("h2", { text: "Tables" }),
            el("p", {
              class: "blurb",
              text:
                "Every table here is a real SQLite table, living inside your encrypted vault. " +
                "Importing a spreadsheet or a CSV creates one automatically; you can also build one by hand.",
            }),
          ]),
          el("button", { class: "primary", text: "New table", onclick: () => designerDialog().then(App.refresh) }),
        ]),
      ])
    );

    if (!tables.length) {
      panel.appendChild(
        el("div", { class: "empty" }, [
          el("div", { class: "empty-title", text: "No tables yet" }),
          el("p", {
            text: "Add a CSV or spreadsheet to a folder and Kosha turns it into a table, or design one here from scratch.",
          }),
          el("button", { class: "primary", text: "Design a table", onclick: () => designerDialog().then(App.refresh) }),
        ])
      );
      container.appendChild(panel);
      return;
    }

    if (selectedTable && !tables.some((t) => t.name === selectedTable)) selectedTable = null;
    if (!selectedTable) selectedTable = tables[0].name;

    panel.appendChild(
      el("div", { class: "toolbar" }, [
        UI.select(
          tables.map((t) => [t.name, `${t.name} — ${UI.count(t.rowCount)} rows${t.type === "view" ? " (view)" : ""}`]),
          selectedTable,
          (v) => {
            openTable(v);
            App.refresh();
          }
        ),
        el("input", {
          type: "search",
          class: "grow",
          placeholder: "Filter rows containing…",
          value: page.filter,
          oninput: (e) => {
            page.filter = e.target.value;
            page.offset = 0;
            clearTimeout(renderTables._t);
            renderTables._t = setTimeout(() => App.refresh(), 220);
          },
        }),
        el("button", { text: "Query this table", onclick: () => App.openQuery(`SELECT *\nFROM ${KoshaEngine.quoteIdent(selectedTable)}\nLIMIT 100;`) }),
        el("button", { text: "Export…", onclick: () => exportTable(selectedTable) }),
        el("button", { class: "danger", text: "Drop", onclick: () => dropTable(selectedTable) }),
      ])
    );

    const info = db.describeTable(selectedTable);
    let data;
    try {
      data = db.page(selectedTable, page);
    } catch (e) {
      panel.appendChild(el("div", { class: "result-error", text: e.message }));
      container.appendChild(panel);
      return;
    }

    panel.appendChild(
      el("div", { class: "split" }, [
        el("div", {}, [
          UI.grid({
            columns: data.columns.map((c) => ({ key: c, label: c })),
            rows: data.rows,
            sort: page.orderBy ? { key: page.orderBy, desc: page.desc } : null,
            onSort: (key) => {
              page.desc = page.orderBy === key ? !page.desc : false;
              page.orderBy = key;
              App.refresh();
            },
            emptyMessage: page.filter ? "No rows match that filter." : "This table has no rows yet.",
          }),
          el("div", { class: "grid-foot" }, [
            el("span", {
              text: data.total
                ? `Rows ${UI.count(page.offset + 1)}–${UI.count(Math.min(page.offset + page.limit, data.total))} of ${UI.count(data.total)}`
                : "No rows",
            }),
            el("div", { class: "row" }, [
              el("button", {
                class: "tiny",
                text: "← Previous",
                disabled: page.offset === 0,
                onclick: () => {
                  page.offset = Math.max(0, page.offset - page.limit);
                  App.refresh();
                },
              }),
              el("button", {
                class: "tiny",
                text: "Next →",
                disabled: page.offset + page.limit >= data.total,
                onclick: () => {
                  page.offset += page.limit;
                  App.refresh();
                },
              }),
            ]),
          ]),
        ]),

        el("div", {}, [
          el("div", { class: "card" }, [
            el("h3", { text: "Columns" }),
            el(
              "div",
              {},
              info.columns.map((c) =>
                el("div", { class: "row spread", style: { padding: "4px 0", borderBottom: "1px solid var(--hairline)" } }, [
                  el("span", { class: "mono small", text: c.name }),
                  el("span", { class: "row", style: { gap: "4px" } }, [
                    c.primaryKey ? el("span", { class: "pill accent", text: "PK" }) : null,
                    c.notNull ? el("span", { class: "pill", text: "NOT NULL" }) : null,
                    el("span", { class: "pill", text: c.type || "ANY" }),
                  ]),
                ])
              )
            ),
          ]),

          info.indexes.length
            ? el("div", { class: "card" }, [
                el("h3", { text: "Indexes" }),
                el(
                  "div",
                  {},
                  info.indexes.map((i) =>
                    el("div", { class: "row spread small", style: { padding: "3px 0" } }, [
                      el("span", { class: "mono", text: i.name }),
                      i.unique ? el("span", { class: "pill", text: "UNIQUE" }) : null,
                    ])
                  )
                ),
              ])
            : null,

          el("div", { class: "card" }, [
            el("h3", { text: "How it was made" }),
            el("pre", { class: "preview-pane", style: { maxHeight: "200px" }, text: tables.find((t) => t.name === selectedTable)?.ddl || "" }),
          ]),
        ]),
      ])
    );

    container.appendChild(panel);
  }

  // -------------------------------------------------------------------
  // The table designer
  // -------------------------------------------------------------------

  /**
   * Build a CREATE TABLE without writing one — and show the statement
   * it produces, live, so the next table can be written by hand.
   */
  async function designerDialog() {
    const state = {
      name: "",
      columns: [{ name: "id", type: "INTEGER", pk: true, notNull: false, unique: false, dflt: "" }],
    };

    let ddlNode;
    let columnsNode;

    const buildDdl = () => {
      const table = KoshaEngine.safeTableName(state.name || "new_table");
      const defs = state.columns
        .filter((c) => c.name.trim())
        .map((c) => {
          const parts = [KoshaEngine.quoteIdent(KoshaEngine.safeColumnName(c.name, 0)), c.type];
          if (c.pk) parts.push("PRIMARY KEY");
          if (c.notNull && !c.pk) parts.push("NOT NULL");
          if (c.unique && !c.pk) parts.push("UNIQUE");
          if (c.dflt.trim()) parts.push(`DEFAULT ${KoshaEngine.quoteLiteral(c.dflt.trim())}`);
          return "  " + parts.join(" ");
        });
      return `CREATE TABLE ${KoshaEngine.quoteIdent(table)} (\n${defs.join(",\n")}\n);`;
    };

    const refresh = () => {
      ddlNode.textContent = buildDdl();
      UI.clear(columnsNode);
      state.columns.forEach((col, i) => columnsNode.appendChild(columnRow(col, i)));
    };

    const columnRow = (col, i) =>
      el("div", { class: "row", style: { gap: "6px", marginBottom: "6px", alignItems: "center" } }, [
        el("input", {
          type: "text",
          class: "grow mono",
          placeholder: "column_name",
          value: col.name,
          oninput: (e) => {
            col.name = e.target.value;
            ddlNode.textContent = buildDdl();
          },
        }),
        UI.select(
          KoshaEngine.TYPES.map((t) => [t, t]),
          col.type,
          (v) => {
            col.type = v;
            ddlNode.textContent = buildDdl();
          }
        ),
        el("label", { class: "row small nowrap", style: { gap: "4px", margin: 0 } }, [
          el("input", {
            type: "checkbox",
            checked: col.pk,
            onchange: (e) => {
              // SQLite allows exactly one column-level PRIMARY KEY.
              if (e.target.checked) state.columns.forEach((c) => (c.pk = false));
              col.pk = e.target.checked;
              refresh();
            },
          }),
          "PK",
        ]),
        el("label", { class: "row small nowrap", style: { gap: "4px", margin: 0 } }, [
          el("input", { type: "checkbox", checked: col.notNull, onchange: (e) => ((col.notNull = e.target.checked), refresh()) }),
          "Required",
        ]),
        el("button", {
          class: "tiny ghost",
          text: "✕",
          title: "Remove this column",
          disabled: state.columns.length === 1,
          onclick: () => {
            state.columns.splice(i, 1);
            refresh();
          },
        }),
      ]);

    const result = await UI.modal({
      title: "Design a table",
      subtitle: "Fill this in and Kosha writes the SQL. The statement is shown as you go, so you can see exactly what it builds.",
      wide: true,
      build: () => {
        columnsNode = el("div", {});
        ddlNode = el("pre", { class: "preview-pane", style: { maxHeight: "180px" } });

        const body = el("div", {}, [
          UI.field(
            "Table name",
            el("input", {
              type: "text",
              class: "mono",
              placeholder: "invoices",
              oninput: (e) => {
                state.name = e.target.value;
                ddlNode.textContent = buildDdl();
              },
            }),
            "Spaces and punctuation are turned into underscores automatically."
          ),
          el("div", { class: "kicker-label", style: { marginBottom: "6px" }, text: "Columns" }),
          columnsNode,
          el("button", {
            class: "tiny",
            text: "+ Add column",
            onclick: () => {
              state.columns.push({ name: "", type: "TEXT", pk: false, notNull: false, unique: false, dflt: "" });
              refresh();
            },
          }),
          el("hr", { class: "hair" }),
          el("div", { class: "kicker-label", style: { marginBottom: "6px" }, text: "The SQL this writes" }),
          ddlNode,
          el("p", {
            class: "note",
            text:
              "TEXT holds any text. INTEGER holds whole numbers. REAL holds decimals. " +
              "SQLite is relaxed about types, so when in doubt TEXT is a safe choice — you can always CAST it in a query.",
          }),
        ]);
        setTimeout(refresh, 0);
        return body;
      },
      actions: [
        {
          label: "Create table",
          kind: "primary",
          onClick: (setError) => {
            if (!state.name.trim()) {
              setError("Give the table a name.");
              return false;
            }
            if (!state.columns.some((c) => c.name.trim())) {
              setError("Add at least one column.");
              return false;
            }
            try {
              KoshaVault.db.exec(buildDdl());
              KoshaVault.save();
              UI.ok(`Table created.`, "Done");
              return true;
            } catch (e) {
              setError(e.message);
              return false;
            }
          },
        },
      ],
    });
    return result;
  }

  async function dropTable(name) {
    const confirmed = await UI.confirm({
      title: `Drop "${name}"?`,
      message: "The table and every row in it are deleted. Any file that was imported to build it keeps its stored copy. This cannot be undone.",
      confirmLabel: "Drop table",
      requireText: name,
    });
    if (!confirmed) return;
    KoshaVault.db.exec(`DROP TABLE IF EXISTS ${KoshaEngine.quoteIdent(name)}`);
    KoshaVault.db.run("UPDATE kosha_files SET table_name = NULL WHERE table_name = ?", [name]);
    await KoshaVault.save();
    selectedTable = null;
    UI.ok(`"${name}" dropped.`);
    App.refresh();
  }

  async function exportTable(name) {
    let format = "csv";
    const go = await UI.modal({
      title: `Export "${name}"`,
      subtitle: "Converted in your browser and handed straight to you. Nothing is uploaded.",
      build: () =>
        UI.field(
          "Format",
          UI.select(
            KoshaConvert.targetFormats()
              .filter((f) => f.family === "tabular")
              .map((f) => [f.id, `${f.label} (.${f.ext})`]),
            format,
            (v) => (format = v)
          )
        ),
      actions: [{ label: "Download", kind: "primary", value: true }],
    });
    if (!go) return;
    await UI.withBusy("Exporting…", async () => {
      const ds = KoshaVault.db.exportDataset(name);
      const bytes = await KoshaConvert.writeDataset(format, ds, { name });
      UI.download(`${name}.${KoshaConvert.FORMATS[format].ext}`, bytes, KoshaConvert.FORMATS[format].mime);
    });
  }

  // ===================================================================
  // Query
  // ===================================================================

  function setQuery(sql) {
    editorValue = sql;
    lastRun = null;
  }

  function renderQuery(container) {
    UI.clear(container);
    const db = KoshaVault.db;
    const tables = db.listTables();

    const panel = el("div", { class: "panel" });
    panel.appendChild(
      el("div", { class: "panel-head" }, [
        el("h2", { text: "Query" }),
        el("p", {
          class: "blurb",
          text:
            "Real SQLite, running inside this browser tab. Anything SQLite understands works here — joins, GROUP BY, " +
            "window functions, views, transactions. Press ⌘/Ctrl + Enter to run.",
        }),
      ])
    );

    const editor = el("textarea", {
      id: "sql-editor",
      spellcheck: "false",
      value: editorValue,
      oninput: (e) => (editorValue = e.target.value),
      onkeydown: (e) => {
        if ((e.metaKey || e.ctrlKey) && e.key === "Enter") {
          e.preventDefault();
          run();
        }
        // A literal tab inside the editor rather than a focus change —
        // indentation matters in a multi-line query.
        if (e.key === "Tab") {
          e.preventDefault();
          const { selectionStart: s, selectionEnd: t, value } = e.target;
          e.target.value = value.slice(0, s) + "  " + value.slice(t);
          e.target.selectionStart = e.target.selectionEnd = s + 2;
          editorValue = e.target.value;
        }
      },
    });

    const resultsNode = el("div", {});

    const run = () => {
      UI.clear(resultsNode);
      const sql = editorValue.trim();
      if (!sql) return;
      let outcome;
      try {
        outcome = db.runScript(sql);
        lastRun = outcome;
      } catch (e) {
        resultsNode.appendChild(
          el("div", { class: "result-block" }, [
            el("div", { class: "result-error", text: explainSqlError(e.message) }),
          ])
        );
        return;
      }

      // A statement that changed something means the vault must be
      // saved. A pure SELECT does not, and marking it dirty would
      // re-upload the whole database every time someone read a row.
      if (/^\s*(insert|update|delete|create|drop|alter|replace|begin|commit|pragma|vacuum|with .*\b(insert|update|delete))/i.test(sql)) {
        KoshaVault.save().catch((e) => UI.fail(e.message, "Could not save"));
        App.refreshSidebar();
      }

      if (!outcome.results.length) {
        resultsNode.appendChild(el("p", { class: "note positive", text: `Done in ${UI.duration(outcome.elapsedMs)}. Nothing to show.` }));
        return;
      }

      outcome.results.forEach((r, i) => {
        const block = el("div", { class: "result-block" });
        if (r.columns.length) {
          block.appendChild(
            el("div", { class: "result-head" }, [
              el("span", { text: `${UI.count(r.rows.length)} row${r.rows.length === 1 ? "" : "s"} · ${UI.duration(outcome.elapsedMs)}` }),
              el("div", { class: "row" }, [
                el("button", { class: "tiny ghost", text: "Download CSV", onclick: () => downloadResult(r, i) }),
                el("button", { class: "tiny ghost", text: "Save as a table", onclick: () => saveResultAsTable(r) }),
              ]),
            ])
          );
          block.appendChild(
            UI.grid({
              columns: r.columns.map((c) => ({ key: c, label: c })),
              rows: r.rows.slice(0, 500),
              emptyMessage: "The query ran and matched no rows.",
            })
          );
          if (r.rows.length > 500) {
            block.appendChild(el("p", { class: "muted small", text: `Showing the first 500 of ${UI.count(r.rows.length)} rows. Download the CSV for all of them.` }));
          }
        } else {
          block.appendChild(
            el("p", {
              class: "note positive",
              text: `${r.changes === null ? "Statement" : `${UI.count(r.changes)} row(s)`} affected · ${UI.duration(outcome.elapsedMs)}`,
            })
          );
        }
        resultsNode.appendChild(block);
      });
    };

    panel.appendChild(
      el("div", { class: "split" }, [
        el("div", {}, [
          editor,
          el("div", { class: "toolbar", style: { marginTop: "10px" } }, [
            el("button", { class: "primary", text: "Run", onclick: run }),
            el("button", { text: "Build a query…", onclick: () => builderDialog(tables, (sql) => { setQuery(sql); App.refresh(); }) }),
            el("button", { text: "Save this query", onclick: () => saveCurrentQuery() }),
            el("button", { class: "ghost", text: "Clear", onclick: () => { setQuery(""); App.refresh(); } }),
          ]),
          resultsNode,
        ]),

        el("div", {}, [
          el("div", { class: "card" }, [
            el("h3", { text: "Your tables" }),
            tables.length
              ? el(
                  "div",
                  {},
                  tables.map((t) =>
                    el("button", { class: "snippet", onclick: () => insert(`${KoshaEngine.quoteIdent(t.name)}`) }, [
                      el("span", { class: "snip-title", text: `${t.name}${t.type === "view" ? " (view)" : ""}` }),
                      el("span", {
                        class: "snip-sql",
                        text: db.describeTable(t.name).columns.map((c) => c.name).join(", ").slice(0, 70),
                      }),
                    ])
                  )
                )
              : el("p", { class: "muted small", text: "No tables yet — import a file or design one." }),
          ]),

          el("div", { class: "card" }, [
            el("h3", { text: "Starting points" }),
            el(
              "div",
              {},
              snippets(tables).map((s) =>
                el("button", { class: "snippet", onclick: () => { setQuery(s.sql); App.refresh(); } }, [
                  el("span", { class: "snip-title", text: s.title }),
                  el("span", { class: "snip-sql", text: s.sql.replace(/\s+/g, " ").slice(0, 80) }),
                ])
              )
            ),
          ]),

          savedQueriesCard(),
        ]),
      ])
    );

    container.appendChild(panel);

    function insert(text) {
      const ta = document.getElementById("sql-editor");
      const s = ta.selectionStart;
      ta.value = ta.value.slice(0, s) + text + ta.value.slice(ta.selectionEnd);
      editorValue = ta.value;
      ta.focus();
      ta.selectionStart = ta.selectionEnd = s + text.length;
    }
  }

  function downloadResult(result, index) {
    const ds = { columns: result.columns, rows: result.rows };
    KoshaConvert.writeDataset("csv", ds).then((bytes) => UI.download(`query-result-${index + 1}.csv`, bytes, "text/csv"));
  }

  async function saveResultAsTable(result) {
    let name = "query_result";
    const go = await UI.modal({
      title: "Save these results as a table",
      subtitle: "The rows are copied into a new table in your vault, so you can query them further or export them later.",
      build: () => UI.field("Table name", el("input", { type: "text", class: "mono", value: name, oninput: (e) => (name = e.target.value) })),
      actions: [{ label: "Create table", kind: "primary", value: true }],
    });
    if (!go) return;
    try {
      const created = KoshaVault.db.importDataset(name, { columns: result.columns, rows: result.rows });
      await KoshaVault.save();
      UI.ok(`Created "${created.table}" with ${UI.count(created.rowCount)} rows.`, "Saved");
      App.refresh();
    } catch (e) {
      UI.fail(e.message);
    }
  }

  async function saveCurrentQuery() {
    if (!editorValue.trim()) return;
    let name = "";
    const go = await UI.modal({
      title: "Save this query",
      subtitle: "Saved queries live inside your encrypted vault alongside everything else.",
      build: () => UI.field("Name", el("input", { type: "text", placeholder: "Monthly totals", oninput: (e) => (name = e.target.value) })),
      actions: [{ label: "Save", kind: "primary", value: true }],
    });
    if (!go || !name.trim()) return;
    KoshaVault.saveQuery(name.trim(), editorValue);
    UI.ok("Query saved.");
    App.refresh();
  }

  function savedQueriesCard() {
    const saved = KoshaVault.listQueries();
    if (!saved.length) return null;
    return el("div", { class: "card" }, [
      el("h3", { text: "Saved queries" }),
      el(
        "div",
        {},
        saved.map((q) =>
          el("div", { class: "row spread", style: { borderBottom: "1px solid var(--hairline)" } }, [
            el("button", { class: "snippet grow", onclick: () => { setQuery(q.sql); App.refresh(); } }, [
              el("span", { class: "snip-title", text: q.name }),
              el("span", { class: "snip-sql", text: q.sql.replace(/\s+/g, " ").slice(0, 60) }),
            ]),
            el("button", {
              class: "tiny ghost",
              text: "✕",
              onclick: () => {
                KoshaVault.deleteQuery(q.id);
                App.refresh();
              },
            }),
          ])
        )
      ),
    ]);
  }

  /** Context-aware starting points, using a real table name where possible. */
  function snippets(tables) {
    const t = tables[0]?.name;
    const q = t ? KoshaEngine.quoteIdent(t) : '"your_table"';
    const col = t ? KoshaVault.db.describeTable(t).columns[0]?.name : "column";
    const c = KoshaEngine.quoteIdent(col || "column");
    return [
      { title: "Look at everything", sql: `SELECT *\nFROM ${q}\nLIMIT 100;` },
      { title: "Count the rows", sql: `SELECT COUNT(*) AS rows\nFROM ${q};` },
      { title: "Count by category", sql: `SELECT ${c}, COUNT(*) AS n\nFROM ${q}\nGROUP BY ${c}\nORDER BY n DESC;` },
      { title: "Find duplicates", sql: `SELECT ${c}, COUNT(*) AS times\nFROM ${q}\nGROUP BY ${c}\nHAVING times > 1\nORDER BY times DESC;` },
      { title: "Rows with a missing value", sql: `SELECT *\nFROM ${q}\nWHERE ${c} IS NULL OR TRIM(${c}) = '';` },
      {
        title: "Your biggest files (Kosha's own tables)",
        sql: `SELECT f.name, f.format, f.size, d.name AS folder\nFROM kosha_files f\nJOIN kosha_folders d ON d.id = f.folder_id\nORDER BY f.size DESC\nLIMIT 20;`,
      },
      {
        title: "How many files of each format",
        sql: `SELECT format, COUNT(*) AS files, SUM(size) AS bytes\nFROM kosha_files\nGROUP BY format\nORDER BY bytes DESC;`,
      },
    ];
  }

  /**
   * Turn SQLite's terse errors into something a beginner can act on,
   * while still showing the original underneath — the real message is
   * what they will find if they search for it.
   */
  function explainSqlError(message) {
    const m = String(message);
    const hints = [
      [/no such table: (\w+)/i, (x) => `There is no table called "${x[1]}". Check the list of tables in the sidebar — names are case-sensitive here.`],
      [/no such column: ([\w.]+)/i, (x) => `There is no column called "${x[1]}". If the name has spaces or punctuation, wrap it in double quotes: "${x[1]}".`],
      [/syntax error/i, () => `SQLite could not parse that. A missing comma between columns, or a missing quote, is the usual cause.`],
      [/UNIQUE constraint failed: (.+)/i, (x) => `A row with that value already exists in ${x[1]}, and that column must be unique.`],
      [/NOT NULL constraint failed: (.+)/i, (x) => `${x[1]} is required, so it cannot be left empty.`],
      [/table (\w+) already exists/i, (x) => `A table called "${x[1]}" already exists. Pick a different name, or DROP the old one first.`],
    ];
    for (const [pattern, explain] of hints) {
      const match = m.match(pattern);
      if (match) return `${explain(match)}\n\nSQLite said:\n${m}`;
    }
    return m;
  }

  // -------------------------------------------------------------------
  // The query builder
  // -------------------------------------------------------------------

  /**
   * A form that writes SQL. The generated statement is visible the
   * whole time and lands in the editor when you accept it, which is
   * the point: the builder is a way into the language rather than a
   * substitute for it.
   */
  async function builderDialog(tables, onApply) {
    if (!tables.length) {
      UI.warn("There are no tables to query yet.");
      return;
    }
    const db = KoshaVault.db;
    const state = {
      table: tables[0].name,
      columns: [],
      where: [],
      groupBy: "",
      aggregate: "",
      aggregateColumn: "",
      orderBy: "",
      desc: false,
      limit: 100,
    };

    let sqlNode;
    let bodyNode;

    const columnsOf = (t) => db.describeTable(t).columns.map((c) => c.name);

    /**
     * A sensible column to aggregate over.
     *
     * Falling back to "the first column" produces SUM(region) the
     * moment someone picks SUM — summing a text column, which SQLite
     * will happily do and answer 0 to. Preferring a numeric column
     * that is not the one being grouped by gets the obviously-intended
     * query right without another decision to make.
     */
    const defaultAggregateColumn = (table, groupBy) => {
      const cols = db.describeTable(table).columns;
      const numeric = cols.find((c) => /INT|REAL|NUM|DEC|FLOA|DOUB/i.test(c.type) && c.name !== groupBy);
      return (numeric || cols.find((c) => c.name !== groupBy) || cols[0])?.name;
    };

    const buildSql = () => {
      const q = KoshaEngine.quoteIdent(state.table);
      const sel = [];
      if (state.groupBy) sel.push(KoshaEngine.quoteIdent(state.groupBy));
      if (state.aggregate) {
        const inner =
          state.aggregate === "COUNT"
            ? "*"
            : KoshaEngine.quoteIdent(state.aggregateColumn || defaultAggregateColumn(state.table, state.groupBy));
        sel.push(`${state.aggregate}(${inner}) AS ${state.aggregate.toLowerCase()}_result`);
      }
      if (!sel.length) {
        sel.push(state.columns.length ? state.columns.map(KoshaEngine.quoteIdent).join(", ") : "*");
      }

      const lines = [`SELECT ${sel.join(", ")}`, `FROM ${q}`];
      const conditions = state.where
        .filter((w) => w.column && w.op)
        .map((w) => {
          const col = KoshaEngine.quoteIdent(w.column);
          if (w.op === "IS NULL" || w.op === "IS NOT NULL") return `${col} ${w.op}`;
          if (w.op === "LIKE") return `${col} LIKE ${KoshaEngine.quoteLiteral(`%${w.value}%`)}`;
          const numeric = /^-?\d+(\.\d+)?$/.test(String(w.value).trim());
          return `${col} ${w.op} ${numeric ? w.value : KoshaEngine.quoteLiteral(w.value)}`;
        });
      if (conditions.length) lines.push(`WHERE ${conditions.join("\n  AND ")}`);
      if (state.groupBy) lines.push(`GROUP BY ${KoshaEngine.quoteIdent(state.groupBy)}`);
      if (state.orderBy) lines.push(`ORDER BY ${KoshaEngine.quoteIdent(state.orderBy)}${state.desc ? " DESC" : ""}`);
      if (state.limit) lines.push(`LIMIT ${Number(state.limit)}`);
      return lines.join("\n") + ";";
    };

    const refresh = () => {
      sqlNode.textContent = buildSql();
      UI.clear(bodyNode);
      bodyNode.appendChild(buildBody());
    };

    const buildBody = () => {
      const cols = columnsOf(state.table);
      return el("div", {}, [
        UI.field(
          "From which table",
          UI.select(
            tables.map((t) => [t.name, t.name]),
            state.table,
            (v) => {
              state.table = v;
              state.columns = [];
              state.where = [];
              state.groupBy = "";
              state.orderBy = "";
              state.aggregateColumn = ""; // belongs to the old table
              refresh();
            }
          )
        ),

        UI.field(
          "Showing",
          el(
            "div",
            { class: "row wrap", style: { gap: "4px" } },
            [
              el("button", {
                class: state.columns.length ? "tiny" : "tiny primary",
                text: "Every column",
                onclick: () => {
                  state.columns = [];
                  refresh();
                },
              }),
              ...cols.map((c) =>
                el("button", {
                  class: state.columns.includes(c) ? "tiny primary" : "tiny",
                  text: c,
                  onclick: () => {
                    state.columns = state.columns.includes(c) ? state.columns.filter((x) => x !== c) : [...state.columns, c];
                    refresh();
                  },
                })
              ),
            ]
          ),
          "Click to pick specific columns, or leave it on “Every column”."
        ),

        el("div", { class: "kicker-label", style: { marginBottom: "6px" }, text: "Only rows where" }),
        ...state.where.map((w, i) =>
          el("div", { class: "row", style: { gap: "6px", marginBottom: "6px" } }, [
            UI.select(cols.map((c) => [c, c]), w.column, (v) => ((w.column = v), refresh())),
            UI.select(
              [["=", "is"], ["!=", "is not"], [">", "more than"], ["<", "less than"], [">=", "at least"], ["<=", "at most"], ["LIKE", "contains"], ["IS NULL", "is empty"], ["IS NOT NULL", "is not empty"]],
              w.op,
              (v) => ((w.op = v), refresh())
            ),
            w.op === "IS NULL" || w.op === "IS NOT NULL"
              ? el("span", { class: "grow" })
              : el("input", { type: "text", class: "grow", value: w.value, oninput: (e) => ((w.value = e.target.value), (sqlNode.textContent = buildSql())) }),
            el("button", { class: "tiny ghost", text: "✕", onclick: () => (state.where.splice(i, 1), refresh()) }),
          ])
        ),
        el("button", {
          class: "tiny",
          text: "+ Add a condition",
          onclick: () => {
            state.where.push({ column: cols[0], op: "=", value: "" });
            refresh();
          },
        }),

        el("hr", { class: "hair" }),

        el("div", { class: "row", style: { gap: "10px" } }, [
          el("div", { class: "grow" }, [
            UI.field(
              "Group by",
              UI.select([["", "— no grouping —"], ...cols.map((c) => [c, c])], state.groupBy, (v) => ((state.groupBy = v), refresh())),
              "Collapses rows that share this value into one."
            ),
          ]),
          el("div", { class: "grow" }, [
            UI.field(
              "And calculate",
              UI.select(
                [["", "— nothing —"], ["COUNT", "how many"], ["SUM", "total"], ["AVG", "average"], ["MIN", "smallest"], ["MAX", "largest"]],
                state.aggregate,
                (v) => {
                  state.aggregate = v;
                  if (v && v !== "COUNT" && !state.aggregateColumn) {
                    state.aggregateColumn = defaultAggregateColumn(state.table, state.groupBy);
                  }
                  refresh();
                }
              )
            ),
          ]),
          state.aggregate && state.aggregate !== "COUNT"
            ? el("div", { class: "grow" }, [
                UI.field(
                  "Of column",
                  UI.select(
                    cols.map((c) => [c, c]),
                    state.aggregateColumn || defaultAggregateColumn(state.table, state.groupBy),
                    (v) => ((state.aggregateColumn = v), refresh())
                  )
                ),
              ])
            : null,
        ]),

        el("div", { class: "row", style: { gap: "10px" } }, [
          el("div", { class: "grow" }, [
            UI.field("Sort by", UI.select([["", "— unsorted —"], ...cols.map((c) => [c, c])], state.orderBy, (v) => ((state.orderBy = v), refresh()))),
          ]),
          el("div", { class: "grow" }, [
            UI.field("Direction", UI.select([["asc", "Smallest first"], ["desc", "Largest first"]], state.desc ? "desc" : "asc", (v) => ((state.desc = v === "desc"), refresh()))),
          ]),
          el("div", { class: "grow" }, [
            UI.field("At most", el("input", { type: "number", min: "1", value: state.limit, oninput: (e) => ((state.limit = e.target.value), (sqlNode.textContent = buildSql())) })),
          ]),
        ]),
      ]);
    };

    const sql = await UI.modal({
      title: "Build a query",
      subtitle: "Answer these and Kosha writes the SQL. Read what it produces — that is how the next one gets written by hand.",
      wide: true,
      build: () => {
        bodyNode = el("div", {});
        sqlNode = el("pre", { class: "preview-pane", style: { maxHeight: "160px" } });
        setTimeout(refresh, 0);
        return el("div", {}, [
          bodyNode,
          el("hr", { class: "hair" }),
          el("div", { class: "kicker-label", style: { marginBottom: "6px" }, text: "The SQL this writes" }),
          sqlNode,
        ]);
      },
      actions: [{ label: "Put it in the editor", kind: "primary", onClick: () => buildSql() }],
    });

    if (sql) onApply(sql);
  }

  return { renderTables, renderQuery, openTable, setQuery, designerDialog };
})();
