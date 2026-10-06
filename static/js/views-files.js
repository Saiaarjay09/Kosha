/**
 * The Files view: a folder's contents, the rules that govern it, and
 * the path a dropped file takes on its way in.
 *
 * The idea this screen exists to express is that a folder is not just
 * a bag. It declares a format, and Kosha holds everything in it to
 * that declaration — converting what it can, refusing what it cannot,
 * and filing the result under a name the folder's own template
 * decides. So "my exports folder is CSVs, named by year and month" is
 * a setting rather than a habit you have to keep.
 */

const ViewFiles = (() => {
  "use strict";
  const { el, $ } = UI;

  let currentFolderId = null;
  let selectedFileId = null;

  function setFolder(id) {
    currentFolderId = id;
    selectedFileId = null;
  }

  function getFolderId() {
    return currentFolderId;
  }

  // -------------------------------------------------------------------
  // The folder rules editor
  // -------------------------------------------------------------------

  /**
   * One dialog for both "new folder" and "folder settings": the
   * fields are identical, and keeping them in one place means the
   * explanation of what `strict` means cannot drift between the two.
   */
  async function folderDialog({ folder = null, parentId = null } = {}) {
    const creating = !folder;
    const state = {
      name: folder?.name || "",
      filetype: folder?.filetype || "any",
      autoConvert: folder ? !!folder.auto_convert : true,
      strict: folder ? !!folder.strict : true,
      sortKey: folder?.sort_key || "name",
      sortDir: folder?.sort_dir || "asc",
      pathTemplate: folder?.path_template || "{name}.{ext}",
      note: folder?.note || "",
    };

    let previewNode;
    const renderPreview = () => {
      const fmt = KoshaConvert.FORMATS[state.filetype] || KoshaConvert.FORMATS.any;
      const sample = KoshaVault.resolvePath(state.pathTemplate, {
        name: "quarterly-report",
        ext: fmt.ext || "dat",
        format: state.filetype,
        folderName: state.name || "Folder",
        index: 7,
      });
      UI.clear(previewNode);
      previewNode.appendChild(el("span", { class: "muted small", text: "A file dropped here today would be stored as " }));
      previewNode.appendChild(el("code", { class: "inline", text: sample }));
    };

    const result = await UI.modal({
      title: creating ? "New folder" : `Folder: ${folder.name}`,
      subtitle: creating
        ? "A folder declares what it holds. Anything you add is converted to that format automatically."
        : "Changing these rules affects files added from now on. Use “Re-file everything” afterwards to apply them to what is already here.",
      wide: true,
      build: () => {
        const nameInput = el("input", {
          type: "text",
          value: state.name,
          placeholder: "Invoices",
          oninput: (e) => {
            state.name = e.target.value;
            renderPreview();
          },
        });

        const formatSelect = UI.select(
          KoshaConvert.targetFormats().map((f) => [
            f.id,
            f.id === "any" ? "Any file — store exactly as uploaded" : `${f.label} (.${f.ext})`,
          ]),
          state.filetype,
          (v) => {
            state.filetype = v;
            renderPreview();
          }
        );

        const templateInput = el("input", {
          type: "text",
          class: "mono",
          value: state.pathTemplate,
          oninput: (e) => {
            state.pathTemplate = e.target.value;
            renderPreview();
          },
        });

        const tokenButtons = el(
          "div",
          { class: "token-list" },
          KoshaVault.TEMPLATE_TOKENS.map(([token, description]) =>
            el("button", {
              type: "button",
              text: token,
              title: description,
              onclick: () => {
                templateInput.value += token;
                state.pathTemplate = templateInput.value;
                renderPreview();
              },
            })
          )
        );

        previewNode = el("div", { style: { marginTop: "6px" } });

        const node = el("div", {}, [
          UI.field("Name", nameInput),

          UI.field(
            "This folder holds",
            formatSelect,
            "Every file added is converted to this format. Pick “Any file” for a folder that should keep things exactly as they arrive."
          ),

          UI.checkboxField(
            "Convert automatically",
            state.autoConvert,
            (v) => {
              state.autoConvert = v;
              renderPreview();
            },
            "Off means files are stored in whatever format they arrive in, even though the folder declares one."
          ),

          UI.checkboxField(
            "Refuse files that cannot be converted",
            state.strict,
            (v) => (state.strict = v),
            "On: a PNG dropped into a CSV folder is rejected with an explanation. Off: it is stored as-is instead."
          ),

          el("hr", { class: "hair" }),

          UI.field(
            "Stored as",
            templateInput,
            "The name each file is filed under. Click a token to insert it; slashes create sub-paths."
          ),
          tokenButtons,
          previewNode,

          el("hr", { class: "hair" }),

          el("div", { class: "row" }, [
            el("div", { class: "grow" }, [UI.field("Order by", UI.select(KoshaVault.SORT_KEYS, state.sortKey, (v) => (state.sortKey = v)))]),
            el("div", { class: "grow" }, [
              UI.field(
                "Direction",
                UI.select(
                  [
                    ["asc", "Ascending (A→Z, oldest first)"],
                    ["desc", "Descending (Z→A, newest first)"],
                  ],
                  state.sortDir,
                  (v) => (state.sortDir = v)
                )
              ),
            ]),
          ]),

          UI.field(
            "Note (optional)",
            el("textarea", { rows: 2, value: state.note, oninput: (e) => (state.note = e.target.value) }),
            "A reminder to yourself about what belongs in here."
          ),
        ]);

        // Draw the preview once the nodes exist, so the dialog opens
        // already showing what the current settings would do rather
        // than staying blank until the first keystroke.
        setTimeout(renderPreview, 0);
        return node;
      },
      actions: [
        {
          label: creating ? "Create folder" : "Save",
          kind: "primary",
          onClick: (setError) => {
            if (!state.name.trim()) {
              setError("Give the folder a name.");
              return false;
            }
            if (!state.pathTemplate.trim()) {
              setError("The storage template cannot be empty.");
              return false;
            }
            try {
              if (creating) {
                const id = KoshaVault.createFolder({ ...state, parentId });
                return { created: id };
              }
              KoshaVault.updateFolder(folder.id, state);
              return { updated: folder.id };
            } catch (e) {
              setError(e.message);
              return false;
            }
          },
        },
      ],
    });

    // Defer rendering the preview until the dialog exists in the DOM.
    return result;
  }

  // -------------------------------------------------------------------
  // Adding files
  // -------------------------------------------------------------------

  /**
   * Show what will happen to each file before anything is stored.
   *
   * A silent conversion is the thing most likely to make someone
   * distrust a tool like this — you drop an .xlsx in and later find a
   * .csv with the formatting gone. So the plan is shown first, with
   * its losses spelled out, and the user presses Add.
   */
  async function addFilesDialog(folderId, fileList) {
    const folder = KoshaVault.getFolder(folderId);
    const entries = [];
    for (const f of fileList) {
      const bytes = new Uint8Array(await f.arrayBuffer());
      let plan;
      try {
        plan = KoshaVault.previewAdd(folderId, f.name, bytes);
      } catch (e) {
        plan = { possible: false, from: "?", to: folder.filetype, action: "reject", notes: [e.message] };
      }
      entries.push({ name: f.name, bytes, plan });
    }

    const acceptable = entries.filter((e) => e.plan.possible);
    const refused = entries.filter((e) => !e.plan.possible);

    const confirmed = await UI.modal({
      title: entries.length === 1 ? "Add this file?" : `Add ${entries.length} files?`,
      subtitle: `Into ${KoshaVault.folderPath(folderId)} — which holds ${
        KoshaConvert.FORMATS[folder.filetype]?.label || folder.filetype
      }.`,
      wide: true,
      build: () =>
        el("div", { class: "stack" }, [
          UI.grid({
            columns: [
              { key: "name", label: "File", render: (r) => el("span", { class: "mono small", text: r.name }) },
              {
                key: "from",
                label: "Detected as",
                render: (r) => el("span", { class: "pill", text: KoshaConvert.FORMATS[r.plan.from]?.label || r.plan.from }),
              },
              {
                key: "action",
                label: "Action",
                render: (r) => {
                  if (!r.plan.possible) return el("span", { class: "pill caution", text: "Refused" });
                  if (r.plan.action === "store") return el("span", { class: "pill", text: "Stored as-is" });
                  return el("span", {
                    class: "pill accent",
                    text: `→ ${KoshaConvert.FORMATS[r.plan.to]?.label || r.plan.to}`,
                  });
                },
              },
              { key: "size", label: "Size", render: (r) => UI.bytes(r.bytes.length) },
            ],
            rows: entries,
          }),

          ...entries
            .filter((e) => e.plan.notes.length)
            .map((e) =>
              el("div", { class: `note ${e.plan.possible ? "" : "caution"}` }, [
                el("strong", { text: e.name + ": " }),
                document.createTextNode(e.plan.notes.join(" ")),
              ])
            ),

          refused.length && acceptable.length
            ? el("p", {
                class: "note caution",
                text: `${refused.length} file(s) will be skipped. The other ${acceptable.length} will be added.`,
              })
            : null,
        ]),
      actions: acceptable.length
        ? [{ label: acceptable.length === 1 ? "Add file" : `Add ${acceptable.length} files`, kind: "primary", value: true }]
        : [],
    });

    if (!confirmed) return;

    const results = [];
    await UI.withBusy("Adding files…", async (update) => {
      for (let i = 0; i < acceptable.length; i++) {
        const entry = acceptable[i];
        update(`${i + 1} of ${acceptable.length}: ${entry.name}`);
        try {
          const res = await KoshaVault.addFile(folderId, entry.name, entry.bytes, {
            onProgress: (msg) => update(`${entry.name} — ${msg}`),
          });
          results.push({ name: entry.name, ok: true, res });
        } catch (e) {
          results.push({ name: entry.name, ok: false, error: e.message });
        }
      }
    });

    const added = results.filter((r) => r.ok);
    const failed = results.filter((r) => !r.ok);
    const tables = added.filter((r) => r.res.importedTable).map((r) => r.res.importedTable.table);

    if (added.length) {
      UI.ok(
        `${added.length} file${added.length === 1 ? "" : "s"} added` +
          (tables.length ? `, and ${tables.length} became queryable table${tables.length === 1 ? "" : "s"}: ${tables.join(", ")}` : "") +
          ".",
        "Stored"
      );
    }
    for (const f of failed) UI.fail(f.error, `Could not add ${f.name}`);
    App.refresh();
  }

  // -------------------------------------------------------------------
  // File preview
  // -------------------------------------------------------------------

  async function previewFile(fileId) {
    const file = KoshaVault.getFile(fileId);
    if (!file) return;
    const { bytes } = await UI.withBusy("Fetching and decrypting…", () => KoshaVault.readFile(fileId));
    const family = KoshaConvert.familyOf(file.format);

    let body;
    if (family === "image") {
      const url = URL.createObjectURL(new Blob([bytes], { type: KoshaConvert.FORMATS[file.format].mime }));
      body = el("img", { class: "preview-img", src: url, alt: file.name });
      setTimeout(() => URL.revokeObjectURL(url), 60000);
    } else if (family === "tabular") {
      try {
        const ds = await KoshaConvert.readDataset(file.format, bytes, file.name);
        body = el("div", { class: "stack" }, [
          el("p", {
            class: "muted small",
            text: `${UI.count(ds.rows.length)} rows × ${ds.columns.length} columns. Showing the first 50.`,
          }),
          UI.grid({ columns: ds.columns, rows: ds.rows.slice(0, 50) }),
        ]);
      } catch (e) {
        body = el("pre", { class: "preview-pane", text: `This file could not be read as a table:\n${e.message}` });
      }
    } else {
      const text = new TextDecoder().decode(bytes.subarray(0, 20000));
      body = el("pre", {
        class: "preview-pane",
        text: text + (bytes.length > 20000 ? "\n\n… truncated for preview …" : ""),
      });
    }

    await UI.modal({
      title: file.name,
      subtitle: `${KoshaConvert.FORMATS[file.format]?.label || file.format} · ${UI.bytes(file.size)} · stored at ${file.stored_path}`,
      wide: true,
      build: () => body,
      actions: [
        {
          label: "Download",
          onClick: () => {
            UI.download(file.name, bytes, KoshaConvert.FORMATS[file.format]?.mime || "application/octet-stream");
            return false; // keep the dialog open
          },
        },
        { label: "Close", kind: "primary", value: true },
      ],
    });
  }

  /** Download in a different format than the one stored. */
  async function exportAs(fileId) {
    const file = KoshaVault.getFile(fileId);
    const targets = KoshaConvert.targetFormats().filter(
      (f) => f.id !== "any" && f.family === KoshaConvert.familyOf(file.format)
    );
    if (!targets.length) {
      UI.warn("There is no other format Kosha can write this file as.");
      return;
    }
    let choice = targets[0].id;
    const go = await UI.modal({
      title: `Export "${file.name}"`,
      subtitle: "The file is converted here in your browser. Nothing is uploaded and the stored copy is unchanged.",
      build: () =>
        UI.field(
          "Convert to",
          UI.select(
            targets.map((f) => [f.id, `${f.label} (.${f.ext})`]),
            choice,
            (v) => (choice = v)
          )
        ),
      actions: [{ label: "Download", kind: "primary", value: true }],
    });
    if (!go) return;

    await UI.withBusy("Converting…", async () => {
      const { bytes } = await KoshaVault.readFile(fileId);
      const out = await KoshaConvert.convert(file.name, bytes, choice);
      UI.download(out.name, out.bytes, KoshaConvert.FORMATS[choice].mime);
      if (out.notes.length) UI.warn(out.notes.join(" "), "Converted, with losses");
    });
  }

  // -------------------------------------------------------------------
  // Rendering
  // -------------------------------------------------------------------

  function render(container) {
    UI.clear(container);

    const tree = KoshaVault.listFolders();
    if (!tree.flat.length) {
      container.appendChild(
        el("div", { class: "panel" }, [
          el("div", { class: "empty" }, [
            el("div", { class: "empty-title", text: "No folders yet" }),
            el("p", {
              text: "A folder in Kosha declares what it holds — CSV, Excel, JSON, images — and converts anything you put in it to match.",
            }),
            el("button", {
              class: "primary",
              text: "Create your first folder",
              onclick: async () => {
                const r = await folderDialog();
                if (r?.created) currentFolderId = r.created;
                App.refresh();
              },
            }),
          ]),
        ])
      );
      return;
    }

    if (currentFolderId == null || !KoshaVault.getFolder(currentFolderId)) {
      currentFolderId = tree.roots[0]?.id ?? tree.flat[0].id;
    }

    const folder = KoshaVault.getFolder(currentFolderId);
    const files = KoshaVault.listFiles(currentFolderId);
    const format = KoshaConvert.FORMATS[folder.filetype] || KoshaConvert.FORMATS.any;

    const panel = el("div", { class: "panel" });

    // -- header
    panel.appendChild(
      el("div", { class: "panel-head" }, [
        el("div", { class: "row spread" }, [
          el("div", {}, [
            el("h2", { text: folder.name }),
            el("div", { class: "path", text: KoshaVault.folderPath(folder.id) }),
          ]),
          el("div", { class: "row" }, [
            el("button", { class: "tiny", text: "Folder rules", onclick: () => folderDialog({ folder }).then(App.refresh) }),
            el("button", {
              class: "tiny",
              text: "Sub-folder",
              onclick: async () => {
                const r = await folderDialog({ parentId: folder.id });
                if (r?.created) currentFolderId = r.created;
                App.refresh();
              },
            }),
            el("button", { class: "tiny danger", text: "Delete", onclick: () => deleteFolder(folder) }),
          ]),
        ]),
        el("div", { class: "row wrap", style: { marginTop: "8px", gap: "6px" } }, [
          el("span", { class: "pill accent", text: `Holds ${format.label}` }),
          folder.auto_convert ? el("span", { class: "pill", text: "Auto-converts" }) : el("span", { class: "pill caution", text: "No conversion" }),
          folder.strict ? el("span", { class: "pill", text: "Strict" }) : el("span", { class: "pill caution", text: "Accepts anything" }),
          el("span", { class: "pill", text: `Ordered by ${(KoshaVault.SORT_KEYS.find((s) => s[0] === folder.sort_key) || ["", folder.sort_key])[1].toLowerCase()}` }),
          el("span", { class: "pill mono", text: folder.path_template }),
        ]),
        folder.note ? el("p", { class: "blurb", text: folder.note }) : null,
      ])
    );

    // -- drop zone
    const input = el("input", {
      type: "file",
      multiple: true,
      hidden: true,
      onchange: (e) => {
        const chosen = Array.from(e.target.files);
        e.target.value = "";
        if (chosen.length) addFilesDialog(folder.id, chosen);
      },
    });

    const dz = el("div", { class: "dropzone" }, [
      el("div", { class: "dz-title", text: `Drop files here, or click to choose` }),
      el("div", {
        class: "dz-sub",
        text:
          folder.filetype === "any"
            ? "They will be stored exactly as they are."
            : `Anything you add is converted to ${format.label} before it is encrypted and stored.`,
      }),
      input,
    ]);
    dz.addEventListener("click", () => input.click());
    dz.addEventListener("dragover", (e) => {
      e.preventDefault();
      dz.classList.add("over");
    });
    dz.addEventListener("dragleave", () => dz.classList.remove("over"));
    dz.addEventListener("drop", (e) => {
      e.preventDefault();
      dz.classList.remove("over");
      const dropped = Array.from(e.dataTransfer.files);
      if (dropped.length) addFilesDialog(folder.id, dropped);
    });
    panel.appendChild(dz);

    // -- the file table
    panel.appendChild(el("div", { style: { height: "16px" } }));

    if (!files.length) {
      panel.appendChild(
        el("div", { class: "empty" }, [
          el("div", { class: "empty-title", text: "This folder is empty" }),
          el("p", {
            text:
              folder.filetype === "any"
                ? "Add anything. Kosha will store it unchanged and encrypted."
                : `Add a spreadsheet, a CSV, a JSON export — Kosha converts it to ${format.label} on the way in, and if it is a table, you can query it in SQL straight away.`,
          }),
        ])
      );
    } else {
      panel.appendChild(
        UI.grid({
          columns: [
            {
              key: "name",
              label: "Name",
              render: (f) =>
                el("div", {}, [
                  el("div", { text: f.name }),
                  f.converted
                    ? el("div", {
                        class: "faint small mono",
                        text: `was ${f.original_name} (${KoshaConvert.FORMATS[f.original_format]?.label || f.original_format})`,
                      })
                    : null,
                ]),
            },
            { key: "stored_path", label: "Stored as", mono: true, render: (f) => el("span", { class: "mono small", text: f.stored_path }) },
            { key: "format", label: "Format", render: (f) => el("span", { class: "pill", text: KoshaConvert.FORMATS[f.format]?.label || f.format }) },
            { key: "size", label: "Size", render: (f) => UI.bytes(f.size), cellClass: "num" },
            {
              key: "rows",
              label: "Rows",
              cellClass: "num",
              render: (f) => (f.row_count === null ? "—" : `${UI.count(f.row_count)} × ${f.col_count}`),
            },
            {
              key: "table",
              label: "SQL table",
              render: (f) =>
                f.table_name
                  ? el("button", {
                      class: "tiny",
                      text: f.table_name,
                      title: "Open this table in the Tables view",
                      onclick: (e) => {
                        e.stopPropagation();
                        App.openTable(f.table_name);
                      },
                    })
                  : el("span", { class: "faint", text: "—" }),
            },
            { key: "created_at", label: "Added", render: (f) => UI.when(f.created_at) },
            {
              key: "actions",
              label: "",
              sortable: false,
              render: (f) =>
                el("div", { class: "row" }, [
                  el("button", { class: "tiny ghost", text: "View", onclick: (e) => (e.stopPropagation(), previewFile(f.id)) }),
                  el("button", { class: "tiny ghost", text: "Export", onclick: (e) => (e.stopPropagation(), exportAs(f.id)) }),
                  el("button", { class: "tiny ghost", text: "⋯", title: "More", onclick: (e) => (e.stopPropagation(), fileMenu(f)) }),
                ]),
            },
          ],
          rows: files,
          onRowClick: (f) => previewFile(f.id),
        })
      );

      panel.appendChild(
        el("div", { class: "grid-foot" }, [
          el("span", {
            text: `${UI.count(files.length)} file${files.length === 1 ? "" : "s"} · ${UI.bytes(
              files.reduce((n, f) => n + f.size, 0)
            )}`,
          }),
          el("button", {
            class: "tiny",
            text: "Re-file everything with the current rules",
            title: "Convert and rename every file here to match this folder's settings as they are now.",
            onclick: () => reapply(folder),
          }),
        ])
      );
    }

    container.appendChild(panel);
  }

  async function fileMenu(file) {
    const folders = KoshaVault.listFolders().flat.filter((f) => f.id !== file.folder_id);
    let moveTarget = folders[0]?.id;
    let newName = file.name;

    const action = await UI.modal({
      title: file.name,
      subtitle: `Added ${UI.when(file.created_at)} · ${UI.bytes(file.size)}`,
      build: () =>
        el("div", {}, [
          UI.field("Rename", el("input", { type: "text", value: file.name, oninput: (e) => (newName = e.target.value) })),
          folders.length
            ? UI.field(
                "Move to",
                UI.select(
                  folders.map((f) => [f.id, KoshaVault.folderPath(f.id)]),
                  moveTarget,
                  (v) => (moveTarget = Number(v))
                ),
                "Moving does not re-convert the file. Use the destination folder's “Re-file everything” for that."
              )
            : null,
          file.table_name
            ? el("p", { class: "note", text: `This file also exists as the SQL table "${file.table_name}".` })
            : null,
        ]),
      actions: [
        { label: "Delete file", kind: "danger", value: "delete" },
        { label: "Save changes", kind: "primary", value: "save" },
      ],
    });

    if (action === "save") {
      if (newName !== file.name) KoshaVault.renameFile(file.id, newName);
      if (moveTarget && moveTarget !== file.folder_id) KoshaVault.moveFile(file.id, moveTarget);
      App.refresh();
    } else if (action === "delete") {
      const dropTable = file.table_name
        ? await UI.confirm({
            title: `Delete "${file.name}"?`,
            message: `This also removes its SQL table "${file.table_name}" and everything in it. This cannot be undone.`,
            confirmLabel: "Delete file and table",
          })
        : await UI.confirm({
            title: `Delete "${file.name}"?`,
            message: "The encrypted copy on the server is deleted too. This cannot be undone.",
            confirmLabel: "Delete",
          });
      if (!dropTable) return;
      await UI.withBusy("Deleting…", () => KoshaVault.deleteFile(file.id, { dropTable: !!file.table_name }));
      UI.ok(`"${file.name}" deleted.`);
      App.refresh();
    }
  }

  async function deleteFolder(folder) {
    const files = KoshaVault.listFiles(folder.id);
    const confirmed = await UI.confirm({
      title: `Delete "${folder.name}"?`,
      message:
        `This removes the folder, its sub-folders, and ${files.length} file${files.length === 1 ? "" : "s"}, ` +
        "including the encrypted copies on the server. SQL tables built from those files are left alone. This cannot be undone.",
      confirmLabel: "Delete folder",
      requireText: folder.name,
    });
    if (!confirmed) return;
    await UI.withBusy("Deleting…", () => KoshaVault.deleteFolder(folder.id));
    currentFolderId = null;
    UI.ok(`"${folder.name}" deleted.`);
    App.refresh();
  }

  async function reapply(folder) {
    const confirmed = await UI.confirm({
      title: "Re-file everything?",
      message:
        `Every file in "${folder.name}" will be converted to ${
          KoshaConvert.FORMATS[folder.filetype]?.label || folder.filetype
        } and renamed using the current template. Files that cannot be converted are left exactly as they are.`,
      confirmLabel: "Re-file",
      kind: "caution",
    });
    if (!confirmed) return;

    const report = await UI.withBusy("Re-filing…", (update) => KoshaVault.reapplyFolderRules(folder.id, update));
    if (report.skipped.length) {
      UI.warn(
        `${report.converted.length} converted, ${report.skipped.length} left alone: ` +
          report.skipped.map((s) => `${s.name} (${s.reason})`).join("; "),
        "Re-filed with exceptions"
      );
    } else {
      UI.ok(`${report.converted.length} of ${report.total} file(s) converted and re-filed.`, "Done");
    }
    App.refresh();
  }

  return { render, setFolder, getFolderId, folderDialog, addFilesDialog };
})();
