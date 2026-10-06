/**
 * The shell: sign-in, routing between the four views, the folder
 * sidebar, Settings, and the save indicator.
 */

const App = (() => {
  "use strict";
  const { el, $ } = UI;

  let view = "files";

  // -------------------------------------------------------------------
  // Login screen
  // -------------------------------------------------------------------

  function setLoginTab(which) {
    for (const [tab, form] of [
      ["signin", "form-signin"],
      ["signup", "form-signup"],
      ["recover", "form-recover"],
    ]) {
      $(`#tab-${tab}`).classList.toggle("active", tab === which);
      $(`#${form}`).hidden = tab !== which;
    }
    status("");
  }

  function status(message, working = false) {
    const node = $("#login-status");
    node.textContent = message;
    node.classList.toggle("working", working);
  }

  function busyButton(form, on) {
    const btn = form.querySelector('button[type="submit"]');
    btn.classList.toggle("loading", on);
    btn.disabled = on;
  }

  /**
   * Show the recovery phrase once, and make the user confirm they have
   * written it down. This is the only moment it exists in a readable
   * form anywhere — the server holds only a hash of a key derived from
   * it, so if it is lost here it is lost permanently.
   */
  async function showRecoveryPhrase(phrase, { rotated = false } = {}) {
    let acknowledged = false;
    await UI.modal({
      title: rotated ? "Your new recovery phrase" : "Write this down now",
      subtitle:
        "These twelve words are the only other key to your vault. If you forget your password, this is what gets you back in — " +
        "and nobody, including whoever runs this server, can produce it for you.",
      dismissable: false,
      wide: true,
      build: (finish, setError) =>
        el("div", { class: "stack" }, [
          el("div", { class: "phrase-box", text: phrase }),
          el("div", { class: "row" }, [
            el("button", {
              text: "Copy",
              onclick: async (e) => {
                const copied = await UI.copyToClipboard(phrase);
                e.target.textContent = copied ? "Copied" : "Select it above and copy by hand";
              },
            }),
            el("button", {
              text: "Download as a text file",
              onclick: () => UI.download("kosha-recovery-phrase.txt", `Kosha recovery phrase\n\n${phrase}\n\nKeep this somewhere safe and offline.\n`, "text/plain"),
            }),
          ]),
          rotated
            ? el("p", { class: "note caution", text: "Your previous recovery phrase stopped working the moment this one was created." })
            : null,
          UI.checkboxField(
            "I have written these words down somewhere safe",
            false,
            (v) => {
              acknowledged = v;
              setError("");
            }
          ),
        ]),
      actions: [
        {
          label: "Continue",
          kind: "primary",
          onClick: (setError) => {
            if (!acknowledged) {
              setError("Tick the box once you have actually saved the phrase. There is no second chance to see it.");
              return false;
            }
            return true;
          },
        },
      ],
    });
  }

  function bindLogin() {
    $("#tab-signin").onclick = () => setLoginTab("signin");
    $("#tab-signup").onclick = () => setLoginTab("signup");
    $("#tab-recover").onclick = () => setLoginTab("recover");

    $("#form-signin").onsubmit = async (e) => {
      e.preventDefault();
      const form = e.target;
      busyButton(form, true);
      try {
        const res = await KoshaAPI.login($("#signin-username").value.trim(), $("#signin-password").value, (m) => status(m, true));
        await enterApp(res);
      } catch (err) {
        status(err.message);
      } finally {
        busyButton(form, false);
      }
    };

    $("#form-signup").onsubmit = async (e) => {
      e.preventDefault();
      const form = e.target;
      const password = $("#signup-password").value;
      if (password !== $("#signup-password2").value) return status("The two passwords do not match.");
      if (password.length < 10) {
        return status("Use at least 10 characters. This password is the only thing that can decrypt your data — length matters more than symbols.");
      }
      busyButton(form, true);
      try {
        const res = await KoshaAPI.signup($("#signup-username").value.trim(), password, (m) => status(m, true));
        await showRecoveryPhrase(res.recoveryPhrase);
        await enterApp(res);
      } catch (err) {
        status(err.message);
      } finally {
        busyButton(form, false);
      }
    };

    $("#form-recover").onsubmit = async (e) => {
      e.preventDefault();
      const form = e.target;
      const password = $("#recover-password").value;
      if (password.length < 10) return status("Use at least 10 characters for the new password.");
      busyButton(form, true);
      try {
        const res = await KoshaAPI.recover(
          $("#recover-username").value.trim(),
          $("#recover-phrase").value,
          password,
          (m) => status(m, true)
        );
        await enterApp(res);
      } catch (err) {
        status(err.message);
      } finally {
        busyButton(form, false);
      }
    };
  }

  // -------------------------------------------------------------------
  // Entering the app
  // -------------------------------------------------------------------

  async function enterApp(session) {
    status("Opening your vault…", true);
    try {
      await KoshaVault.open(session.masterKey, (m) => status(m, true));
    } catch (err) {
      status(err.message);
      await KoshaAPI.logout();
      return;
    }

    $("#login-screen").hidden = true;
    $("#app-screen").hidden = false;
    $("#who").textContent = session.username;
    $("#mode-pill").hidden = false;

    KoshaVault.on(onVaultEvent);
    $("#save-state").textContent = `Encrypted · v${KoshaVault.version}`;
    bindShell();
    refresh();

    // A blunt but genuinely useful guard: the vault holds decrypted
    // data in memory, and the browser will happily discard an unsaved
    // change if the tab closes. This at least asks.
    window.addEventListener("beforeunload", (e) => {
      if (KoshaVault.isDirty) {
        e.preventDefault();
        e.returnValue = "";
      }
    });
  }

  function onVaultEvent(event, detail) {
    const node = $("#save-state");
    if (event === "dirty") {
      node.className = "dirty";
      node.textContent = "Unsaved";
    } else if (event === "saving") {
      node.className = "saving";
      node.textContent = "Encrypting…";
    } else if (event === "saved") {
      node.className = "saved";
      node.textContent = `Saved · v${detail.version}`;
      setTimeout(() => {
        if (!KoshaVault.isDirty && node.textContent.startsWith("Saved")) {
          node.className = "";
          node.textContent = `Encrypted · v${detail.version}`;
        }
      }, 2500);
    } else if (event === "save-failed") {
      node.className = "error";
      node.textContent = "Not saved";
      UI.fail(
        detail.error.message +
          (detail.error.status === 409 ? " Reload this page to pick up the other version before making more changes." : ""),
        "Could not save your vault"
      );
    }
  }

  function bindShell() {
    for (const btn of UI.$$("#tabs button")) {
      btn.onclick = () => {
        view = btn.dataset.view;
        refresh();
      };
    }
    $("#btn-new-folder").onclick = async () => {
      const result = await ViewFiles.folderDialog({ parentId: null });
      if (result?.created) ViewFiles.setFolder(result.created);
      refresh();
    };
    $("#btn-logout").onclick = signOut;
  }

  async function signOut() {
    if (KoshaVault.isDirty) {
      const wait = await UI.confirm({
        title: "You have unsaved changes",
        message: "Save them before signing out?",
        confirmLabel: "Save and sign out",
        kind: "caution",
      });
      if (wait) await UI.withBusy("Saving…", () => KoshaVault.save({ immediate: true }));
    }
    KoshaVault.close();
    await KoshaAPI.logout();
    // A reload is the simplest way to guarantee no decrypted bytes are
    // left reachable in this page's memory. Clearing variables by hand
    // would leave copies in the engine's WASM heap.
    location.reload();
  }

  // -------------------------------------------------------------------
  // Rendering
  // -------------------------------------------------------------------

  function refresh() {
    if (!KoshaVault.isOpen) return;
    for (const btn of UI.$$("#tabs button")) btn.classList.toggle("active", btn.dataset.view === view);
    refreshSidebar();
    const content = $("#content");
    if (view === "files") ViewFiles.render(content);
    else if (view === "tables") ViewData.renderTables(content);
    else if (view === "query") ViewData.renderQuery(content);
    else renderSettings(content);
  }

  function refreshSidebar() {
    if (!KoshaVault.isOpen) return;
    const tree = KoshaVault.listFolders();
    const host = UI.clear($("#folder-tree"));
    const selected = ViewFiles.getFolderId();

    const renderNode = (node, depth) => {
      const fmt = KoshaConvert.FORMATS[node.filetype] || KoshaConvert.FORMATS.any;
      const item = el(
        "div",
        {
          class: `tree-item${node.id === selected && view === "files" ? " selected" : ""}`,
          style: { paddingLeft: `${8 + depth * 14}px` },
          title: `${KoshaVault.folderPath(node.id)} — holds ${fmt.label}`,
          onclick: () => {
            ViewFiles.setFolder(node.id);
            view = "files";
            refresh();
          },
        },
        [
          el("span", { class: "tree-twisty", text: node.children.length ? "▾" : "·" }),
          el("span", { class: "tree-name", text: node.name }),
          el("span", { class: "tree-count", text: String(node.file_count) }),
        ]
      );
      // Dropping a file straight onto a folder in the tree is the
      // shortest path from "I have this file" to "it is filed".
      item.addEventListener("dragover", (e) => {
        e.preventDefault();
        item.classList.add("drop-target");
      });
      item.addEventListener("dragleave", () => item.classList.remove("drop-target"));
      item.addEventListener("drop", (e) => {
        e.preventDefault();
        item.classList.remove("drop-target");
        const files = Array.from(e.dataTransfer.files);
        if (files.length) ViewFiles.addFilesDialog(node.id, files);
      });
      host.appendChild(item);
      for (const child of node.children) renderNode(child, depth + 1);
    };

    for (const root of tree.roots) renderNode(root, 0);

    const s = KoshaVault.stats();
    UI.clear($("#sidebar-stats")).appendChild(
      el("div", {}, [
        el("div", { text: `${UI.count(s.files)} files · ${UI.bytes(s.fileBytes)}` }),
        el("div", { text: `${UI.count(s.tables)} tables · ${UI.count(s.rows)} rows` }),
      ])
    );
  }

  function openTable(name) {
    ViewData.openTable(name);
    view = "tables";
    refresh();
  }

  function openQuery(sql) {
    ViewData.setQuery(sql);
    view = "query";
    refresh();
  }

  // -------------------------------------------------------------------
  // Settings
  // -------------------------------------------------------------------

  function renderSettings(container) {
    UI.clear(container);
    const panel = el("div", { class: "panel" });
    const s = KoshaVault.stats();

    panel.appendChild(
      el("div", { class: "panel-head" }, [
        el("h2", { text: "Settings" }),
        el("p", { class: "blurb", text: "Your account, your keys, and an honest account of what this server can and cannot see." }),
      ])
    );

    const usageNode = el("div", { class: "card" }, [el("h3", { text: "Storage" }), el("p", { class: "muted small", text: "Loading…" })]);
    KoshaAPI.usage()
      .then((u) => {
        UI.clear(usageNode);
        usageNode.appendChild(el("h3", { text: "Storage" }));
        usageNode.appendChild(
          el("dl", { class: "facts" }, [
            fact("Files stored", `${UI.count(u.blob_count)} · ${UI.bytes(u.blob_bytes)}`),
            fact("Vault database", UI.bytes(u.vault_bytes)),
            fact("Quota", UI.bytes(u.quota_bytes)),
            fact("Vault version", `v${u.vault_version}`),
            fact("Last saved", UI.when(u.vault_updated_at)),
            fact("Account created", UI.when(u.created_at)),
          ])
        );
        usageNode.appendChild(
          el("button", {
            class: "tiny",
            style: { marginTop: "12px" },
            text: "Clean up unreferenced files",
            title: "Deletes encrypted blobs on the server that nothing in your vault points at any more.",
            onclick: async () => {
              const res = await UI.withBusy("Cleaning up…", () => KoshaVault.collectGarbage());
              UI.ok(res.removed ? `Removed ${res.removed} unreferenced file(s).` : "Nothing to clean up.", "Done");
              refresh();
            },
          })
        );
      })
      .catch((e) => {
        UI.clear(usageNode);
        usageNode.appendChild(el("h3", { text: "Storage" }));
        usageNode.appendChild(el("p", { class: "note caution", text: e.message }));
      });

    const fingerprintNode = el("div", { class: "card" }, [el("h3", { text: "Vault fingerprint" })]);
    KoshaCrypto.vaultFingerprint(KoshaVault.masterKey).then((fp) => {
      fingerprintNode.appendChild(el("div", { class: "phrase-box", text: fp }));
      fingerprintNode.appendChild(
        el("p", {
          class: "muted small",
          style: { marginTop: "10px" },
          text:
            "A short summary of the key your vault is encrypted with. It never changes, even when you change your password. " +
            "If it ever looks different from what you remember, something about your account changed that you did not do.",
        })
      );
    });

    panel.appendChild(
      el("div", { class: "split" }, [
        el("div", {}, [
          KoshaAPI.isLocal
            ? el("div", { class: "card" }, [
                el("h3", { text: "Where your data is" }),
                el("dl", { class: "facts" }, [
                  fact("Stored in", "This browser, on this device"),
                  fact("Sent to a server", no("There is no server")),
                  fact("Readable by anyone else", no("Encrypted with your password")),
                  fact("Synced to your other devices", yes("Not synced — export to move it")),
                  fact("Survives clearing site data", yes("No — the export file is the only backup")),
                ]),
                el("p", {
                  class: "note",
                  style: { marginTop: "12px" },
                  text:
                    "This copy has no server to trust, which removes the biggest caveat the hosted version has to make. " +
                    "What it adds instead is that the only copy of your vault is the one in this browser. Browsers do " +
                    "evict storage — Safari after seven days without a visit, any browser under disk pressure — so the " +
                    "export above is not optional if the data matters.",
                }),
              ])
            : el("div", { class: "card" }, [
            el("h3", { text: "What this server can see" }),
            el("dl", { class: "facts" }, [
              fact("Your files' contents", no("Encrypted here, before upload")),
              fact("Your filenames and folders", no("Inside the encrypted vault")),
              fact("Your table and column names", no("Inside the encrypted vault")),
              fact("Your password", no("Never sent — only a one-way proof")),
              fact("Your username", yes("Needed to find your account")),
              fact("How many files you have, and how big", yes("File sizes are visible")),
              fact("When you last saved", yes("A timestamp per save")),
            ]),
            el("p", {
              class: "note",
              style: { marginTop: "12px" },
              text:
                "The honest caveat: this page's code is delivered by the same server on every load. Zero-knowledge storage " +
                "protects your data at rest and in transit; it cannot protect you from a server that serves you altered " +
                "code before you type your password. That risk is real for every browser-delivered encryption tool, " +
                "including this one.",
            }),
          ]),

          el("div", { class: "card" }, [
            el("h3", { text: "Your vault, as data" }),
            el("dl", { class: "facts" }, [
              fact("Folders", UI.count(s.folders)),
              fact("Files", UI.count(s.files)),
              fact("SQL tables", UI.count(s.tables)),
              fact("Rows across all tables", UI.count(s.rows)),
              fact("Vault database size", UI.bytes(s.vaultBytes)),
            ]),
            el("div", { class: "row", style: { marginTop: "12px", flexWrap: "wrap" } }, [
              el("button", {
                class: "tiny",
                text: "Download the vault as a SQLite file",
                title: "Decrypted, so you can open it in any SQLite tool. Treat the downloaded file as sensitive.",
                onclick: () => {
                  UI.download("kosha-vault.sqlite", KoshaVault.db.serialize(), "application/vnd.sqlite3");
                  UI.warn("That file is decrypted. Anyone who gets it can read everything in it.", "Downloaded");
                },
              }),
              el("button", {
                class: "tiny",
                text: "Save now",
                onclick: async () => {
                  await UI.withBusy("Encrypting and uploading…", () => KoshaVault.save({ immediate: true }));
                  UI.ok("Vault saved.");
                },
              }),
            ]),
          ]),
        ]),

        el("div", {}, [
          usageNode,
          fingerprintNode,

          el("div", { class: "card" }, [
            el("h3", { text: "Move or back up this vault" }),
            KoshaAPI.isLocal
              ? el("p", {
                  class: "note caution",
                  text:
                    "This vault lives in this browser and nowhere else. If you clear your site data, " +
                    "lose this device, or want it on your phone, an export file is the only way across.",
                })
              : el("p", {
                  class: "note",
                  text:
                    "Export a copy you can import into the browser-only version — which is how you reach this data " +
                    "when the machine hosting Kosha is switched off.",
                }),
            el("div", { class: "stack", style: { marginTop: "12px" } }, [
              el("button", { text: "Export encrypted vault file", onclick: exportVaultFile }),
              el("button", { text: "Import a vault file…", onclick: () => $("#import-file").click() }),
            ]),
            el("p", {
              class: "muted small",
              style: { marginTop: "10px" },
              text:
                "The file contains only already-encrypted bytes — it is exactly as safe as the password that opens it, " +
                "and no safer. Keep it somewhere you would keep a password manager backup.",
            }),
          ]),

          el("div", { class: "card" }, [
            el("h3", { text: "Account" }),
            el("div", { class: "stack" }, [
              el("button", { text: "Change password", onclick: changePasswordDialog }),
              el("button", { text: "New recovery phrase", onclick: rotateRecoveryDialog }),
              el("button", { class: "danger", text: "Delete everything", onclick: deleteAccountDialog }),
            ]),
          ]),
        ]),
      ])
    );

    container.appendChild(panel);
  }

  const fact = (label, value) =>
    el("div", {}, [el("dt", { text: label }), value instanceof Node ? el("dd", {}, [value]) : el("dd", { text: value })]);
  const yes = (text) => el("span", {}, [el("span", { class: "pill caution", text: "Visible" }), el("span", { class: "faint small", text: ` ${text}` })]);
  const no = (text) => el("span", {}, [el("span", { class: "pill positive", text: "Hidden" }), el("span", { class: "faint small", text: ` ${text}` })]);

  async function exportVaultFile() {
    // Save first: an export of a vault with unsaved changes would be a
    // backup of yesterday, which is the worst kind of backup.
    if (KoshaVault.isDirty) await UI.withBusy("Saving first…", () => KoshaVault.save({ immediate: true }));
    const bundle = await UI.withBusy("Collecting encrypted data…", () => KoshaAPI.exportVault());
    const stamp = new Date().toISOString().slice(0, 10);
    UI.download(`kosha-${KoshaAPI.session.username}-${stamp}.kosha.json`, JSON.stringify(bundle), "application/json");
    UI.ok(
      `Exported ${bundle.blobs.length} file(s) and your vault database, all still encrypted.`,
      "Saved to your downloads"
    );
  }

  async function changePasswordDialog() {
    let current = "";
    let next = "";
    let again = "";
    const done = await UI.modal({
      title: "Change password",
      subtitle:
        "Your vault is not re-encrypted — only the small wrapper around its key is replaced. That is why this is instant no matter how much you have stored.",
      build: () =>
        el("div", {}, [
          UI.field("Current password", el("input", { type: "password", autocomplete: "current-password", oninput: (e) => (current = e.target.value) })),
          UI.field("New password", el("input", { type: "password", autocomplete: "new-password", oninput: (e) => (next = e.target.value) })),
          UI.field("New password again", el("input", { type: "password", autocomplete: "new-password", oninput: (e) => (again = e.target.value) })),
          el("p", { class: "note caution", text: "Every other signed-in session is ended by this change." }),
        ]),
      actions: [
        {
          label: "Change password",
          kind: "primary",
          onClick: async (setError) => {
            if (next.length < 10) {
              setError("Use at least 10 characters.");
              return false;
            }
            if (next !== again) {
              setError("The two new passwords do not match.");
              return false;
            }
            await KoshaAPI.changePassword(current, next);
            return true;
          },
        },
      ],
    });
    if (done) UI.ok("Password changed. Your recovery phrase still works.", "Done");
  }

  async function rotateRecoveryDialog() {
    let password = "";
    const phrase = await UI.modal({
      title: "New recovery phrase",
      subtitle: "Generates a fresh twelve-word phrase and retires the old one immediately.",
      build: () =>
        el("div", {}, [
          UI.field("Your password", el("input", { type: "password", autocomplete: "current-password", oninput: (e) => (password = e.target.value) })),
          el("p", { class: "note caution", text: "Your current recovery phrase stops working the moment the new one is created." }),
        ]),
      actions: [{ label: "Generate", kind: "primary", onClick: () => KoshaAPI.rotateRecoveryPhrase(password) }],
    });
    if (typeof phrase === "string") await showRecoveryPhrase(phrase, { rotated: true });
  }

  async function deleteAccountDialog() {
    const username = KoshaAPI.session.username;
    const confirmed = await UI.confirm({
      title: "Delete everything?",
      message:
        "Your account, your vault and every encrypted file are permanently removed from the server. " +
        "Because nobody else holds your key, there is no backup anywhere and nothing to restore from. This cannot be undone.",
      confirmLabel: "Delete my account",
      requireText: username,
    });
    if (!confirmed) return;
    await UI.withBusy("Deleting…", () => KoshaAPI.deleteAccount());
    KoshaVault.close();
    location.reload();
  }

  // -------------------------------------------------------------------

  /**
   * Say which deployment this is, on the login screen, before anyone
   * types anything.
   *
   * The two modes differ in a way the user genuinely needs to know up
   * front — one syncs across devices and needs a machine awake, the
   * other lives in this browser and does not sync. Discovering that
   * after putting a year of data in would be a bad surprise, so it is
   * stated at the door.
   */
  async function announceMode() {
    const mode = await KoshaAPI.detectMode();
    const kicker = $("#login-screen .masthead .kicker");
    const banner = $("#mode-banner");

    if (mode === "local") {
      kicker.textContent = "Encrypted Store · This Device";
      banner.className = "note accent";
      banner.innerHTML = "";
      banner.append(
        el("strong", { text: "This copy stores your vault in this browser. " }),
        document.createTextNode(
          "It works with every machine you own switched off, and nothing ever leaves this device — but it does not sync, " +
            "and clearing your browser's site data erases it. Export a backup from Settings once you have anything worth keeping."
        )
      );
      banner.hidden = false;

      const vaults = await KoshaAPI.listLocalVaults();
      if (vaults.length) {
        $("#signin-username").value = vaults[0];
        $("#signin-password").focus();
      }
      // A fresh browser has nothing to sign in to, so lead with the
      // two things that can actually work here.
      $("#tab-signup").classList.add("suggest");
      $("#import-row").hidden = false;
    } else {
      kicker.textContent = "Encrypted Store · Zero Knowledge";
      banner.hidden = true;
      $("#import-row").hidden = true;
    }
    // The two deployments make different promises. Printing the wrong
    // one would be a false claim about privacy, so this is filled in
    // only once the deployment is known.
    UI.clear($("#login-foot")).append(
      ...(mode === "local"
        ? [
            document.createTextNode("Everything is encrypted and stored in this browser."),
            el("br"),
            document.createTextNode("There is no server, and nothing leaves this device."),
          ]
        : [
            document.createTextNode("Everything is encrypted in this browser before it is sent."),
            el("br"),
            document.createTextNode("The server stores bytes it has no way to read."),
          ])
    );
    $("#mode-pill").textContent = mode === "local" ? "this device" : "synced";
    $("#mode-pill").title =
      mode === "local"
        ? "Your vault is stored in this browser. It does not sync between devices."
        : "Your vault is stored on the Kosha server and syncs to every device you sign in from.";
  }

  async function importVaultFile(file) {
    let bundle;
    try {
      bundle = JSON.parse(await file.text());
    } catch {
      UI.fail("That file could not be read as a Kosha vault export.");
      return;
    }
    try {
      const existing = await KoshaAPI.listLocalVaults();
      const clash = existing.some((n) => n.toLowerCase() === String(bundle?.account?.username || "").toLowerCase());
      if (clash) {
        const overwrite = await UI.confirm({
          title: `Replace the vault called "${bundle.account.username}"?`,
          message:
            "There is already a vault with that name in this browser. Importing will replace it entirely, " +
            "including any changes made here that are not in the file. This cannot be undone.",
          confirmLabel: "Replace it",
        });
        if (!overwrite) return;
        await KoshaAPI.importVault(bundle, { overwrite: true });
      } else {
        await KoshaAPI.importVault(bundle);
      }
      UI.ok(
        `Vault "${bundle.account.username}" imported. Sign in with the password it had when it was exported.`,
        "Imported"
      );
      $("#signin-username").value = bundle.account.username;
      setLoginTab("signin");
      $("#signin-password").focus();
    } catch (e) {
      UI.fail(e.message, "Could not import that vault");
    }
  }

  function start() {
    bindLogin();
    // A browser with no WebCrypto cannot do any of this safely, and
    // failing at the first decrypt with a confusing error would be
    // much worse than saying so up front.
    if (!window.crypto?.subtle) {
      status("This browser does not provide WebCrypto, which Kosha needs. A secure (https) connection is usually what is missing.");
      UI.$$(".login-panel button").forEach((b) => (b.disabled = true));
      return;
    }
    $("#import-file").onchange = (e) => {
      const file = e.target.files[0];
      e.target.value = "";
      if (file) importVaultFile(file);
    };
    $("#import-btn").onclick = () => $("#import-file").click();
    announceMode();
    $("#signin-username").focus();
  }

  return { start, refresh, refreshSidebar, openTable, openQuery, signOut };
})();

document.addEventListener("DOMContentLoaded", App.start);
