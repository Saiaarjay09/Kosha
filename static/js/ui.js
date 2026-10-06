/**
 * The small toolkit the views are built from: element construction,
 * modals, toasts, the data grid, and the handful of formatters that
 * would otherwise be re-written slightly differently in four places.
 *
 * No framework. The whole interface is a few hundred lines of DOM
 * calls, which for an app this size is less code than the framework's
 * own setup would be — and it means the page has no build step, so
 * what is in the repository is exactly what runs in the browser. For
 * a tool whose security story depends on the client code being
 * auditable, that is worth more than the convenience.
 */

const UI = (() => {
  "use strict";

  /**
   * Build an element. Text is assigned via textContent, never
   * innerHTML — so a filename like `<img onerror=...>` is rendered as
   * those characters rather than parsed as markup. In an app that
   * displays names, column headings and cell values that came from
   * files, that is the whole of the XSS defence and it has to be
   * unconditional.
   */
  function el(tag, props = {}, children = []) {
    const node = document.createElement(tag);
    for (const [k, v] of Object.entries(props)) {
      if (v === null || v === undefined || v === false) continue;
      if (k === "class") node.className = v;
      else if (k === "text") node.textContent = v;
      else if (k === "html") node.innerHTML = v; // only ever called with literals in this file
      else if (k === "dataset") Object.assign(node.dataset, v);
      else if (k === "style") Object.assign(node.style, v);
      else if (k.startsWith("on") && typeof v === "function") node.addEventListener(k.slice(2).toLowerCase(), v);
      else if (k === "value") node.value = v;
      else if (k === "checked" || k === "disabled" || k === "hidden" || k === "selected") node[k] = !!v;
      else node.setAttribute(k, v);
    }
    for (const child of [].concat(children)) {
      if (child === null || child === undefined || child === false) continue;
      node.appendChild(typeof child === "string" ? document.createTextNode(child) : child);
    }
    return node;
  }

  const $ = (sel, root = document) => root.querySelector(sel);
  const $$ = (sel, root = document) => Array.from(root.querySelectorAll(sel));

  function clear(node) {
    while (node.firstChild) node.removeChild(node.firstChild);
    return node;
  }

  // -------------------------------------------------------------------
  // Formatting
  // -------------------------------------------------------------------

  function bytes(n) {
    if (n === null || n === undefined) return "—";
    if (n < 1024) return `${n} B`;
    const units = ["KB", "MB", "GB", "TB"];
    let v = n / 1024;
    let i = 0;
    while (v >= 1024 && i < units.length - 1) {
      v /= 1024;
      i++;
    }
    return `${v < 10 ? v.toFixed(1) : Math.round(v)} ${units[i]}`;
  }

  function count(n) {
    return n === null || n === undefined ? "—" : n.toLocaleString();
  }

  function when(timestamp) {
    if (!timestamp) return "—";
    const d = new Date(timestamp * 1000);
    const diff = (Date.now() - d.getTime()) / 1000;
    if (diff < 60) return "just now";
    if (diff < 3600) return `${Math.floor(diff / 60)} min ago`;
    if (diff < 86400) return `${Math.floor(diff / 3600)} h ago`;
    if (diff < 86400 * 7) return `${Math.floor(diff / 86400)} d ago`;
    return d.toLocaleDateString(undefined, { year: "numeric", month: "short", day: "numeric" });
  }

  function duration(ms) {
    return ms < 1 ? "<1 ms" : ms < 1000 ? `${Math.round(ms)} ms` : `${(ms / 1000).toFixed(2)} s`;
  }

  // -------------------------------------------------------------------
  // Toasts
  // -------------------------------------------------------------------

  function toast(message, { title = "", kind = "", timeout = 5000 } = {}) {
    const node = el("div", { class: `toast ${kind}` }, [
      title ? el("strong", { class: "toast-title", text: title }) : null,
      el("span", { text: message }),
    ]);
    $("#toasts").appendChild(node);
    const remove = () => node.remove();
    // A long message needs longer to read; an error stays until it is
    // clicked, because an error that vanishes before it is read is the
    // same as no error at all.
    if (timeout && kind !== "danger") setTimeout(remove, Math.max(timeout, message.length * 45));
    node.addEventListener("click", remove);
    return remove;
  }

  const ok = (m, t) => toast(m, { title: t, kind: "positive" });
  const warn = (m, t) => toast(m, { title: t, kind: "caution" });
  const fail = (m, t = "Something went wrong") => toast(m, { title: t, kind: "danger", timeout: 0 });

  // -------------------------------------------------------------------
  // Busy overlay
  // -------------------------------------------------------------------

  let busyDepth = 0;
  function busy(text) {
    busyDepth++;
    $("#busy-text").textContent = text || "Working";
    $("#busy").hidden = false;
    let released = false;
    return {
      update(t) {
        $("#busy-text").textContent = t;
      },
      done() {
        if (released) return;
        released = true;
        busyDepth = Math.max(0, busyDepth - 1);
        if (busyDepth === 0) $("#busy").hidden = true;
      },
    };
  }

  /** Run an async job behind the overlay, releasing it even on failure. */
  async function withBusy(text, fn) {
    const b = busy(text);
    try {
      return await fn(b.update);
    } finally {
      b.done();
    }
  }

  // -------------------------------------------------------------------
  // Modals
  // -------------------------------------------------------------------

  /**
   * Open a modal. `build(close, setError)` returns the body; actions
   * are buttons along the bottom. Resolves with whatever an action's
   * handler returns, or null if dismissed.
   */
  function modal({ title, subtitle = "", build, actions = [], wide = false, dismissable = true }) {
    return new Promise((resolve) => {
      let settled = false;
      const finish = (value) => {
        if (settled) return;
        settled = true;
        document.removeEventListener("keydown", onKey);
        backdrop.remove();
        resolve(value);
      };

      const errorNode = el("div", { class: "modal-error" });
      const setError = (msg) => {
        errorNode.textContent = msg || "";
      };

      const body = build(finish, setError);

      const actionNodes = actions.map((a) =>
        el("button", {
          class: a.kind || "",
          text: a.label,
          onclick: async (e) => {
            const btn = e.currentTarget;
            setError("");
            if (!a.onClick) return finish(a.value ?? true);
            btn.classList.add("loading");
            btn.appendChild(el("span", { class: "spinner" }));
            try {
              const result = await a.onClick(setError);
              if (result !== false) finish(result);
            } catch (err) {
              setError(err.message || String(err));
            } finally {
              btn.classList.remove("loading");
              btn.querySelector(".spinner")?.remove();
            }
          },
        })
      );

      const dialog = el("div", { class: `modal${wide ? " wide" : ""}`, role: "dialog", "aria-modal": "true" }, [
        el("h2", { text: title }),
        subtitle ? el("p", { class: "modal-sub", text: subtitle }) : null,
        body,
        errorNode,
        el("div", { class: "modal-actions" }, [
          dismissable ? el("button", { class: "ghost", text: "Cancel", onclick: () => finish(null) }) : null,
          ...actionNodes,
        ]),
      ]);

      const backdrop = el(
        "div",
        {
          class: "modal-backdrop",
          onclick: (e) => {
            if (e.target === backdrop && dismissable) finish(null);
          },
        },
        [dialog]
      );

      const onKey = (e) => {
        if (e.key === "Escape" && dismissable) finish(null);
      };
      document.addEventListener("keydown", onKey);
      document.body.appendChild(backdrop);
      // Focus the first field so the keyboard works straight away.
      (dialog.querySelector("input, textarea, select") || actionNodes[actionNodes.length - 1])?.focus();
    });
  }

  function confirm({ title, message, confirmLabel = "Confirm", kind = "danger", requireText = null }) {
    return modal({
      title,
      build: (finish, setError) => {
        const input = requireText
          ? el("input", {
              type: "text",
              placeholder: requireText,
              autocapitalize: "none",
              spellcheck: "false",
              oninput: () => setError(""),
            })
          : null;
        return el("div", { class: "stack" }, [
          el("p", { class: "note " + (kind === "danger" ? "danger" : "caution"), text: message }),
          requireText
            ? el("label", { class: "field" }, [
                el("span", { class: "label-text", text: `Type "${requireText}" to confirm` }),
                input,
              ])
            : null,
        ]);
      },
      actions: [
        {
          label: confirmLabel,
          kind: kind === "danger" ? "danger" : "primary",
          onClick: (setError) => {
            if (requireText) {
              const typed = $(".modal input")?.value?.trim();
              if (typed !== requireText) {
                setError(`Type "${requireText}" exactly to confirm.`);
                return false;
              }
            }
            return true;
          },
        },
      ],
    });
  }

  // -------------------------------------------------------------------
  // The data grid
  // -------------------------------------------------------------------

  /**
   * Render a table of rows.
   *
   * `columns` may be plain names (for query results) or objects with a
   * `render` function (for the file list). Cells are produced with
   * textContent throughout; a `render` that wants markup must build
   * and return a node, not a string of HTML.
   */
  function grid({ columns, rows, onRowClick = null, selectedIndex = null, emptyMessage = "Nothing here yet.", sort = null, onSort = null }) {
    const cols = columns.map((c) => (typeof c === "string" ? { key: c, label: c } : c));

    if (!rows.length) {
      return el("div", { class: "empty" }, [el("p", { text: emptyMessage })]);
    }

    const head = el(
      "tr",
      {},
      cols.map((c) =>
        el(
          "th",
          {
            class: [c.mono ? "mono" : "", onSort && c.sortable !== false ? "sortable" : ""].filter(Boolean).join(" "),
            onclick: onSort && c.sortable !== false ? () => onSort(c.key) : null,
          },
          [
            document.createTextNode(c.label),
            sort && sort.key === c.key ? el("span", { class: "sort-mark", text: sort.desc ? "▾" : "▴" }) : null,
          ]
        )
      )
    );

    const body = el(
      "tbody",
      {},
      rows.map((row, i) =>
        el(
          "tr",
          {
            class: [onRowClick ? "clickable" : "", selectedIndex === i ? "selected" : ""].filter(Boolean).join(" "),
            onclick: onRowClick ? () => onRowClick(row, i) : null,
          },
          cols.map((c) => {
            if (c.render) {
              const out = c.render(row, i);
              return el("td", { class: c.cellClass || "" }, [out instanceof Node ? out : document.createTextNode(String(out ?? ""))]);
            }
            const value = Array.isArray(row) ? row[cols.indexOf(c)] : row[c.key];
            if (value === null || value === undefined) {
              return el("td", { class: "null", text: "null" });
            }
            const isNum = typeof value === "number";
            return el("td", {
              class: [isNum ? "num" : "", c.mono ? "mono" : ""].filter(Boolean).join(" "),
              text: value instanceof Uint8Array ? `«${value.length} bytes»` : String(value),
              title: String(value).length > 60 ? String(value) : null,
            });
          })
        )
      )
    );

    return el("div", { class: "grid-wrap" }, [el("table", { class: "grid" }, [el("thead", {}, [head]), body])]);
  }

  // -------------------------------------------------------------------
  // Misc
  // -------------------------------------------------------------------

  /** Hand the user a file. Used for exports and downloads. */
  function download(filename, bytesOrText, mime = "application/octet-stream") {
    const blob = bytesOrText instanceof Uint8Array ? new Blob([bytesOrText], { type: mime }) : new Blob([bytesOrText], { type: mime });
    const url = URL.createObjectURL(blob);
    const a = el("a", { href: url, download: filename });
    document.body.appendChild(a);
    a.click();
    a.remove();
    // Revoking immediately races the download in Safari; a tick is enough.
    setTimeout(() => URL.revokeObjectURL(url), 2000);
  }

  async function copyToClipboard(text) {
    try {
      await navigator.clipboard.writeText(text);
      return true;
    } catch {
      // Clipboard access is refused on insecure origins and in some
      // embedded views. Falling back to a selection the user can copy
      // by hand beats a silent no-op.
      return false;
    }
  }

  function field(labelText, control, hint) {
    return el("label", { class: "field" }, [
      el("span", { class: "label-text", text: labelText }),
      control,
      hint ? el("span", { class: "hint", text: hint }) : null,
    ]);
  }

  function select(options, value, onChange) {
    return el(
      "select",
      { onchange: (e) => onChange(e.target.value) },
      options.map(([v, label]) => el("option", { value: v, selected: String(v) === String(value), text: label }))
    );
  }

  function checkboxField(labelText, checked, onChange, hint) {
    return el("label", { class: "inline" }, [
      el("input", { type: "checkbox", checked, onchange: (e) => onChange(e.target.checked) }),
      el("span", {}, [el("span", { text: labelText }), hint ? el("span", { class: "hint", text: hint }) : null]),
    ]);
  }

  return {
    el, $, $$, clear,
    bytes, count, when, duration,
    toast, ok, warn, fail,
    busy, withBusy,
    modal, confirm,
    grid,
    download, copyToClipboard,
    field, select, checkboxField,
  };
})();
