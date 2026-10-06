/**
 * Format detection and conversion.
 *
 * Kosha folders are *typed*: a folder declares one format, and
 * anything dropped into it is converted to that format on the way in.
 * This file is what makes that promise keepable.
 *
 * The design is a hub, not a mesh. Nothing converts directly from CSV
 * to XLSX; everything reads into one of three neutral shapes and
 * writes back out of it:
 *
 *      csv  tsv  json  xlsx  xml  …        ->  Dataset {columns, rows}
 *      txt  md   html  sql   log  …        ->  TextDoc {text}
 *      png  jpg  webp  gif   bmp           ->  Image   {bitmap}
 *
 * With n formats, a mesh needs n² converters and n² chances to get one
 * wrong; a hub needs 2n, and adding a format means writing one reader
 * and one writer. The cost of the hub is that a conversion can lose
 * what the neutral shape has no room for — a spreadsheet's formulas
 * and cell colours do not survive a trip through Dataset, because
 * Dataset is columns and rows and nothing else. Kosha says so out
 * loud at conversion time rather than letting you find out later.
 *
 * Everything here runs in the browser on plaintext, before encryption.
 * No file is ever sent anywhere to be converted.
 */

const KoshaConvert = (() => {
  "use strict";

  // -------------------------------------------------------------------
  // The format registry
  // -------------------------------------------------------------------

  const FORMATS = {
    csv:    { family: "tabular", label: "CSV",            mime: "text/csv", ext: "csv" },
    tsv:    { family: "tabular", label: "TSV",            mime: "text/tab-separated-values", ext: "tsv" },
    json:   { family: "tabular", label: "JSON",           mime: "application/json", ext: "json" },
    ndjson: { family: "tabular", label: "NDJSON",         mime: "application/x-ndjson", ext: "ndjson" },
    xlsx:   { family: "tabular", label: "Excel",          mime: "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", ext: "xlsx" },
    xml:    { family: "tabular", label: "XML",            mime: "application/xml", ext: "xml" },
    yaml:   { family: "tabular", label: "YAML",           mime: "application/yaml", ext: "yaml" },
    md:     { family: "tabular", label: "Markdown table", mime: "text/markdown", ext: "md" },
    html:   { family: "tabular", label: "HTML table",     mime: "text/html", ext: "html" },
    sqlite: { family: "tabular", label: "SQLite",         mime: "application/vnd.sqlite3", ext: "sqlite" },

    txt:    { family: "text", label: "Plain text", mime: "text/plain", ext: "txt" },
    sql:    { family: "text", label: "SQL script", mime: "application/sql", ext: "sql" },
    text_md: { family: "text", label: "Markdown (prose)", mime: "text/markdown", ext: "md" },

    png:    { family: "image", label: "PNG",  mime: "image/png",  ext: "png" },
    jpg:    { family: "image", label: "JPEG", mime: "image/jpeg", ext: "jpg" },
    webp:   { family: "image", label: "WebP", mime: "image/webp", ext: "webp" },
    gif:    { family: "image", label: "GIF",  mime: "image/gif",  ext: "gif", readOnly: true },
    bmp:    { family: "image", label: "BMP",  mime: "image/bmp",  ext: "bmp", readOnly: true },

    any:    { family: "any", label: "Any file (no conversion)", mime: "application/octet-stream", ext: "" },
  };

  // What a folder may be set to. `gif`/`bmp` can be read but the
  // browser's canvas cannot re-encode to them, so they are not
  // offerable as a destination — listing a target Kosha cannot
  // actually produce would be a trap.
  function targetFormats() {
    return Object.entries(FORMATS)
      .filter(([, f]) => !f.readOnly)
      .map(([id, f]) => ({ id, ...f }));
  }

  const EXT_ALIASES = {
    csv: "csv", tsv: "tsv", tab: "tsv",
    json: "json", ndjson: "ndjson", jsonl: "ndjson",
    xlsx: "xlsx", xlsm: "xlsx", xls: "xlsx",
    xml: "xml", yaml: "yaml", yml: "yaml",
    md: "md", markdown: "md",
    html: "html", htm: "html",
    sqlite: "sqlite", db: "sqlite", sqlite3: "sqlite",
    txt: "txt", log: "txt", sql: "sql",
    png: "png", jpg: "jpg", jpeg: "jpg", webp: "webp", gif: "gif", bmp: "bmp",
  };

  function extOf(filename) {
    const m = String(filename || "").match(/\.([A-Za-z0-9]+)$/);
    return m ? m[1].toLowerCase() : "";
  }

  function baseName(filename) {
    return String(filename || "file").replace(/\.[^.]+$/, "");
  }

  /**
   * Work out what a file actually is.
   *
   * The extension is a hint, not evidence — a `.csv` that is really a
   * tab-separated export, or a `.txt` holding JSON, are both common
   * enough to be worth catching. So the magic bytes are checked first
   * (those cannot lie), then the content is sniffed, and the extension
   * only decides what the content leaves genuinely ambiguous.
   */
  function detect(filename, bytes) {
    const ext = EXT_ALIASES[extOf(filename)] || "";

    if (bytes && bytes.length >= 4) {
      const b = bytes;
      const starts = (sig) => sig.every((v, i) => b[i] === v);
      if (starts([0x89, 0x50, 0x4e, 0x47])) return "png";
      if (starts([0xff, 0xd8, 0xff])) return "jpg";
      if (starts([0x47, 0x49, 0x46, 0x38])) return "gif";
      if (starts([0x42, 0x4d])) return "bmp";
      if (starts([0x52, 0x49, 0x46, 0x46]) && b[8] === 0x57 && b[9] === 0x45) return "webp";
      // "SQLite format 3\0"
      if (starts([0x53, 0x51, 0x4c, 0x69, 0x74, 0x65])) return "sqlite";
      // A ZIP header. xlsx is a zip; so is docx and much else, so the
      // extension is what disambiguates — but only among zip formats.
      if (starts([0x50, 0x4b, 0x03, 0x04])) return ext === "xlsx" ? "xlsx" : "any";
    }

    if (!bytes) return ext || "any";

    // Binary-ish? A NUL byte in the first kilobyte means this is not
    // text, whatever the extension says.
    const probe = bytes.subarray(0, 1024);
    if (probe.includes(0)) return ext && FORMATS[ext] ? ext : "any";

    let head;
    try {
      head = new TextDecoder("utf-8", { fatal: false }).decode(bytes.subarray(0, 8192)).trim();
    } catch {
      return ext || "any";
    }

    if (head.startsWith("{") || head.startsWith("[")) {
      // One JSON value per line is NDJSON; one value overall is JSON.
      const lines = head.split("\n").filter((l) => l.trim());
      if (lines.length > 1 && lines.slice(0, 3).every((l) => l.trim().startsWith("{") && l.trim().endsWith("}"))) {
        return "ndjson";
      }
      return "json";
    }
    if (head.startsWith("<?xml") || /^<(\w+)[\s>]/.test(head)) {
      return /<table[\s>]/i.test(head) || /^<!doctype html/i.test(head) ? "html" : "xml";
    }
    if (/^\s*\|.*\|\s*$/m.test(head) && /\|\s*-{2,}/.test(head)) return "md";

    if (ext && FORMATS[ext]) {
      // Catch a .csv that is really tab-separated, and vice versa.
      if (ext === "csv" || ext === "tsv") return sniffDelimiter(head) === "\t" ? "tsv" : "csv";
      return ext;
    }

    // No usable extension and it looks like text: if the first lines
    // have a consistent delimiter count, treat it as a table.
    const delim = sniffDelimiter(head);
    if (delim) return delim === "\t" ? "tsv" : "csv";
    return "txt";
  }

  /** Pick the delimiter whose per-line count is most consistent. */
  function sniffDelimiter(text) {
    const lines = text.split(/\r?\n/).filter((l) => l.trim()).slice(0, 10);
    if (lines.length < 2) return null;
    let best = null;
    let bestScore = 0;
    for (const d of [",", "\t", ";", "|"]) {
      const counts = lines.map((l) => (l.match(new RegExp(`\\${d}`, "g")) || []).length);
      if (counts[0] === 0) continue;
      const consistent = counts.every((c) => c === counts[0]);
      const score = consistent ? counts[0] * 10 : counts[0];
      if (score > bestScore) {
        bestScore = score;
        best = d;
      }
    }
    return best;
  }

  function familyOf(format) {
    return (FORMATS[format] || FORMATS.any).family;
  }

  // -------------------------------------------------------------------
  // Delimited text
  // -------------------------------------------------------------------

  /**
   * An RFC 4180 parser, written out rather than regex'd.
   *
   * `line.split(",")` is the classic wrong answer: it breaks on the
   * very first quoted field containing a comma, which in real
   * spreadsheet exports is approximately always. This walks the text
   * character by character and handles quoted fields, doubled quotes
   * inside them, embedded newlines, and both line ending conventions.
   */
  function parseDelimited(text, delimiter = ",") {
    const rows = [];
    let row = [];
    let field = "";
    let inQuotes = false;
    let i = 0;
    // A UTF-8 BOM would otherwise become part of the first column's
    // name, giving the mystifying "no column called id" on a file
    // whose first column is plainly called id.
    if (text.charCodeAt(0) === 0xfeff) i = 1;

    while (i < text.length) {
      const ch = text[i];
      if (inQuotes) {
        if (ch === '"') {
          if (text[i + 1] === '"') {
            field += '"';
            i += 2;
            continue;
          }
          inQuotes = false;
          i++;
          continue;
        }
        field += ch;
        i++;
        continue;
      }
      if (ch === '"' && field === "") {
        inQuotes = true;
        i++;
        continue;
      }
      if (ch === delimiter) {
        row.push(field);
        field = "";
        i++;
        continue;
      }
      if (ch === "\n" || ch === "\r") {
        row.push(field);
        field = "";
        rows.push(row);
        row = [];
        if (ch === "\r" && text[i + 1] === "\n") i++;
        i++;
        continue;
      }
      field += ch;
      i++;
    }
    if (field !== "" || row.length) {
      row.push(field);
      rows.push(row);
    }
    return rows.filter((r) => r.length > 1 || (r[0] !== undefined && r[0] !== ""));
  }

  function writeDelimited(dataset, delimiter = ",") {
    const esc = (v) => {
      if (v === null || v === undefined) return "";
      const s = typeof v === "object" ? JSON.stringify(v) : String(v);
      // Quote only when necessary. A file where every field is quoted
      // is valid but unpleasant to read, and these files are meant to
      // be opened by humans as often as by programs.
      return /["\n\r]|^\s|\s$/.test(s) || s.includes(delimiter) ? `"${s.replace(/"/g, '""')}"` : s;
    };
    const lines = [dataset.columns.map(esc).join(delimiter)];
    for (const row of dataset.rows) lines.push(row.map(esc).join(delimiter));
    return lines.join("\n") + "\n";
  }

  // -------------------------------------------------------------------
  // Dataset <-> record objects
  // -------------------------------------------------------------------

  function rowsToRecords(dataset) {
    return dataset.rows.map((r) => {
      const o = {};
      dataset.columns.forEach((c, i) => (o[c] = r[i] === undefined ? null : r[i]));
      return o;
    });
  }

  /**
   * Records -> Dataset, with the union of all keys as columns.
   *
   * Taking only the first record's keys is the tempting shortcut and
   * it silently drops every field that happens to be absent from
   * record #1 — which, in any JSON export with optional fields, is a
   * lot of data lost without a word. The union costs one pass.
   */
  function recordsToRows(records) {
    const columns = [];
    const seen = new Set();
    for (const rec of records) {
      for (const k of Object.keys(rec || {})) {
        if (!seen.has(k)) {
          seen.add(k);
          columns.push(k);
        }
      }
    }
    const rows = records.map((rec) =>
      columns.map((c) => {
        const v = rec ? rec[c] : null;
        if (v === undefined) return null;
        // A nested object has no cell to live in. JSON in the cell
        // keeps the information (and SQLite's json_extract can still
        // reach into it) rather than discarding it.
        return v !== null && typeof v === "object" ? JSON.stringify(v) : v;
      })
    );
    return { columns, rows };
  }

  // -------------------------------------------------------------------
  // Readers
  // -------------------------------------------------------------------

  const decoder = () => new TextDecoder("utf-8");
  const encoder = () => new TextEncoder();

  async function readDataset(format, bytes, filename) {
    const text = () => decoder().decode(bytes);

    switch (format) {
      case "csv":
        return fromMatrix(parseDelimited(text(), sniffDelimiter(text().slice(0, 8192)) || ","));
      case "tsv":
        return fromMatrix(parseDelimited(text(), "\t"));

      case "json": {
        const data = JSON.parse(text());
        if (Array.isArray(data)) {
          if (!data.length) return { columns: [], rows: [] };
          // An array of scalars is a single-column table, not an error.
          if (typeof data[0] !== "object" || data[0] === null) {
            return { columns: ["value"], rows: data.map((v) => [v]) };
          }
          return recordsToRows(data);
        }
        if (data && typeof data === "object") {
          // A common export shape: {"rows": [...]} or {"data": [...]}.
          for (const key of ["rows", "data", "items", "records", "results"]) {
            if (Array.isArray(data[key])) return recordsToRows(data[key]);
          }
          // Otherwise a single object is one row.
          return recordsToRows([data]);
        }
        return { columns: ["value"], rows: [[data]] };
      }

      case "ndjson": {
        const records = text()
          .split("\n")
          .map((l) => l.trim())
          .filter(Boolean)
          .map((l, i) => {
            try {
              return JSON.parse(l);
            } catch {
              throw new Error(`Line ${i + 1} is not valid JSON.`);
            }
          });
        return recordsToRows(records);
      }

      case "xlsx": {
        requireXLSX();
        const wb = XLSX.read(bytes, { type: "array" });
        const sheetName = wb.SheetNames[0];
        if (!sheetName) throw new Error("That spreadsheet has no sheets.");
        const matrix = XLSX.utils.sheet_to_json(wb.Sheets[sheetName], { header: 1, defval: null, raw: true });
        const ds = fromMatrix(matrix);
        // Only the first sheet is imported. Saying so is better than
        // quietly losing four other sheets a user believed were saved.
        if (wb.SheetNames.length > 1) {
          ds.warnings = [`Only the first sheet ("${sheetName}") was read; ${wb.SheetNames.length - 1} other sheet(s) were skipped.`];
        }
        return ds;
      }

      case "xml": {
        const doc = new DOMParser().parseFromString(text(), "application/xml");
        const err = doc.querySelector("parsererror");
        if (err) throw new Error("That XML could not be parsed.");
        const root = doc.documentElement;
        // Treat the most common repeated child element as the rows.
        const counts = new Map();
        for (const child of root.children) counts.set(child.tagName, (counts.get(child.tagName) || 0) + 1);
        let rowTag = null;
        let best = 0;
        for (const [tag, n] of counts) if (n > best) ((best = n), (rowTag = tag));
        const rowEls = rowTag ? Array.from(root.children).filter((c) => c.tagName === rowTag) : [root];
        const records = rowEls.map((el) => {
          const rec = {};
          for (const attr of el.attributes) rec[attr.name] = attr.value;
          for (const child of el.children) rec[child.tagName] = child.textContent;
          if (!el.children.length && !el.attributes.length) rec.value = el.textContent;
          return rec;
        });
        return recordsToRows(records);
      }

      case "yaml":
        return parseSimpleYaml(text());

      case "md": {
        const lines = text().split(/\r?\n/).filter((l) => l.trim().startsWith("|"));
        if (lines.length < 2) throw new Error("No Markdown table found in that file.");
        const cells = (l) =>
          l.trim().replace(/^\||\|$/g, "").split("|").map((c) => c.trim().replace(/\\\|/g, "|"));
        const header = cells(lines[0]);
        // Line 2 is the |---|---| separator; skip it.
        const body = lines.slice(2).map(cells);
        return { columns: header, rows: body.map((r) => header.map((_, i) => r[i] ?? null)) };
      }

      case "html": {
        const doc = new DOMParser().parseFromString(text(), "text/html");
        const table = doc.querySelector("table");
        if (!table) throw new Error("No <table> found in that HTML.");
        const trs = Array.from(table.querySelectorAll("tr"));
        if (!trs.length) throw new Error("That table has no rows.");
        const headerCells = Array.from(trs[0].querySelectorAll("th,td")).map((c) => c.textContent.trim());
        const body = trs.slice(1).map((tr) => Array.from(tr.querySelectorAll("th,td")).map((c) => c.textContent.trim()));
        return { columns: headerCells, rows: body.map((r) => headerCells.map((_, i) => r[i] ?? null)) };
      }

      case "sqlite": {
        await KoshaEngine.init();
        const db = KoshaEngine.Database.open(bytes);
        try {
          const tables = db.listTables(true).filter((t) => t.type === "table");
          if (!tables.length) throw new Error("That SQLite file has no tables.");
          const ds = db.exportDataset(tables[0].name);
          if (tables.length > 1) {
            ds.warnings = [`Only the first table ("${tables[0].name}") was read; ${tables.length - 1} other table(s) were skipped.`];
          }
          return ds;
        } finally {
          db.close();
        }
      }

      default:
        throw new Error(`Cannot read ${format} as a table.`);
    }
  }

  /** First row as the header, the rest as data; ragged rows padded. */
  function fromMatrix(matrix) {
    if (!matrix.length) return { columns: [], rows: [] };
    const columns = matrix[0].map((c, i) => (String(c ?? "").trim() || `column_${i + 1}`));
    const rows = matrix.slice(1).map((r) => columns.map((_, i) => (r[i] === undefined ? null : r[i])));
    return { columns, rows };
  }

  /**
   * A deliberately small YAML reader: a top-level list of flat
   * mappings, which is the shape data files actually come in. Anchors,
   * multi-line scalars, nesting and tags are not supported, and this
   * says so rather than parsing them wrongly — a YAML parser that is
   * 90% right is worse than one that refuses the other 10% loudly.
   */
  function parseSimpleYaml(text) {
    const lines = text.split(/\r?\n/);
    const records = [];
    let current = null;
    for (const raw of lines) {
      const line = raw.replace(/\s+$/, "");
      if (!line.trim() || line.trim().startsWith("#")) continue;
      const item = line.match(/^(\s*)-\s+(.*)$/);
      if (item) {
        current = {};
        records.push(current);
        const rest = item[2];
        const kv = rest.match(/^([\w .\-]+):\s*(.*)$/);
        if (kv) current[kv[1].trim()] = parseScalar(kv[2]);
        else current.value = parseScalar(rest);
        continue;
      }
      const kv = line.match(/^(\s*)([\w .\-]+):\s*(.*)$/);
      if (kv && current) {
        current[kv[2].trim()] = parseScalar(kv[3]);
        continue;
      }
      if (kv && !current) {
        current = {};
        records.push(current);
        current[kv[2].trim()] = parseScalar(kv[3]);
        continue;
      }
      throw new Error(
        "Kosha reads a simple subset of YAML: a list of flat key/value records. " +
          `This line is outside that subset:\n  ${line.trim()}`
      );
    }
    if (!records.length) throw new Error("No records found in that YAML file.");
    return recordsToRows(records);
  }

  function parseScalar(s) {
    const t = String(s).trim().replace(/^["']|["']$/g, "");
    if (t === "" || t === "null" || t === "~") return null;
    if (t === "true") return true;
    if (t === "false") return false;
    if (/^-?\d+$/.test(t)) return parseInt(t, 10);
    if (/^-?\d*\.\d+$/.test(t)) return parseFloat(t);
    return t;
  }

  function requireXLSX() {
    if (typeof XLSX === "undefined") {
      throw new Error("The spreadsheet library did not load, so Excel files are unavailable right now.");
    }
  }

  // -------------------------------------------------------------------
  // Writers
  // -------------------------------------------------------------------

  async function writeDataset(format, dataset, { name = "data" } = {}) {
    const enc = encoder();
    switch (format) {
      case "csv":
        return enc.encode(writeDelimited(dataset, ","));
      case "tsv":
        return enc.encode(writeDelimited(dataset, "\t"));
      case "json":
        return enc.encode(JSON.stringify(rowsToRecords(dataset), null, 2) + "\n");
      case "ndjson":
        return enc.encode(rowsToRecords(dataset).map((r) => JSON.stringify(r)).join("\n") + "\n");

      case "xlsx": {
        requireXLSX();
        const aoa = [dataset.columns, ...dataset.rows];
        const ws = XLSX.utils.aoa_to_sheet(aoa);
        const wb = XLSX.utils.book_new();
        // Excel rejects sheet names over 31 characters or containing
        // []:*?/\ — a file named after a long query would otherwise
        // produce a workbook Excel refuses to open.
        const sheet = String(name).replace(/[[\]:*?/\\]/g, "_").slice(0, 31) || "Sheet1";
        XLSX.utils.book_append_sheet(wb, ws, sheet);
        return new Uint8Array(XLSX.write(wb, { type: "array", bookType: "xlsx" }));
      }

      case "xml": {
        const esc = (s) =>
          String(s ?? "").replace(/[<>&'"]/g, (c) => ({ "<": "&lt;", ">": "&gt;", "&": "&amp;", "'": "&apos;", '"': "&quot;" }[c]));
        const tag = (s) => String(s).replace(/[^A-Za-z0-9_.-]/g, "_").replace(/^[^A-Za-z_]/, "_");
        const parts = ['<?xml version="1.0" encoding="UTF-8"?>', "<rows>"];
        for (const row of dataset.rows) {
          parts.push("  <row>");
          dataset.columns.forEach((c, i) => parts.push(`    <${tag(c)}>${esc(row[i])}</${tag(c)}>`));
          parts.push("  </row>");
        }
        parts.push("</rows>");
        return enc.encode(parts.join("\n") + "\n");
      }

      case "yaml": {
        const scalar = (v) => {
          if (v === null || v === undefined) return "null";
          if (typeof v === "number" || typeof v === "boolean") return String(v);
          const s = String(v);
          // Quote anything that YAML would otherwise read as a number,
          // a boolean, or a structure character.
          return /^[\w .\-/@]+$/.test(s) && !/^(true|false|null|yes|no|on|off|-?\d)/i.test(s)
            ? s
            : JSON.stringify(s);
        };
        const out = [];
        for (const row of dataset.rows) {
          out.push(`- ${dataset.columns[0]}: ${scalar(row[0])}`);
          for (let i = 1; i < dataset.columns.length; i++) {
            out.push(`  ${dataset.columns[i]}: ${scalar(row[i])}`);
          }
        }
        return enc.encode(out.join("\n") + "\n");
      }

      case "md": {
        const cell = (v) => String(v ?? "").replace(/\|/g, "\\|").replace(/\n/g, " ");
        const lines = [
          `| ${dataset.columns.map(cell).join(" | ")} |`,
          `| ${dataset.columns.map(() => "---").join(" | ")} |`,
          ...dataset.rows.map((r) => `| ${r.map(cell).join(" | ")} |`),
        ];
        return enc.encode(lines.join("\n") + "\n");
      }

      case "html": {
        const esc = (s) => String(s ?? "").replace(/[<>&]/g, (c) => ({ "<": "&lt;", ">": "&gt;", "&": "&amp;" }[c]));
        const html = `<!doctype html>
<meta charset="utf-8">
<title>${esc(name)}</title>
<style>
  body { font: 14px -apple-system, Segoe UI, sans-serif; background: #faf7f0; color: #211d16; padding: 24px; }
  table { border-collapse: collapse; font-variant-numeric: tabular-nums; }
  th, td { border-bottom: 1px solid #ddd5c4; padding: 6px 12px; text-align: left; }
  th { font: 600 11px/1 ui-monospace, Menlo, monospace; letter-spacing: .08em; text-transform: uppercase; color: #7a7362; }
</style>
<table>
<thead><tr>${dataset.columns.map((c) => `<th>${esc(c)}</th>`).join("")}</tr></thead>
<tbody>
${dataset.rows.map((r) => `<tr>${r.map((v) => `<td>${esc(v)}</td>`).join("")}</tr>`).join("\n")}
</tbody>
</table>
`;
        return enc.encode(html);
      }

      case "sqlite": {
        await KoshaEngine.init();
        const db = KoshaEngine.Database.create();
        try {
          db.importDataset(name || "data", dataset);
          return db.serialize();
        } finally {
          db.close();
        }
      }

      default:
        throw new Error(`Cannot write a table as ${format}.`);
    }
  }

  // -------------------------------------------------------------------
  // Images
  // -------------------------------------------------------------------

  async function convertImage(bytes, fromFormat, toFormat, { quality = 0.92 } = {}) {
    const target = FORMATS[toFormat];
    const blob = new Blob([bytes], { type: FORMATS[fromFormat].mime });
    let bitmap;
    try {
      bitmap = await createImageBitmap(blob);
    } catch {
      throw new Error("That image could not be decoded by this browser.");
    }
    const canvas = document.createElement("canvas");
    canvas.width = bitmap.width;
    canvas.height = bitmap.height;
    const ctx = canvas.getContext("2d");
    // JPEG has no alpha. Without this, a transparent PNG converts to a
    // JPEG with a black background, which looks like corruption.
    if (toFormat === "jpg") {
      ctx.fillStyle = "#ffffff";
      ctx.fillRect(0, 0, canvas.width, canvas.height);
    }
    ctx.drawImage(bitmap, 0, 0);
    bitmap.close?.();

    const out = await new Promise((resolve, reject) =>
      canvas.toBlob((b) => (b ? resolve(b) : reject(new Error(`This browser cannot write ${target.label}.`))), target.mime, quality)
    );
    // A browser that does not support the requested type silently
    // falls back to PNG rather than failing, so verify rather than
    // trust — otherwise Kosha would file a PNG under a .webp name.
    if (out.type !== target.mime) {
      throw new Error(`This browser cannot write ${target.label} images.`);
    }
    return new Uint8Array(await out.arrayBuffer());
  }

  // -------------------------------------------------------------------
  // The public conversion entry point
  // -------------------------------------------------------------------

  /**
   * Explain, before anything is uploaded, what converting this file
   * into this folder would do. The UI shows the result; nothing is
   * written until the user has seen it.
   */
  function plan(filename, bytes, targetFormat) {
    const from = detect(filename, bytes);
    const fromFam = familyOf(from);
    const toFam = familyOf(targetFormat);

    if (targetFormat === "any" || from === targetFormat) {
      return { from, to: targetFormat, action: "store", possible: true, notes: [] };
    }
    if (fromFam !== toFam) {
      // Tabular -> text is the one cross-family case worth allowing:
      // every tabular format already has a faithful text rendering.
      if (fromFam === "tabular" && toFam === "text") {
        return {
          from, to: targetFormat, action: "convert", possible: true,
          notes: ["The table will be written out as text; column types are not preserved."],
        };
      }
      return {
        from, to: targetFormat, action: "reject", possible: false,
        notes: [
          `A ${FORMATS[from]?.label || from} file is ${fromFam === "image" ? "an image" : `a ${fromFam} file`}, ` +
            `and this folder holds ${FORMATS[targetFormat]?.label || targetFormat} (${toFam}). ` +
            "Kosha will not invent a conversion between them.",
        ],
      };
    }

    const notes = [];
    if (from === "xlsx") notes.push("Formulas, formatting and extra sheets are not carried over — only the first sheet's values.");
    if (from === "sqlite") notes.push("Only the first table is read; indexes and views are not carried over.");
    if (targetFormat === "jpg") notes.push("JPEG is lossy and has no transparency; transparent areas become white.");
    if (fromFam === "tabular" && (targetFormat === "md" || targetFormat === "html")) {
      notes.push("Markdown and HTML tables store everything as text — numbers lose their type.");
    }
    return { from, to: targetFormat, action: "convert", possible: true, notes };
  }

  /**
   * Do the conversion. Returns the new bytes plus everything the
   * caller needs to record what happened.
   */
  async function convert(filename, bytes, targetFormat) {
    const p = plan(filename, bytes, targetFormat);
    if (!p.possible) throw new Error(p.notes[0]);
    const base = baseName(filename);

    if (p.action === "store") {
      return { bytes, format: p.from, name: filename, dataset: null, notes: p.notes, converted: false };
    }

    const fam = familyOf(p.from);
    if (fam === "image") {
      const out = await convertImage(bytes, p.from, targetFormat);
      return {
        bytes: out, format: targetFormat, name: `${base}.${FORMATS[targetFormat].ext}`,
        dataset: null, notes: p.notes, converted: true,
      };
    }

    if (fam === "text") {
      // Within the text family a conversion is a rename: the bytes are
      // already the thing. Pretending otherwise would mean "converting"
      // a .log to a .txt by rewriting it identically.
      return {
        bytes, format: targetFormat, name: `${base}.${FORMATS[targetFormat].ext}`,
        dataset: null, notes: p.notes, converted: true,
      };
    }

    const dataset = await readDataset(p.from, bytes, filename);
    if (dataset.warnings) p.notes.push(...dataset.warnings);

    if (familyOf(targetFormat) === "text") {
      const asCsv = writeDelimited(dataset, ",");
      return {
        bytes: encoder().encode(asCsv), format: targetFormat,
        name: `${base}.${FORMATS[targetFormat].ext}`, dataset, notes: p.notes, converted: true,
      };
    }

    const out = await writeDataset(targetFormat, dataset, { name: base });
    return {
      bytes: out, format: targetFormat, name: `${base}.${FORMATS[targetFormat].ext}`,
      dataset, notes: p.notes, converted: true,
    };
  }

  /** Read a file as a table without converting it — used on import. */
  async function toDataset(filename, bytes) {
    const format = detect(filename, bytes);
    if (familyOf(format) !== "tabular") return null;
    return readDataset(format, bytes, filename);
  }

  return {
    FORMATS,
    targetFormats,
    detect,
    familyOf,
    extOf,
    baseName,
    plan,
    convert,
    toDataset,
    readDataset,
    writeDataset,
    parseDelimited,
    writeDelimited,
    rowsToRecords,
    recordsToRows,
  };
})();
