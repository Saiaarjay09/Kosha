# How Kosha's code works

A tour of the repository, file by file. `README.md` is the pitch and
the setup; this is the document to read to understand the *code* —
what happens between dropping a spreadsheet on a folder and being able
to run a `GROUP BY` over it, and which file is responsible for which
part of that.

## The shape of the thing

Kosha is one Python process and one browser page, and almost all of
the interesting work happens in the browser. That is not a stylistic
preference; it falls directly out of the encryption.

If the server could run your queries, the server could read your data.
There is no arrangement where it indexes, filters or sorts rows it
cannot see. So the engine moved to where the key already is: SQLite is
compiled to WebAssembly and runs inside your tab, and the server is
reduced to a store for opaque bytes.

What that leaves on each side:

- **The server** (`server/`) holds account records, one encrypted blob
  per user's database, and one encrypted blob per stored file. It can
  check a login proof and it can hand those blobs back. It has no
  endpoint that takes a query, because it could not implement one.
- **The browser** (`static/`) does the key derivation, the decryption,
  the SQL, the format conversion and the entire user interface.

### The journey of one file

Worth following once end to end, because it touches nearly every file:

1. You drop `sales.xlsx` onto a folder set to hold CSV.
   `views-files.js` reads the bytes and asks `vault.js` what would
   happen.
2. `vault.js` asks `convert.js`, which sniffs the magic bytes (a ZIP
   header plus an `.xlsx` extension), decides this is a spreadsheet,
   and returns a *plan*: convert to CSV, losing formulas and extra
   sheets. You see that plan in a dialog before anything is stored.
3. You accept. `convert.js` reads the workbook into a neutral
   `{columns, rows}` dataset via the vendored SheetJS, then writes
   that dataset back out as CSV.
4. `vault.js` resolves the folder's template — say
   `{yyyy}/{mm}/{slug}.{ext}` — into `2026/10/sales.csv`.
5. `crypto.js` encrypts the CSV bytes under a key derived from your
   vault master key. `api.js` uploads the ciphertext. The server
   assigns it an id and writes it to disk, having learned nothing.
6. `vault.js` records a row in `kosha_files` — name, format, size, row
   count, blob id, stored path — and, because the file is tabular,
   calls `engine.js` to `CREATE TABLE sales` and insert the rows.
7. The vault database, now containing both that bookkeeping row and
   your actual sales data, is serialised, encrypted under a *different*
   subkey, and uploaded as one blob with a version check.

From here, `SELECT * FROM sales` works, and so does joining `sales`
against `kosha_files` to ask which of your files it came from.

## Repository layout

```
server/        the API: account records, opaque blob storage
static/        the app — no build step, no framework, no bundler
  css/           one stylesheet
  js/            one file per concern, loaded as plain <script> tags
  vendor/        SQLite (WASM) and SheetJS, vendored not CDN'd
docs/          the always-on GitHub Pages site
deploy/        Tailscale, launchd, systemd, link publishing
tests/         RFC vectors for the crypto; behaviour for the server
```

There is no build step anywhere. What is in the repository is exactly
what runs in the browser — which, for a tool whose security story
depends on its client code being auditable, is worth more than the
convenience a bundler would buy.

---

## `server/` — the part that knows nothing

### `server/vault_db.py`

All server-side state, and the file to read if you want to *check* the
zero-knowledge claim rather than believe it. Its docstring walks every
stored column and asks of each one whether somebody holding it could
read a user's data.

The storage is SQLite for records and plain files on disk for
encrypted blobs — blobs can be large, and a 200 MB BLOB column is a
worse idea than a 200 MB file. Passwords and recovery phrases are
never seen; what is stored is an Argon2id hash of the *auth* half of
the client's split derivation, which proves a login and decrypts
nothing.

Three details that carry weight:

- `put_vault` is a compare-and-swap on a version counter. The client
  sends the version it started from, and a write built on a stale
  version is refused. Two tabs editing the same vault is a real
  situation, and silently letting the second one win would discard
  whatever the first did.
- `set_password` deletes every session for that account. If the reason
  for the change was "someone else got in", leaving their session alive
  would make the change pointless.
- `delete_account` removes the blob *files*, not just the index rows.
  "Deleted" should mean the bytes are gone.

Sessions are bearer tokens stored only as their SHA-256, so a stolen
database cannot be used to impersonate a live session.

### `server/server.py`

The HTTP layer: request shapes, validation, rate limiting, sessions,
and — mounted last, at the root — the static files.

One process serving both the page and the API from one origin is a
deliberate simplification over the two-service split Haven uses. It
means no CORS configuration, no second Tailscale endpoint, and no
"paste your API server URL here" box on the login screen for someone
to get wrong.

The security headers live here too, and two of them are worth
explaining. `script-src 'self' 'wasm-unsafe-eval'` reads alarmingly
but is the narrow modern permission to compile WebAssembly — it does
not re-enable `eval()` or inline scripts, and without it the query
engine does not start. `connect-src 'self'` means the page may not
contact any other host at all, which is a meaningful backstop: even a
bug in Kosha's own JavaScript cannot send a decrypted row somewhere
else.

The API surface is four verbs wide on purpose: prove who you are,
fetch your encrypted vault, store your encrypted vault, store and
fetch encrypted file blobs. The rate limiter is in-memory and holds
timestamps only — no addresses are written to disk, and no request is
logged with its body.

---

## `static/js/` — the app

### `crypto.js`

Every primitive, and the one file where being clever is dangerous.

WebCrypto provides HKDF, HMAC and AES-GCM natively, so those are the
browser's audited implementations rather than anything written here.
It does **not** provide scrypt, so scrypt is implemented from RFC 7914
— and checked against RFC 7914's own published vectors by
`tests/test_crypto.mjs`, which is the only reason to trust it.

The scrypt core is written in an ugly style — sixteen local variables,
no allocation, a bitwise mask where the spec says modulo — and the
comments say why at each point. The short version: the readable
version allocated two objects per Salsa20 call, of which a single
login makes about two million. On identical input, same runtime and
same machine, the readable version took **1.6 s** where this one takes
**0.14 s** — about 12× — and in the browser a sign-in went from
unusable to roughly **270 ms**. Same algorithm, same output, verified
against RFC 7914's vectors before and after.

That speed is what let the cost factor be set to OWASP's actual
recommended minimum (N = 2¹⁷, which costs an attacker 128 MB per
guess) rather than the weaker setting a slow implementation would have
forced. The same tradeoff is visible in Haven, which still carries the
earlier implementation and sets N = 2¹⁶ with a comment explaining that
2¹⁷ was too slow to be bearable — it was, for that code.

The key hierarchy:

```
password ──scrypt──> combined ──HKDF──> authKey   → sent to the server
                               ──HKDF──> encKey   → stays in the browser
                                            │
                                            └─unwraps─> masterKey (random, 32 bytes)
                                                            ├─HKDF─> vault database key
                                                            └─HKDF─> file blob key
recovery phrase ──scrypt──> ... ──HKDF──> encKey' ─unwraps─> the same masterKey
```

The master key indirection is what makes a password change cost 60
bytes instead of re-encrypting everything you own, and what lets the
recovery phrase be a genuinely independent second key rather than a
copy of the password.

### `scrypt-worker.js` / `scrypt-worker-client.js`

Key derivation moved off the main thread. The ROMix loop has no
`await` in it, so on the main thread it freezes the tab outright — no
repaint, no input, the spinner you just showed sitting perfectly
still. Running the identical computation in a Worker makes it no
faster but keeps the page alive.

### `api.js`

Everything that talks to the server, and notable for how little it
contains: signup, login, recovery, and four verbs for moving opaque
bytes. There is no `search`, no `listFiles`, no `runQuery`, because the
server could not implement them.

The session token is kept in memory only, never `localStorage` —
closing the tab should end the session, and a token in storage is
readable by any script that manages to run on this origin.

The signup flow is worth reading as the clearest statement of the
whole design: generate two salts, derive two key pairs, generate one
random master key, wrap it twice, send the server the salts, the two
auth proofs and the two wrapped copies. The server receives nothing
that can unwrap either.

### `engine.js`

The SQLite wrapper. Real SQLite, compiled to WebAssembly, served from
this origin — the `.wasm` is vendored, so the app works offline and
the CSP's `connect-src 'self'` stays truthful.

Three things here are load-bearing beyond the obvious:

- `quoteIdent` exists because SQLite's parameter binding covers values
  but not identifiers — you cannot write `SELECT * FROM ?`. Table and
  column names must be interpolated as text, which is exactly where
  injection lives, so every one goes through SQLite's own escaping
  rule.
- `inferType` only ever widens. One non-numeric value in ten thousand
  makes the whole column TEXT. A column silently typed INTEGER because
  the first thousand rows looked numeric will mangle the row where
  someone wrote "n/a", and a wrong number is far worse than a number
  stored as text you can still CAST.
- `importDataset` wraps its inserts in one transaction and one
  prepared statement. SQLite autocommits every bare INSERT, so a
  50,000-row import done naively is 50,000 transactions and takes
  minutes rather than a moment.

### `convert.js`

Format detection and conversion, built as a **hub rather than a mesh**.
Nothing converts directly from CSV to XLSX; everything reads into one
of three neutral shapes — `Dataset`, `TextDoc`, `Image` — and writes
back out of it. With n formats a mesh needs n² converters and n²
chances to get one wrong; a hub needs 2n, and adding a format means
writing one reader and one writer.

The cost of a hub is that a conversion loses whatever the neutral shape
has no room for. `plan()` exists to say so *before* anything is stored,
which is the difference between a tool you trust and one that quietly
drops your spreadsheet's formulas.

Detection checks magic bytes first (those cannot lie), then sniffs
content, and only then falls back to the extension — so a `.csv` that
is really tab-separated, or a `.txt` holding JSON, are both caught.

The delimited parser is written out character by character rather than
regex'd, because `line.split(",")` breaks on the first quoted field
containing a comma, which in real spreadsheet exports is approximately
always.

`recordsToRows` takes the **union** of keys across all records. Using
the first record's keys is the tempting shortcut and it silently drops
every field absent from record #1 — in any JSON export with optional
fields, a lot of data lost without a word.

### `vault.js`

Kosha's own data model, and the sync that keeps it on the server
without the server understanding it.

A vault is one SQLite database holding two kinds of thing side by
side: Kosha's bookkeeping in `kosha_`-prefixed tables, and your actual
tables as ordinary SQLite tables. Because both live in one database, a
query can join your data against your filing system — which is the
single most distinctive thing about the project and falls out of the
design rather than being built as a feature.

File *contents* are deliberately not in there. A 40 MB spreadsheet
inside the vault database would mean re-encrypting and re-uploading 40
MB every time you renamed a folder. Each file's bytes are encrypted
separately, uploaded once, and referenced by id.

Saves are debounced, because one user action is often a dozen writes
and each save is a full encrypt-and-upload. Ordering is deliberate
throughout: a blob is uploaded *before* its row is written, so a
failure half way leaves an unreferenced blob (which the garbage
collector sweeps) rather than a row pointing at a file that was never
stored (a permanent broken entry).

`reapplyFolderRules` is what makes a folder's declared type mean
something retroactively: change the type and every existing file is
fetched, converted, re-uploaded and re-filed, with anything that
cannot be converted reported and left exactly as it was.

### `ui.js`

DOM helpers, modals, toasts, the data grid, formatters.

The one rule that is not negotiable: text is assigned via
`textContent`, never `innerHTML`. This app displays filenames, column
headings and cell values that came out of files, and that is the whole
of the XSS defence, so it has to be unconditional.

### `views-files.js`

The Files view — a folder's contents, its rules, and the path a
dropped file takes. One dialog serves both "new folder" and "folder
settings", so the explanation of what *strict* means cannot drift
between the two.

### `views-data.js`

The Tables and Query views. The query builder here does not hide SQL
behind a form; it *writes* SQL into the editor, visibly, as you change
the form. A tool that generates queries you never see leaves you stuck
the first time it cannot express what you want.

`explainSqlError` translates SQLite's terse messages into something
actionable while still printing the original underneath — the real
message is what you will find if you search for it.

### `app.js`

The shell: sign-in, routing between the four views, the folder
sidebar, Settings, the save indicator.

Signing out reloads the page rather than clearing variables, which is
the only reliable way to ensure no decrypted bytes remain reachable —
clearing by hand would leave copies in the WASM heap.

The Settings view contains the "what this server can see" table and
the honest caveat about browser-delivered code. Putting that in the
product, not only in the README, is deliberate: a privacy claim the
user cannot check is worth very little.

---

## `tests/`

- **`test_crypto.mjs`** evaluates `crypto.js` in a Node VM context and
  checks it against RFC 7914's scrypt vectors, Node's own PBKDF2, and
  the properties the design depends on (the two split halves differ;
  tampered ciphertext, wrong AAD, wrong key and truncation are each
  rejected).
- **`test_server.py`** runs the API against a throwaway data directory
  and pins the behaviours the security story needs: wrong proofs
  refused, stale writes refused, one account unable to touch another's
  blobs or vault, deletion actually removing bytes from disk.

## `deploy/` and `docs/`

`setup-tailscale.sh` defaults to `tailscale serve` — your tailnet only
— rather than `funnel`, because a private data store should not be on
the public internet by default. `funnel` is available and the script
says what it costs before doing it.

`docs/` is a standalone GitHub Pages site with no shared stylesheet,
no scripts and no external fonts. It is the one part of Kosha that is
always up, so it should have nothing in it that can fail.
`publish-links.sh` re-derives the tailnet hostname and updates that
page only when it has actually changed.
