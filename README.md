# Kosha

**कोश** — a treasury, a repository, the sheath a thing is kept in.

A database and a filing system in one, where nothing that stores your
data can read it.

### → **[Open Kosha](https://saiaarjay09.github.io/Kosha/)** ←

That link always works. It runs entirely in your browser, needs no
server, and keeps working with every machine you own switched off.

---

## The idea

Most tools make you choose one or the other.

A **database** gives you real queries, but it wants your data in tables
you define before you have it, and it has nothing to say about the
spreadsheet sitting in your downloads folder.

A **file store** takes anything, but all it can ever tell you about a
file is its name and its size. Ask it which of your CSVs has more than
a thousand rows and it has no idea what a row is.

Kosha is both halves at once. Drop a spreadsheet into a folder and
three things happen in one action: it is converted to the format that
folder holds, it is filed under the name that folder's template
decides, and it becomes a SQL table you can query immediately. Your
folders and files live in the *same* database as your data, so the
filing system is queryable too.

And the whole thing is encrypted in your browser before any of it is
sent anywhere.

## What it does

**Folders have a type.** A folder declares that it holds CSV, or
Excel, or JSON, or PNG. Anything you add is converted to match. A PNG
dropped into a CSV folder is refused with an explanation rather than
quietly accepted — Kosha will not invent a conversion between an image
and a table.

Formats it reads and writes: CSV, TSV, JSON, NDJSON, Excel (.xlsx),
XML, YAML, Markdown tables, HTML tables, SQLite, plain text, PNG, JPEG
and WebP. It also reads GIF and BMP, and will store anything at all
unconverted in a folder set to "any file".

**You define how things are filed.** Each folder has a storage
template — `{yyyy}/{mm}/{slug}.{ext}`, or `{folder}-{nnn}.{ext}`, or
just `{name}.{ext}`. That decides the path every file lands under, so
a filing convention becomes a setting rather than a habit you have to
keep. Change it later and "Re-file everything" applies it to what is
already there.

**Real SQL.** Not an imitation and not a subset: SQLite itself,
compiled to WebAssembly, running in your browser tab. Joins,
subqueries, CTEs, window functions, views, triggers, indexes,
transactions, JSON functions. If SQLite does it, Kosha does it.

**A query builder that shows its work.** Answer a few questions —
which table, which columns, only rows where, grouped by — and it
writes the SQL into the editor, where you can read it, change it, and
eventually stop needing the builder. A tool that generates queries you
never see teaches you nothing.

**Errors in plain English.** `no such column: totl` becomes "There is
no column called *totl*. If the name has spaces or punctuation, wrap it
in double quotes" — with SQLite's original message underneath, because
that is what you will find if you search for it.

## How the encryption works

Your password is turned into **two independent keys**.

One (`authKey`) is a login proof. The other (`encKey`) never leaves
your browser, and it is the only thing in the world that can decrypt
your vault. Neither can be computed from the other — that is HKDF's
guarantee, and the whole design rests on it.

`encKey` does not encrypt your data directly. It unwraps a random
32-byte **master key**, stored wrapped under `encKey` and separately
wrapped under a key derived from your 12-word recovery phrase. The
indirection is what makes changing your password instant: only the
60-byte wrapper is replaced, not a single byte of your data.

So what gets stored — on a server, or in your browser's own storage —
is an encrypted SQLite database, a pile of encrypted files, and two
wrapped keys that nothing there can unwrap.

That is also *why* SQL runs in your browser: anything able to index or
filter your rows would be able to read them. There is no query
endpoint in this API, and there cannot be one. It is the same reason
the browser-only deployment was possible at all — once the engine is
already client-side, the server has so little left to do that it can
be removed entirely.

### In the browser copy

Nothing is sent anywhere, because there is nowhere to send it. The
encrypted vault goes into IndexedDB on your own device.

There is not even a stored password hash: with no server to prove
anything to, AES-GCM failing to unwrap your keyring **is** the
password check — and a better one, because there is no separate hash
sitting around for an attacker to grind against.

### In the hosted copy: what the server can and cannot see

| | |
|---|---|
| Your files' contents | **Hidden** — encrypted before upload |
| Your filenames and folder names | **Hidden** — inside the encrypted vault |
| Your table and column names | **Hidden** — inside the encrypted vault |
| Your password | **Never sent** — only a one-way proof |
| Your username | Visible — needed to find your account |
| How many files you have, and how big | Visible — file sizes are not hidden |
| When you last saved | Visible — a timestamp per save |

`server/vault_db.py` lists every column the server stores, with the
reasoning for each. It is the file to read if you would rather check
than take this on faith.

### The honest caveat

Whatever serves you this page — your own machine, or GitHub Pages —
delivers the app's code fresh on every load. Something that is
compromised **before** you log in can serve you altered JavaScript,
and no amount of client-side encryption protects you from that. This
is true of every browser-delivered encryption tool, Kosha included.
Zero-knowledge storage is a real and worthwhile property; it is not a
defence against a hostile host rewriting the client.

The practical mitigations, such as they are: run it yourself, keep the
hosted copy on your own tailnet rather than the public internet, and
note that `connect-src 'self'` in the Content-Security-Policy means the
page may not contact any other host at all — so even a bug in Kosha's
own code cannot send a decrypted row somewhere else.

Worth being precise about one thing: the browser-only copy removes the
*storage* side of this risk entirely — there is no server holding your
data to be breached — but not the *delivery* side, since GitHub still
serves the page. Fewer moving parts, not zero.

### What it will not do

If you lose both your password and your recovery phrase, your data is
gone. Not "contact support" gone — gone, because nobody else ever held
anything that could decrypt it. That is the cost of the guarantee, and
it is not negotiable.

## Two ways to run it

Kosha is the same application either way — identical code, identical
encryption. The only thing that differs is where the encrypted bytes
come to rest, and the app works out which deployment it is in by
itself.

### 1. In your browser, no server at all

**[saiaarjay09.github.io/Kosha](https://saiaarjay09.github.io/Kosha/)**

Nothing to install, nothing to run, no account on anybody's machine.
The encrypted vault goes into your browser's own storage (IndexedDB),
which means this copy works offline, works with every computer you own
switched off, and never sends a single byte anywhere — there is no
server to compromise, which removes the one real caveat the hosted
version has to admit to.

What you give up, and it is not small: **the vault lives in that
browser on that device.** It does not sync. Open it on your phone and
you get a separate, empty vault. Clear your browser's site data and it
is gone. Safari also evicts storage for sites you have not visited in
seven days. That is why Settings has an encrypted export — it is the
only backup this copy has, and the only way to move it to another
device. Use it.

### 2. On your own machine, synced across devices

```bash
git clone git@github.com:Saiaarjay09/Kosha.git
cd Kosha
pip3 install -r requirements.txt
python3 -m uvicorn server.server:app --host 127.0.0.1 --port 8711
```

Open http://localhost:8711. One process serves both the page and the
API on one port, so there is no second service to start and no URL to
configure.

Everything you store is now shared across every device you sign in
from — at the cost of that machine needing to be awake, and of there
being a server at all (which still cannot read your data, but could in
principle serve you altered code; see the caveat above).

To reach it from your other devices, put it on your tailnet:

```bash
./deploy/setup-tailscale.sh serve
```

That publishes it to devices signed in to **your** tailnet only —
invisible to everyone else, which is the right default for a private
data store. Pass `funnel` instead of `serve` to put it on the public
internet; the script says what that costs you before it does it.

To keep it running across reboots:

```bash
cp deploy/com.kosha.server.plist ~/Library/LaunchAgents/
launchctl load ~/Library/LaunchAgents/com.kosha.server.plist
```

(`deploy/kosha-server.service` is the systemd equivalent for Linux.)

### Moving between the two

Settings → **Export encrypted vault file** produces one file holding
your vault database and every stored file, all still encrypted. Import
it on the other side and everything comes back, including the links
between files and their SQL tables.

Every byte in that file is ciphertext — it is exactly as safe as the
password that opens it, and no safer. Treat it the way you would treat
a password manager export.

### Rebuilding the browser copy

`static/` is the only copy of the app. `docs/app/` is generated from it
for GitHub Pages and should never be edited by hand:

```bash
./deploy/build-pages.sh
```

Then commit `docs/` and push. Pages is configured to serve the `main`
branch's `/docs` folder.

### Tests

```bash
node tests/test_crypto.mjs    # scrypt against RFC 7914's own vectors
python3 tests/test_server.py  # auth, isolation, versioning, deletion
```

The crypto tests matter more than they look. The scrypt core is
hand-written — WebCrypto has no native scrypt — and it was rewritten
once for speed, a change that is invisible if it is subtly wrong and
catastrophic if it ships. The tests check it against the published
standard, not against yesterday's build.

## Where things are

```
server/        the API — about 500 lines, and deliberately dull
  vault_db.py    every byte the server keeps, with reasoning
  server.py      request shapes, rate limiting, sessions, static files
static/        the app itself (no build step, no framework)
  js/crypto.js      scrypt, HKDF, AES-GCM, the split-key derivation
  js/engine.js      SQLite-in-WebAssembly
  js/convert.js     format detection and conversion
  js/vault.js       folders, files, and encrypted sync
  js/store-local.js the browser-only storage backend
  js/api.js         picks a backend and runs the account flows
  vendor/           SQLite and a spreadsheet reader, vendored not CDN'd
docs/          the GitHub Pages site: landing page + a copy of the app
deploy/        Tailscale, launchd, systemd, the Pages build
tests/         crypto vectors and server behaviour
```

`ARCHITECTURE.md` is the file-by-file tour.

## Honest limits

- **Your whole database lives in the browser tab.** Comfortable into
  the hundreds of megabytes; a bad idea in the low gigabytes. For a
  personal or small-team store that is the right trade. For a
  hundred-gigabyte warehouse, this is the wrong tool — and you should
  know that before you load it, not after.
- **Conversions lose what the neutral format has no room for.** A
  spreadsheet's formulas, colours and extra sheets do not survive a
  trip through "columns and rows". Kosha says so at conversion time
  rather than letting you discover it later.
- **YAML support is a deliberate subset** — a list of flat key/value
  records, which is the shape data files actually come in. Anchors,
  nesting and multi-line scalars are refused rather than parsed
  wrongly.
- **One writer at a time.** Saves use a version check, so a second tab
  is told to reload rather than allowed to silently overwrite the
  first. That is the right failure for a database, but it is a failure,
  not a merge.
- **The browser copy does not sync, and browsers evict storage.** It is
  genuinely private and genuinely always-available, but it is one
  device's copy with no server behind it. The export file is not
  optional there.

## No third-party services

No API keys, no accounts anywhere but your own machine, nothing paid.
The only outside code is SQLite and SheetJS, both vendored into this
repository rather than loaded from a CDN — so the app works with no
network at all, and `connect-src 'self'` stays literally true.

---

Built in the same house style as Vyuha, Sabha, Bureau, Marga and Haven.
The split-key auth is a direct descendant of Haven's.
