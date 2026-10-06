"""Kosha's storage layer — and, more usefully, the file to read if you
want to check the central claim rather than take it on faith.

Below is *everything* this server keeps. Go through it field by field
and ask of each one: could someone holding this read a user's data?

    username, display_name   Public-ish. Needed to find an account.
    password_salt, kdf_n     Public by construction. A salt is not a
                             secret; it exists to make precomputed
                             rainbow tables useless, and the client
                             must be told it to derive the same key.
    auth_hash                Argon2id of the *auth* half of the split
                             (see static/js/crypto.js). Proves a login.
                             Cannot decrypt anything, and the enc half
                             cannot be computed from it.
    recovery_* fields        Exactly the same shape, for the 12-word
                             phrase instead of the password.
    keyring_password         The vault master key, AES-256-GCM
    keyring_recovery         encrypted under a key this server has
                             never seen and cannot derive. To us these
                             are 60 opaque bytes each.
    vault_blob               An encrypted SQLite database. Opaque.
    blobs on disk            Encrypted file contents. Opaque.

What that leaves genuinely visible to whoever runs or steals this
server: who has an account, when they signed up, how many files they
hold, how big those files are, and when they last changed. That is
real metadata and it is not nothing — it is the same residual leak
Haven's relay accepts, and it is stated here rather than glossed over.
What is *not* visible is any filename, any column name, any row, any
byte of any file.

The honest caveat, the same one webapp/README.md makes for Haven: all
of this rests on the browser running the crypto code faithfully, and a
browser fetches that code fresh from this server on every page load. A
server that is compromised *before* you log in can serve you altered
JavaScript. Zero-knowledge storage is a real and worthwhile property;
it is not a defence against a hostile server rewriting the client.
"""

from __future__ import annotations

import os
import secrets
import sqlite3
import threading
import time
from pathlib import Path

import argon2
from argon2.exceptions import InvalidHash, VerifyMismatchError

# Argon2id is OWASP's first-choice password hash — meaningfully harder
# to attack with GPUs than bcrypt's small fixed memory footprint. It
# guards the auth/recovery proofs at rest. Note what it is *not* doing:
# it never touches the encryption half of the split, which is why a
# dump of this table does not get an attacker any closer to plaintext.
_hasher = argon2.PasswordHasher()

SESSION_TTL_SECONDS = 12 * 60 * 60

# Per-account ceiling. Not a security control — a courtesy, so one
# runaway import cannot fill the disk of a machine you also use for
# other things. Raise it freely; it is read at startup only.
DEFAULT_QUOTA_BYTES = int(os.environ.get("KOSHA_QUOTA_BYTES", 4 * 1024 * 1024 * 1024))


class UsernameTaken(Exception):
    pass


class QuotaExceeded(Exception):
    pass


class VersionConflict(Exception):
    """Raised when two tabs (or two devices) try to save a vault built
    on the same starting version. The second one loses deliberately —
    silently overwriting would discard whatever the first one did, and
    for a database that is a much worse outcome than an error message
    telling you to reload."""

    def __init__(self, current_version: int):
        super().__init__(f"vault was modified elsewhere (now at version {current_version})")
        self.current_version = current_version


SCHEMA = """
CREATE TABLE IF NOT EXISTS accounts (
    username        TEXT PRIMARY KEY,
    display_name    TEXT NOT NULL,
    password_salt   TEXT NOT NULL,
    password_kdf_n  INTEGER NOT NULL,
    auth_hash       TEXT NOT NULL,
    recovery_salt   TEXT NOT NULL,
    recovery_kdf_n  INTEGER NOT NULL,
    recovery_hash   TEXT NOT NULL,
    keyring_password TEXT NOT NULL,
    keyring_recovery TEXT NOT NULL,
    vault_blob      BLOB,
    vault_version   INTEGER NOT NULL DEFAULT 0,
    vault_updated_at INTEGER,
    created_at      INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS blobs (
    id          TEXT PRIMARY KEY,
    username    TEXT NOT NULL,
    size        INTEGER NOT NULL,
    created_at  INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_blobs_user ON blobs(username);

CREATE TABLE IF NOT EXISTS sessions (
    token_hash  TEXT PRIMARY KEY,
    username    TEXT NOT NULL,
    expires_at  INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(username);
"""


def _now() -> int:
    return int(time.time())


class VaultStore:
    """All server-side state. Thread-safe via one lock around one
    connection — this is a personal-scale service (a handful of users
    on a Tailnet), and a connection pool would be complexity bought
    for a load that will not arrive."""

    def __init__(self, db_path: str | Path, blob_dir: str | Path, quota_bytes: int = DEFAULT_QUOTA_BYTES):
        self.db_path = Path(db_path)
        self.blob_dir = Path(blob_dir)
        self.quota_bytes = quota_bytes
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.blob_dir.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        # WAL keeps a reader (someone downloading a vault) from blocking
        # a writer (someone saving one) on the same file.
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.executescript(SCHEMA)
        self._conn.commit()

    # -- accounts ----------------------------------------------------

    def create_account(
        self,
        username: str,
        display_name: str,
        password_salt: str,
        password_kdf_n: int,
        auth_key: str,
        recovery_salt: str,
        recovery_kdf_n: int,
        recovery_key: str,
        keyring_password: str,
        keyring_recovery: str,
    ) -> None:
        key = username.lower()
        with self._lock:
            existing = self._conn.execute(
                "SELECT 1 FROM accounts WHERE username = ?", (key,)
            ).fetchone()
            if existing:
                raise UsernameTaken(username)
            self._conn.execute(
                """INSERT INTO accounts (username, display_name, password_salt, password_kdf_n,
                                         auth_hash, recovery_salt, recovery_kdf_n, recovery_hash,
                                         keyring_password, keyring_recovery, vault_blob,
                                         vault_version, created_at)
                   VALUES (?,?,?,?,?,?,?,?,?,?,NULL,0,?)""",
                (
                    key,
                    display_name,
                    password_salt,
                    password_kdf_n,
                    _hasher.hash(auth_key),
                    recovery_salt,
                    recovery_kdf_n,
                    _hasher.hash(recovery_key),
                    keyring_password,
                    keyring_recovery,
                    _now(),
                ),
            )
            self._conn.commit()

    def get_account(self, username: str) -> sqlite3.Row | None:
        with self._lock:
            return self._conn.execute(
                "SELECT * FROM accounts WHERE username = ?", (username.lower(),)
            ).fetchone()

    def _verify(self, stored_hash: str, offered: str, username: str, column: str) -> bool:
        """Verify a proof, and transparently re-hash it if Argon2's
        recommended parameters have moved on since it was stored. The
        user never notices; they just keep logging in."""
        try:
            _hasher.verify(stored_hash, offered)
        except (VerifyMismatchError, InvalidHash):
            return False
        if _hasher.check_needs_rehash(stored_hash):
            with self._lock:
                self._conn.execute(
                    f"UPDATE accounts SET {column} = ? WHERE username = ?",
                    (_hasher.hash(offered), username.lower()),
                )
                self._conn.commit()
        return True

    def verify_password(self, username: str, auth_key: str) -> bool:
        row = self.get_account(username)
        if not row:
            # Still burn comparable time on a missing account, so the
            # response latency does not quietly answer "does this
            # username exist?" for someone enumerating names.
            _hasher.hash(auth_key)
            return False
        return self._verify(row["auth_hash"], auth_key, username, "auth_hash")

    def verify_recovery(self, username: str, recovery_key: str) -> bool:
        row = self.get_account(username)
        if not row:
            _hasher.hash(recovery_key)
            return False
        return self._verify(row["recovery_hash"], recovery_key, username, "recovery_hash")

    def set_password(
        self,
        username: str,
        password_salt: str,
        password_kdf_n: int,
        auth_key: str,
        keyring_password: str,
    ) -> None:
        """Rotate the password. Note what does NOT change: the vault
        master key, and therefore not a single encrypted byte. Only the
        wrapper around that key is replaced, which is the whole reason
        crypto.js bothers with a keyring instead of encrypting
        everything under the password key directly."""
        with self._lock:
            self._conn.execute(
                """UPDATE accounts SET password_salt=?, password_kdf_n=?, auth_hash=?,
                                       keyring_password=? WHERE username=?""",
                (password_salt, password_kdf_n, _hasher.hash(auth_key), keyring_password, username.lower()),
            )
            # Every existing session dies with the old password. If the
            # reason for the change was "someone else got in", leaving
            # their session alive would make the change pointless.
            self._conn.execute("DELETE FROM sessions WHERE username = ?", (username.lower(),))
            self._conn.commit()

    def set_recovery(
        self, username: str, recovery_salt: str, recovery_kdf_n: int, recovery_key: str, keyring_recovery: str
    ) -> None:
        with self._lock:
            self._conn.execute(
                """UPDATE accounts SET recovery_salt=?, recovery_kdf_n=?, recovery_hash=?,
                                       keyring_recovery=? WHERE username=?""",
                (recovery_salt, recovery_kdf_n, _hasher.hash(recovery_key), keyring_recovery, username.lower()),
            )
            self._conn.commit()

    # -- sessions ----------------------------------------------------

    def create_session(self, username: str) -> tuple[str, int]:
        """Issue a bearer token. Only its SHA-256 is stored, so a stolen
        database still cannot be used to impersonate a live session."""
        import hashlib

        token = secrets.token_urlsafe(32)
        expires = _now() + SESSION_TTL_SECONDS
        with self._lock:
            self._conn.execute("DELETE FROM sessions WHERE expires_at < ?", (_now(),))
            self._conn.execute(
                "INSERT INTO sessions (token_hash, username, expires_at) VALUES (?,?,?)",
                (hashlib.sha256(token.encode()).hexdigest(), username.lower(), expires),
            )
            self._conn.commit()
        return token, expires

    def resolve_session(self, token: str) -> str | None:
        import hashlib

        if not token:
            return None
        h = hashlib.sha256(token.encode()).hexdigest()
        with self._lock:
            row = self._conn.execute(
                "SELECT username, expires_at FROM sessions WHERE token_hash = ?", (h,)
            ).fetchone()
        if not row or row["expires_at"] < _now():
            return None
        return row["username"]

    def end_session(self, token: str) -> None:
        import hashlib

        with self._lock:
            self._conn.execute(
                "DELETE FROM sessions WHERE token_hash = ?",
                (hashlib.sha256(token.encode()).hexdigest(),),
            )
            self._conn.commit()

    # -- the vault database blob -------------------------------------

    def get_vault(self, username: str) -> tuple[bytes | None, int]:
        with self._lock:
            row = self._conn.execute(
                "SELECT vault_blob, vault_version FROM accounts WHERE username = ?", (username.lower(),)
            ).fetchone()
        if not row:
            return None, 0
        return row["vault_blob"], row["vault_version"]

    def put_vault(self, username: str, blob: bytes, expected_version: int) -> int:
        """Compare-and-swap on the version counter. The client sends the
        version it started from; if the stored one has moved, somebody
        else saved in between and this write is refused rather than
        allowed to clobber them."""
        with self._lock:
            row = self._conn.execute(
                "SELECT vault_version FROM accounts WHERE username = ?", (username.lower(),)
            ).fetchone()
            if row is None:
                raise KeyError(username)
            current = row["vault_version"]
            if current != expected_version:
                raise VersionConflict(current)
            new_version = current + 1
            self._conn.execute(
                "UPDATE accounts SET vault_blob=?, vault_version=?, vault_updated_at=? WHERE username=?",
                (blob, new_version, _now(), username.lower()),
            )
            self._conn.commit()
        return new_version

    # -- encrypted file blobs ----------------------------------------

    def _blob_path(self, blob_id: str) -> Path:
        # Fan out over the first two hex characters. One flat directory
        # with tens of thousands of entries is slow to list on every
        # filesystem that matters, and this costs nothing to do now.
        return self.blob_dir / blob_id[:2] / blob_id

    def usage_bytes(self, username: str) -> int:
        with self._lock:
            row = self._conn.execute(
                "SELECT COALESCE(SUM(size), 0) AS total FROM blobs WHERE username = ?", (username.lower(),)
            ).fetchone()
        return int(row["total"])

    def put_blob(self, username: str, data: bytes) -> str:
        if self.usage_bytes(username) + len(data) > self.quota_bytes:
            raise QuotaExceeded()
        blob_id = secrets.token_hex(16)
        path = self._blob_path(blob_id)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        with self._lock:
            self._conn.execute(
                "INSERT INTO blobs (id, username, size, created_at) VALUES (?,?,?,?)",
                (blob_id, username.lower(), len(data), _now()),
            )
            self._conn.commit()
        return blob_id

    def get_blob(self, username: str, blob_id: str) -> bytes | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT 1 FROM blobs WHERE id = ? AND username = ?", (blob_id, username.lower())
            ).fetchone()
        if not row:
            return None
        path = self._blob_path(blob_id)
        return path.read_bytes() if path.exists() else None

    def delete_blob(self, username: str, blob_id: str) -> bool:
        with self._lock:
            cur = self._conn.execute(
                "DELETE FROM blobs WHERE id = ? AND username = ?", (blob_id, username.lower())
            )
            self._conn.commit()
            deleted = cur.rowcount > 0
        if deleted:
            path = self._blob_path(blob_id)
            if path.exists():
                path.unlink()
        return deleted

    def list_blob_ids(self, username: str) -> list[str]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT id FROM blobs WHERE username = ?", (username.lower(),)
            ).fetchall()
        return [r["id"] for r in rows]

    def delete_account(self, username: str) -> None:
        """Irreversible, and genuinely complete: every blob file is
        removed from disk, not just unlinked from the index."""
        for blob_id in self.list_blob_ids(username):
            path = self._blob_path(blob_id)
            if path.exists():
                path.unlink()
        with self._lock:
            key = username.lower()
            self._conn.execute("DELETE FROM blobs WHERE username = ?", (key,))
            self._conn.execute("DELETE FROM sessions WHERE username = ?", (key,))
            self._conn.execute("DELETE FROM accounts WHERE username = ?", (key,))
            self._conn.commit()

    def stats(self, username: str) -> dict:
        with self._lock:
            row = self._conn.execute(
                """SELECT COUNT(*) AS n, COALESCE(SUM(size),0) AS total
                   FROM blobs WHERE username = ?""",
                (username.lower(),),
            ).fetchone()
            acct = self._conn.execute(
                "SELECT vault_version, vault_updated_at, created_at, LENGTH(vault_blob) AS vault_size "
                "FROM accounts WHERE username = ?",
                (username.lower(),),
            ).fetchone()
        return {
            "blob_count": row["n"],
            "blob_bytes": int(row["total"]),
            "vault_bytes": int(acct["vault_size"] or 0) if acct else 0,
            "vault_version": acct["vault_version"] if acct else 0,
            "vault_updated_at": acct["vault_updated_at"] if acct else None,
            "created_at": acct["created_at"] if acct else None,
            "quota_bytes": self.quota_bytes,
        }

    def close(self) -> None:
        with self._lock:
            self._conn.close()
