"""Kosha's HTTP API.

Read `vault_db.py`'s docstring first — it explains what this service
can and cannot see. This file is the thin layer on top: request
shapes, validation, rate limiting, and session handling.

A deliberate design note, because it is unusual enough to look like an
omission: there is **no query endpoint**. Nothing here runs SQL on your
behalf, because nothing here can — your database arrives as one
encrypted blob and leaves as one encrypted blob, and SQLite itself runs
inside your browser (static/js/engine.js). The API surface is
intentionally four verbs wide: prove who you are, fetch your encrypted
vault, store an encrypted vault, store and fetch encrypted file blobs.
Anything richer would mean the server understood your data, which is
exactly the property Kosha is built not to have.

Run:  uvicorn server.server:app --host 127.0.0.1 --port 8700
"""

from __future__ import annotations

import os
import re
import threading
import time
from collections import defaultdict, deque
from pathlib import Path

from fastapi import Body, Depends, FastAPI, Header, HTTPException, Request, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, field_validator

from .vault_db import QuotaExceeded, UsernameTaken, VaultStore, VersionConflict

# A username is a public identifier other people may one day have to
# type, so: starts with a letter, letters/digits/underscore after,
# 3-24 characters. Case is preserved for display and folded for
# uniqueness (see vault_db).
USERNAME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_]{2,23}$")

# Must match static/js/crypto.js's SCRYPT_N (OWASP's minimum
# recommendation for scrypt). The client sends the cost it actually
# used and the server records it per account, so raising this later
# does not lock anyone out — /api/login-salt hands an existing account
# back the cost it was created under, and the client derives with
# that rather than with today's constant.
SCRYPT_N_CURRENT = 2**17

MAX_VAULT_BYTES = int(os.environ.get("KOSHA_MAX_VAULT_BYTES", 512 * 1024 * 1024))
MAX_BLOB_BYTES = int(os.environ.get("KOSHA_MAX_BLOB_BYTES", 256 * 1024 * 1024))

DATA_DIR = Path(os.environ.get("KOSHA_DATA_DIR", Path.home() / ".kosha"))

store = VaultStore(DATA_DIR / "kosha.db", DATA_DIR / "blobs")

STATIC_DIR = Path(__file__).resolve().parent.parent / "static"

app = FastAPI(title="Kosha", docs_url=None, redoc_url=None)


# One process serves both the page and the API, on one port, from one
# origin. That is a deliberate simplification over the two-service
# split Haven uses: it means no CORS configuration, no second
# Tailscale Funnel, and no "paste your API server URL here" box on the
# login screen for a beginner to get wrong. The page simply calls its
# own origin.
@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["Content-Security-Policy"] = CSP
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    # Nothing here may be shared with another origin, and nothing here
    # may embed one. Together these put the tab in its own process on
    # browsers that honour them, which is what makes the fine-grained
    # timers behind Spectre-style attacks unavailable to any script
    # that does somehow get loaded alongside the decryption keys.
    response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
    response.headers["Cross-Origin-Resource-Policy"] = "same-origin"

    # The page must always revalidate. index.html is what names the
    # script versions, so a browser holding a cached copy of it keeps
    # loading yesterday's JavaScript however many times the files
    # beside it change — which for an app whose crypto lives in those
    # files is a correctness and security problem, not a staleness
    # annoyance. `no-cache` still allows a 304, so this costs one
    # conditional request, not a re-download. The assets themselves are
    # fine to cache: they carry a ?v= in their URLs and get a new URL
    # whenever they change.
    path = request.url.path
    if path == "/" or path.endswith(".html"):
        response.headers["Cache-Control"] = "no-cache"
    return response


# `wasm-unsafe-eval` reads alarmingly but is the narrow, modern
# permission to compile WebAssembly — it does NOT re-enable eval() or
# inline scripts. SQLite runs as WASM in the page (static/vendor/
# sql-wasm.wasm), so without it the whole query engine fails to start.
# Note `connect-src 'self'`: this page is not permitted to talk to any
# other host at all, which is a meaningful backstop — even a bug in
# this app's own JavaScript cannot exfiltrate a decrypted row to
# somewhere else.
CSP = (
    "default-src 'self'; "
    "script-src 'self' 'wasm-unsafe-eval'; "
    "worker-src 'self' blob:; "
    "style-src 'self' 'unsafe-inline'; "
    "img-src 'self' data: blob:; "
    "font-src 'self'; "
    "connect-src 'self'; "
    "frame-ancestors 'none'; "
    "base-uri 'self'; "
    "form-action 'self'; "
    "object-src 'none'"
)


# ---------------------------------------------------------------------
# Rate limiting
# ---------------------------------------------------------------------

# Deliberately in-memory and deliberately coarse. It exists to make
# online guessing of a password or a recovery phrase pointless, not to
# survive a restart. In keeping with the project's data-retention
# stance it holds timestamps and nothing else — no addresses are
# written to disk, no request is logged with its body.
class _RateLimiter:
    def __init__(self, limit: int, window_seconds: int):
        self.limit = limit
        self.window = window_seconds
        self._hits: dict[str, deque] = defaultdict(deque)
        self._lock = threading.Lock()

    def check(self, key: str) -> bool:
        now = time.time()
        with self._lock:
            q = self._hits[key]
            while q and q[0] < now - self.window:
                q.popleft()
            if len(q) >= self.limit:
                return False
            q.append(now)
            if len(self._hits) > 10_000:  # bound the dict against churn
                for k in [k for k, v in self._hits.items() if not v]:
                    del self._hits[k]
            return True


_auth_limiter = _RateLimiter(limit=12, window_seconds=300)


def _client_key(request: Request) -> str:
    return request.client.host if request.client else "unknown"


def _guard_auth(request: Request) -> None:
    if not _auth_limiter.check(_client_key(request)):
        raise HTTPException(429, "Too many attempts. Wait five minutes and try again.")


# ---------------------------------------------------------------------
# Session dependency
# ---------------------------------------------------------------------


def current_user(authorization: str = Header(default="")) -> str:
    token = authorization[7:] if authorization.lower().startswith("bearer ") else ""
    username = store.resolve_session(token)
    if not username:
        raise HTTPException(401, "Session expired. Please sign in again.")
    return username


# ---------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------


class SignupRequest(BaseModel):
    username: str
    password_salt: str
    password_kdf_n: int = SCRYPT_N_CURRENT
    auth_key: str
    recovery_salt: str
    recovery_kdf_n: int = SCRYPT_N_CURRENT
    recovery_key: str
    keyring_password: str
    keyring_recovery: str

    @field_validator("username")
    @classmethod
    def _valid_username(cls, v: str) -> str:
        if not USERNAME_RE.match(v):
            raise ValueError(
                "Username must start with a letter and be 3-24 letters, numbers or underscores."
            )
        return v

    @field_validator("auth_key", "recovery_key", "password_salt", "recovery_salt")
    @classmethod
    def _hexish(cls, v: str) -> str:
        if not re.fullmatch(r"[0-9a-f]{16,128}", v):
            raise ValueError("expected a lowercase hex string")
        return v

    @field_validator("keyring_password", "keyring_recovery")
    @classmethod
    def _keyring_size(cls, v: str) -> str:
        # A wrapped 32-byte key is 12 (nonce) + 32 + 16 (tag) = 60
        # bytes, i.e. 80 base64 characters. Anything wildly different
        # is a client bug, and catching it here beats storing a vault
        # nobody can ever open.
        if not (40 <= len(v) <= 256):
            raise ValueError("keyring entry has an unexpected size")
        return v


class LoginRequest(BaseModel):
    username: str
    auth_key: str


class ResetRequest(BaseModel):
    username: str
    recovery_key: str
    password_salt: str
    password_kdf_n: int = SCRYPT_N_CURRENT
    auth_key: str
    keyring_password: str


class ChangePasswordRequest(BaseModel):
    current_auth_key: str
    password_salt: str
    password_kdf_n: int = SCRYPT_N_CURRENT
    auth_key: str
    keyring_password: str


class RotateRecoveryRequest(BaseModel):
    current_auth_key: str
    recovery_salt: str
    recovery_kdf_n: int = SCRYPT_N_CURRENT
    recovery_key: str
    keyring_recovery: str


# ---------------------------------------------------------------------
# Accounts
# ---------------------------------------------------------------------


@app.get("/api/health")
def health() -> dict:
    return {"ok": True, "service": "kosha", "scrypt_n": SCRYPT_N_CURRENT}


@app.post("/api/signup")
def signup(req: SignupRequest, request: Request) -> dict:
    _guard_auth(request)
    try:
        store.create_account(
            username=req.username,
            display_name=req.username,
            password_salt=req.password_salt,
            password_kdf_n=req.password_kdf_n,
            auth_key=req.auth_key,
            recovery_salt=req.recovery_salt,
            recovery_kdf_n=req.recovery_kdf_n,
            recovery_key=req.recovery_key,
            keyring_password=req.keyring_password,
            keyring_recovery=req.keyring_recovery,
        )
    except UsernameTaken:
        raise HTTPException(409, "That username is already taken.")
    token, expires = store.create_session(req.username)
    return {"username": req.username, "token": token, "expires_at": expires, "vault_version": 0}


@app.get("/api/login-salt")
def login_salt(username: str) -> dict:
    """The salt and KDF cost for an account, needed before the client
    can derive anything.

    This endpoint confirms whether a username exists, which is
    unavoidable: the client cannot derive the right key without the
    right salt, and inventing a plausible fake salt for unknown names
    would only move the tell to "your password is always wrong".
    Signup already leaks the same fact by rejecting taken names.
    """
    row = store.get_account(username)
    if not row:
        raise HTTPException(404, "No account with that username.")
    return {"password_salt": row["password_salt"], "password_kdf_n": row["password_kdf_n"]}


@app.get("/api/recovery-salt")
def recovery_salt(username: str) -> dict:
    row = store.get_account(username)
    if not row:
        raise HTTPException(404, "No account with that username.")
    return {"recovery_salt": row["recovery_salt"], "recovery_kdf_n": row["recovery_kdf_n"]}


@app.post("/api/login")
def login(req: LoginRequest, request: Request) -> dict:
    _guard_auth(request)
    if not store.verify_password(req.username, req.auth_key):
        raise HTTPException(401, "Wrong username or password.")
    row = store.get_account(req.username)
    token, expires = store.create_session(req.username)
    return {
        "username": row["display_name"],
        "token": token,
        "expires_at": expires,
        # The wrapped master key. Useless to anyone who cannot already
        # derive this account's enc_key, which is why it is safe to
        # hand out on a successful login and why the server handing it
        # out does not weaken anything.
        "keyring_password": row["keyring_password"],
        "vault_version": row["vault_version"],
    }


@app.post("/api/logout")
def logout(authorization: str = Header(default="")) -> dict:
    token = authorization[7:] if authorization.lower().startswith("bearer ") else ""
    if token:
        store.end_session(token)
    return {"ok": True}


@app.post("/api/recover")
def recover(req: ResetRequest, request: Request) -> dict:
    """Reset a forgotten password using the 12-word phrase.

    The server's part is small and stays small: check the recovery
    proof, then accept a new password wrapper for a master key it still
    cannot see. The client has already unwrapped the master key with
    the phrase and re-wrapped it under the new password locally. No
    plaintext key passes through here at any point.
    """
    _guard_auth(request)
    if not store.verify_recovery(req.username, req.recovery_key):
        raise HTTPException(401, "That recovery phrase does not match this account.")
    row = store.get_account(req.username)
    store.set_password(req.username, req.password_salt, req.password_kdf_n, req.auth_key, req.keyring_password)
    token, expires = store.create_session(req.username)
    return {
        "username": row["display_name"],
        "token": token,
        "expires_at": expires,
        "keyring_password": req.keyring_password,
        "vault_version": row["vault_version"],
    }


@app.get("/api/recovery-keyring")
def recovery_keyring(username: str, recovery_key: str, request: Request) -> dict:
    """Hand back the phrase-wrapped master key so the client can unwrap
    it and re-wrap under a new password. Gated on the recovery proof —
    the blob is opaque to us either way, but there is no reason to
    serve it to someone who has not demonstrated they can open it."""
    _guard_auth(request)
    if not store.verify_recovery(username, recovery_key):
        raise HTTPException(401, "That recovery phrase does not match this account.")
    row = store.get_account(username)
    return {"keyring_recovery": row["keyring_recovery"]}


@app.post("/api/change-password")
def change_password(req: ChangePasswordRequest, request: Request, username: str = Depends(current_user)) -> dict:
    _guard_auth(request)
    if not store.verify_password(username, req.current_auth_key):
        raise HTTPException(401, "Current password is wrong.")
    store.set_password(username, req.password_salt, req.password_kdf_n, req.auth_key, req.keyring_password)
    # set_password drops every session, including this one, so issue a
    # fresh token rather than logging the user out of the tab they are
    # standing in.
    token, expires = store.create_session(username)
    return {"ok": True, "token": token, "expires_at": expires}


@app.post("/api/rotate-recovery")
def rotate_recovery(req: RotateRecoveryRequest, request: Request, username: str = Depends(current_user)) -> dict:
    _guard_auth(request)
    if not store.verify_password(username, req.current_auth_key):
        raise HTTPException(401, "Current password is wrong.")
    store.set_recovery(username, req.recovery_salt, req.recovery_kdf_n, req.recovery_key, req.keyring_recovery)
    return {"ok": True}


# ---------------------------------------------------------------------
# The vault
# ---------------------------------------------------------------------


@app.get("/api/vault")
def get_vault(username: str = Depends(current_user)) -> Response:
    blob, version = store.get_vault(username)
    if blob is None:
        # A brand-new account. 204 rather than 404 so the client can
        # tell "you have no vault yet, create one" apart from "the
        # thing you asked for is missing", which would be alarming.
        return Response(status_code=204, headers={"X-Kosha-Version": "0"})
    return Response(
        content=blob,
        media_type="application/octet-stream",
        headers={"X-Kosha-Version": str(version), "Cache-Control": "no-store"},
    )


@app.put("/api/vault")
async def put_vault(request: Request, username: str = Depends(current_user)) -> dict:
    expected = request.headers.get("X-Kosha-Version")
    if expected is None or not expected.isdigit():
        raise HTTPException(400, "Missing X-Kosha-Version header.")
    body = await request.body()
    if not body:
        raise HTTPException(400, "Empty vault body.")
    if len(body) > MAX_VAULT_BYTES:
        raise HTTPException(413, f"Vault exceeds the {MAX_VAULT_BYTES // (1024 * 1024)} MB limit.")
    try:
        new_version = store.put_vault(username, body, int(expected))
    except VersionConflict as e:
        raise HTTPException(
            409,
            f"Your vault was changed in another tab or on another device (version {e.current_version}). "
            "Reload before saving again so nothing is lost.",
        )
    return {"ok": True, "vault_version": new_version}


# ---------------------------------------------------------------------
# Encrypted file blobs
# ---------------------------------------------------------------------


@app.post("/api/blob")
async def put_blob(request: Request, username: str = Depends(current_user)) -> dict:
    body = await request.body()
    if not body:
        raise HTTPException(400, "Empty blob.")
    if len(body) > MAX_BLOB_BYTES:
        raise HTTPException(413, f"File exceeds the {MAX_BLOB_BYTES // (1024 * 1024)} MB limit.")
    try:
        blob_id = store.put_blob(username, body)
    except QuotaExceeded:
        raise HTTPException(507, "You have used all of your storage quota.")
    return {"blob_id": blob_id, "size": len(body)}


@app.get("/api/blob/{blob_id}")
def fetch_blob(blob_id: str, username: str = Depends(current_user)) -> Response:
    if not re.fullmatch(r"[0-9a-f]{32}", blob_id):
        raise HTTPException(400, "Malformed blob id.")
    data = store.get_blob(username, blob_id)
    if data is None:
        raise HTTPException(404, "No such file.")
    return Response(content=data, media_type="application/octet-stream", headers={"Cache-Control": "no-store"})


@app.delete("/api/blob/{blob_id}")
def remove_blob(blob_id: str, username: str = Depends(current_user)) -> dict:
    if not re.fullmatch(r"[0-9a-f]{32}", blob_id):
        raise HTTPException(400, "Malformed blob id.")
    return {"deleted": store.delete_blob(username, blob_id)}


@app.post("/api/blob/gc")
def garbage_collect(keep: list[str] = Body(embed=True), username: str = Depends(current_user)) -> dict:
    """Delete blobs the vault no longer references.

    The client sends the complete set of ids its vault still points at,
    and anything else belonging to this account is removed. The server
    cannot work this out alone — knowing which blobs are still
    referenced would mean reading the vault, which it cannot do. That
    inversion of the usual arrangement (client decides, server obeys)
    is a direct consequence of the encryption, not an oversight.
    """
    keep_set = {k for k in keep if re.fullmatch(r"[0-9a-f]{32}", k)}
    removed = 0
    for blob_id in store.list_blob_ids(username):
        if blob_id not in keep_set:
            if store.delete_blob(username, blob_id):
                removed += 1
    return {"removed": removed}


@app.get("/api/keyring")
def keyring(username: str = Depends(current_user)) -> dict:
    """Both wrapped copies of the master key, for an export.

    Safe to serve to an authenticated session: these are 60 opaque
    bytes each, and the only things that open them are the password
    and the recovery phrase, neither of which this server has. The
    recovery wrapper is normally fetched via /api/recovery-keyring
    behind a phrase proof — that gate exists so a stranger cannot
    harvest wrappers by guessing usernames, not because a wrapper is
    secret from its own owner.
    """
    row = store.get_account(username)
    return {"keyring_password": row["keyring_password"], "keyring_recovery": row["keyring_recovery"]}


@app.get("/api/usage")
def usage(username: str = Depends(current_user)) -> dict:
    return store.stats(username)


@app.delete("/api/account")
def delete_account(confirm: str, username: str = Depends(current_user)) -> dict:
    """Delete everything. `confirm` must be the username, so a stray
    request cannot do this by accident."""
    if confirm.lower() != username.lower():
        raise HTTPException(400, "Confirmation did not match the username.")
    store.delete_account(username)
    return {"deleted": True}


# ---------------------------------------------------------------------
# The app itself
# ---------------------------------------------------------------------

# Mounted last, at the root, so it cannot shadow any /api route above.
# html=True makes "/" serve index.html.
app.mount("/", StaticFiles(directory=str(STATIC_DIR), html=True), name="static")
