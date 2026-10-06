"""Server-side checks, run against a throwaway data directory.

These exist mostly to pin down the properties the security story
depends on: that a wrong proof is refused, that one tab cannot silently
overwrite another's vault, that one account cannot reach another's
blobs, and that deleting an account really removes the bytes.

Run:  python3 tests/test_server.py
"""

from __future__ import annotations

import os
import shutil
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

DATA = tempfile.mkdtemp(prefix="kosha-test-")
os.environ["KOSHA_DATA_DIR"] = DATA

from fastapi.testclient import TestClient  # noqa: E402

from server.server import app  # noqa: E402

client = TestClient(app)

passed = failed = 0


def check(name: str, ok: bool, detail: str = "") -> None:
    global passed, failed
    if ok:
        passed += 1
        print(f"  ok   {name}")
    else:
        failed += 1
        print(f"  FAIL {name}" + (f"\n       {detail}" if detail else ""))


def make_account(username: str, suffix: str = "a") -> dict:
    body = {
        "username": username,
        "password_salt": suffix * 32,
        "password_kdf_n": 2**17,
        "auth_key": suffix * 64,
        "recovery_salt": suffix * 32,
        "recovery_kdf_n": 2**17,
        "recovery_key": (suffix.upper() if suffix.isalpha() else suffix) * 64,
        "keyring_password": "P" * 80,
        "keyring_recovery": "R" * 80,
    }
    # auth/recovery keys must be lowercase hex
    body["recovery_key"] = ("b" if suffix == "a" else "e") * 64
    return body


print("Accounts")
r = client.post("/api/signup", json=make_account("alice"))
check("signup succeeds", r.status_code == 200, str(r.json()))
alice = {"Authorization": f"Bearer {r.json()['token']}"}

check("duplicate username is refused", client.post("/api/signup", json=make_account("ALICE")).status_code == 409)
check("a bad username is refused", client.post("/api/signup", json=make_account("1nope")).status_code == 422)

r = client.post("/api/login", json={"username": "alice", "auth_key": "a" * 64})
check("login with the right proof succeeds", r.status_code == 200)
check("login returns the wrapped master key", r.json().get("keyring_password") == "P" * 80)
alice = {"Authorization": f"Bearer {r.json()['token']}"}

check("login with a wrong proof is refused", client.post("/api/login", json={"username": "alice", "auth_key": "0" * 64}).status_code == 401)
check("an unknown account is a 404, not a 500", client.get("/api/login-salt?username=nobody").status_code == 404)
check(
    "the stored KDF cost is handed back",
    client.get("/api/login-salt?username=alice").json()["password_kdf_n"] == 2**17,
)

print("\nThe vault")
check("a new account has no vault yet", client.get("/api/vault", headers=alice).status_code == 204)
r = client.put("/api/vault", headers={**alice, "X-Kosha-Version": "0"}, content=b"ciphertext-one")
check("the first save works", r.status_code == 200 and r.json()["vault_version"] == 1)
check(
    "a save against a stale version is refused",
    client.put("/api/vault", headers={**alice, "X-Kosha-Version": "0"}, content=b"clobber").status_code == 409,
)
r = client.get("/api/vault", headers=alice)
check("the vault comes back byte for byte", r.content == b"ciphertext-one")
check("the version travels with it", r.headers.get("X-Kosha-Version") == "1")
check(
    "a save with no version header is refused",
    client.put("/api/vault", headers=alice, content=b"x").status_code == 400,
)

print("\nBlobs and isolation")
blob_id = client.post("/api/blob", headers=alice, content=b"encrypted-file").json()["blob_id"]
check("a blob can be stored and fetched", client.get(f"/api/blob/{blob_id}", headers=alice).content == b"encrypted-file")
check("a malformed blob id is refused", client.get("/api/blob/not-an-id", headers=alice).status_code == 400)
check("an unknown blob is a 404", client.get(f"/api/blob/{'f' * 32}", headers=alice).status_code == 404)

r = client.post("/api/signup", json=make_account("bob", "c"))
bob = {"Authorization": f"Bearer {r.json()['token']}"}
check("another account cannot read your blob", client.get(f"/api/blob/{blob_id}", headers=bob).status_code == 404)
check("another account cannot delete your blob", client.delete(f"/api/blob/{blob_id}", headers=bob).json()["deleted"] is False)
check("another account cannot read your vault", client.get("/api/vault", headers=bob).status_code == 204)
check("no token means no access", client.get("/api/usage").status_code == 401)
check("a forged token means no access", client.get("/api/usage", headers={"Authorization": "Bearer nope"}).status_code == 401)

print("\nHousekeeping")
usage = client.get("/api/usage", headers=alice).json()
check("usage counts the blob", usage["blob_count"] == 1 and usage["blob_bytes"] == len(b"encrypted-file"))
check("gc keeps what is referenced", client.post("/api/blob/gc", headers=alice, json={"keep": [blob_id]}).json()["removed"] == 0)
check("gc removes what is not", client.post("/api/blob/gc", headers=alice, json={"keep": []}).json()["removed"] == 1)

kept = client.post("/api/blob", headers=alice, content=b"keep-me").json()["blob_id"]
on_disk = list(Path(DATA, "blobs").rglob("*"))
check("blob bytes are on disk", any(p.is_file() for p in on_disk))
check(
    "deleting an account needs a matching confirmation",
    client.delete("/api/account?confirm=wrong", headers=alice).status_code == 400,
)
check("deleting an account succeeds", client.delete("/api/account?confirm=alice", headers=alice).json()["deleted"] is True)
check("its blob files are gone from disk", not [p for p in Path(DATA, "blobs").rglob("*") if p.is_file() and kept in p.name])
check("its session no longer works", client.get("/api/usage", headers=alice).status_code == 401)

print("\nSecurity headers")
h = client.get("/api/health").headers
check("CSP forbids outbound connections", "connect-src 'self'" in h.get("Content-Security-Policy", ""))
check("CSP allows WebAssembly", "'wasm-unsafe-eval'" in h.get("Content-Security-Policy", ""))
check("framing is denied", h.get("X-Frame-Options") == "DENY")
check("no referrer is sent", h.get("Referrer-Policy") == "no-referrer")

shutil.rmtree(DATA, ignore_errors=True)
print(f"\n{passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
