"""_auth.py — Authentication, TLS and security hardening for pr0t31n Flask apps.

Drop this file into any app directory. It self-references its own location so
all credential / cert / key files land in the same folder as app.py.
"""
from __future__ import annotations

import json
import os
import secrets
import ssl
import subprocess
import threading
import time
from pathlib import Path
from typing import Optional

from flask import redirect, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash

# ── Directory (same folder this file lives in, i.e. the app root) ────────────
_DIR = Path(__file__).parent.resolve()

_DEFAULT_USERNAME = "admin"
_DEFAULT_PASSWORD = "t3mpPas$w0rd"

# ── Credential policy ─────────────────────────────────────────────────────────

_BLOCKED_USERNAMES: frozenset = frozenset({
    "admin", "administrator", "root", "user", "users", "guest", "test",
    "demo", "superuser", "super", "sysadmin", "operator", "manager",
    "owner", "service", "support", "helpdesk", "webmaster", "postmaster",
    "nobody", "default", "anonymous", "anon", "public", "system",
    "login", "logon", "access", "account", "info", "mail", "noreply",
})

_BLOCKED_PASSWORDS: frozenset = frozenset({
    "password", "password1", "password123", "passwords",
    "123456", "1234567", "12345678", "123456789", "1234567890",
    "qwerty", "qwerty123", "qwertyuiop", "asdfghjkl", "zxcvbnm",
    "abc123", "letmein", "welcome", "welcome1", "welcome123",
    "admin", "admin123", "admin1234", "administrator",
    "changeme", "change_me", "changeme1", "iloveyou",
    "monkey", "dragon", "master", "shadow", "sunshine",
    "princess", "superman", "batman", "trustno1",
    "baseball", "football", "soccer", "hockey", "hockey1",
    "pass", "pass123", "pass1234", "passw0rd",
    "test", "test123", "test1234", "testing",
    "guest", "login", "logon", "access",
    "t3mppass", _DEFAULT_PASSWORD.lower(),
})

def is_weak_username(username: str) -> Optional[str]:
    """Return an error string if the username is invalid, else None."""
    if not username:
        return "Username cannot be empty."
    if len(username) < 3:
        return "Username must be at least 3 characters."
    if len(username) > 32:
        return "Username must be 32 characters or fewer."
    if username.lower() in _BLOCKED_USERNAMES:
        return f"'{username}' is not allowed. Choose a unique username."
    return None

def is_weak_password(password: str, username: str = "") -> Optional[str]:
    """Return an error string if the password is too common or matches the username, else None."""
    if password.lower() in _BLOCKED_PASSWORDS:
        return "That password is too common. Choose a stronger password."
    if username and password.lower() == username.lower():
        return "Password cannot be the same as the username."
    return None

# ── Persistent secret key ─────────────────────────────────────────────────────

def load_secret_key() -> str:
    """Return a persistent 64-hex-char secret key, creating the file on first run."""
    key_file = _DIR / ".secret_key"
    if key_file.exists():
        key = key_file.read_text().strip()
        if len(key) >= 32:
            return key
    key = secrets.token_hex(32)
    key_file.write_text(key + "\n")
    key_file.chmod(0o600)
    return key

# ── Credential store ──────────────────────────────────────────────────────────

_AUTH_FILE = _DIR / ".auth.json"

def init_auth() -> None:
    """Create default credentials if the auth file does not exist."""
    if not _AUTH_FILE.exists():
        _write_auth({
            "username": _DEFAULT_USERNAME,
            "password_hash": generate_password_hash(_DEFAULT_PASSWORD),
            "must_change": True,
        })

def _load_auth() -> dict:
    return json.loads(_AUTH_FILE.read_text())

def _write_auth(data: dict) -> None:
    _AUTH_FILE.write_text(json.dumps(data, indent=2))
    _AUTH_FILE.chmod(0o600)

def verify_credentials(username: str, password: str) -> bool:
    try:
        data = _load_auth()
        return (data.get("username") == username and
                check_password_hash(data.get("password_hash", ""), password))
    except Exception:
        return False

def must_change_password() -> bool:
    try:
        return bool(_load_auth().get("must_change"))
    except Exception:
        return False

def get_username() -> str:
    try:
        return _load_auth().get("username", "admin")
    except Exception:
        return "admin"

def check_current_password(password: str) -> bool:
    try:
        return check_password_hash(_load_auth().get("password_hash", ""), password)
    except Exception:
        return False

def update_password(new_password: str) -> None:
    data = _load_auth()
    data["password_hash"] = generate_password_hash(new_password)
    data["must_change"] = False
    _write_auth(data)

def update_credentials(new_username: str, new_password: str) -> None:
    """Replace username and password atomically. Clears must_change flag."""
    _write_auth({
        "username": new_username,
        "password_hash": generate_password_hash(new_password),
        "must_change": False,
    })

# ── CSRF (server-side synchronizer token) ────────────────────────────────────

_csrf_store: dict = {}
_csrf_lock = threading.Lock()

def generate_csrf() -> str:
    """Issue a one-time CSRF token stored server-side (no cookie/session needed)."""
    token = secrets.token_hex(16)
    now = time.time()
    with _csrf_lock:
        # Prune expired tokens
        expired = [t for t, exp in list(_csrf_store.items()) if exp < now]
        for t in expired:
            del _csrf_store[t]
        _csrf_store[token] = now + 3600   # valid for 1 hour
    return token

def validate_csrf(token: Optional[str]) -> bool:
    """Consume and validate a CSRF token from the server-side store."""
    if not token:
        return False
    with _csrf_lock:
        expiry = _csrf_store.pop(token, None)
    if expiry is None:
        return False
    return time.time() < expiry

# ── TLS ───────────────────────────────────────────────────────────────────────

_CIPHERS = (
    "ECDHE-ECDSA-AES256-GCM-SHA384:"
    "ECDHE-RSA-AES256-GCM-SHA384:"
    "ECDHE-ECDSA-CHACHA20-POLY1305:"
    "ECDHE-RSA-CHACHA20-POLY1305:"
    "ECDHE-ECDSA-AES128-GCM-SHA256:"
    "ECDHE-RSA-AES128-GCM-SHA256:"
    "!aNULL:!eNULL:!EXPORT:!DES:!RC4:!MD5:!PSK:!SRP:!3DES"
)

def _local_ips_for_cert() -> str:
    """Return a comma-separated SAN string covering all local IPv4 addresses."""
    ips: set = {"127.0.0.1"}
    try:
        if os.path.exists("/sbin/ip") or os.path.exists("/usr/sbin/ip"):
            out = subprocess.check_output(["ip", "-4", "addr"], text=True, timeout=5)
            for line in out.splitlines():
                line = line.strip()
                if line.startswith("inet "):
                    ip = line.split()[1].split("/")[0]
                    if not ip.startswith("127."):
                        ips.add(ip)
        else:
            out = subprocess.check_output(["ifconfig"], text=True, timeout=5)
            for line in out.splitlines():
                line = line.strip()
                if line.startswith("inet ") and "127.0.0.1" not in line:
                    parts = line.split()
                    idx = parts.index("inet") + 1
                    ip = parts[idx]
                    if not ip.startswith("127."):
                        ips.add(ip)
    except Exception:
        pass
    return ",".join(f"IP:{ip}" for ip in sorted(ips)) + ",DNS:localhost"


def make_ssl_context() -> ssl.SSLContext:
    """Return a hardened SSLContext, generating a self-signed cert if absent."""
    cert = _DIR / "ssl.crt"
    key  = _DIR / "ssl.key"
    if not cert.exists() or not key.exists():
        san = _local_ips_for_cert()
        subprocess.run(
            [
                "openssl", "req", "-x509", "-newkey", "rsa:4096",
                "-nodes", "-days", "3650",
                "-keyout", str(key), "-out", str(cert),
                "-subj", "/C=US/ST=Local/L=Local/O=pr0t31n/CN=localhost",
                "-addext", f"subjectAltName={san}",
            ],
            check=True, capture_output=True,
        )
        key.chmod(0o600)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(str(cert), str(key))
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    try:
        ctx.set_ciphers(_CIPHERS)
    except ssl.SSLError:
        pass  # fall back to platform defaults if the cipher string is rejected
    return ctx

# ── Security headers ──────────────────────────────────────────────────────────

_CSP = (
    "default-src 'self'; "
    "script-src 'self' 'unsafe-inline' https://cdn.socket.io; "
    "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
    "font-src 'self' https://fonts.gstatic.com data:; "
    "img-src 'self' data:; "
    "connect-src 'self' wss: ws:; "
    "frame-ancestors 'none'; "
    "base-uri 'self'; "
    "form-action 'self'"
)

def apply_security_headers(response):
    h = response.headers
    h["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    h["Content-Security-Policy"]   = _CSP
    h["X-Frame-Options"]           = "DENY"
    h["X-Content-Type-Options"]    = "nosniff"
    h["Referrer-Policy"]           = "strict-origin-when-cross-origin"
    h["Permissions-Policy"]        = "geolocation=(), microphone=(), camera=()"
    h["X-XSS-Protection"]          = "1; mode=block"
    return response

# ── Request gate ──────────────────────────────────────────────────────────────

_PUBLIC = {"/login", "/logout", "/api/nexus-status"}

def auth_gate():
    """Call from app.before_request. Returns a redirect Response if auth needed, else None."""
    path = request.path
    if path.startswith("/static/") or path.startswith("/socket.io/"):
        return None
    if path in _PUBLIC:
        return None
    if not session.get("authenticated"):
        return redirect(url_for("login", next=request.path))
    if must_change_password() and path != "/auth/change-password":
        return redirect(url_for("change_password"))
    return None
