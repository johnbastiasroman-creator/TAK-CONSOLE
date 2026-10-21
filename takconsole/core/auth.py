# SPDX-License-Identifier: Apache-2.0
"""Autenticación de la consola: un usuario administrador, sesión y CSRF."""
import hmac
import secrets
import threading
import time

from werkzeug.security import check_password_hash, generate_password_hash

from .. import config
from .settings import write_json_atomic

MIN_PASSWORD = 12
_FAILS = {}
_FAILS_LOCK = threading.Lock()
MAX_FAILS = 5
LOCK_SECONDS = 300


def _auth_path():
    return config.CONFIG_DIR / "auth.json"


def is_configured() -> bool:
    return _auth_path().exists()


def _load():
    import json
    try:
        with open(_auth_path(), encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return {}


def set_password(password: str, username: str = "admin"):
    if len(password) < MIN_PASSWORD:
        raise ValueError(f"La contraseña debe tener al menos {MIN_PASSWORD} caracteres")
    write_json_atomic(_auth_path(), {
        "username": username,
        "hash": generate_password_hash(password),
        "changed": int(time.time()),
    })


def username() -> str:
    return _load().get("username", "admin")


def verify(user: str, password: str) -> bool:
    data = _load()
    if not data.get("hash"):
        return False
    user_ok = hmac.compare_digest(user or "", data.get("username", "admin"))
    pass_ok = check_password_hash(data["hash"], password or "")
    return user_ok and pass_ok


# ── limitación de intentos por IP ───────────────────────────────────────────
def locked_out(ip: str) -> int:
    """Segundos restantes de bloqueo para la IP (0 si no está bloqueada)."""
    with _FAILS_LOCK:
        count, first = _FAILS.get(ip, (0, 0))
        if count >= MAX_FAILS:
            remaining = int(LOCK_SECONDS - (time.time() - first))
            if remaining > 0:
                return remaining
            _FAILS.pop(ip, None)
        return 0


def record_failure(ip: str):
    with _FAILS_LOCK:
        count, first = _FAILS.get(ip, (0, time.time()))
        if time.time() - first > LOCK_SECONDS:
            count, first = 0, time.time()
        _FAILS[ip] = (count + 1, first)


def clear_failures(ip: str):
    with _FAILS_LOCK:
        _FAILS.pop(ip, None)


# ── CSRF ────────────────────────────────────────────────────────────────────
def csrf_token(session) -> str:
    tok = session.get("csrf")
    if not tok:
        tok = secrets.token_urlsafe(32)
        session["csrf"] = tok
    return tok


def csrf_valid(session, supplied: str) -> bool:
    tok = session.get("csrf")
    return bool(tok and supplied and hmac.compare_digest(tok, supplied))


def secret_key() -> bytes:
    p = config.CONFIG_DIR / "secret_key"
    if p.exists():
        return p.read_bytes()
    key = secrets.token_bytes(48)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(key)
    p.chmod(0o600)
    return key
