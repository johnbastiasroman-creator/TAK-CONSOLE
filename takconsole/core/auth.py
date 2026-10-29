# SPDX-License-Identifier: Apache-2.0
"""Autenticación de la consola: inicio de sesión, límite de intentos y CSRF.

Los usuarios y sus roles viven en core/users.py."""
import hmac
import secrets
import threading
import time

from .. import config
from . import users
from .users import MIN_PASSWORD  # noqa: F401  (lo usa la CLI)

_FAILS = {}
_FAILS_LOCK = threading.Lock()
MAX_FAILS = 5
LOCK_SECONDS = 300


def is_configured() -> bool:
    return users.is_configured()


def authenticate(username: str, password: str):
    """Usuario (dict público) si las credenciales son válidas y la cuenta está activa."""
    return users.authenticate(username, password)


def verify(user: str, password: str) -> bool:
    """¿Es `password` la contraseña de `user`? (confirmación de acciones peligrosas)"""
    return users.authenticate(user, password) is not None


def set_password(password: str, username: str = "admin"):
    """Recuperación desde el servidor: fija la contraseña (y reactiva la cuenta); crea el
    usuario como administrador si no existe."""
    return users.reset_or_create_admin(username, password)


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
