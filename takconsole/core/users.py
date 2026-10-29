# SPDX-License-Identifier: Apache-2.0
"""Usuarios de la consola: almacén en config/users.json con contraseñas con hash.

Reglas que se cumplen siempre (aquí, no en la interfaz):
  · siempre queda al menos un administrador activo;
  · los nombres son únicos sin distinguir mayúsculas;
  · la contraseña tiene al menos MIN_PASSWORD caracteres;
  · cambiar la contraseña o desactivar la cuenta invalida sus sesiones (campo «changed»).

La instalación 0.1.x guardaba un único usuario en config/auth.json; se migra solo, la primera
vez, como administrador. El archivo viejo se deja donde está (no se borra nada del usuario).
"""
import json
import re
import threading
import time

from werkzeug.security import check_password_hash, generate_password_hash

from .. import config
from . import rbac
from .settings import write_json_atomic

MIN_PASSWORD = 12
USERNAME = re.compile(r"[A-Za-z0-9._-]{3,32}")
USERNAME_MSG = "3 a 32 caracteres: letras, números, punto, guion y guion bajo"
_LOCK = threading.RLock()
# Hash de relleno: al fallar el usuario se verifica igual una contraseña contra él, para que
# «usuario inexistente» y «contraseña incorrecta» tarden parecido.
_DUMMY = generate_password_hash("relleno-para-igualar-tiempos")


def _path():
    return config.CONFIG_DIR / "users.json"


def _legacy_path():
    return config.CONFIG_DIR / "auth.json"


def _read(path):
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def _load() -> list:
    """Lista de usuarios (dicts). Migra auth.json la primera vez."""
    with _LOCK:
        data = _read(_path())
        if "users" in data:
            return [u for u in data["users"] if isinstance(u, dict) and u.get("username")]
        legacy = _read(_legacy_path())
        if legacy.get("hash"):
            users = [{"username": legacy.get("username", "admin"), "hash": legacy["hash"],
                      "role": "admin", "disabled": False,
                      "created": legacy.get("changed", int(time.time())),
                      "changed": legacy.get("changed", int(time.time()))}]
            _save(users)
            return users
        return []


def _save(users: list):
    write_json_atomic(_path(), {"version": 1, "users": users})


def _find(users, username):
    low = (username or "").lower()
    return next((u for u in users if u["username"].lower() == low), None)


def _enabled_admins(users):
    return [u for u in users if u.get("role") == "admin" and not u.get("disabled")]


def _check_password(password):
    if len(password or "") < MIN_PASSWORD:
        raise ValueError(f"La contraseña debe tener al menos {MIN_PASSWORD} caracteres")


def _stamp(u):
    """Marca de cambio de credenciales. Estrictamente creciente: dos cambios en el mismo segundo
    siguen invalidando las sesiones abiertas."""
    u["changed"] = max(int(time.time()), int(u.get("changed", 0)) + 1)


def _public(u):
    return {"username": u["username"], "role": u.get("role", "viewer"),
            "disabled": bool(u.get("disabled")), "created": u.get("created", 0),
            "changed": u.get("changed", 0), "last_login": u.get("last_login", 0)}


# ── consulta ────────────────────────────────────────────────────────────────
def is_configured() -> bool:
    return bool(_load())


def list_users() -> list:
    return sorted((_public(u) for u in _load()), key=lambda u: (rbac.ROLE_ORDER.index(u["role"])
                                                               if u["role"] in rbac.ROLE_ORDER else 9,
                                                               u["username"].lower()))


def get(username):
    """Usuario público (sin hash) o None."""
    with _LOCK:
        u = _find(_load(), username)
        return _public(u) if u else None


def authenticate(username, password):
    """Devuelve el usuario (público) si las credenciales son válidas y la cuenta está activa."""
    with _LOCK:
        u = _find(_load(), username)
    ok = check_password_hash(u["hash"] if u else _DUMMY, password or "")
    if u and ok and not u.get("disabled"):
        return _public(u)
    return None


def touch_login(username):
    with _LOCK:
        users = _load()
        u = _find(users, username)
        if u:
            u["last_login"] = int(time.time())
            _save(users)


# ── cambios ─────────────────────────────────────────────────────────────────
def create(username, password, role):
    if not USERNAME.fullmatch(username or ""):
        raise ValueError(USERNAME_MSG)
    if role not in rbac.ROLES:
        raise ValueError("Rol inválido")
    _check_password(password)
    with _LOCK:
        users = _load()
        if _find(users, username):
            raise ValueError("Ya existe un usuario con ese nombre")
        now = int(time.time())
        users.append({"username": username, "hash": generate_password_hash(password),
                      "role": role, "disabled": False, "created": now, "changed": now})
        _save(users)
        return _public(users[-1])


def set_password(username, password):
    _check_password(password)
    with _LOCK:
        users = _load()
        u = _find(users, username)
        if not u:
            raise ValueError("No existe ese usuario")
        u["hash"] = generate_password_hash(password)
        _stamp(u)
        _save(users)
        return _public(u)


def set_role(username, role):
    if role not in rbac.ROLES:
        raise ValueError("Rol inválido")
    with _LOCK:
        users = _load()
        u = _find(users, username)
        if not u:
            raise ValueError("No existe ese usuario")
        if u.get("role") == "admin" and role != "admin" and _enabled_admins(users) == [u]:
            raise ValueError("No puedes quitar el rol al único administrador activo")
        u["role"] = role
        _save(users)
        return _public(u)


def set_disabled(username, disabled: bool):
    with _LOCK:
        users = _load()
        u = _find(users, username)
        if not u:
            raise ValueError("No existe ese usuario")
        if disabled and u.get("role") == "admin" and _enabled_admins(users) == [u]:
            raise ValueError("No puedes desactivar al único administrador activo")
        u["disabled"] = bool(disabled)
        _stamp(u)   # invalida sus sesiones abiertas
        _save(users)
        return _public(u)


def delete(username):
    with _LOCK:
        users = _load()
        u = _find(users, username)
        if not u:
            raise ValueError("No existe ese usuario")
        if u.get("role") == "admin" and not u.get("disabled") and _enabled_admins(users) == [u]:
            raise ValueError("No puedes eliminar al único administrador activo")
        users.remove(u)
        _save(users)


def reset_or_create_admin(username, password):
    """Recuperación desde el servidor (CLI): fija la contraseña y reactiva la cuenta; si el
    usuario no existe lo crea como administrador."""
    _check_password(password)
    with _LOCK:
        users = _load()
        u = _find(users, username)
        if u is None:
            return create(username, password, "admin")
        u["hash"] = generate_password_hash(password)
        u["disabled"] = False
        _stamp(u)
        _save(users)
        return _public(u)
