# SPDX-License-Identifier: Apache-2.0
"""Registro de actividad de los usuarios de la consola (quién hizo qué y desde dónde).

Se escribe en logs/audit.log (0600), una línea por evento:
  2026-10-29T09:21:05-03:00  maria  operator  10.0.0.8  POST /api/m/takserver/users  200
Nunca se guardan datos de formularios, cabeceras ni cadenas de consulta: ahí van las contraseñas.
"""
import os
import re
import threading
from datetime import datetime

from .. import config

MAX_BYTES = 1_000_000
KEEP = 3
_LOCK = threading.Lock()
_CLEAN = re.compile(r"[^\x20-\x7e -￿]")


def _path():
    return config.LOG_DIR / "audit.log"


def clean(value, limit=120) -> str:
    """Una sola línea, sin caracteres de control (evita falsificar líneas del registro)."""
    return _CLEAN.sub("?", str(value if value is not None else "-")).replace(" ", "_")[:limit] or "-"


def _rotate(path):
    try:
        if path.stat().st_size < MAX_BYTES:
            return
    except OSError:
        return
    for i in range(KEEP, 0, -1):
        src = path if i == 1 else path.with_name(f"{path.name}.{i - 1}")
        dst = path.with_name(f"{path.name}.{i}")
        if src.exists():
            os.replace(src, dst)


def record(user, role, ip, action, status="") -> None:
    line = "  ".join([datetime.now().astimezone().isoformat(timespec="seconds"), clean(user),
                      clean(role), clean(ip), clean(action, 200), clean(status)]) + "\n"
    path = _path()
    with _LOCK:
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            _rotate(path)
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
            with os.fdopen(fd, "a", encoding="utf-8") as fh:
                fh.write(line)
        except OSError:
            pass   # el registro nunca debe impedir la acción


def tail(n=100) -> list:
    try:
        with open(_path(), "rb") as fh:
            fh.seek(0, os.SEEK_END)
            size = fh.tell()
            fh.seek(max(0, size - 64_000))
            text = fh.read().decode("utf-8", errors="replace")
    except OSError:
        return []
    return text.splitlines()[-n:][::-1]   # lo más reciente primero
