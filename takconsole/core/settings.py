# SPDX-License-Identifier: Apache-2.0
"""Estado persistente en JSON (sin base de datos).

Todo el estado vive en data/config/settings.json con permisos 600.
Las escrituras son atómicas (archivo temporal + os.replace).
"""
import copy
import json
import os
import tempfile
import threading
from pathlib import Path

from .. import config

_LOCK = threading.RLock()


def _path() -> Path:
    return config.CONFIG_DIR / "settings.json"


def write_json_atomic(path: Path, data, mode=0o600):
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix=".tmp-")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2, ensure_ascii=False, sort_keys=True)
            fh.write("\n")
        os.chmod(tmp, mode)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def load() -> dict:
    with _LOCK:
        p = _path()
        if not p.exists():
            return {}
        try:
            with open(p, encoding="utf-8") as fh:
                data = json.load(fh)
            return data if isinstance(data, dict) else {}
        except (OSError, ValueError):
            return {}


def save(data: dict):
    with _LOCK:
        write_json_atomic(_path(), data)


def section(name: str) -> dict:
    """Copia de la sección de un módulo (modificar y guardar con update_section)."""
    return copy.deepcopy(load().get(name, {}))


def update_section(name: str, values: dict) -> dict:
    with _LOCK:
        data = load()
        sec = data.get(name, {})
        sec.update(values)
        data[name] = sec
        save(data)
        return copy.deepcopy(sec)


def replace_section(name: str, values: dict):
    with _LOCK:
        data = load()
        data[name] = values
        save(data)


def delete_section(name: str):
    with _LOCK:
        data = load()
        if name in data:
            del data[name]
            save(data)
