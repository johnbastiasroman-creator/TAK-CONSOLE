# SPDX-License-Identifier: Apache-2.0
"""Ayudas para Docker y Docker Compose."""
import json
import os
from pathlib import Path

import yaml

from .shell import capture, run


def available() -> bool:
    return capture(["docker", "info", "--format", "{{.ServerVersion}}"], timeout=10).ok


def compose_file(stack_dir: Path) -> Path:
    return Path(stack_dir) / "compose.yaml"


def write_compose(stack_dir: Path, data: dict):
    stack_dir = Path(stack_dir)
    stack_dir.mkdir(parents=True, exist_ok=True)
    os.chmod(stack_dir, 0o700)
    text = "# Generado por la consola. Los cambios manuales se sobrescriben al redesplegar.\n"
    text += yaml.safe_dump(data, sort_keys=False, default_flow_style=False, allow_unicode=True)
    write_private(compose_file(stack_dir), text)


def write_private(path: Path, text: str, mode=0o600):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name("." + path.name + ".tmp")
    with open(tmp, "w", encoding="utf-8") as fh:
        fh.write(text)
    os.chmod(tmp, mode)
    os.replace(tmp, path)


def write_env(path: Path, values: dict):
    """Archivo .env para env_file (permisos 600).

    Cada valor va entre comillas simples: Docker Compose lo toma literal (sin
    interpolar $ ni quitar comillas dobles internas)."""
    lines = []
    for k, v in values.items():
        v = "" if v is None else str(v)
        if "\n" in v or "\r" in v or "'" in v:
            raise ValueError(f"valor no permitido en {k} (salto de línea o comilla simple)")
        lines.append(f"{k}='{v}'")
    write_private(path, "\n".join(lines) + "\n")


def compose(stack_dir: Path, *args, log=None, timeout=1800, check=True):
    stack_dir = Path(stack_dir)
    argv = ["docker", "compose", "--project-directory", str(stack_dir),
            "-f", str(compose_file(stack_dir)), *args]
    return run(argv, log=log, timeout=timeout, check=check)


def container_state(name: str) -> dict:
    """{'exists': bool, 'running': bool, 'status': str, 'health': str|None}"""
    res = capture(["docker", "inspect", "--format", "{{json .State}}", name], timeout=8)
    if not res.ok:
        return {"exists": False, "running": False, "status": "ausente", "health": None}
    try:
        st = json.loads(res.output.strip().splitlines()[0])
    except (ValueError, IndexError):
        return {"exists": False, "running": False, "status": "desconocido", "health": None}
    health = (st.get("Health") or {}).get("Status")
    return {"exists": True, "running": bool(st.get("Running")),
            "status": st.get("Status", ""), "health": health}


def logs(name: str, lines=200) -> str:
    res = capture(["docker", "logs", "--tail", str(lines), name], timeout=15, merge=True)
    return res.output


def exec_(name: str, *args, timeout=30):
    return capture(["docker", "exec", name, *args], timeout=timeout)
