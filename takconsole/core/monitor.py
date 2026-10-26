# SPDX-License-Identifier: Apache-2.0
"""Consolas de estado y actividad de cada servicio.

Cada módulo describe sus fuentes con cuatro ganchos opcionales (ver modules/base.py):
  log_lines(n, source)  → líneas de registro recientes
  line_level(line)      → 'info' | 'warn' | 'err'
  EVENT_RULES           → [(regex, tipo, etiqueta)] de eventos clave
  checks()              → comprobaciones de salud [{label, ok, detail}]
  connected()           → quién está conectado (tabla)

Aquí se combinan en una instantánea JSON que la interfaz vuelve a pedir cada pocos
segundos. Todo lo que viene de los registros (indicativos, nombres, rutas de video) lo
escribe un tercero: la interfaz lo muestra siempre con textContent, y aquí se
enmascaran los valores que parecen contraseñas o tokens.
"""
import re
import time
from datetime import datetime, timezone

LINE_CAP = 300       # líneas que se envían en cada instantánea
MAX_LINE = 600       # caracteres por línea
ROW_CAP = 500        # filas de la tabla de conectados
VIEWS = ("events", "raw", "clients")

SECRET = re.compile(r"(?i)\b(pass(?:word)?|pwd|token|secret|apikey|api_key)=([^&\s\"']+)")
GENERIC_ERR = re.compile(r"\b(ERROR|ERR|FATAL|SEVERE|CRITICAL)\b")
GENERIC_WARN = re.compile(r"\b(WARN|WARNING|WAR)\b")


def redact(text: str) -> str:
    return SECRET.sub(lambda m: f"{m.group(1)}=******", text)


def generic_level(line: str) -> str:
    if GENERIC_ERR.search(line):
        return "err"
    if GENERIC_WARN.search(line):
        return "warn"
    return "info"


def classify(rules, line: str):
    """Primera regla que coincide → {'kind', 'tag'} (kind: ok | info | warn | err)."""
    for rx, kind, tag in rules:
        if rx.search(line):
            return {"kind": kind, "tag": tag}
    return None


def process_lines(module, lines):
    out = []
    for raw in lines[-LINE_CAP:]:
        line = redact(raw.rstrip("\r\n"))[:MAX_LINE]
        if not line.strip():
            continue
        level = module.line_level(line)
        ev = classify(module.EVENT_RULES, line)
        if ev is None and level in ("warn", "err"):
            ev = {"kind": level, "tag": "ERROR" if level == "err" else "AVISO"}
        out.append({"text": line, "level": level, "event": ev})
    return out


def table(columns, rows, note="", error=None):
    return {"columns": columns, "rows": [[("" if c is None else str(c)) for c in r]
                                          for r in rows[:ROW_CAP]],
            "total": len(rows), "note": note, "error": error}


def parse_ts(value):
    """RFC 3339 (como lo escribe Go, con hasta 9 decimales) → segundos epoch, o None."""
    if not isinstance(value, str) or not value:
        return None
    s = re.sub(r"(\.\d{6})\d+", r"\1", value.strip().replace("Z", "+00:00"))
    try:
        dt = datetime.fromisoformat(s)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.timestamp()


def human_bytes(n) -> str:
    try:
        n = float(n)
    except (TypeError, ValueError):
        return "—"
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return "—"


def age(seconds) -> str:
    try:
        s = int(seconds)
    except (TypeError, ValueError):
        return "—"
    if s < 0:
        s = 0
    if s < 90:
        return f"{s} s"
    if s < 5400:
        return f"{s // 60} min"
    if s < 172800:
        return f"{s // 3600} h"
    return f"{s // 86400} d"


def snapshot(module, view: str, source: str = "") -> dict:
    """Instantánea del servicio para la interfaz. Nunca lanza: los fallos van en 'error'."""
    if view not in VIEWS:
        view = "events"
    st = module.status()
    snap = {"installed": bool(st.get("installed")), "level": st.get("level", "off"),
            "label": st.get("label", ""), "view": view, "now": int(time.time()),
            "sources": [{"id": i, "label": l} for i, l in module.log_sources()],
            "events_note": module.EVENTS_NOTE, "checks": [], "lines": [], "clients": None}
    if not snap["installed"]:
        return snap
    try:
        snap["checks"] = module.checks()
    except Exception as e:  # noqa: BLE001 - una comprobación rota no debe tumbar la consola
        snap["checks"] = [{"label": "Comprobaciones", "ok": False, "detail": str(e)[:160]}]
    valid = [i for i, _ in module.log_sources()]   # el primero es el predeterminado
    if source not in valid:
        source = valid[0] if valid else ""
    snap["source"] = source
    try:
        snap["lines"] = process_lines(module, module.log_lines(LINE_CAP, source))
    except Exception as e:  # noqa: BLE001
        snap["lines"] = []
        snap["log_error"] = f"No se pudo leer el registro: {str(e)[:160]}"
    if view == "clients":
        try:
            snap["clients"] = module.connected()
        except Exception as e:  # noqa: BLE001
            snap["clients"] = table([], [], error=f"No se pudo consultar: {str(e)[:160]}")
    return snap
