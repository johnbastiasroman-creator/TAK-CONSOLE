# SPDX-License-Identifier: Apache-2.0
"""Buscar y aplicar actualizaciones: sistema operativo, la propia consola, módulos y TAK Server.

Reglas de diseño:
  * Buscar nunca cambia nada (salvo la lista de paquetes de apt, como hace apt-get update).
  * Aplicar es siempre una decisión del administrador; la comprobación diaria solo avisa.
  * Los módulos en contenedores usan versiones FIJADAS y probadas por la consola. Aquí se
    muestra si el proveedor ya publicó algo más nuevo, pero no se aplica solo: esa versión
    llega, probada, con una actualización de la consola.
  * La consola se actualiza en una unidad de systemd aparte (el reinicio del servicio
    mataría una tarea que viviera dentro de él).
"""
import os
import re
import threading
import time
from pathlib import Path

from .. import config
from . import settings, system
from .jobs import JOBS, Busy, JobFailed
from .shell import capture, run

SECTION = "updates"
CHECK_EVERY = 24 * 3600
UNIT_SELF = "tak-console-selfupdate"
UNIT_REBOOT = "tak-console-reboot"
REBOOT_FLAG = Path("/var/run/reboot-required")
APT_ENV = {"DEBIAN_FRONTEND": "noninteractive",
           # needrestart (Ubuntu) reiniciaría servicios por su cuenta: aquí solo se avisa.
           "NEEDRESTART_SUSPEND": "1", "NEEDRESTART_MODE": "l"}
APT_OPTS = ["-y", "-o", "DPkg::Lock::Timeout=600",
            "-o", "Dpkg::Options::=--force-confdef", "-o", "Dpkg::Options::=--force-confold"]
INST = re.compile(r"^Inst (\S+)(?: \[([^\]]+)\])? \((\S+) ([^\[)]*)")
CONTAINER_PKGS = re.compile(r"^(docker|containerd|runc)")
MAX_PKGS = 300


class UpdateError(RuntimeError):
    pass


# ── estado guardado ─────────────────────────────────────────────────────────
def state() -> dict:
    return settings.section(SECTION)


def save(**values):
    return settings.update_section(SECTION, values)


def record(what: str, ok: bool, detail: str = ""):
    """Historial corto de lo aplicado (los últimos 15)."""
    hist = state().get("history", [])
    hist.append({"ts": int(time.time()), "what": what, "ok": bool(ok), "detail": detail})
    save(history=hist[-15:])


# ── versiones ───────────────────────────────────────────────────────────────
def version_key(tag: str) -> tuple:
    """'v1.21.3' → (1, 21, 3); 'stable-11248-2' → (11248, 2). Compara por números."""
    return tuple(int(n) for n in re.findall(r"\d+", tag))


def latest_tag(repo: str, pattern: str, timeout=60) -> str:
    """Etiqueta estable más nueva de un repositorio de GitHub (git ls-remote: sin API ni claves)."""
    res = capture(["git", "ls-remote", "--tags", "--refs", f"https://github.com/{repo}"],
                  timeout=timeout, env={"GIT_TERMINAL_PROMPT": "0"})
    if not res.ok:
        raise UpdateError(f"no se pudo consultar github.com/{repo}")
    rx = re.compile(pattern)
    best = None
    for line in res.output.splitlines():
        tag = line.split("refs/tags/", 1)[-1].strip() if "refs/tags/" in line else ""
        if tag and rx.fullmatch(tag) and (best is None or version_key(tag) > version_key(best)):
            best = tag
    if not best:
        raise UpdateError(f"github.com/{repo} no tiene etiquetas que coincidan")
    return best


def image_tag(image: str) -> str:
    return image.rsplit(":", 1)[-1] if ":" in image.rsplit("/", 1)[-1] else ""


# ── sistema operativo ───────────────────────────────────────────────────────
def parse_apt_sim(text: str) -> dict:
    """Interpreta `apt-get -s dist-upgrade`: paquetes a instalar/actualizar y a quitar."""
    pk, rem = [], []
    for line in text.splitlines():
        m = INST.match(line)
        if m:
            name, old, new, origins = m.groups()
            pk.append({"name": name, "old": old or "", "new": new,
                       "security": "security" in origins})
        elif line.startswith("Remv "):
            parts = line.split()
            if len(parts) > 1:
                rem.append(parts[1])
    return {"packages": pk, "removals": rem}


def reboot_required() -> dict:
    pkgs = []
    try:
        pkgs = sorted(set(Path(str(REBOOT_FLAG) + ".pkgs").read_text().split()))
    except OSError:
        pass
    return {"required": REBOOT_FLAG.exists(), "packages": pkgs}


def apt_update(log=None) -> bool:
    res = run(["apt-get", "update", "-q", "-o", "DPkg::Lock::Timeout=300"], env=APT_ENV,
              log=log, check=False, timeout=900, quiet=log is None)
    return res.ok


def simulate_upgrade() -> dict:
    res = capture(["apt-get", "-s", "-o", "Debug::NoLocking=1", "dist-upgrade"], timeout=180,
                  env=APT_ENV)
    if not res.ok and not res.output:
        raise UpdateError("apt-get no pudo calcular las actualizaciones")
    return parse_apt_sim(res.output)


def os_check(log=None) -> dict:
    out = {"count": 0, "security": 0, "packages": [], "removals": [], "error": "", "warn": ""}
    if not apt_update(log):
        out["warn"] = "No se pudo actualizar la lista de paquetes (¿sin conexión?); se usa la última conocida."
    try:
        sim = simulate_upgrade()
    except UpdateError as e:
        out["error"] = str(e)
        return out
    out["count"] = len(sim["packages"])
    out["security"] = sum(1 for p in sim["packages"] if p["security"])
    out["packages"] = sim["packages"][:MAX_PKGS]
    out["removals"] = sim["removals"]
    return out


def _held() -> set:
    return set(capture(["apt-mark", "showhold"]).output.split())


def os_apply(job):
    """apt-get dist-upgrade con TAK Server retenido (nunca lo cambia el sistema operativo)."""
    total = 4
    job.step(1, total, "Comprobaciones")
    free = system.disk_gb("/").get("free")
    if free and free < 2:
        raise JobFailed(f"Quedan {free} GB libres en /: se necesitan al menos 2 GB")
    job.ok("Espacio en disco suficiente")

    job.step(2, total, "Lista de paquetes")
    if not apt_update(job.log):
        raise JobFailed("No se pudo actualizar la lista de paquetes de apt")
    try:
        sim = simulate_upgrade()
    except UpdateError as e:
        raise JobFailed(str(e))
    pk = sim["packages"]
    if not pk:
        job.ok("El sistema ya está al día")
        save(os={"count": 0, "security": 0, "packages": [], "removals": [], "error": "", "warn": ""})
        record("Sistema operativo", True, "ya estaba al día")
        return
    sec = sum(1 for p in pk if p["security"])
    job.log(f"{len(pk)} paquetes por actualizar ({sec} de seguridad)")
    if sim["removals"]:
        raise JobFailed("La actualización quitaría paquetes (" + ", ".join(sim["removals"][:10]) +
                        "). Por seguridad no se aplica desde aquí: revísalo con apt a mano.")
    if any(CONTAINER_PKGS.match(p["name"]) for p in pk):
        job.warn("Se actualiza Docker: los contenedores (ZeroTier, Streaming Server, Mumble, "
                 "Tactical VCO) se reiniciarán unos segundos.")
    if any(p["name"].startswith("postgresql") for p in pk):
        job.warn("Se actualiza PostgreSQL: la base de TAK Server se reiniciará un momento.")

    job.step(3, total, "Actualización de paquetes")
    held_by_us = False
    if "takserver" in capture(["dpkg-query", "-W", "-f=${Package}\n", "takserver"]).output.split() \
            and "takserver" not in _held():
        run(["apt-mark", "hold", "takserver"], log=job.log)
        held_by_us = True
        job.log("TAK Server retenido durante la actualización (se actualiza desde su módulo)")
    try:
        run(["apt-get", *APT_OPTS, "dist-upgrade"], env=APT_ENV, log=job.log, timeout=3600)
    finally:
        if held_by_us:
            run(["apt-mark", "unhold", "takserver"], log=job.log, check=False)

    job.step(4, total, "Resultado")
    try:
        left = len(simulate_upgrade()["packages"])
    except UpdateError:
        left = -1
    rb = reboot_required()
    if rb["required"]:
        job.warn("Hay que reiniciar el servidor para terminar" +
                 (f" (por: {', '.join(rb['packages'][:6])})" if rb["packages"] else "") +
                 ". Usa «Reiniciar servidor» en esta página cuando puedas.")
    save(os={"count": max(left, 0), "security": 0, "packages": [], "removals": [], "error": "",
             "warn": ""}, checked_at=int(time.time()))
    record("Sistema operativo", True, f"{len(pk)} paquetes")
    job.ok(f"{len(pk)} paquetes actualizados")


def reboot(log=None):
    """Reinicio diferido unos segundos (deja responder a la petición web)."""
    run(["systemd-run", "--unit", UNIT_REBOOT, "--collect", "--on-active=5s", "systemctl", "reboot"],
        log=log)


# ── la propia consola (git) ─────────────────────────────────────────────────
def _git_argv(*args):
    return ["git", "-c", f"safe.directory={config.BASE_DIR}", "-C", str(config.BASE_DIR), *args]


def _git(*args, timeout=60):
    return capture(_git_argv(*args), timeout=timeout, env={"GIT_TERMINAL_PROMPT": "0"})


def console_check(log=None) -> dict:
    out = {"version": "", "latest": "", "behind": 0, "ahead": 0, "commits": [], "dirty": [],
           "branch": "", "error": ""}
    if not (config.BASE_DIR / ".git").exists():
        out["error"] = "La consola no está instalada desde git: no se puede comprobar."
        return out
    out["version"] = _git("describe", "--tags", "--always").output.strip()
    out["branch"] = _git("rev-parse", "--abbrev-ref", "HEAD").output.strip()
    fetched = run(_git_argv("fetch", "--tags", "origin"), env={"GIT_TERMINAL_PROMPT": "0"},
                  log=log, check=False, timeout=180, quiet=log is None)
    if not fetched.ok:
        out["error"] = "No se pudo consultar el repositorio remoto (¿sin conexión?)."
        return out
    up = _git("rev-parse", "--abbrev-ref", "--symbolic-full-name", "@{u}")
    if not up.ok:
        out["error"] = "La rama actual no sigue a ninguna rama remota."
        return out
    behind = _git("rev-list", "--count", "HEAD..@{u}").output.strip()
    ahead = _git("rev-list", "--count", "@{u}..HEAD").output.strip()
    out["behind"] = int(behind) if behind.isdigit() else 0
    out["ahead"] = int(ahead) if ahead.isdigit() else 0
    if out["behind"]:
        out["commits"] = _git("log", "--format=%h %s", "-n", "15", "HEAD..@{u}").output.splitlines()
        out["latest"] = _git("describe", "--tags", "--always", "@{u}").output.strip()
    out["dirty"] = [ln[3:] for ln in
                    _git("status", "--porcelain", "--untracked-files=no").output.splitlines()]
    return out


def selfupdate_status() -> dict:
    active = capture(["systemctl", "is-active", UNIT_SELF]).output.strip() in ("active", "activating")
    log_tail, started = "", None
    meta = state().get("selfupdate") or {}
    lp = Path(meta.get("log", ""))
    if meta.get("log") and lp.is_file():
        started = meta.get("started")
        try:
            log_tail = "\n".join(lp.read_text(encoding="utf-8", errors="replace").splitlines()[-40:])
        except OSError:
            pass
    return {"running": active, "log": log_tail, "started": started, "from": meta.get("from", "")}


def console_apply(job):
    info = console_check(job.log)
    if info["error"]:
        raise JobFailed(info["error"])
    if not info["behind"]:
        job.ok("La consola ya está al día")
        return
    if info["ahead"]:
        raise JobFailed("Esta copia tiene commits propios que no están en el repositorio remoto: "
                        "actualiza a mano con git.")
    if info["dirty"]:
        raise JobFailed("Hay archivos modificados a mano: " + ", ".join(info["dirty"][:8]) +
                        ". Descártalos (git checkout -- .) o guárdalos y vuelve a intentar.")
    if capture(["systemctl", "is-active", UNIT_SELF]).output.strip() in ("active", "activating"):
        raise JobFailed("Ya hay una actualización de la consola en curso")
    script = config.BASE_DIR / "scripts" / "update.sh"
    if not script.is_file() and not config.DRY_RUN:
        raise JobFailed("No se encontró scripts/update.sh")
    config.LOG_DIR.mkdir(parents=True, exist_ok=True)
    log = config.LOG_DIR / f"consola-actualizacion-{time.strftime('%Y%m%d-%H%M%S')}.log"
    save(selfupdate={"log": str(log), "started": int(time.time()), "from": info["version"]})
    job.log(f"{info['behind']} cambios nuevos ({info['version']} → {info['latest']})")
    run(["systemd-run", "--unit", UNIT_SELF, "--collect",
         "--description=Actualización de TAK-CONSOLE",
         "--setenv=HOME=/root", f"--property=StandardOutput=append:{log}",
         f"--property=StandardError=append:{log}", "/bin/bash", str(script)], log=job.log)
    record("Consola", True, f"{info['version']} → {info['latest']}")
    job.ok("Actualización iniciada. La consola se reiniciará sola en unos segundos; "
           "esta página se recarga cuando vuelva.")


# ── módulos en contenedores ─────────────────────────────────────────────────
def running_image(container: str):
    res = capture(["docker", "inspect", "--format", "{{.Config.Image}}", container], timeout=8)
    return res.output.strip() if res.ok and res.output.strip() else None


def module_images(m) -> dict:
    """{'pending': bool, 'containers': [{name, running, pinned, ok}]} de un módulo instalado."""
    rows = []
    for name, pinned in m.containers().items():
        run_img = running_image(name)
        rows.append({"name": name, "running": run_img or "", "pinned": pinned,
                     "ok": run_img == pinned if run_img else None})
    return {"pending": any(r["ok"] is False for r in rows), "containers": rows}


def modules_check(log=None, upstream=True) -> list:
    from ..modules import MODULES
    out, cache = [], {}
    for key, m in MODULES.items():
        if not m.containers() or not m.installed():
            continue
        row = {"key": key, "name": m.name, **module_images(m), "upstream": []}
        if upstream:
            for u in m.upstream():
                item = {"label": u["label"], "current": u["current"], "latest": "", "newer": False,
                        "error": ""}
                try:
                    ck = (u["repo"], u["pattern"])
                    if ck not in cache:
                        cache[ck] = latest_tag(u["repo"], u["pattern"])
                    item["latest"] = cache[ck]
                    item["newer"] = version_key(cache[ck]) > version_key(u["current"])
                except UpdateError as e:
                    item["error"] = str(e)
                row["upstream"].append(item)
        out.append(row)
    return out


def module_apply(job, key):
    from ..modules import MODULES
    m = MODULES.get(key)
    if not m or not m.containers() or not m.installed():
        raise JobFailed("Ese módulo no está instalado o no usa contenedores")
    job.log(f"Se aplican las versiones fijadas por la consola a {m.name}")
    m.reapply(job)
    rows = [r for r in state().get("modules", []) if r["key"] != key]
    fresh = [r for r in modules_check(upstream=False) if r["key"] == key]
    old = {r["key"]: r for r in state().get("modules", [])}.get(key, {})
    for r in fresh:
        r["upstream"] = old.get("upstream", [])
    save(modules=sorted(rows + fresh, key=lambda r: r["key"]))
    record(m.name, True, "versión fijada aplicada")


# ── TAK Server (solo estado; la actualización vive en el módulo) ────────────
def takserver_info() -> dict:
    from ..modules import MODULES
    m = MODULES["takserver"]
    st = m.state()
    installed = m.package_version()
    pkg = st.get("package")
    staged = st.get("package_version") if pkg and Path(pkg).exists() else None
    newer = bool(installed and staged and
                 capture(["dpkg", "--compare-versions", staged, "gt", installed]).ok)
    return {"installed": installed or "", "staged": staged or "",
            "staged_name": os.path.basename(pkg) if staged else "", "newer": newer,
            "has_key": bool(st.get("gpg_key") and st.get("policy"))}


# ── búsqueda completa ───────────────────────────────────────────────────────
def check_all(job):
    total = 4
    job.step(1, total, "Sistema operativo")
    osr = os_check(job.log)
    job.log(f"{osr['count']} paquetes por actualizar ({osr['security']} de seguridad)"
            if not osr["error"] else f"✗ {osr['error']}")
    job.step(2, total, "Consola")
    con = console_check(job.log)
    job.log(f"{con['behind']} cambios nuevos" if not con["error"] else f"✗ {con['error']}")
    job.step(3, total, "Módulos")
    mods = modules_check(job.log)
    for r in mods:
        newer = [u for u in r["upstream"] if u["newer"]]
        job.log(f"{r['name']}: " + ("pendiente de aplicar la versión fijada" if r["pending"] else "al día")
                + (f"; el proveedor publicó {', '.join(u['latest'] for u in newer)}" if newer else ""))
    job.step(4, total, "TAK Server")
    tak = takserver_info()
    job.log(f"Instalado {tak['installed'] or '—'}" +
            (f"; paquete subido {tak['staged']}" if tak["staged"] else ""))
    save(os=osr, console=con, modules=mods, takserver=tak, checked_at=int(time.time()))
    job.ok("Búsqueda terminada")


def pending_count() -> int:
    """Lo accionable según la última búsqueda (para la insignia del menú); no consulta nada."""
    st = state()
    n = 1 if (st.get("os") or {}).get("count") else 0
    n += 1 if (st.get("console") or {}).get("behind") else 0
    n += sum(1 for r in st.get("modules") or [] if r.get("pending"))
    n += 1 if (st.get("takserver") or {}).get("newer") else 0
    return n


def start_scheduler():
    """Comprobación diaria: solo busca y deja el resultado; nunca aplica nada."""
    if config.DRY_RUN or os.environ.get("TAKCONSOLE_AUTOCHECK") == "0":
        return None

    def _loop():
        time.sleep(120)
        while True:
            try:
                if time.time() - state().get("checked_at", 0) >= CHECK_EVERY:
                    JOBS.start("updates", "Buscar actualizaciones (automático)", check_all)
            except Busy:
                pass
            except Exception:  # noqa: BLE001 - el hilo no debe morir
                pass
            time.sleep(3600)

    t = threading.Thread(target=_loop, name="updates-scheduler", daemon=True)
    t.start()
    return t
