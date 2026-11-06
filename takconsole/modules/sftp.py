# SPDX-License-Identifier: Apache-2.0
"""Repositorio de archivos: SFTP + cliente web (SFTPGo).

Imagen oficial drakkan/sftpgo en red de host. Un mismo servicio ofrece:
  · SFTP (puerto 2022 de la imagen) para WinSCP, FileZilla, scp, etc.
  · cliente web (/web/client): subir archivos, crear carpetas, descargar.
  · administración web (/web/admin): usuarios, cuotas, permisos.

La configuración se pasa con variables de entorno SFTPGO_* desde un .env con
permisos 600. El administrador inicial se crea con SFTPGO_DEFAULT_ADMIN_* (solo
si todavía no existe ninguno) y, tras el despliegue, la consola intenta crear
un usuario de repositorio por la API REST; si falla, se crea en /web/admin.
"""
import base64
import json
import os
import re
import shutil
import ssl
import time
import urllib.error
import urllib.request

from flask import jsonify

from .. import config
from ..core import certs, docker, monitor, system, validate
from ..core.jobs import JobFailed
from ..core.shell import capture, run
from .base import Module

IMAGE = "drakkan/sftpgo:v2.7.6"
CONTAINER = "tak-console-sftp"
SFTP_PORT = 2022          # puerto por defecto de la imagen (README docker de SFTPGo)
DEFAULT_HTTP_PORT = 8085  # 8080 (el de la imagen) suele estar ocupado en un servidor TAK
UID = 1000                # usuario con el que corre la imagen
HOME_BASE = "/srv/sftpgo/data"  # carpeta de datos por defecto de los usuarios


def stack_dir():
    return config.STACKS_DIR / "sftp"


def env_values(p) -> dict:
    env = {
        "SFTPGO_DATA_PROVIDER__CREATE_DEFAULT_ADMIN": "1",
        "SFTPGO_DEFAULT_ADMIN_USERNAME": p["admin_user"],
        "SFTPGO_DEFAULT_ADMIN_PASSWORD": p["admin_pass"],
        "SFTPGO_HTTPD__BINDINGS__0__PORT": p["http_port"],
    }
    if p.get("tls"):
        env.update({
            "SFTPGO_HTTPD__BINDINGS__0__ENABLE_HTTPS": "1",
            "SFTPGO_HTTPD__BINDINGS__0__CERTIFICATE_FILE": "/tls/server.crt",
            "SFTPGO_HTTPD__BINDINGS__0__CERTIFICATE_KEY_FILE": "/tls/server.key",
        })
    return env


def compose_data():
    return {
        "name": "tak-console-sftp",
        "services": {
            "sftp": {
                "image": IMAGE,
                "container_name": CONTAINER,
                "restart": "unless-stopped",
                "network_mode": "host",
                "env_file": ["sftp.env"],
                "volumes": ["./data/srv:/srv/sftpgo", "./data/lib:/var/lib/sftpgo",
                            "./tls:/tls:ro"],
                "logging": {"driver": "json-file", "options": {"max-size": "20m", "max-file": "3"}},
            }
        },
    }


# ── API REST de SFTPGo (solo para crear el usuario inicial) ────────────────────
def _base_url(p) -> str:
    return f"{'https' if p.get('tls') else 'http'}://127.0.0.1:{p['http_port']}"


def _ctx(p):
    if not p.get("tls"):
        return None
    ctx = ssl.create_default_context()
    # Solo se usa contra 127.0.0.1 (el certificado de la consola lleva las IP públicas).
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _request(p, method, path, headers=None, body=None, timeout=10):
    data = json.dumps(body).encode() if body is not None else None
    hdrs = dict(headers or {})
    if data is not None:
        hdrs["Content-Type"] = "application/json"
    req = urllib.request.Request(_base_url(p) + path, data=data, method=method, headers=hdrs)
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=_ctx(p)) as r:
            raw = r.read().decode("utf-8", "replace")
            return r.status, (json.loads(raw) if raw.strip().startswith(("{", "[")) else raw)
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")[:300]


def wait_ready(p, seconds=60, sleep=time.sleep) -> bool:
    """Espera a que la web responda (cualquier respuesta HTTP sirve)."""
    end = time.monotonic() + seconds
    while True:
        try:
            _request(p, "GET", "/web/client/login", timeout=3)  # un 404/302 también vale
            return True
        except (OSError, ValueError):
            pass
        if time.monotonic() >= end:
            return False
        sleep(2)


def create_repo_user(p) -> str:
    """Crea (si no existe) el usuario de repositorio. Devuelve 'creado' | 'existe'.

    Levanta RuntimeError con un texto para el operador si no se pudo."""
    basic = base64.b64encode(f"{p['admin_user']}:{p['admin_pass']}".encode()).decode()
    code, tok = _request(p, "GET", "/api/v2/token", {"Authorization": f"Basic {basic}"})
    if code == 405:  # por si la versión pide POST
        code, tok = _request(p, "POST", "/api/v2/token", {"Authorization": f"Basic {basic}"})
    if code in (401, 403):
        raise RuntimeError("el administrador de SFTPGo ya existía con otra contraseña "
                           "(la de la consola no coincide)")
    if code != 200 or not isinstance(tok, dict) or not tok.get("access_token"):
        raise RuntimeError(f"la API no entregó un token (HTTP {code})")
    code, resp = _request(p, "POST", "/api/v2/users",
                          {"Authorization": f"Bearer {tok['access_token']}"},
                          {"username": p["repo_user"], "password": p["repo_pass"], "status": 1,
                           "home_dir": f"{HOME_BASE}/{p['repo_user']}",
                           "permissions": {"/": ["*"]}})
    if code in (200, 201):
        return "creado"
    if code == 409:
        return "existe"
    raise RuntimeError(f"la API rechazó crear el usuario (HTTP {code}): {str(resp)[:160]}")


def tcp_peers(port) -> list:
    res = capture(["ss", "-Htn", "state", "established", "sport", "=", f":{port}"])
    if not res.ok:
        return []
    return [cols[3] for cols in (ln.split() for ln in res.output.splitlines()) if len(cols) >= 4]


class Sftp(Module):
    key = "sftp"
    name = "Repositorio SFTP"
    summary = "Archivos y carpetas por SFTP o desde el navegador, para los equipos de la VPN"
    order = 45
    template = "modules/sftp.html"

    def _port(self):
        return int(self.state().get("params", {}).get("http_port", DEFAULT_HTTP_PORT))

    def status(self):
        st = self.state()
        if not st.get("installed"):
            return {"installed": False, "running": False, "level": "off",
                    "label": "No instalado", "endpoints": []}
        c = docker.container_state(CONTAINER)
        ports = system.listening_ports()
        hp = self._port()
        return {
            "installed": True, "running": c["running"],
            "level": "ok" if c["running"] else "err",
            "label": "En servicio" if c["running"] else f"Contenedor: {c['status']}",
            "endpoints": [
                {"label": "SFTP", "value": f"{SFTP_PORT}/tcp", "up": (SFTP_PORT, "tcp") in ports},
                {"label": "Web", "value": f"{hp}/tcp", "up": (hp, "tcp") in ports},
            ],
        }

    def ports(self):
        return [{"port": str(SFTP_PORT), "proto": "tcp", "label": "SFTP"},
                {"port": str(self._port()), "proto": "tcp", "label": "SFTP web"}]

    def page_context(self):
        st = self.state()
        p = st.get("params", {})
        return {"st": st, "p": p, "hosts": system.candidate_hosts(), "image": IMAGE,
                "sftp_port": SFTP_PORT, "default_http_port": DEFAULT_HTTP_PORT,
                "scheme": "https" if p.get("tls") else "http",
                "http_port": p.get("http_port", DEFAULT_HTTP_PORT)}

    # ── despliegue ──────────────────────────────────────────────────────────
    def validate_deploy(self, data):
        f = validate.Form(data)
        prev = self.state().get("params", {})
        p = {
            "http_port": f.integer("http_port", 1024, 65535,
                                   int(prev.get("http_port", DEFAULT_HTTP_PORT))),
            "tls": f.boolean("tls"),
            "admin_user": f.text("admin_user", validate.USERNAME, validate.USERNAME_MSG,
                                 default=prev.get("admin_user", "admin")),
            "admin_pass": f.raw("admin_pass") or prev.get("admin_pass")
            or validate.random_password(20),
            "repo_user": f.text("repo_user", validate.USERNAME, validate.USERNAME_MSG,
                                default=prev.get("repo_user", "repositorio")),
            "repo_pass": f.raw("repo_pass") or prev.get("repo_pass")
            or validate.random_password(20),
        }
        for k in ("admin_pass", "repo_pass"):
            if not re.fullmatch(validate.SERVICE_PASS, p[k]):
                f.error(k, validate.SERVICE_PASS_MSG)
        if p["admin_user"].lower() == p["repo_user"].lower():
            f.error("repo_user", "Debe ser distinto del usuario administrador")
        if "http_port" not in f.errors:
            if p["http_port"] == SFTP_PORT:
                f.error("http_port", f"El {SFTP_PORT} lo usa el propio SFTP")
            elif (p["http_port"], "tcp") in system.listening_ports() \
                    and not (self.installed() and p["http_port"] == prev.get("http_port")):
                f.error("http_port", f"El puerto {p['http_port']} ya está en uso en este servidor")
        return p, f.errors

    def deploy(self, job, p):
        d = stack_dir()
        total = 6
        job.step(1, total, "Docker")
        if not docker.available():
            raise JobFailed("Docker no está disponible. Ejecuta de nuevo install.sh")
        job.ok("Docker disponible")

        job.step(2, total, "Carpetas y certificado")
        for sub in ("data/srv", "data/lib", "tls"):
            (d / sub).mkdir(parents=True, exist_ok=True)
        if p["tls"]:
            if not (config.CONSOLE_CERT.exists() and config.CONSOLE_KEY.exists()):
                certs.make_console_cert(system.candidate_hosts(), log=job.log)
            shutil.copyfile(config.CONSOLE_CERT, d / "tls" / "server.crt")
            shutil.copyfile(config.CONSOLE_KEY, d / "tls" / "server.key")
            os.chmod(d / "tls" / "server.key", 0o600)
            job.ok("HTTPS con el certificado de la consola")
        else:
            for name in ("server.crt", "server.key"):
                (d / "tls" / name).unlink(missing_ok=True)
            job.log("La web se sirve sin HTTPS (el tráfico de la VPN ya va cifrado por ZeroTier)")
        run(["chown", "-R", f"{UID}:{UID}", str(d / "data"), str(d / "tls")], log=job.log)
        os.chmod(d / "data", 0o700)
        os.chmod(d / "tls", 0o700)

        job.step(3, total, "Configuración")
        docker.write_env(d / "sftp.env", env_values(p))
        docker.write_compose(d, compose_data())
        job.ok("sftp.env y compose.yaml escritos")

        job.step(4, total, "Contenedor")
        docker.compose(d, "pull", log=job.log)
        docker.compose(d, "up", "-d", "--force-recreate", log=job.log)
        job.ok("SFTPGo iniciado")

        job.step(5, total, "Usuario del repositorio")
        self._ensure_repo_user(job, p)

        job.step(6, total, "Firewall")
        self.save_state(installed=True, params=p)
        self.apply_firewall(log=job.log)

    def _ensure_repo_user(self, job, p):
        if config.DRY_RUN:
            job.log("[simulación] se crearía el usuario del repositorio por la API")
            return
        if not wait_ready(p):
            job.warn("La web de SFTPGo no respondió a tiempo: crea el usuario a mano en "
                     "«Administración» (o aplica la configuración de nuevo)")
            return
        try:
            res = create_repo_user(p)
        except (RuntimeError, OSError, ValueError) as e:
            job.warn(f"No se pudo crear el usuario «{p['repo_user']}» automáticamente: {e}. "
                     "Créalo en «Administración» (Users → Add).")
            return
        job.ok(f"Usuario «{p['repo_user']}» {res}")

    def containers(self):
        return {CONTAINER: IMAGE}

    def upstream(self):
        return [{"label": "SFTPGo", "repo": "drakkan/sftpgo",
                 "pattern": r"v\d+\.\d+\.\d+", "current": IMAGE.rsplit(":", 1)[1]}]

    def actions(self):
        def c(*args):
            def _do(job):
                docker.compose(stack_dir(), *args, log=job.log)
            return _do

        return {"start": ("Iniciar", c("up", "-d")), "stop": ("Detener", c("stop")),
                "restart": ("Reiniciar", c("restart"))}

    def uninstall(self, job, params):
        if docker.compose_file(stack_dir()).exists():
            docker.compose(stack_dir(), "down", log=job.log, check=False)
        self.remove_firewall(log=job.log)
        self.save_state(installed=False)
        job.warn(f"Los archivos del repositorio y la base de usuarios se conservan en "
                 f"{stack_dir() / 'data'}")

    # ── consolas de estado y actividad ──────────────────────────────────────
    EVENTS_NOTE = ("El registro de SFTPGo no se clasifica por tipo de evento: se muestra tal cual, "
                   "marcando como error o aviso las líneas que lo indican.")

    def log_lines(self, n, source=""):
        return docker.logs(CONTAINER, n).splitlines()

    def checks(self):
        c = docker.container_state(CONTAINER)
        ports = system.listening_ports()
        hp = self._port()
        out = [{"label": "Contenedor", "ok": c["running"], "detail": c["status"] or "—"},
               {"label": "SFTP", "ok": (SFTP_PORT, "tcp") in ports, "detail": f"{SFTP_PORT}/tcp"},
               {"label": "Web", "ok": (hp, "tcp") in ports, "detail": f"{hp}/tcp"}]
        n = len(tcp_peers(SFTP_PORT)) + len(tcp_peers(hp))
        if n or not config.DRY_RUN:
            out.append({"label": "Conexiones abiertas", "ok": True, "detail": str(n)})
        return out

    def connected(self):
        hp = self._port()
        rows = [["SFTP", a] for a in tcp_peers(SFTP_PORT)] + [["Web", a] for a in tcp_peers(hp)]
        return monitor.table(["Servicio", "Dirección del cliente"], rows,
                             note="Conexiones TCP abiertas ahora (ss). El navegador abre y cierra "
                                  "conexiones continuamente: una lista vacía es normal.")

    def routes(self):
        return [("/api/m/sftp/logs", "sftp_logs", self.view_logs, ["GET"])]

    def view_logs(self):
        return jsonify(ok=True, text=docker.logs(CONTAINER, 300))
