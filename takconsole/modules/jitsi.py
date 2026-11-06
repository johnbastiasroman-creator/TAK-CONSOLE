# SPDX-License-Identifier: Apache-2.0
"""Jitsi Meet: videollamadas en el navegador (salas por enlace).

Se despliega con el compose oficial de docker-jitsi-meet (etiqueta fijada, ver RELEASE):
cuatro contenedores —web (nginx), prosody (XMPP), jicofo y jvb (videopuente)— que hablan
entre sí por una red interna de Docker. Por eso este módulo NO puede usar `network_mode: host`
como MediaMTX y Mumble, y Docker publica sus puertos saltándose UFW.

Para no dejar el servicio abierto en todas las interfaces, el compose publica la web (HTTPS)
y el audio/video (UDP 10000) solo en las direcciones IP del servidor que el administrador
elige. Lo demás (API REST del videopuente) va solo a 127.0.0.1 y el XMPP no se publica.

Sin autenticación: quien llegue a la URL puede crear salas (decisión del administrador).

Diseño: la página de bienvenida puede pasarse a un tema monocromático con nombre y subtítulo
propios. Se hace con los dos archivos de personalización que la imagen web de Jitsi anexa a su
configuración (custom-interface_config.js y custom-config.js), sin tocar las imágenes.
"""
import copy
import ipaddress
import json
import os
import re
import secrets
import urllib.request
from functools import lru_cache
from pathlib import Path

import yaml

from .. import config
from ..core import certs, docker, monitor, settings, system, validate
from ..core.jobs import JobFailed
from ..core.shell import run
from .base import Module

IMAGE_REPO = "ghcr.io/jitsi"
RELEASE = "stable-11248-2"          # etiqueta de docker-jitsi-meet y de las 4 imágenes
PROJECT = "tak-console-jitsi"
SERVICES = ("web", "prosody", "jicofo", "jvb")
LABELS = {"web": "Web (nginx)", "prosody": "Prosody (XMPP)", "jicofo": "Jicofo (conferencias)",
          "jvb": "Videopuente (JVB)"}
JVB_PORT = 10000                    # UDP, audio y video
COLIBRI_PORT = 18080                # REST del videopuente, solo 127.0.0.1 (el 8080 puede estar ocupado)
DEFAULT_HTTPS_PORT = 443
UID = 1000                          # los contenedores corren como uid/gid 1000
UPSTREAM = Path(__file__).with_name("jitsi_compose.upstream.yml")
THEME_CSS = Path(__file__).with_name("jitsi_theme.css")
DEFAULT_APP_NAME = "Tactical VCO"
DEFAULT_SUBTITLE = "Sistema de Video Conferencia Táctica"
# Letras (con tildes), números, espacio y signos simples: va dentro de CSS y JavaScript.
THEME_TEXT = r"[A-Za-z\u00c0-\u00ff0-9 .,:()\-]{1,60}"
THEME_TEXT_MESSAGE = "Hasta 60 caracteres: letras, números, espacio y . , : ( ) -"
THEME_FILES = ("web/custom-interface_config.js", "web/custom-config.js")

# Directorios que exige el compose (handbook de Jitsi, «stable-11146 y posteriores») más los
# custom-ca que monta de solo lectura.
CONFIG_DIRS = ("web", "web/custom-ca", "prosody/config", "prosody/prosody-plugins-custom",
               "prosody/custom-ca", "jicofo", "jicofo/custom-ca", "jvb", "jvb/custom-ca",
               "jigasi", "jibri", "transcriber",
               "storage/jibri", "storage/prosody", "storage/transcripts", "storage/web",
               "tmp/web-crontabs", "tmp/web-load-test")
# Contraseñas internas que genera gen-passwords.sh del proyecto (openssl rand -hex 16).
SECRET_NAMES = ("JICOFO_AUTH_PASSWORD", "JVB_AUTH_PASSWORD", "JIGASI_XMPP_PASSWORD",
                "JIBRI_RECORDER_PASSWORD", "JIBRI_XMPP_PASSWORD", "JIGASI_TRANSCRIBER_PASSWORD")

HOST_NAME = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9.\-]{0,251}[A-Za-z0-9])?")
TZ_NAME = re.compile(r"[A-Za-z0-9_+\-]+(?:/[A-Za-z0-9_+\-]+){0,2}")


def stack_dir():
    return config.STACKS_DIR / "jitsi"


def config_dir():
    return stack_dir() / "config"


def container(service):
    return f"{PROJECT}-{service}"


@lru_cache(maxsize=1)
def _upstream():
    with open(UPSTREAM, encoding="utf-8") as fh:
        return yaml.safe_load(fh)


def compose_data(p):
    """Compose oficial con imágenes fijas, nombres propios y puertos solo en las IP elegidas."""
    data = copy.deepcopy(_upstream())
    out = {"name": PROJECT, "services": data["services"], "networks": data["networks"]}
    for name in SERVICES:
        svc = out["services"][name]
        svc["image"] = f"{IMAGE_REPO}/{name}:{RELEASE}"
        svc["container_name"] = container(name)
        svc["logging"] = {"driver": "json-file", "options": {"max-size": "20m", "max-file": "3"}}
    ips = list(p["bind_ips"])
    out["services"]["web"]["ports"] = [f"{ip}:{p['https_port']}:8443" for ip in ips]
    # La API REST de Jicofo no se publica; la del videopuente solo en el propio equipo.
    out["services"]["jicofo"].pop("ports", None)
    out["services"]["jvb"]["ports"] = (
        [f"{ip}:{JVB_PORT}:{JVB_PORT}/udp" for ip in ips] + [f"127.0.0.1:{COLIBRI_PORT}:8080"])
    return out


def public_url(host, port):
    return f"https://{host}" + ("" if int(port) == 443 else f":{port}")


def env_values(p, secrets_=None):
    """Variables del .env (el compose las toma por nombre). Ver env.example de docker-jitsi-meet."""
    env = {
        "CONFIG": str(config_dir()),
        "TZ": p["tz"],
        "PUBLIC_URL": public_url(p["host"], p["https_port"]),
        "JVB_ADVERTISE_IPS": ",".join(p["bind_ips"]),
        # REST del videopuente (conferencias/participantes); alcanzable solo desde 127.0.0.1
        "COLIBRI_REST_ENABLED": "true",
    }
    if not p.get("stun"):
        # Sin esto el videopuente consulta servidores STUN públicos para averiguar su IP.
        env["JVB_DISABLE_STUN"] = "true"
    env.update(secrets_ or {n: secrets.token_hex(16) for n in SECRET_NAMES})
    return env


def _css_string(text):
    """Texto para un `content: "..."` de CSS: lo que no es ASCII simple va como escape hexadecimal."""
    return "".join(c if 32 <= ord(c) < 127 and c not in '"\\' else f"\\{ord(c):X} " for c in text)


def theme_files(p):
    """{ruta relativa a CONFIG: contenido} de los dos archivos que la imagen web anexa a sus
    interface_config.js y config.js. Solo ASCII (los acentos van escapados)."""
    css = THEME_CSS.read_text(encoding="utf-8")
    css = css.replace("__TITLE__", _css_string(p["app_name"])).replace(
        "__SUBTITLE__", _css_string(p["subtitle"]))
    interface = ("// Generado por TAK-CONSOLE\n"
                 f"interfaceConfig.APP_NAME = {json.dumps(p['app_name'])};\n"
                 "interfaceConfig.SHOW_JITSI_WATERMARK = false;\n")
    custom = ("// Generado por TAK-CONSOLE: aplica el tema monocromatico a la pagina de bienvenida.\n"
              "(function () {\n"
              "  try {\n"
              "    var s = document.createElement('style');\n"
              "    s.id = 'tak-console-theme';\n"
              f"    s.textContent = {json.dumps(css)};\n"
              "    document.head.appendChild(s);\n"
              "  } catch (e) { /* sin tema: la pagina sigue funcionando */ }\n"
              "})();\n")
    return {"web/custom-interface_config.js": interface, "web/custom-config.js": custom}


def system_tz():
    try:
        tz = Path("/etc/timezone").read_text(encoding="utf-8").strip()
    except OSError:
        return "UTC"
    return tz if TZ_NAME.fullmatch(tz) else "UTC"


def local_ipv4():
    return [ip for ip in system.candidate_hosts() if _is_ipv4(ip)]


def _is_ipv4(value):
    try:
        return ipaddress.ip_address(value).version == 4
    except ValueError:
        return False


def valid_host(value):
    """Dirección con la que los usuarios abrirán la web: IPv4 o nombre DNS."""
    if _is_ipv4(value):
        return True
    return bool(HOST_NAME.fullmatch(value)) and not value.replace(".", "").isdigit()


def stats(timeout=3):
    """Cifras del videopuente (conferences, endpoints); levanta OSError/ValueError si falla."""
    with urllib.request.urlopen(f"http://127.0.0.1:{COLIBRI_PORT}/colibri/stats", timeout=timeout) as r:
        return json.loads(r.read().decode())


class Jitsi(Module):
    key = "jitsi"
    name = "Tactical VCO"
    summary = "Videollamadas en el navegador, con salas por enlace"
    order = 50
    template = "modules/jitsi.html"

    # ── estado ──────────────────────────────────────────────────────────────
    def _states(self):
        return {s: docker.container_state(container(s)) for s in SERVICES}

    def status(self):
        st = self.state()
        if not st.get("installed"):
            return {"installed": False, "running": False, "level": "off",
                    "label": "No instalado", "endpoints": []}
        states = self._states()
        up = sum(1 for s in states.values() if s["running"])
        p = st.get("params", {})
        ports = system.listening_ports()
        if up == len(SERVICES):
            level, label = "ok", "En servicio"
        elif up == 0:
            level, label = "err", "Detenido"
        else:
            level, label = "warn", f"{up} de {len(SERVICES)} contenedores activos"
        return {
            "installed": True, "running": up == len(SERVICES), "level": level, "label": label,
            "endpoints": [
                {"label": "Web", "value": public_url(p.get("host", "?"), p.get("https_port", 443)),
                 "up": (int(p.get("https_port", 443)), "tcp") in ports},
                {"label": "Audio y video", "value": f"{JVB_PORT}/udp",
                 "up": states["jvb"]["running"]},
            ],
        }

    def ports(self):
        # Docker publica estos puertos saltándose UFW: no hay reglas que aplicar aquí.
        return []

    def page_context(self):
        st = self.state()
        p = st.get("params", {})
        ips = local_ipv4()
        return {"st": st, "p": p, "ips": ips, "tak_ca": certs.tak_ca_available(),
                "release": RELEASE, "https_port": p.get("https_port", DEFAULT_HTTPS_PORT),
                "jvb_port": JVB_PORT, "default_host": (ips[0] if ips else ""),
                "default_tz": system_tz(), "default_app_name": DEFAULT_APP_NAME,
                "default_subtitle": DEFAULT_SUBTITLE,
                "open_url": public_url(p["host"], p.get("https_port", DEFAULT_HTTPS_PORT))
                if p.get("host") else ""}

    # ── despliegue ──────────────────────────────────────────────────────────
    def validate_deploy(self, data):
        f = validate.Form(data)
        st = self.state()
        prev = st.get("params", {})
        ips = local_ipv4()
        host = f.raw("host") or (prev.get("host") or (ips[0] if ips else ""))
        if not host:
            f.error("host", "Indica la dirección con la que se abrirá Tactical VCO")
        elif not valid_host(host):
            f.error("host", "Usa una dirección IPv4 o un nombre (letras, números, punto y guion)")
        port = f.integer("https_port", 1, 65535, prev.get("https_port", DEFAULT_HTTPS_PORT))
        if "https_port" not in f.errors and (not st.get("installed") or port != prev.get("https_port")):
            if (port, "tcp") in system.listening_ports():
                f.error("https_port", f"El puerto {port} ya está en uso en este equipo")
        if hasattr(data, "getlist"):
            chosen = [v.strip() for v in data.getlist("bind_ip")]
        else:
            raw = (data or {}).get("bind_ip", [])
            chosen = [v.strip() for v in (raw if isinstance(raw, (list, tuple)) else str(raw).split(","))]
        chosen = [v for v in dict.fromkeys(chosen) if v]
        if not chosen:
            f.error("bind_ip", "Elige al menos una dirección del servidor")
        elif any(v not in ips for v in chosen):
            f.error("bind_ip", "Hay direcciones que no pertenecen a este equipo")
        tz = f.raw("tz") or prev.get("tz") or system_tz()
        if not TZ_NAME.fullmatch(tz):
            f.error("tz", "Zona horaria inválida (por ejemplo America/Santiago)")
        theme = f.boolean("theme")
        app_name = f.text("app_name", THEME_TEXT, THEME_TEXT_MESSAGE,
                          default=prev.get("app_name") or DEFAULT_APP_NAME, required=theme)
        subtitle = f.text("subtitle", THEME_TEXT, THEME_TEXT_MESSAGE,
                          default=prev.get("subtitle") or DEFAULT_SUBTITLE, required=theme)
        p = {"host": host, "https_port": port, "bind_ips": chosen, "tz": tz,
             "tls": f.boolean("tls"), "stun": f.boolean("stun"),
             "theme": theme, "app_name": app_name or DEFAULT_APP_NAME,
             "subtitle": subtitle or DEFAULT_SUBTITLE}
        if p["tls"] and not certs.tak_ca_available():
            f.error("tls", "Necesita la CA de TAK Server: despliega TAK Server primero")
        return p, f.errors

    def deploy(self, job, p):
        d = stack_dir()
        cfg = config_dir()
        total = 6
        job.step(1, total, "Docker")
        if not docker.available():
            raise JobFailed("Docker no está disponible. Ejecuta de nuevo install.sh")
        job.ok("Docker disponible")

        job.step(2, total, "Directorios")
        cfg.mkdir(parents=True, exist_ok=True)
        for sub in CONFIG_DIRS:
            (cfg / sub).mkdir(parents=True, exist_ok=True)
        job.ok(f"Configuración en {cfg}")

        job.step(3, total, "Certificado TLS")
        keys, kept = cfg / "web" / "keys", cfg / "storage" / "web" / "keys"
        if p["tls"]:
            tak = settings.section("takserver")
            tmp = d / "tls"
            res = certs.sign_with_tak_ca("jitsi", [p["host"], *p["bind_ips"]], tmp,
                                         tak.get("cert_pass", ""), log=job.log)
            keys.mkdir(parents=True, exist_ok=True)
            # nginx necesita el certificado seguido de la cadena de la CA
            docker.write_private(keys / "cert.crt",
                                 res["cert"].read_text() + res["chain"].read_text(), mode=0o644)
            docker.write_private(keys / "cert.key", res["key"].read_text(), mode=0o600)
            for leftover in tmp.glob("*"):
                leftover.unlink()
            tmp.rmdir()
            job.ok("Certificado firmado por la CA de TAK (los equipos que confían en ella lo validan)")
        else:
            # El contenedor conserva la copia de /config/keys en storage: quitar las dos para que
            # genere un certificado autofirmado nuevo.
            for base in (keys, kept):
                for name in ("cert.crt", "cert.key"):
                    (base / name).unlink(missing_ok=True)
            job.log("Tactical VCO generará un certificado autofirmado: el navegador pedirá aceptarlo y "
                    "las apps móviles de Jitsi no se conectarán con él")

        job.step(4, total, "Configuración")
        prev = self._saved_secrets()
        self._write_theme(p, job)
        docker.write_env(d / ".env", env_values(p, prev))
        docker.write_compose(d, compose_data(p))
        run(["chown", "-R", f"{UID}:{UID}", str(cfg)], log=job.log)
        os.chmod(cfg, 0o700)
        job.ok(".env y compose.yaml escritos")

        job.step(5, total, "Contenedores")
        docker.compose(d, "pull", log=job.log)
        docker.compose(d, "up", "-d", "--force-recreate", log=job.log)
        job.ok("Tactical VCO iniciado")

        job.step(6, total, "Firewall")
        self.save_state(installed=True, params=p)
        self.remove_firewall(log=job.log)
        job.warn("Docker publica estos puertos saltándose UFW: la política de «Red y firewall» no "
                 f"se aplica a Tactical VCO. Solo escuchan en {', '.join(p['bind_ips'])}.")
        job.ok(f"Abre {public_url(p['host'], p['https_port'])} desde un navegador de la red")

    def _write_theme(self, p, job):
        """Escribe (o quita) los archivos de personalización que anexa la imagen web."""
        cfg = config_dir()
        if p.get("theme"):
            for rel, text in theme_files(p).items():
                docker.write_private(cfg / rel, text, mode=0o644)
            job.ok(f"Diseño «{p['app_name']}» aplicado a la página de bienvenida")
        else:
            for rel in THEME_FILES:
                (cfg / rel).unlink(missing_ok=True)
            job.log("Sin diseño propio: Jitsi mostrará su página de bienvenida original")

    def _saved_secrets(self):
        """Conserva las contraseñas internas entre despliegues (si no, prosody las rechazaría)."""
        path = stack_dir() / ".env"
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except OSError:
            return None
        found = {}
        for line in lines:
            k, _, v = line.partition("=")
            if k in SECRET_NAMES and len(v) >= 3 and v[0] == v[-1] == "'":
                found[k] = v[1:-1]
        return found if set(found) == set(SECRET_NAMES) else None

    # ── control ─────────────────────────────────────────────────────────────
    def containers(self):
        return {container(n): f"{IMAGE_REPO}/{n}:{RELEASE}" for n in SERVICES}

    def upstream(self):
        return [{"label": "Jitsi Meet (docker-jitsi-meet)", "repo": "jitsi/docker-jitsi-meet",
                 "pattern": r"stable-\d+(-\d+)?", "current": RELEASE}]

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
        job.warn(f"La configuración y el certificado de Tactical VCO se conservan en {config_dir()}")

    # ── consolas de estado y actividad ──────────────────────────────────────
    EVENT_RULES = []
    EVENTS_NOTE = ("La consola aún no reconoce eventos de Tactical VCO: usa «Registro en vivo» y elige el "
                   "componente (Jicofo registra las conferencias, el videopuente el audio y video).")

    def log_sources(self):
        return [("jicofo", LABELS["jicofo"]), ("jvb", LABELS["jvb"]),
                ("prosody", LABELS["prosody"]), ("web", LABELS["web"])]

    def log_lines(self, n, source=""):
        name = source if source in SERVICES else "jicofo"
        return docker.logs(container(name), n).splitlines()

    def checks(self):
        out = []
        for s, c in self._states().items():
            detail = c["status"] or "—"
            if c.get("health"):
                detail += f" ({c['health']})"
            out.append({"label": LABELS[s], "ok": c["running"], "detail": detail})
        p = self.state().get("params", {})
        port = int(p.get("https_port", DEFAULT_HTTPS_PORT))
        out.append({"label": "Web", "ok": (port, "tcp") in system.listening_ports(),
                    "detail": f"{port}/tcp"})
        if p.get("theme", None) is None:
            # Instalación anterior al diseño: los archivos solo se escriben al aplicar.
            out.append({"label": "Diseño de la página", "ok": False,
                        "detail": "aún no aplicado: pulsa «Aplicar configuración»"})
        elif p["theme"]:
            out.append(self._theme_check())
        return out

    def _theme_check(self):
        """¿Llegó el diseño al contenedor web? Compara lo escrito en disco con lo que sirve nginx."""
        label = "Diseño de la página"
        on_disk = (config_dir() / THEME_FILES[1]).is_file()
        if not on_disk:
            return {"label": label, "ok": False,
                    "detail": "falta custom-config.js: pulsa «Aplicar configuración»"}
        res = docker.exec_(container("web"), "grep", "-c", "tak-console-theme",
                           "/run/web/config/config.js")
        if res.ok and res.output.strip() not in ("", "0"):
            return {"label": label, "ok": True, "detail": "aplicado en el contenedor web"}
        return {"label": label, "ok": False,
                "detail": "escrito en disco pero el contenedor no lo cargó: pulsa «Aplicar configuración»"}

    def connected(self):
        try:
            s = stats()
        except (OSError, ValueError) as e:
            return monitor.table([], [], error=f"El videopuente no respondió: {str(e)[:120]}")
        rows = [["Conferencias activas", s.get("conferences", "—")],
                ["Participantes", s.get("endpoints", s.get("participants", "—"))]]
        return monitor.table(
            ["Dato", "Valor"], rows,
            note="Cifras que informa el videopuente (se actualizan cada pocos segundos). El servidor no "
                 "entrega aquí los nombres de los participantes.")
