# SPDX-License-Identifier: Apache-2.0
"""MediaMTX: servidor de video (RTSP, RTMP, SRT, HLS, WebRTC).

Imagen oficial bluenviron/mediamtx en red de host (UFW controla los puertos y
RTSP/UDP recibe las direcciones reales). La configuración se genera completa
en mediamtx.yml y se valida con `mediamtx --validate-conf` antes de arrancar.

Por defecto no se pide usuario ni contraseña ni para publicar ni para ver (usuario
«any» de MediaMTX). La autenticación con usuarios separados de publicación y lectura
sigue disponible marcando «Exigir usuario y contraseña».
"""
import json
import re
import time
import urllib.request

import yaml
from flask import jsonify

from .. import config
from ..core import certs, docker, monitor, settings, system, validate
from ..core.jobs import JobFailed
from ..core.shell import run
from .base import Module

IMAGE = "bluenviron/mediamtx:1.21.2"
CONTAINER = "tak-console-mediamtx"
API = "http://127.0.0.1:9997"

PROTOCOLS = {
    "rtsp": {"label": "RTSP", "ports": [("8554", "tcp"), ("8000", "udp"), ("8001", "udp")]},
    "rtmp": {"label": "RTMP", "ports": [("1935", "tcp")]},
    "srt": {"label": "SRT", "ports": [("8890", "udp")]},
    "hls": {"label": "HLS", "ports": [("8888", "tcp")]},
    "webrtc": {"label": "WebRTC", "ports": [("8889", "tcp"), ("8189", "udp")]},
}
RTSPS_PORT = ("8322", "tcp")

# Conexiones y sesiones que expone la API de MediaMTX 1.21.2 (api/openapi.yaml de esa versión).
CLIENT_ENDPOINTS = [("RTSP", "/v3/rtsp/sessions/list"), ("RTSPS", "/v3/rtsps/sessions/list"),
                    ("RTMP", "/v3/rtmp/conns/list"), ("RTMPS", "/v3/rtmps/conns/list"),
                    ("SRT", "/v3/srt/conns/list"), ("WebRTC", "/v3/webrtc/sessions/list"),
                    ("HLS", "/v3/hls/sessions/list")]
STATE_LABEL = {"publish": "Publica", "read": "Lee", "idle": "Conectado"}

# Formato de línea (internal/logger): «2026/10/26 14:21:17 INF [RTSP] [conn 1.2.3.4:5] opened».
LOG_LEVEL = re.compile(r"^\d{4}/\d\d/\d\d \d\d:\d\d:\d\d (ERR|WAR|INF|DEB)\b")
_PROTO = r"\[(?:RTSPS?|RTMPS?|SRT|WebRTC|HLS|MoQ)\]"
EVENT_RULES = [
    (re.compile(r"authentication failed|unauthorized", re.I), "err", "CLAVE RECHAZADA"),
    (re.compile(r"is publishing to path"), "ok", "PUBLICA"),
    (re.compile(r"is reading from path"), "info", "LEE"),
    (re.compile(r"stream is available"), "ok", "STREAM ACTIVO"),
    (re.compile(r"closing existing publisher"), "warn", "REEMPLAZO"),
    (re.compile(_PROTO + r".*(?:\bopened$|created by )"), "ok", "CONEXIÓN"),
    (re.compile(_PROTO + r".*(?:\bclosed|destroyed)\b"), "info", "DESCONEXIÓN"),
]


def stack_dir():
    return config.STACKS_DIR / "mediamtx"


def _api_get(path, timeout=3):
    with urllib.request.urlopen(f"{API}{path}?itemsPerPage=100", timeout=timeout) as r:
        return json.loads(r.read().decode())


def build_config(p, tls=False) -> dict:
    """Configuración completa de MediaMTX a partir de los parámetros del formulario.

    Sin `auth` (valor por defecto del formulario) nadie necesita usuario ni contraseña
    para publicar ni para ver: es el usuario «any» de MediaMTX («cualquier usuario,
    incluso anónimo», sin restricción de IP), igual que su configuración por defecto.
    Si falta la clave `auth` se exige autenticación (falla hacia lo seguro).
    """
    if p.get("auth", True):
        users = [{
            "user": p["publish_user"], "pass": p["publish_pass"], "ips": [],
            "permissions": [{"action": "publish"}, {"action": "read"}, {"action": "playback"}],
        }]
        if p["anonymous_read"]:
            users.append({"user": "any", "pass": "", "ips": [],
                          "permissions": [{"action": "read"}, {"action": "playback"}]})
        else:
            users.append({"user": p["read_user"], "pass": p["read_pass"], "ips": [],
                          "permissions": [{"action": "read"}, {"action": "playback"}]})
    else:
        users = [{"user": "any", "pass": "", "ips": [],
                  "permissions": [{"action": "publish"}, {"action": "read"},
                                  {"action": "playback"}]}]
    # API, métricas y pprof solo desde el propio equipo (la consola lee el estado).
    users.append({"user": "any", "pass": "", "ips": ["127.0.0.1", "::1"],
                  "permissions": [{"action": "api"}, {"action": "metrics"}, {"action": "pprof"}]})

    cfg = {
        "logLevel": "info",
        "authMethod": "internal",
        "authInternalUsers": users,
        "api": True,
        "apiAddress": "127.0.0.1:9997",
        "metrics": False,
        "pprof": False,
        "playback": False,
        "rtsp": p["rtsp"],
        "rtspTransports": ["udp", "multicast", "tcp"],
        "rtspEncryption": "optional" if (p["rtsp"] and tls) else "no",
        "rtspAddress": ":8554",
        "rtspsAddress": ":8322",
        "rtpAddress": ":8000",
        "rtcpAddress": ":8001",
        "rtmp": p["rtmp"],
        "rtmpAddress": ":1935",
        "hls": p["hls"],
        "hlsAddress": ":8888",
        "webrtc": p["webrtc"],
        "webrtcAddress": ":8889",
        "webrtcLocalUDPAddress": ":8189",
        "srt": p["srt"],
        "srtAddress": ":8890",
        "pathDefaults": {
            "record": p["record"],
            "recordPath": "/recordings/%path/%Y-%m-%d_%H-%M-%S-%f",
            "recordFormat": "fmp4",
            "recordSegmentDuration": "1h",
            "recordDeleteAfter": f"{p['record_days']}d",
        },
        "paths": {"all_others": None},
    }
    if tls:
        cfg["rtspServerKey"] = "/config/tls/server.key"
        cfg["rtspServerCert"] = "/config/tls/server.crt"
    return cfg


def compose_data():
    return {
        "name": "tak-console-mediamtx",
        "services": {
            "mediamtx": {
                "image": IMAGE,
                "container_name": CONTAINER,
                "restart": "unless-stopped",
                "network_mode": "host",
                "working_dir": "/config",
                "command": ["/config/mediamtx.yml"],
                "volumes": ["./config:/config:ro", "./recordings:/recordings"],
                "logging": {"driver": "json-file", "options": {"max-size": "20m", "max-file": "3"}},
            }
        },
    }


class MediaMTX(Module):
    key = "mediamtx"
    name = "MediaMTX"
    summary = "Video en vivo de drones y cámaras: RTSP, RTMP, SRT, HLS y WebRTC"
    order = 30
    template = "modules/mediamtx.html"

    def status(self):
        st = self.state()
        if not st.get("installed"):
            return {"installed": False, "running": False, "level": "off",
                    "label": "No instalado", "endpoints": []}
        c = docker.container_state(CONTAINER)
        p = st.get("params", {})
        ports = system.listening_ports()
        eps = []
        for k, meta in PROTOCOLS.items():
            if p.get(k):
                port, proto = meta["ports"][0]
                eps.append({"label": meta["label"], "value": f"{port}/{proto}",
                            "up": (int(port), proto) in ports})
        if st.get("tls"):
            eps.append({"label": "RTSPS", "value": "8322/tcp",
                        "up": (8322, "tcp") in ports})
        level = "ok" if c["running"] else "err"
        return {"installed": True, "running": c["running"], "level": level,
                "label": "En servicio" if c["running"] else f"Contenedor: {c['status']}",
                "endpoints": eps}

    def ports(self):
        st = self.state()
        p = st.get("params", {})
        out = []
        for k, meta in PROTOCOLS.items():
            if p.get(k):
                out += [{"port": port, "proto": proto, "label": f"MediaMTX {meta['label']}"}
                        for port, proto in meta["ports"]]
        if st.get("tls"):
            out.append({"port": RTSPS_PORT[0], "proto": RTSPS_PORT[1], "label": "MediaMTX RTSPS"})
        return out

    def page_context(self):
        st = self.state()
        return {"st": st, "p": st.get("params", {}), "protocols": PROTOCOLS,
                "hosts": system.candidate_hosts(), "tak_ca": certs.tak_ca_available(),
                "image": IMAGE}

    def validate_deploy(self, data):
        f = validate.Form(data)
        prev = self.state().get("params", {})
        p = {k: f.boolean(k) for k in PROTOCOLS}
        # Por defecto SIN usuario ni contraseña, para publicar y para ver.
        p["auth"] = f.boolean("auth")
        if p["auth"]:
            p["publish_user"] = f.text("publish_user", validate.USERNAME, validate.USERNAME_MSG,
                                       default="publicador")
            p["publish_pass"] = f.raw("publish_pass") or prev.get("publish_pass") or \
                validate.random_password(20)
            p["anonymous_read"] = f.boolean("anonymous_read")
            p["read_user"] = f.text("read_user", validate.USERNAME, validate.USERNAME_MSG,
                                    default="visor", required=not p["anonymous_read"])
            p["read_pass"] = f.raw("read_pass") or prev.get("read_pass") or \
                validate.random_password(20)
            for k in ("publish_pass", "read_pass"):
                if not re.fullmatch(validate.SERVICE_PASS, p[k]):
                    f.error(k, validate.SERVICE_PASS_MSG)
            if p["publish_user"] == p["read_user"] and not p["anonymous_read"]:
                f.error("read_user", "Usa un usuario distinto al de publicación")
        else:
            p.update(publish_user="", publish_pass="", read_user="", read_pass="",
                     anonymous_read=False)
        p["record"] = f.boolean("record")
        p["record_days"] = f.integer("record_days", 1, 365, 7)
        p["tls"] = f.boolean("tls")
        if not any(p[k] for k in PROTOCOLS):
            f.error("rtsp", "Activa al menos un protocolo")
        if p["tls"] and not certs.tak_ca_available():
            f.error("tls", "RTSPS necesita la CA de TAK Server: despliega TAK Server primero")
        if p["tls"] and not p["rtsp"]:
            f.error("tls", "RTSPS requiere RTSP activado")
        return p, f.errors

    def deploy(self, job, p):
        d = stack_dir()
        total = 5
        job.step(1, total, "Docker")
        if not docker.available():
            raise JobFailed("Docker no está disponible. Ejecuta de nuevo install.sh")
        job.ok("Docker disponible")

        job.step(2, total, "Certificado TLS (opcional)")
        if p["tls"]:
            tak = settings.section("takserver")
            certs.sign_with_tak_ca("mediamtx", system.candidate_hosts(), d / "config" / "tls",
                                   tak.get("cert_pass", ""), log=job.log)
            job.ok("Certificado RTSPS firmado por la CA de TAK")
        else:
            job.log("RTSPS desactivado")

        job.step(3, total, "Configuración")
        cfg = build_config(p, tls=p["tls"])
        (d / "config").mkdir(parents=True, exist_ok=True)
        (d / "recordings").mkdir(parents=True, exist_ok=True)
        docker.write_private(d / "config" / "mediamtx.yml",
                             "# Generado por la consola\n" + yaml.safe_dump(cfg, sort_keys=False))
        docker.write_compose(d, compose_data())
        job.ok("mediamtx.yml y compose.yaml escritos")
        if not p.get("auth"):
            job.warn("Sin autenticación: quien llegue a los puertos activos puede publicar y ver "
                     "video sin usuario ni contraseña. Limita la exposición con el firewall "
                     "(por ejemplo, solo ZeroTier o la LAN).")

        job.step(4, total, "Contenedor")
        docker.compose(d, "pull", log=job.log)
        run(["docker", "run", "--rm", "-v", f"{d / 'config'}:/config:ro", IMAGE,
             "--validate-conf=/config/mediamtx.yml"], log=job.log, timeout=120)
        docker.compose(d, "up", "-d", "--force-recreate", log=job.log)
        job.ok("MediaMTX iniciado")

        job.step(5, total, "Firewall")
        self.save_state(installed=True, params=p, tls=p["tls"])
        self.apply_firewall(log=job.log)

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
        job.warn(f"Las grabaciones se conservan en {stack_dir() / 'recordings'}")


    # ── consolas de estado y actividad ──────────────────────────────────────
    EVENT_RULES = EVENT_RULES
    EVENTS_NOTE = ("Eventos tomados de los mensajes de MediaMTX 1.21.2: conexiones, quién publica "
                   "o lee cada ruta, streams activos y claves rechazadas.")

    def log_lines(self, n, source=""):
        return docker.logs(CONTAINER, n).splitlines()

    def line_level(self, line):
        m = LOG_LEVEL.match(line)
        return {"ERR": "err", "WAR": "warn"}.get(m.group(1) if m else "", "info")

    def checks(self):
        c = docker.container_state(CONTAINER)
        out = [{"label": "Contenedor", "ok": c["running"], "detail": c["status"] or "—"}]
        try:
            n = len(_api_get("/v3/paths/list").get("items") or [])
            out.append({"label": "API local", "ok": True, "detail": f"{n} rutas"})
        except (OSError, ValueError) as e:
            out.append({"label": "API local", "ok": False, "detail": str(e)[:80]})
        for ep in self.status().get("endpoints", []):
            out.append({"label": ep["label"], "ok": ep["up"], "detail": ep["value"]})
        return out

    def connected(self):
        now = time.time()
        rows, unreachable = [], []
        for proto, path in CLIENT_ENDPOINTS:
            try:
                items = _api_get(path).get("items") or []
            except (OSError, ValueError):
                unreachable.append(proto)  # protocolo desactivado o sin respuesta
                continue
            for i in items:
                created = monitor.parse_ts(i.get("created"))
                rows.append([proto, STATE_LABEL.get(i.get("state"), "Lee" if proto == "HLS"
                                                    else i.get("state") or "—"),
                             i.get("remoteAddr") or "—", i.get("path") or "—",
                             i.get("user") or "—",
                             monitor.age(now - created) if created else "—",
                             monitor.human_bytes(i.get("bytesReceived", i.get("inboundBytes"))),
                             monitor.human_bytes(i.get("bytesSent", i.get("outboundBytes")))])
        note = ""
        try:
            paths = _api_get("/v3/paths/list").get("items") or []
            live = [f"{p.get('name')} ({len(p.get('readers') or [])} lectores)"
                    for p in paths if p.get("ready")]
            note = "Transmisiones activas: " + (", ".join(live) if live else "ninguna") + "."
        except (OSError, ValueError):
            pass
        if unreachable and len(unreachable) == len(CLIENT_ENDPOINTS):
            return monitor.table([], [], error="La API local de MediaMTX no responde.")
        return monitor.table(["Protocolo", "Función", "Origen", "Ruta", "Usuario", "Tiempo",
                              "Recibido", "Enviado"], rows, note=note)

    def routes(self):
        return [("/api/m/mediamtx/paths", "mtx_paths", self.view_paths, ["GET"]),
                ("/api/m/mediamtx/logs", "mtx_logs", self.view_logs, ["GET"])]

    def view_paths(self):
        try:
            with urllib.request.urlopen(f"{API}/v3/paths/list", timeout=3) as r:
                data = json.loads(r.read().decode())
        except (OSError, ValueError):
            return jsonify(ok=False, items=[])
        items = [{"name": i.get("name"), "ready": i.get("ready"),
                  "source": (i.get("source") or {}).get("type"),
                  "readers": len(i.get("readers") or []),
                  "tracks": i.get("tracks") or []} for i in data.get("items", [])]
        return jsonify(ok=True, items=items)

    def view_logs(self):
        return jsonify(ok=True, text=docker.logs(CONTAINER, 300))
