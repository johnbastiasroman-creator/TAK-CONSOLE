# SPDX-License-Identifier: Apache-2.0
"""MediaMTX: servidor de video (RTSP, RTMP, SRT, HLS, WebRTC).

Imagen oficial bluenviron/mediamtx en red de host (UFW controla los puertos y
RTSP/UDP recibe las direcciones reales). La configuración se genera completa
en mediamtx.yml y se valida con `mediamtx --validate-conf` antes de arrancar.
"""
import json
import re
import urllib.request

import yaml
from flask import jsonify

from .. import config
from ..core import certs, docker, settings, system, validate
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


def stack_dir():
    return config.STACKS_DIR / "mediamtx"


def build_config(p, tls=False) -> dict:
    """Configuración completa de MediaMTX a partir de los parámetros del formulario."""
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
        p["publish_user"] = f.text("publish_user", validate.USERNAME, validate.USERNAME_MSG,
                                   default="publicador")
        p["publish_pass"] = f.raw("publish_pass") or prev.get("publish_pass") or \
            validate.random_password(20)
        p["anonymous_read"] = f.boolean("anonymous_read")
        p["read_user"] = f.text("read_user", validate.USERNAME, validate.USERNAME_MSG,
                                default="visor", required=not p["anonymous_read"])
        p["read_pass"] = f.raw("read_pass") or prev.get("read_pass") or validate.random_password(20)
        p["record"] = f.boolean("record")
        p["record_days"] = f.integer("record_days", 1, 365, 7)
        p["tls"] = f.boolean("tls")
        for k in ("publish_pass", "read_pass"):
            if not re.fullmatch(validate.SERVICE_PASS, p[k]):
                f.error(k, validate.SERVICE_PASS_MSG)
        if p["publish_user"] == p["read_user"] and not p["anonymous_read"]:
            f.error("read_user", "Usa un usuario distinto al de publicación")
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
