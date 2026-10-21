# SPDX-License-Identifier: Apache-2.0
"""Mumble: voz de baja latencia (compatible con el plugin ATAK Vx y Mumla).

Imagen oficial mumblevoip/mumble-server en red de host. La configuración se
pasa con variables MUMBLE_CONFIG_* (equivalentes a murmur.ini) desde un
archivo .env con permisos 600, y la contraseña de SuperUser con
MUMBLE_SUPERUSER_PASSWORD.
"""
import os
import re

from flask import jsonify

from .. import config
from ..core import certs, docker, settings, system, validate
from ..core.jobs import JobFailed
from ..core.shell import run
from .base import Module

IMAGE = "mumblevoip/mumble-server:v1.6.870"
CONTAINER = "tak-console-mumble"
PORT = 64738
UID = 10000  # usuario por defecto de la imagen oficial


def stack_dir():
    return config.STACKS_DIR / "mumble"


def env_values(p, tls=False) -> dict:
    env = {
        "MUMBLE_SUPERUSER_PASSWORD": p["superuser_pass"],
        "MUMBLE_CONFIG_PORT": PORT,
        "MUMBLE_CONFIG_USERS": p["max_users"],
        # El entrypoint escribe nombre=valor en el .ini; las comillas dobles evitan que
        # Qt interprete comas o espacios del texto.
        "MUMBLE_CONFIG_REGISTER_NAME": f'"{p["register_name"]}"',
        "MUMBLE_CONFIG_WELCOMETEXT": f'"{p["welcome"] or "Canal de voz del equipo"}"',
        "MUMBLE_CONFIG_SERVER_PASSWORD": p["server_pass"],
    }
    if tls:
        env.update({
            "MUMBLE_CONFIG_SSL_CERT": "/data/tls/server.crt",
            "MUMBLE_CONFIG_SSL_KEY": "/data/tls/server.key",
            "MUMBLE_CONFIG_SSL_CA": "/data/tls/chain.pem",
        })
    return env


def compose_data():
    return {
        "name": "tak-console-mumble",
        "services": {
            "mumble": {
                "image": IMAGE,
                "container_name": CONTAINER,
                "restart": "unless-stopped",
                "network_mode": "host",
                "env_file": ["mumble.env"],
                "volumes": ["./data:/data"],
                "logging": {"driver": "json-file", "options": {"max-size": "20m", "max-file": "3"}},
            }
        },
    }


class Mumble(Module):
    key = "mumble"
    name = "Mumble"
    summary = "Voz por canales para equipos en terreno (plugin ATAK Vx, Mumla, Mumble)"
    order = 40
    template = "modules/mumble.html"

    def status(self):
        st = self.state()
        if not st.get("installed"):
            return {"installed": False, "running": False, "level": "off",
                    "label": "No instalado", "endpoints": []}
        c = docker.container_state(CONTAINER)
        ports = system.listening_ports()
        return {
            "installed": True, "running": c["running"],
            "level": "ok" if c["running"] else "err",
            "label": "En servicio" if c["running"] else f"Contenedor: {c['status']}",
            "endpoints": [
                {"label": "Voz", "value": f"{PORT}/tcp+udp",
                 "up": (PORT, "tcp") in ports and (PORT, "udp") in ports},
            ],
        }

    def ports(self):
        return [{"port": str(PORT), "proto": "tcp", "label": "Mumble control"},
                {"port": str(PORT), "proto": "udp", "label": "Mumble voz"}]

    def page_context(self):
        st = self.state()
        return {"st": st, "p": st.get("params", {}), "hosts": system.candidate_hosts(),
                "tak_ca": certs.tak_ca_available(), "port": PORT, "image": IMAGE}

    def validate_deploy(self, data):
        f = validate.Form(data)
        prev = self.state().get("params", {})
        p = {
            "register_name": f.text("register_name", r"[A-Za-z0-9 ._\-]{1,40}",
                                    "Hasta 40 caracteres: letras, números, espacio, . _ -",
                                    default="Red TAK"),
            "welcome": f.text("welcome", r"[^<>\"'\\$`]{0,200}",
                              "Hasta 200 caracteres, sin < > \" ' \\ $ ni `", required=False),
            "max_users": f.integer("max_users", 2, 1000, 100),
            "server_pass": f.raw("server_pass"),
            "superuser_pass": f.raw("superuser_pass") or prev.get("superuser_pass")
            or validate.random_password(20),
            "tls": f.boolean("tls"),
        }
        if p["server_pass"] and not re.fullmatch(validate.SERVICE_PASS, p["server_pass"]):
            f.error("server_pass", validate.SERVICE_PASS_MSG)
        if not re.fullmatch(validate.SERVICE_PASS, p["superuser_pass"]):
            f.error("superuser_pass", validate.SERVICE_PASS_MSG)
        if p["tls"] and not certs.tak_ca_available():
            f.error("tls", "Necesita la CA de TAK Server: despliega TAK Server primero")
        return p, f.errors

    def deploy(self, job, p):
        d = stack_dir()
        data = d / "data"
        total = 5
        job.step(1, total, "Docker")
        if not docker.available():
            raise JobFailed("Docker no está disponible. Ejecuta de nuevo install.sh")
        job.ok("Docker disponible")

        job.step(2, total, "Certificado TLS")
        data.mkdir(parents=True, exist_ok=True)
        if p["tls"]:
            tak = settings.section("takserver")
            certs.sign_with_tak_ca("mumble", system.candidate_hosts(), data / "tls",
                                   tak.get("cert_pass", ""), log=job.log)
            job.ok("Certificado firmado por la CA de TAK (los EUD enrolados confían en él)")
        else:
            job.log("Mumble generará su propio certificado autofirmado")

        job.step(3, total, "Configuración")
        docker.write_env(d / "mumble.env", env_values(p, tls=p["tls"]))
        docker.write_compose(d, compose_data())
        run(["chown", "-R", f"{UID}:{UID}", str(data)], log=job.log)
        os.chmod(data, 0o700)
        job.ok("mumble.env y compose.yaml escritos")

        job.step(4, total, "Contenedor")
        docker.compose(d, "pull", log=job.log)
        docker.compose(d, "up", "-d", "--force-recreate", log=job.log)
        job.ok("Mumble iniciado")

        job.step(5, total, "Firewall")
        self.save_state(installed=True, params=p)
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
        job.warn(f"La base de datos de Mumble (canales, usuarios registrados) se conserva en "
                 f"{stack_dir() / 'data'}")

    def routes(self):
        return [("/api/m/mumble/logs", "mumble_logs", self.view_logs, ["GET"])]

    def view_logs(self):
        return jsonify(ok=True, text=docker.logs(CONTAINER, 300))
