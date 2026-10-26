# SPDX-License-Identifier: Apache-2.0
"""ZeroTier local: controlador propio + interfaz web ZTNET.

Componentes (todos en este equipo):
  * zerotier  zyclonite/zerotier:1.14.2   nodo + controlador, red de host
  * postgres  postgres:15-alpine          base de datos de ZTNET (solo 127.0.0.1)
  * ztnet     sinamics/ztnet:0.8.5        interfaz web del controlador (127.0.0.1:3000)
  * https     caddy:2.11.7                HTTPS para ZTNET en :3443 con el certificado de la consola

Por qué ZeroTier 1.14.2: desde 1.16 el código del controlador está bajo la
"ZeroTier Source-Available License" (uso no comercial; excluye expresamente el
uso por o para entidades gubernamentales o militares). La 1.14.2 se publicó
bajo BSL 1.1 con fecha de cambio 2026-01-01 a Apache-2.0. Ver NOTICE.

Raíces (planet):
  * públicas: las de ZeroTier Inc. (compatibles con las apps oficiales móviles)
  * privada:  un planet propio (generado en ZTNET o subido aquí); las apps
              oficiales de Android/iOS no aceptan planets personalizados.
"""
import json
import re
import secrets
import shutil
import time
import urllib.request
from pathlib import Path

from flask import abort, jsonify, request, send_file

from .. import config
from ..core import docker, monitor, settings, system, validate
from ..core.jobs import JOBS, Busy, JobFailed
from ..core.shell import run
from .base import Module

ZT_IMAGE = "zyclonite/zerotier:1.14.2"
ZTNET_IMAGE = "sinamics/ztnet:0.8.5"
PG_IMAGE = "postgres:15-alpine"
CADDY_IMAGE = "caddy:2.11.7"
ZT_CONTAINER = "tak-console-zerotier"
ZTNET_CONTAINER = "tak-console-ztnet"
PG_CONTAINER = "tak-console-ztnet-db"
CADDY_CONTAINER = "tak-console-ztnet-https"
ZTNET_PORT = 3443
PG_PORT = 5434
ZT_API = "http://127.0.0.1:9993"
# Raíces públicas de ZeroTier Inc. (rol PLANET en `zerotier-cli listpeers`).
PUBLIC_ROOTS = {"62f865ae71", "778cde7190", "cafe04eba9", "cafe9efeb9"}
NWID = re.compile(r"[0-9a-f]{16}")


def stack_dir():
    return config.STACKS_DIR / "zerotier"


def zt_home():
    return stack_dir() / "zerotier-one"


def caddyfile() -> str:
    return (
        "{\n"
        "\tadmin off\n"
        "\tauto_https off\n"
        "}\n\n"
        f":{ZTNET_PORT} {{\n"
        "\ttls /certs/console.crt /certs/console.key\n"
        "\treverse_proxy 127.0.0.1:3000\n"
        "}\n"
    )


def compose_data():
    return {
        "name": "tak-console-zerotier",
        "services": {
            "zerotier": {
                "image": ZT_IMAGE,
                "container_name": ZT_CONTAINER,
                "restart": "unless-stopped",
                "network_mode": "host",
                "cap_add": ["NET_ADMIN", "SYS_ADMIN"],
                "devices": ["/dev/net/tun:/dev/net/tun"],
                "volumes": ["./zerotier-one:/var/lib/zerotier-one"],
            },
            "postgres": {
                "image": PG_IMAGE,
                "container_name": PG_CONTAINER,
                "restart": "unless-stopped",
                "env_file": ["ztnet.env"],
                "ports": [f"127.0.0.1:{PG_PORT}:5432"],
                "volumes": ["./postgres:/var/lib/postgresql/data"],
            },
            "ztnet": {
                "image": ZTNET_IMAGE,
                "container_name": ZTNET_CONTAINER,
                "restart": "unless-stopped",
                "network_mode": "host",
                "working_dir": "/app",
                "env_file": ["ztnet.env"],
                "volumes": ["./zerotier-one:/var/lib/zerotier-one"],
                "depends_on": ["postgres", "zerotier"],
            },
            "https": {
                "image": CADDY_IMAGE,
                "container_name": CADDY_CONTAINER,
                "restart": "unless-stopped",
                "network_mode": "host",
                "volumes": ["./Caddyfile:/etc/caddy/Caddyfile:ro",
                            f"{config.CERTS_DIR}:/certs:ro",
                            "./caddy-data:/data"],
                "depends_on": ["ztnet"],
            },
        },
    }


def ztnet_env(st, public_url):
    return {
        "POSTGRES_HOST": "127.0.0.1",
        "POSTGRES_PORT": PG_PORT,
        "POSTGRES_USER": "ztnet",
        "POSTGRES_PASSWORD": st["pg_password"],
        "POSTGRES_DB": "ztnet",
        "NEXTAUTH_URL": public_url,
        "NEXTAUTH_SECRET": st["nextauth_secret"],
        "NEXTAUTH_URL_INTERNAL": "http://127.0.0.1:3000",
        "HOSTNAME": "127.0.0.1",
        "PORT": 3000,
        "ZT_ADDR": ZT_API,
    }


def cli(*args, timeout=20):
    return docker.exec_(ZT_CONTAINER, "zerotier-cli", *args, timeout=timeout)


def node_info():
    res = cli("-j", "info")
    try:
        return json.loads(res.output) if res.ok else {}
    except ValueError:
        return {}


def networks():
    res = cli("-j", "listnetworks")
    try:
        data = json.loads(res.output) if res.ok else []
    except ValueError:
        return []
    return [{"id": n.get("nwid") or n.get("id"), "name": n.get("name", ""),
             "status": n.get("status", ""), "iface": n.get("portDeviceName", ""),
             "addresses": n.get("assignedAddresses", [])} for n in data]


def roots():
    res = cli("-j", "listpeers")
    try:
        data = json.loads(res.output) if res.ok else []
    except ValueError:
        return []
    out = []
    for p in data:
        if p.get("role") != "PLANET":
            continue
        paths = [x.get("address", "") for x in p.get("paths", []) if x.get("active")]
        out.append({"address": p.get("address"), "paths": paths, "latency": p.get("latency")})
    return out


LOG_CONTAINERS = [("zerotier", "ZeroTier (nodo)", ZT_CONTAINER),
                  ("ztnet", "ZTNET (web)", ZTNET_CONTAINER),
                  ("https", "HTTPS (Caddy)", CADDY_CONTAINER),
                  ("postgres", "Base de datos", PG_CONTAINER)]


def leaf_peers():
    """Pares «LEAF» que conoce este nodo (zerotier-cli -j listpeers), como lista de dicts."""
    res = cli("-j", "listpeers")
    data = json.loads(res.output) if res.ok else None
    if not isinstance(data, list):
        raise ValueError("zerotier-cli no devolvió la lista de pares")
    return [p for p in data if p.get("role") == "LEAF"]


def root_mode(peer_roots) -> str:
    if not peer_roots:
        return "desconocido"
    ids = {r["address"] for r in peer_roots}
    return "publicas" if ids & PUBLIC_ROOTS else "privada"


class ZeroTier(Module):
    key = "zerotier"
    name = "ZeroTier"
    summary = "Red privada superpuesta con controlador propio y administración web (ZTNET)"
    order = 10
    template = "modules/zerotier.html"

    def status(self):
        st = self.state()
        if not st.get("installed"):
            return {"installed": False, "running": False, "level": "off",
                    "label": "No instalado", "endpoints": []}
        zt = docker.container_state(ZT_CONTAINER)
        web = docker.container_state(ZTNET_CONTAINER)
        https = docker.container_state(CADDY_CONTAINER)
        nets = networks() if zt["running"] else []
        online = node_info().get("online") if zt["running"] else False
        ok = zt["running"] and web["running"] and https["running"]
        level = "ok" if ok and online else ("warn" if zt["running"] else "err")
        label = "En línea" if ok and online else ("Sin conexión a raíces" if zt["running"]
                                                   else "Detenido")
        eps = [{"label": "Transporte", "value": "9993/udp", "up": zt["running"]},
               {"label": "ZTNET", "value": f"{ZTNET_PORT}/tcp", "up": https["running"]}]
        for n in nets:
            if n["addresses"]:
                eps.append({"label": n["name"] or n["id"], "value": ", ".join(n["addresses"]),
                            "up": n["status"] == "OK"})
        return {"installed": True, "running": zt["running"], "level": level,
                "label": label, "endpoints": eps}

    def ports(self):
        return [{"port": "9993", "proto": "udp", "label": "ZeroTier transporte", "always": True},
                {"port": str(ZTNET_PORT), "proto": "tcp", "label": "ZTNET (HTTPS)"}]

    def page_context(self):
        st = self.state()
        ctx = {"st": st, "hosts": system.candidate_hosts(), "lan_ip": system.primary_ip(),
               "images": [ZT_IMAGE, ZTNET_IMAGE, PG_IMAGE, CADDY_IMAGE],
               "ztnet_port": ZTNET_PORT, "info": {}, "networks": [], "roots": [],
               "mode": "desconocido", "planet_file": False}
        if st.get("installed") and docker.container_state(ZT_CONTAINER)["running"]:
            ctx["info"] = node_info()
            ctx["networks"] = networks()
            ctx["roots"] = roots()
            ctx["mode"] = root_mode(ctx["roots"])
        ctx["planet_file"] = (zt_home() / "planet").exists()
        return ctx

    def validate_deploy(self, data):
        f = validate.Form(data)
        p = {"public_host": f.text("public_host", r"[A-Za-z0-9.\-]{1,253}",
                                   "IP o nombre DNS sin esquema ni puerto",
                                   default=system.primary_ip())}
        return p, f.errors

    def deploy(self, job, p):
        d = stack_dir()
        total = 5
        st = self.state()
        st.setdefault("pg_password", secrets.token_hex(24))
        st.setdefault("nextauth_secret", secrets.token_hex(32))
        public_url = f"https://{p['public_host']}:{ZTNET_PORT}"

        job.step(1, total, "Docker y TUN")
        if not docker.available():
            raise JobFailed("Docker no está disponible. Ejecuta de nuevo install.sh")
        if not Path("/dev/net/tun").exists() and not config.DRY_RUN:
            raise JobFailed("No existe /dev/net/tun: el kernel o la VM no permiten interfaces TUN")
        job.ok("Docker y /dev/net/tun disponibles")

        job.step(2, total, "Certificado HTTPS")
        if not config.CONSOLE_CERT.exists():
            raise JobFailed("Falta el certificado de la consola; ejecuta install.sh")
        job.ok(f"ZTNET usará el certificado de la consola en {public_url}")

        job.step(3, total, "Archivos de configuración")
        for sub in ("zerotier-one", "postgres", "caddy-data"):
            (d / sub).mkdir(parents=True, exist_ok=True)
        docker.write_env(d / "ztnet.env", ztnet_env(st, public_url))
        docker.write_private(d / "Caddyfile", caddyfile(), mode=0o644)
        docker.write_compose(d, compose_data())
        job.ok("compose.yaml, ztnet.env y Caddyfile escritos")

        job.step(4, total, "Contenedores")
        docker.compose(d, "pull", log=job.log)
        docker.compose(d, "up", "-d", log=job.log)
        info = {}
        for _ in range(30):
            info = node_info()
            if info.get("address"):
                break
            time.sleep(2)
        if info.get("address"):
            job.ok(f"Nodo ZeroTier {info['address']} (versión {info.get('version', '?')})")
        else:
            job.warn("El nodo aún no responde; revisa el registro del contenedor")

        job.step(5, total, "Firewall")
        self.save_state(installed=True, public_host=p["public_host"], public_url=public_url,
                        pg_password=st["pg_password"], nextauth_secret=st["nextauth_secret"],
                        node_id=info.get("address"))
        self.apply_firewall(log=job.log)
        job.log("")
        job.ok(f"Abre {public_url} y crea de inmediato la cuenta de administrador de ZTNET "
               "(el primer usuario registrado queda como administrador).")

    def actions(self):
        def c(*args):
            def _do(job):
                docker.compose(stack_dir(), *args, log=job.log)
            return _do

        def restart_zt(job):
            run(["docker", "restart", ZT_CONTAINER], log=job.log)

        return {"start": ("Iniciar", c("up", "-d")), "stop": ("Detener", c("stop")),
                "restart": ("Reiniciar todo", c("restart")),
                "restart_zt": ("Reiniciar nodo ZeroTier", restart_zt)}

    def uninstall(self, job, params):
        if docker.compose_file(stack_dir()).exists():
            docker.compose(stack_dir(), "down", log=job.log, check=False)
        self.remove_firewall(log=job.log)
        self.save_state(installed=False)
        settings.update_section("network", {"zt_ifaces": []})
        job.warn(f"La identidad del controlador y sus redes se conservan en {zt_home()}. "
                 "Si la borras, las redes existentes quedan huérfanas.")

    # ── rutas adicionales ───────────────────────────────────────────────────

    # ── consolas de estado y actividad ──────────────────────────────────────
    EVENTS_NOTE = ("No se conoce un formato de eventos de conexión para estos registros: se "
                   "resaltan solo avisos y errores. Los pares conectados aparecen en «Conectados».")

    def log_sources(self):
        return [(k, label) for k, label, _ in LOG_CONTAINERS]

    def log_lines(self, n, source=""):
        name = {k: c for k, _, c in LOG_CONTAINERS}.get(source, ZT_CONTAINER)
        return docker.logs(name, n).splitlines()

    def checks(self):
        out = []
        for _, label, name in LOG_CONTAINERS:
            c = docker.container_state(name)
            out.append({"label": label, "ok": c["running"], "detail": c["status"] or "—"})
        if out and out[0]["ok"]:
            info = node_info()
            out.append({"label": "Nodo en línea", "ok": bool(info.get("online")),
                        "detail": info.get("address", "—")})
            planets = roots()
            out.append({"label": "Raíces alcanzables", "ok": any(r["paths"] for r in planets),
                        "detail": str(sum(1 for r in planets if r["paths"]))})
        return out

    def connected(self):
        try:
            peers = leaf_peers()
        except ValueError as e:
            return monitor.table([], [], error=str(e))
        now_ms = time.time() * 1000
        rows = []
        for p in sorted(peers, key=lambda x: x.get("address", "")):
            active = [x for x in p.get("paths", []) if x.get("active")]
            via = (active[0].get("address", "—") if active else "")
            last = max([x.get("lastReceive", 0) or 0 for x in p.get("paths", [])] or [0])
            lat = p.get("latency")
            rows.append([p.get("address", "—"), "Directo" if active else "Por relé",
                         via or "—", f"{lat} ms" if isinstance(lat, int) and lat >= 0 else "—",
                         p.get("version") or "—",
                         monitor.age((now_ms - last) / 1000) if last else "—"])
        return monitor.table(["Dirección ZeroTier", "Conexión", "Ruta", "Latencia", "Versión",
                              "Último dato"], rows,
                             note="Pares con los que este nodo ha hablado recientemente. Los "
                                  "miembros autorizados de cada red se ven en ZTNET.")

    def routes(self):
        return [
            ("/api/m/zerotier/join", "zt_join", self.view_join, ["POST"]),
            ("/api/m/zerotier/leave", "zt_leave", self.view_leave, ["POST"]),
            ("/api/m/zerotier/planet", "zt_planet_upload", self.view_planet_upload, ["POST"]),
            ("/api/m/zerotier/planet/reset", "zt_planet_reset", self.view_planet_reset, ["POST"]),
            ("/m/zerotier/planet", "zt_planet_download", self.view_planet_download, ["GET"]),
            ("/api/m/zerotier/logs", "zt_logs", self.view_logs, ["GET"]),
        ]

    def _sync_ifaces(self):
        ifaces = sorted({n["iface"] for n in networks() if n["iface"]})
        settings.update_section("network", {"zt_ifaces": ifaces})
        return ifaces

    def _reapply_all_firewalls(self, job):
        from . import MODULES
        for m in MODULES.values():
            if m.installed():
                m.apply_firewall(log=job.log)

    def view_join(self):
        nwid = (request.form.get("nwid") or "").strip().lower()
        authorize = request.form.get("authorize") in ("1", "on", "true")
        if not NWID.fullmatch(nwid):
            return jsonify(ok=False, errors={"nwid": "ID de red de 16 caracteres hexadecimales"}), 400

        def _join(job):
            res = run(["docker", "exec", ZT_CONTAINER, "zerotier-cli", "join", nwid],
                      log=job.log)
            if "200" not in res.output and not config.DRY_RUN:
                raise JobFailed("zerotier-cli no confirmó la unión")
            node = node_info().get("address", "")
            if authorize and node:
                if nwid.startswith(node):
                    self._authorize(job, nwid, node)
                else:
                    job.warn("La red no pertenece a este controlador: autoriza el nodo en su "
                             "controlador")
            for _ in range(15):
                time.sleep(2)
                if any(n["id"] == nwid and n["addresses"] for n in networks()):
                    break
            ifaces = self._sync_ifaces()
            job.ok("Interfaces ZeroTier: " + (", ".join(ifaces) or "ninguna aún"))
            self._reapply_all_firewalls(job)

        try:
            JOBS.start(self.key, f"Unir a la red {nwid}", _join)
        except Busy as e:
            return jsonify(ok=False, error=str(e)), 409
        return jsonify(ok=True)

    def _authorize(self, job, nwid, node):
        token = (zt_home() / "authtoken.secret").read_text().strip()
        req = urllib.request.Request(
            f"{ZT_API}/controller/network/{nwid}/member/{node}",
            data=json.dumps({"authorized": True}).encode(), method="POST",
            headers={"X-ZT1-Auth": token, "Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=10) as r:
            r.read()
        job.ok(f"Nodo {node} autorizado en la red {nwid}")

    def view_leave(self):
        nwid = (request.form.get("nwid") or "").strip().lower()
        if not NWID.fullmatch(nwid):
            abort(400)

        def _leave(job):
            run(["docker", "exec", ZT_CONTAINER, "zerotier-cli", "leave", nwid], log=job.log)
            self._sync_ifaces()
            self._reapply_all_firewalls(job)

        try:
            JOBS.start(self.key, f"Salir de la red {nwid}", _leave)
        except Busy as e:
            return jsonify(ok=False, error=str(e)), 409
        return jsonify(ok=True)

    def view_planet_upload(self):
        fs = request.files.get("planet")
        if not fs:
            return jsonify(ok=False, error="Selecciona el archivo planet"), 400
        data = fs.read(65537)
        if not 32 <= len(data) <= 65536:
            return jsonify(ok=False, error="El archivo no parece un planet de ZeroTier"), 400

        def _apply(job):
            home = zt_home()
            target = home / "planet"
            if target.exists():
                backup = home / f"planet.bak-{time.strftime('%Y%m%d-%H%M%S')}"
                shutil.copy2(target, backup)
                job.log(f"Respaldo del planet anterior: {backup.name}")
            target.write_bytes(data)
            run(["docker", "restart", ZT_CONTAINER], log=job.log)
            self.save_state(custom_planet=True)
            job.ok("Planet personalizado aplicado. Distribúyelo a cada cliente (archivo «planet»).")

        try:
            JOBS.start(self.key, "Aplicar raíz privada (planet)", _apply)
        except Busy as e:
            return jsonify(ok=False, error=str(e)), 409
        return jsonify(ok=True)

    def view_planet_reset(self):
        def _reset(job):
            target = zt_home() / "planet"
            if target.exists():
                backup = zt_home() / f"planet.bak-{time.strftime('%Y%m%d-%H%M%S')}"
                target.rename(backup)
                job.log(f"Planet personalizado movido a {backup.name}")
            run(["docker", "restart", ZT_CONTAINER], log=job.log)
            self.save_state(custom_planet=False)
            job.ok("Restauradas las raíces públicas integradas en ZeroTier")

        try:
            JOBS.start(self.key, "Restaurar raíces públicas", _reset)
        except Busy as e:
            return jsonify(ok=False, error=str(e)), 409
        return jsonify(ok=True)

    def view_planet_download(self):
        target = zt_home() / "planet"
        if not target.exists():
            abort(404)
        return send_file(str(target), as_attachment=True, download_name="planet")

    def view_logs(self):
        which = request.args.get("c", "zerotier")
        name = {"zerotier": ZT_CONTAINER, "ztnet": ZTNET_CONTAINER,
                "https": CADDY_CONTAINER, "postgres": PG_CONTAINER}.get(which, ZT_CONTAINER)
        return jsonify(ok=True, text=docker.logs(name, 300))
