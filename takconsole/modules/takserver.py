# SPDX-License-Identifier: Apache-2.0
"""TAK Server (instalación nativa desde el paquete .deb de tak.gov).

Pasos verificados contra los scripts oficiales del repositorio
TAK-Product-Center/Server (makeRootCa.sh, makeCert.sh, cert-metadata.sh,
CoreConfig.example.xml/CoreConfig.xsd) y las dependencias declaradas del .deb
(openjdk-17-jdk, openssl y PostgreSQL con PostGIS: en 5.8-RELEASE92 es
postgresql-18, que Ubuntu 22.04 no trae y se instala desde el repositorio PGDG).
"""
import glob
import http.client
import io
import json
import os
import re
import shutil
import ssl
import tarfile
import time
import urllib.request
from datetime import datetime
from pathlib import Path

from flask import abort, g, jsonify, request, send_file, session
from werkzeug.utils import secure_filename

from .. import config
from ..core import auth, monitor, rbac, settings, system, validate
from ..core.jobs import JOBS, Busy, JobFailed
from ..core.shell import CommandError, capture, run, which
from . import takserver_files as tf
from .base import Module

TAK_HOME = Path("/opt/tak")
CERTS = TAK_HOME / "certs"
FILES = CERTS / "files"
CORECONFIG = TAK_HOME / "CoreConfig.xml"
CORECONFIG_EXAMPLE = TAK_HOME / "CoreConfig.example.xml"
USERMANAGER = TAK_HOME / "utils" / "UserManager.jar"
TAK_LOGS = TAK_HOME / "logs"
PGDG_KEY_URL = "https://www.postgresql.org/media/keys/ACCC4CF8.asc"
PGDG_KEY = Path("/usr/share/postgresql-common/pgdg/apt.postgresql.org.asc")
PGDG_LIST = Path("/etc/apt/sources.list.d/pgdg.list")
STREAM_PORT = 8089
TOTAL_STEPS = 10

# apt verifica las firmas como el usuario sin privilegios «_apt». Solo se corrigen
# permisos de directorios que cuelgan de estas raíces (nunca las raíces mismas).
APT_SAFE_ROOTS = (Path("/usr/share"), Path("/etc/apt"), Path("/usr/local/share"))
PGP_ARMOR_HEADER = b"-----BEGIN PGP PUBLIC KEY BLOCK-----"

# Borrado de datos (después de desinstalar). Valores de TAK Server 5.8: base «cot» y rol
# «martiuser»; el nombre real se lee de CoreConfig.xml antes de borrar.
PURGE_PHRASE = "BORRAR DATOS"
DB_DEFAULTS = {"name": "cot", "role": "martiuser", "port": 5432}
PG_IDENT = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,62}")
PG_PROTECTED_DBS = {"postgres", "template0", "template1"}
PG_PROTECTED_ROLES = {"postgres"}
# Qué se guarda en el respaldo: certificados y configuración (no la base de datos).
BACKUP_ITEMS = ("certs", "CoreConfig*.xml*", "UserAuthenticationFile.xml*",
                "TAKIgniteConfig.xml*", "conf")
# Estado de la consola que deja de ser válido al borrar los datos.
STATE_RESET = ("installed", "int_ca", "version", "deployed_at", "cert_pass", "users",
               "package", "package_version")
SIGNED_BY = re.compile(r"signed-by=([^\s\]]+)|^Signed-By:\s*(\S+)", re.IGNORECASE | re.MULTILINE)

# Consolas de estado y actividad. La API REST es la del código público de TAK Server (5.7):
# BaseRestController (/Marti/api) + SubscriptionApi (/subscriptions/all). Se consulta en
# 127.0.0.1:8443 con el certificado «admin» de la propia consola.
API_PORT = 8443
SUBSCRIPTIONS_PATH = "/Marti/api/subscriptions/all"
LOG_FILES = {"messaging": ("takserver-messaging.log", "Mensajería (clientes)"),
             "api": ("takserver-api.log", "API y administración")}
# Línea de registro: «2026-10-26-11:36:00.123 [hilo] LEVEL logger - mensaje» (logback-spring.xml);
# si TAK usa el diseño JSON, el nivel va en "level":"…".
TAK_LEVEL = re.compile(r"^\S+ \[[^\]]*\] (TRACE|DEBUG|INFO|WARN|ERROR|FATAL)\b|\"level\"\s*:\s*\"(WARN|ERROR|FATAL)")
EVENT_RULES = [
    (re.compile(r"authenticat\w* (?:failed|unsuccessful)|Authentication Failed", re.I), "err",
     "AUTH FALLIDA"),
    (re.compile(r"ghost connection"), "warn", "FANTASMA"),
    (re.compile(r"New Federate connection"), "ok", "FEDERACIÓN"),
    (re.compile(r"Tomcat started on port"), "ok", "ARRANCADO"),
]


def _upload_dir() -> Path:
    d = config.UPLOAD_DIR / "takserver"
    d.mkdir(parents=True, exist_ok=True)
    return d


def signed_by_path(text: str):
    """Ruta de la llave que declara un archivo de fuentes apt (una línea o deb822)."""
    for m in SIGNED_BY.finditer(text):
        value = m.group(1) or m.group(2)
        if value and value.startswith("/"):
            return Path(value)
    return None


def make_apt_readable(path: Path) -> list:
    """Deja `path` y sus directorios legibles por «_apt»; devuelve los directorios corregidos.

    El servicio de la consola corre con UMask=0077: un `mkdir(parents=True)` crea
    /usr/share/postgresql-common con modo 0700 y apt, que no es root, no puede abrir la
    llave (lo reporta como NO_PUBKEY). Solo se AGREGAN permisos de lectura/entrada.
    """
    path = Path(path)
    changed = []
    if path.is_file():
        os.chmod(path, (path.stat().st_mode & 0o7777) | 0o044)
    for d in path.parents:
        if not any(root in d.parents for root in APT_SAFE_ROOTS):
            break
        st = d.stat()
        if st.st_uid != 0:
            continue
        mode = st.st_mode & 0o7777
        if mode & 0o055 != 0o055:
            os.chmod(d, mode | 0o055)
            changed.append(d)
    return changed


def apt_can_read(path: Path) -> bool:
    """¿Puede el usuario «_apt» leer `path`? (sin usuario _apt, apt verifica como root)."""
    if config.DRY_RUN or not capture(["id", "_apt"]).ok:
        return True
    return capture(["runuser", "-u", "_apt", "--", "test", "-r", str(path)]).ok


def key_is_present(path: Path, armored: bool = True) -> bool:
    try:
        if not path.is_file() or path.stat().st_size == 0:
            return False
        return path.read_bytes().lstrip().startswith(PGP_ARMOR_HEADER) if armored else True
    except OSError:
        return False


def fetch_pgdg_key(dest: Path) -> None:
    """Descarga la llave del repositorio PGDG y la escribe de forma atómica y legible."""
    try:
        with urllib.request.urlopen(PGDG_KEY_URL, timeout=60) as resp:
            data = resp.read()
    except OSError as e:
        raise JobFailed(f"No se pudo descargar la llave de PGDG ({e}). "
                        "Comprueba la salida a internet hacia www.postgresql.org") from e
    if not data.lstrip().startswith(PGP_ARMOR_HEADER):
        raise JobFailed("La respuesta de postgresql.org no es una llave PGP válida")
    dest.parent.mkdir(parents=True, exist_ok=True)
    tmp = dest.with_name(dest.name + ".tmp")
    tmp.write_bytes(data)
    os.chmod(tmp, 0o644)
    os.replace(tmp, dest)


def tak_api_get(path: str, timeout: float = 6.0):
    """GET a la API de TAK Server en el propio equipo con el certificado «admin».

    No se verifica el certificado del servidor: se conecta solo a 127.0.0.1 y la identidad que
    importa aquí es la del cliente (mTLS). Lanza OSError con un mensaje legible si falla."""
    pem, key = FILES / "admin.pem", FILES / "admin.key"
    if not pem.exists() or not key.exists():
        raise OSError("faltan admin.pem/admin.key en los certificados de TAK Server")
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        ctx.load_cert_chain(str(pem), str(key), password=settings.section("takserver").get("cert_pass", ""))
    except (ssl.SSLError, OSError) as e:
        raise OSError(f"no se pudo cargar el certificado admin: {e}")
    conn = http.client.HTTPSConnection("127.0.0.1", API_PORT, context=ctx, timeout=timeout)
    try:
        conn.request("GET", path, headers={"Accept": "application/json"})
        resp = conn.getresponse()
        body = resp.read(4_000_000)
    except (OSError, http.client.HTTPException) as e:
        raise OSError(f"la API en {API_PORT} no responde ({e})")
    finally:
        conn.close()
    if resp.status in (401, 403):
        raise OSError(f"la API rechazó al administrador (HTTP {resp.status})")
    if resp.status != 200:
        raise OSError(f"la API respondió HTTP {resp.status}")
    try:
        return json.loads(body.decode("utf-8", errors="replace"))
    except ValueError:
        raise OSError("la API no devolvió JSON")


def subscription_rows(payload, now: float):
    """Filas de «Conectados» a partir de /subscriptions/all (ApiResponse con 'data')."""
    data = payload.get("data") if isinstance(payload, dict) else payload
    if isinstance(data, dict):
        data = data.get("subscriptions") or list(data.values())
    rows, unknown = [], 0
    for s in data if isinstance(data, list) else []:
        if not isinstance(s, dict):
            continue
        if not (s.get("callsign") or s.get("clientUid")):
            unknown += 1
        last = s.get("lastReportMilliseconds")
        uid = str(s.get("clientUid") or "")
        rows.append([s.get("callsign") or "—", uid[:18] + ("…" if len(uid) > 18 else ""),
                     s.get("ipAddress") or "—", s.get("protocol") or "—",
                     " ".join(x for x in (s.get("takClient"), s.get("takVersion")) if x) or "—",
                     " / ".join(x for x in (s.get("role"), s.get("team")) if x) or "—",
                     monitor.age(now - last / 1000) if isinstance(last, (int, float)) and last > 0 else "—"])
    return rows, unknown


def coreconfig_db(text: str) -> dict:
    """Base, rol y puerto de PostgreSQL declarados en CoreConfig.xml (con valores por defecto)."""
    info = dict(DB_DEFAULTS)
    for tag in re.finditer(r"<connection\b[^>]*>", text):
        node = tag.group(0)
        url = re.search(r'\burl="jdbc:postgresql://[^/":]+(?::(\d+))?/([^"?]+)', node)
        if not url:
            continue
        if url.group(1):
            info["port"] = int(url.group(1))
        info["name"] = url.group(2)
        user = re.search(r'\busername="([^"]*)"', node)
        if user:
            info["role"] = user.group(1)
        break
    return info


def check_db_info(info: dict) -> None:
    """Rechaza nombres que no sean identificadores simples o que sean de PostgreSQL mismo."""
    if not PG_IDENT.fullmatch(info["name"]) or info["name"].lower() in PG_PROTECTED_DBS:
        raise ValueError(f"base de datos «{info['name']}»")
    if not PG_IDENT.fullmatch(info["role"]) or info["role"].lower() in PG_PROTECTED_ROLES:
        raise ValueError(f"rol «{info['role']}»")
    if not 1 <= int(info["port"]) <= 65535:
        raise ValueError(f"puerto {info['port']}")


class TakServer(Module):
    key = "takserver"
    name = "TAK Server"
    summary = "Servidor de conciencia situacional para ATAK, iTAK y WinTAK"
    order = 20
    template = "modules/takserver.html"

    # ── estado ──────────────────────────────────────────────────────────────
    def package_version(self):
        res = capture(["dpkg-query", "-W", "-f=${Status}|${Version}", "takserver"])
        if res.ok and "install ok installed" in res.output:
            return res.output.split("|", 1)[1].strip()
        return None

    def status(self):
        version = self.package_version()
        if not version:
            return {"installed": False, "running": False, "level": "off",
                    "label": "No instalado", "endpoints": []}
        active = capture(["systemctl", "is-active", "takserver"]).output.strip()
        ports = system.listening_ports()
        streaming = (STREAM_PORT, "tcp") in ports
        if active == "active" and streaming:
            level, label = "ok", "En servicio"
        elif active in ("active", "activating"):
            level, label = "warn", "Iniciando"
        else:
            level, label = "err", "Detenido"
        st = self.state()
        return {
            "installed": True, "running": active == "active", "level": level,
            "label": label, "version": version,
            "endpoints": [
                {"label": "Clientes (TLS)", "value": f"{STREAM_PORT}/tcp",
                 "up": streaming},
                {"label": "Admin con certificado", "value": "8443/tcp",
                 "up": (8443, "tcp") in ports},
                {"label": "Admin con usuario/clave", "value": "8446/tcp",
                 "up": (8446, "tcp") in ports},
            ],
            "enrollment": st.get("enrollment", False),
        }

    def ports(self):
        return [
            {"port": "8089", "proto": "tcp", "label": "TAK clientes TLS"},
            {"port": "8443", "proto": "tcp", "label": "TAK admin (certificado)"},
            {"port": "8446", "proto": "tcp", "label": "TAK admin (usuario) y enrolamiento"},
        ]

    def int_ca(self):
        st = self.state()
        if st.get("int_ca"):
            return st["int_ca"]
        for p in sorted(glob.glob(str(FILES / "truststore-*.jks"))):
            name = os.path.basename(p)[len("truststore-"):-len(".jks")]
            if name != "root":
                return name
        return None

    def page_context(self):
        st = self.state()
        pkg = st.get("package")
        pkg_installed = bool(self.package_version())
        summary = None
        if CORECONFIG.exists():
            try:
                summary = tf.coreconfig_summary(CORECONFIG.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                summary = None
        return {
            "st": st,
            "package_ok": bool(pkg and Path(pkg).exists()),
            "package_name": os.path.basename(pkg) if pkg else None,
            "certs_exist": (FILES / "ca.pem").exists(),
            "int_ca": self.int_ca(),
            "users": st.get("users", []),
            "hosts": system.candidate_hosts(),
            "coreconfig": summary,
            "supported_os": system.is_ubuntu_2204(),
            "os_label": system.os_label(),
            "purge": None if pkg_installed else self.purge_overview(),
            "purge_phrase": PURGE_PHRASE,
        }

    # ── validación ──────────────────────────────────────────────────────────
    def validate_deploy(self, data):
        f = validate.Form(data)
        st = self.state()
        p = {
            "country": f.text("country", r"[A-Za-z]{2}", "Código de país de 2 letras (ej. CL)",
                              default="CL").upper(),
            "state": f.text("state", validate.CERT_FIELD, validate.CERT_FIELD_MSG),
            "city": f.text("city", validate.CERT_FIELD, validate.CERT_FIELD_MSG),
            "org": f.text("org", validate.CERT_FIELD, validate.CERT_FIELD_MSG),
            "ou": f.text("ou", validate.CERT_FIELD, validate.CERT_FIELD_MSG),
            "root_ca": f.text("root_ca", validate.CA_NAME, validate.CA_NAME_MSG),
            "int_ca": f.text("int_ca", validate.CA_NAME, validate.CA_NAME_MSG),
            "cert_pass": f.text("cert_pass", validate.CERT_PASS, validate.CERT_PASS_MSG,
                                required=not st.get("cert_pass")) or st.get("cert_pass", ""),
            "admin_user": f.text("admin_user", validate.USERNAME, validate.USERNAME_MSG,
                                 default="webadmin"),
            "admin_pass": f.raw("admin_pass"),
            "enrollment": f.boolean("enrollment"),
            "enroll_days": f.integer("enroll_days", 1, 3650, 365),
            "regenerate": f.boolean("regenerate"),
            "verify_signature": f.boolean("verify_signature"),
        }
        names = {p["root_ca"].lower(), p["int_ca"].lower()}
        if p["root_ca"] and p["int_ca"] and len(names) < 2:
            f.error("int_ca", "La CA intermedia debe tener un nombre distinto de la raíz")
        if names & {"takserver", "admin"}:
            f.error("int_ca", "Los nombres 'takserver' y 'admin' están reservados")
        if p["admin_pass"]:
            probs = validate.tak_password_problems(p["admin_pass"])
            if probs:
                f.error("admin_pass", "La contraseña requiere: " + ", ".join(probs))
        elif not st.get("installed"):
            f.error("admin_pass", "Define la contraseña del administrador web")

        pkg = st.get("package")
        has_pkg = bool(pkg and Path(pkg).exists())
        if not has_pkg and not self.package_version():
            f.error("package", "Sube primero el paquete .deb de TAK Server")
        if (FILES / "ca.pem").exists() and not p["regenerate"]:
            old = st.get("cert_pass")
            if old and p["cert_pass"] and old != p["cert_pass"]:
                f.error("cert_pass", "No coincide con la contraseña de los certificados existentes. "
                                     "Marca «Regenerar certificados» para cambiarla.")
        return p, f.errors

    # ── despliegue ──────────────────────────────────────────────────────────
    def deploy(self, job, p):
        if config.DRY_RUN:
            job.warn("Modo de prueba (TAKCONSOLE_DRY_RUN=1): no se modifica el sistema")
            return
        st = self.state()
        pkg = st.get("package")
        install = bool(pkg and Path(pkg).exists())
        secrets = [p["cert_pass"], p["admin_pass"]]

        job.step(1, TOTAL_STEPS, "Comprobaciones previas")
        self._prechecks(job, install)

        job.step(2, TOTAL_STEPS, "Límites del sistema")
        self._limits(job)

        if install:
            job.step(3, TOTAL_STEPS, "Repositorio de PostgreSQL (PGDG)")
            self._pgdg(job)
            job.step(4, TOTAL_STEPS, "Verificación de firma del paquete")
            self._verify(job, pkg, p["verify_signature"])
            job.step(5, TOTAL_STEPS, "Instalación del paquete")
            run(["apt-get", "install", "-y", "-o", "DPkg::Lock::Timeout=600", pkg],
                env={"DEBIAN_FRONTEND": "noninteractive"}, log=job.log, timeout=3600)
            if not TAK_HOME.exists():
                raise JobFailed("El paquete se instaló pero no existe /opt/tak")
            job.ok(f"TAK Server {self.package_version() or ''} instalado")
        else:
            for n, t in ((3, "Repositorio de PostgreSQL"), (4, "Verificación de firma"),
                         (5, "Instalación del paquete")):
                job.step(n, TOTAL_STEPS, t)
                job.log("Sin paquete nuevo: se reconfigura la instalación existente")

        job.step(6, TOTAL_STEPS, "Certificados")
        int_ca = self._certificates(job, p, secrets)

        job.step(7, TOTAL_STEPS, "CoreConfig.xml")
        self._coreconfig(job, p, int_ca)

        job.step(8, TOTAL_STEPS, "Servicio takserver")
        self._start_and_wait(job)

        job.step(9, TOTAL_STEPS, "Administradores")
        self._admins(job, p, secrets)

        job.step(10, TOTAL_STEPS, "Firewall")
        self.apply_firewall(log=job.log)

        saved = {k: p[k] for k in ("country", "state", "city", "org", "ou", "root_ca",
                                    "cert_pass", "admin_user", "enrollment", "enroll_days")}
        self.save_state(installed=True, int_ca=int_ca, version=self.package_version(),
                        deployed_at=int(time.time()), **saved)
        if install:
            self.save_state(package=None, package_version=None)
        job.log("")
        job.ok("Descarga admin.p12 desde la página del módulo e impórtalo en el navegador "
               "para entrar a https://<servidor>:8443")

    def _prechecks(self, job, install):
        if not system.is_ubuntu_2204():
            job.warn(f"Sistema detectado: {system.os_label()}. Este módulo está probado para "
                     "Ubuntu 22.04 LTS.")
        mem = system.memory_mb()["total"]
        if mem and mem < 7500:
            job.warn(f"Memoria: {mem} MB. TAK Server recomienda 8 GB o más.")
        disk = system.disk_gb("/")
        if disk["free"] and disk["free"] < 20:
            job.warn(f"Disco libre: {disk['free']} GB. Se recomiendan 40 GB o más para TAK Server.")
        if install and not self.package_version():
            busy = [str(port) for port in (8089, 8443, 8446)
                    if system.port_listening(port, "tcp")]
            if busy:
                raise JobFailed("Puertos en uso por otro proceso: " + ", ".join(busy))
        job.ok("Comprobaciones terminadas")

    def _limits(self, job):
        path = Path("/etc/security/limits.conf")
        text = path.read_text() if path.exists() else ""
        if "soft nofile 32768" not in text:
            with open(path, "a", encoding="utf-8") as fh:
                fh.write("\n# TAK Server\n* soft nofile 32768\n* hard nofile 32768\n")
            job.ok("Se agregó nofile 32768 a /etc/security/limits.conf")
        else:
            job.ok("Límites ya configurados")

    def _pgdg(self, job):
        existing = [p for p in glob.glob("/etc/apt/sources.list.d/*")
                    if "apt.postgresql.org" in Path(p).read_text(errors="ignore")]
        if existing:
            job.ok(f"Repositorio PGDG ya presente ({os.path.basename(existing[0])})")
            key = signed_by_path(Path(existing[0]).read_text(errors="ignore"))
        else:
            job.log(f"Descargando llave {PGDG_KEY_URL}")
            fetch_pgdg_key(PGDG_KEY)
            code = system.codename() or "jammy"
            PGDG_LIST.write_text(f"deb [signed-by={PGDG_KEY}] "
                                 f"https://apt.postgresql.org/pub/repos/apt {code}-pgdg main\n")
            os.chmod(PGDG_LIST, 0o644)
            job.ok(f"Repositorio PGDG agregado para {code}")
            key = PGDG_KEY
        # Con o sin pgdg.list previo: la llave debe existir y apt (_apt) debe poder leerla.
        # (No se cambia el umask del proceso: es global y la consola atiende otras peticiones.)
        if key:
            self._pgdg_key_ready(job, key)
        run(["apt-get", "update", "-o", "DPkg::Lock::Timeout=600"], log=job.log, timeout=900)

    def _pgdg_key_ready(self, job, key: Path):
        """Garantiza que la llave declarada existe y que «_apt» puede leerla.

        Un archivo pgdg.list «ya presente» no basta: si la llave falta, está vacía o
        está en un directorio 0700, apt falla con NO_PUBKEY aunque la llave sea correcta.
        """
        ours = key == PGDG_KEY
        if not key_is_present(key, armored=ours):
            if not ours:
                raise JobFailed(f"El repositorio PGDG declara la llave {key}, pero no existe "
                                "o está vacía. Corrige o elimina esa entrada de apt.")
            job.warn("La llave de PGDG falta o está vacía; se descarga de nuevo")
            fetch_pgdg_key(key)
        changed = make_apt_readable(key)
        if changed:
            job.ok("Permisos corregidos para que apt lea la llave: "
                   + ", ".join(str(d) for d in changed))
        if not apt_can_read(key):
            raise JobFailed(f"El usuario _apt no puede leer {key}; apt lo reportaría como "
                            "NO_PUBKEY. Revisa los permisos de sus directorios.")

    def _verify(self, job, pkg, wanted):
        st = self.state()
        key, pol = st.get("gpg_key"), st.get("policy")
        if not wanted:
            job.log("Verificación omitida (no solicitada)")
            return
        if not (key and pol and Path(key).exists() and Path(pol).exists()):
            raise JobFailed("Para verificar la firma sube takserver-public-gpg.key y deb_policy.pol")
        run(["apt-get", "install", "-y", "-o", "DPkg::Lock::Timeout=600", "debsig-verify"],
            env={"DEBIAN_FRONTEND": "noninteractive"}, log=job.log)
        m = re.search(r'id="([0-9A-Fa-f]+)"', Path(pol).read_text(errors="ignore"))
        if not m:
            raise JobFailed("No se encontró el id de la política en deb_policy.pol")
        pid = m.group(1)
        keyring_dir = Path("/usr/share/debsig/keyrings") / pid
        policy_dir = Path("/etc/debsig/policies") / pid
        keyring_dir.mkdir(parents=True, exist_ok=True)
        policy_dir.mkdir(parents=True, exist_ok=True)
        keyring = keyring_dir / "debsig.gpg"
        if keyring.exists():
            keyring.unlink()
        keyring.touch()
        run(["gpg", "--no-default-keyring", "--keyring", str(keyring), "--import", key],
            log=job.log)
        shutil.copy(pol, policy_dir / "debsig.pol")
        res = run(["debsig-verify", "-v", pkg], log=job.log, check=False)
        if not res.ok:
            raise JobFailed("La firma del paquete NO es válida; se detiene el despliegue")
        job.ok("Firma del paquete verificada")

    def _tak(self, args, job, secrets, input=None, env=None):
        return run(["runuser", "-u", "tak", "--", *args], cwd=str(CERTS), input=input,
                   env=env, log=job.log, secrets=secrets, timeout=300)

    def _certificates(self, job, p, secrets):
        if (FILES / "ca.pem").exists() and not p["regenerate"]:
            int_ca = self.int_ca()
            if not int_ca:
                raise JobFailed("Existen certificados pero no se encontró la CA intermedia. "
                                "Marca «Regenerar certificados».")
            job.ok(f"Se conservan los certificados existentes (CA intermedia: {int_ca})")
            return int_ca

        if FILES.exists():
            backup = CERTS / f"files.bak-{datetime.now():%Y%m%d-%H%M%S}"
            FILES.rename(backup)
            job.warn(f"Certificados anteriores movidos a {backup}. Los clientes deberán "
                     "recibir nuevos paquetes de conexión.")

        meta = CERTS / "cert-metadata.sh"
        original = CERTS / "cert-metadata.sh.original"
        if not original.exists():
            shutil.copy2(meta, original)
        text = tf.patch_cert_metadata(original.read_text(), {
            "COUNTRY": p["country"], "STATE": p["state"], "CITY": p["city"],
            "ORGANIZATION": p["org"], "ORGANIZATIONAL_UNIT": p["ou"],
            "CAPASS": p["cert_pass"], "PASS": p["cert_pass"],
        })
        meta.write_text(text)
        os.chmod(meta, 0o600)

        # PrintableString en los sujetos (algunos clientes TAK no aceptan UTF8String).
        ossl_conf = CERTS / ".openssl-tak-console.cnf"
        sys_conf = Path("/etc/ssl/openssl.cnf")
        base = sys_conf.read_text() if sys_conf.exists() else ""
        ossl_conf.write_text(base.replace("string_mask = utf8only", "string_mask = nombstr"))
        run(["chown", "-R", "tak:tak", str(CERTS)], log=job.log)
        env = {"OPENSSL_CONF": str(ossl_conf)}

        root, int_ca = p["root_ca"], p["int_ca"]
        self._tak(["./makeRootCa.sh", "--ca-name", root], job, secrets, env=env)
        self._tak(["./makeCert.sh", "ca", int_ca], job, secrets, input="y\n", env=env)
        self._tak(["./makeCert.sh", "server", "takserver"], job, secrets, env=env)
        self._tak(["./makeCert.sh", "client", "admin"], job, secrets, env=env)
        self._tak(["keytool", "-import", "-trustcacerts", "-noprompt",
                   "-alias", f"{root}-root", "-file", str(FILES / "root-ca.pem"),
                   "-keystore", str(FILES / f"truststore-{int_ca}.jks"),
                   "-storepass", p["cert_pass"]], job, secrets)

        needed = ["takserver.jks", "admin.pem", "admin.p12", f"truststore-{int_ca}.jks",
                  f"truststore-{int_ca}.p12", f"{int_ca}-signing.jks", "root-ca.pem"]
        missing = [n for n in needed if not (FILES / n).exists()]
        if missing:
            raise JobFailed("Faltan certificados tras la generación: " + ", ".join(missing))
        job.ok(f"CA raíz {root}, CA intermedia {int_ca}, certificados takserver y admin")
        return int_ca

    def _coreconfig(self, job, p, int_ca):
        if not CORECONFIG.exists():
            if not CORECONFIG_EXAMPLE.exists():
                raise JobFailed("No existe CoreConfig.xml ni CoreConfig.example.xml en /opt/tak")
            shutil.copy2(CORECONFIG_EXAMPLE, CORECONFIG)
            job.log("CoreConfig.xml creado a partir de CoreConfig.example.xml")
        backup = TAK_HOME / f"CoreConfig.xml.tak-console-{datetime.now():%Y%m%d-%H%M%S}.bak"
        shutil.copy2(CORECONFIG, backup)
        enrollment = False
        if p["enrollment"]:
            enrollment = {"keystore": f"certs/files/{int_ca}-signing.jks", "org": p["org"],
                          "ou": p["ou"], "days": p["enroll_days"]}
        text = tf.patch_coreconfig(CORECONFIG.read_text(encoding="utf-8"),
                                   cert_pass=p["cert_pass"],
                                   truststore=f"certs/files/truststore-{int_ca}.jks",
                                   enrollment=enrollment)
        CORECONFIG.write_text(text, encoding="utf-8")
        run(["chown", "tak:tak", str(CORECONFIG)], log=job.log)
        job.ok(f"CoreConfig.xml actualizado (respaldo: {backup.name})")
        job.log(f"  Truststore: truststore-{int_ca}.jks · Enrolamiento: "
                f"{'activado' if p['enrollment'] else 'desactivado'}")

    def _start_and_wait(self, job, wait=900):
        run(["systemctl", "daemon-reload"], log=job.log)
        run(["systemctl", "enable", "takserver"], log=job.log)
        run(["systemctl", "restart", "takserver"], log=job.log)
        if config.DRY_RUN:
            return
        job.log("Esperando a que TAK Server abra el puerto 8089 (puede tardar varios minutos)...")
        start = time.time()
        while time.time() - start < wait:
            if system.port_listening(STREAM_PORT, "tcp"):
                job.ok(f"8089/tcp en escucha tras {int(time.time() - start)} s")
                break
            time.sleep(10)
        else:
            job.warn("TAK Server no abrió 8089 a tiempo. Revisa /opt/tak/logs/takserver-messaging.log")
            return
        for _ in range(30):
            if system.port_listening(8443, "tcp"):
                job.ok("8443/tcp en escucha")
                return
            time.sleep(10)
        job.warn("8443 aún no responde; el servicio API puede seguir iniciando")

    def _admins(self, job, p, secrets):
        if not USERMANAGER.exists() and not config.DRY_RUN:
            job.warn("No se encontró UserManager.jar; omitiendo administradores")
            return
        res = run(["java", "-jar", str(USERMANAGER), "certmod", "-A", str(FILES / "admin.pem")],
                  cwd=str(TAK_HOME), log=job.log, check=False, timeout=300)
        if res.ok:
            job.ok("Certificado admin autorizado como administrador")
        else:
            job.warn("No se pudo autorizar admin.pem; reintenta con «Reaplicar administradores»")
        if p.get("admin_pass"):
            res = run(["java", "-jar", str(USERMANAGER), "usermod", "-A", "-p", p["admin_pass"],
                       p["admin_user"]], cwd=str(TAK_HOME), log=job.log, secrets=secrets,
                      check=False, timeout=300)
            if res.ok:
                job.ok(f"Usuario web {p['admin_user']} creado (https://<servidor>:8446)")
            else:
                job.warn(f"No se pudo crear el usuario {p['admin_user']}")

    # ── control ─────────────────────────────────────────────────────────────
    def actions(self):
        def svc(verb):
            def _do(job):
                run(["systemctl", verb, "takserver"], log=job.log)
                job.ok(f"takserver: {verb}")
            return _do

        return {"start": ("Iniciar", svc("start")), "stop": ("Detener", svc("stop")),
                "restart": ("Reiniciar", svc("restart"))}

    def uninstall(self, job, params):
        run(["systemctl", "disable", "--now", "takserver"], log=job.log, check=False)
        run(["apt-get", "remove", "-y", "-o", "DPkg::Lock::Timeout=600", "takserver"],
            env={"DEBIAN_FRONTEND": "noninteractive"}, log=job.log, timeout=1800)
        self.remove_firewall(log=job.log)
        self.save_state(installed=False)
        job.warn("Se conservan /opt/tak (certificados, CoreConfig) y la base de datos «cot» "
                 "de PostgreSQL. Si ya no los necesitas, usa «Borrar datos de TAK Server» "
                 "en esta página.")

    # ── borrado de datos (después de desinstalar) ───────────────────────────
    def tak_db(self) -> dict:
        """Base, rol y puerto de PostgreSQL según CoreConfig.xml (o los valores de TAK Server)."""
        try:
            return coreconfig_db(CORECONFIG.read_text(encoding="utf-8"))
        except OSError:
            return dict(DB_DEFAULTS)

    def _psql(self, info, sql, *, job=None, check=True):
        """Ejecuta una sentencia como el usuario «postgres» por el socket local."""
        argv = ["runuser", "-u", "postgres", "--", "psql", "-X", "-v", "ON_ERROR_STOP=1",
                "-p", str(info["port"]), "-d", "postgres", "-c", sql]
        return run(argv, log=job.log if job else None, check=check, timeout=120)

    def db_exists(self, info) -> bool:
        if not which("psql"):
            return False
        res = capture(["runuser", "-u", "postgres", "--", "psql", "-X", "-tA",
                       "-p", str(info["port"]), "-d", "postgres", "-c",
                       f"SELECT 1 FROM pg_database WHERE datname = '{info['name']}'"])
        return res.ok and res.output.strip() == "1"

    def purge_blockers(self) -> list:
        """Motivos por los que NO se puede borrar ahora (lista vacía = se puede)."""
        out = []
        if self.package_version():
            out.append("TAK Server sigue instalado: desinstálalo primero.")
        if capture(["systemctl", "is-active", "takserver"]).output.strip() in ("active", "activating"):
            out.append("El servicio takserver sigue en marcha.")
        ports = system.listening_ports()
        busy = [str(n) for n in (STREAM_PORT, 8443, 8446) if (n, "tcp") in ports]
        if busy:
            out.append("Hay algo escuchando en los puertos " + ", ".join(busy) + "/tcp.")
        if TAK_HOME.is_symlink():
            out.append(f"{TAK_HOME} es un enlace simbólico: bórralo a mano.")
        return out

    def purge_overview(self) -> dict:
        info = self.tak_db()
        try:
            check_db_info(info)
            db_ok = True
        except ValueError:
            db_ok = False
        size = None
        if TAK_HOME.exists():
            res = capture(["du", "-sm", str(TAK_HOME)])
            if res.ok and res.output.split():
                size = res.output.split()[0]
        uploads = sorted(f.name for f in _upload_dir().iterdir()
                         if f.suffix in (".deb", ".key", ".pol")) if config.UPLOAD_DIR.exists() else []
        return {"files": TAK_HOME.exists(), "size_mb": size, "db": info, "db_ok": db_ok,
                "db_exists": db_ok and self.db_exists(info), "uploads": uploads,
                "home": str(TAK_HOME)}

    def view_purge(self):
        if not auth.verify(session.get("user", ""), request.form.get("password", "")):
            return jsonify(ok=False, error="Contraseña de la consola incorrecta"), 403
        if request.form.get("confirm", "").strip() != PURGE_PHRASE:
            return jsonify(ok=False, error=f"Escribe exactamente «{PURGE_PHRASE}» para confirmar"), 400
        blockers = self.purge_blockers()
        if blockers:
            return jsonify(ok=False, error=" ".join(blockers)), 409
        f = validate.Form(request.form)
        backup, uploads = f.boolean("backup"), f.boolean("uploads")
        try:
            JOBS.start(self.key, "Borrar datos de TAK Server", self._purge, backup, uploads)
        except Busy as e:
            return jsonify(ok=False, error=str(e)), 409
        return jsonify(ok=True)

    def _backup(self, job) -> Path:
        dest_dir = config.DATA_DIR / "backups"
        dest_dir.mkdir(parents=True, exist_ok=True)
        os.chmod(dest_dir, 0o700)
        dest = dest_dir / f"takserver-{datetime.now().strftime('%Y%m%d-%H%M%S')}.tar.gz"
        items = []
        for pattern in BACKUP_ITEMS:
            items += sorted(glob.glob(str(TAK_HOME / pattern)))
        fd = os.open(dest, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as raw, tarfile.open(fileobj=raw, mode="w:gz") as tar:
            for item in items:
                tar.add(item, arcname="tak/" + os.path.relpath(item, TAK_HOME))
        job.ok(f"Respaldo de {len(items)} elementos en {dest} (contiene llaves privadas)")
        return dest

    def _purge(self, job, backup=True, uploads=False):
        total = 4
        job.step(1, total, "Comprobaciones")
        blockers = self.purge_blockers()
        if blockers:
            raise JobFailed(" ".join(blockers))
        info = self.tak_db()
        try:
            check_db_info(info)
        except ValueError as e:
            raise JobFailed(f"No borro la {e}: no parece una base de TAK Server. "
                            "Hazlo a mano si es lo que quieres.")
        job.ok(f"TAK Server no está instalado ni en marcha. Base «{info['name']}», rol «{info['role']}»")
        if config.DRY_RUN:
            job.warn("Modo de prueba (DRY_RUN): no se borra nada.")
            return

        job.step(2, total, "Respaldo")
        if not backup:
            job.log("Respaldo omitido")
        elif TAK_HOME.exists():
            self._backup(job)
        else:
            job.log(f"{TAK_HOME} no existe: nada que respaldar")

        job.step(3, total, "Base de datos")
        if not which("psql"):
            job.warn("PostgreSQL no está instalado: no hay base que borrar")
        else:
            try:
                self._psql(info, f'DROP DATABASE IF EXISTS "{info["name"]}" WITH (FORCE)', job=job)
            except CommandError as e:
                raise JobFailed(f"No se pudo borrar la base «{info['name']}»: {e}")
            job.ok(f"Base «{info['name']}» borrada")
            try:
                self._psql(info, f'DROP ROLE IF EXISTS "{info["role"]}"', job=job)
                job.ok(f"Rol «{info['role']}» borrado")
            except CommandError as e:
                job.warn(f"No se pudo borrar el rol «{info['role']}» (puede tener otros objetos): {e}")

        job.step(4, total, "Archivos")
        if TAK_HOME.is_symlink() or len(TAK_HOME.resolve().parts) < 3:
            raise JobFailed(f"Ruta no segura para borrar: {TAK_HOME}")
        if TAK_HOME.exists():
            shutil.rmtree(TAK_HOME)
            job.ok(f"{TAK_HOME} borrado")
        else:
            job.log(f"{TAK_HOME} ya no existe")
        reset = set(STATE_RESET)
        if uploads:
            for f in _upload_dir().iterdir():
                if f.suffix in (".deb", ".key", ".pol"):
                    f.unlink()
            reset |= {"gpg_key", "policy"}
            job.ok("Paquete .deb, llave y política subidos: borrados")
        st = {k: v for k, v in self.state().items() if k not in reset}
        st["installed"] = False
        settings.replace_section(self.key, st)
        job.ok("Estado de la consola restablecido")
        job.warn("No se restauraron los respaldos de pg_hba.conf y postgresql.conf que dejó TAK Server "
                 "(*.backup-<fecha>). Los certificados que otros módulos firmaron con la CA borrada "
                 "(Mumble, RTSPS de MediaMTX) no se podrán renovar con ella: vuelve a desplegarlos "
                 "tras la nueva instalación.")


    # ── consolas de estado y actividad ──────────────────────────────────────
    EVENT_RULES = EVENT_RULES
    EVENTS_NOTE = ("TAK Server no publica una lista de mensajes de conexión de clientes: aquí se "
                   "resaltan avisos y errores, más los pocos eventos que se verificaron en su código "
                   "público (5.7). Quién está conectado se consulta a su API en «Conectados».")

    def log_sources(self):
        return [(k, label) for k, (_, label) in LOG_FILES.items()]

    def log_lines(self, n, source=""):
        path = TAK_LOGS / LOG_FILES.get(source, LOG_FILES["messaging"])[0]
        if not path.exists():
            return [f"(todavía no existe {path})"]
        with open(path, "rb") as fh:
            fh.seek(0, os.SEEK_END)
            size = fh.tell()
            fh.seek(max(0, size - 96_000))
            text = fh.read().decode("utf-8", errors="replace")
        return text.splitlines()[-n:]

    def line_level(self, line):
        m = TAK_LEVEL.search(line)
        lvl = (m.group(1) or m.group(2)) if m else ""
        return "err" if lvl in ("ERROR", "FATAL") else "warn" if lvl == "WARN" else "info"

    def checks(self):
        active = capture(["systemctl", "is-active", "takserver"]).output.strip()
        ports = system.listening_ports()
        out = [{"label": "Servicio takserver", "ok": active == "active", "detail": active or "—"}]
        for label, port in (("Clientes TLS", STREAM_PORT), ("Admin (certificado)", API_PORT),
                            ("Admin (usuario)", 8446)):
            out.append({"label": label, "ok": (port, "tcp") in ports, "detail": f"{port}/tcp"})
        log = TAK_LOGS / LOG_FILES["messaging"][0]
        try:
            out.append({"label": "Registro", "ok": True,
                        "detail": "último dato hace " + monitor.age(time.time() - log.stat().st_mtime)})
        except OSError:
            out.append({"label": "Registro", "ok": False, "detail": "sin archivo"})
        return out

    def connected(self):
        try:
            payload = tak_api_get(SUBSCRIPTIONS_PATH)
        except OSError as e:
            return monitor.table([], [], error=f"No se pudo consultar a TAK Server: {e}")
        rows, unknown = subscription_rows(payload, time.time())
        note = "Clientes con sesión abierta en TAK Server (API /Marti/api/subscriptions/all)."
        if unknown:
            note += (f" {unknown} entradas no traen indicativo ni UID: la respuesta de tu versión "
                     "podría tener otro formato.")
        return monitor.table(["Indicativo", "UID", "Dirección", "Protocolo", "Cliente",
                              "Rol / equipo", "Último reporte"], rows, note=note)

    # ── rutas adicionales ───────────────────────────────────────────────────
    def routes(self):
        return [
            ("/api/m/takserver/upload", "tak_upload", self.view_upload, ["POST"]),
            ("/api/m/takserver/users", "tak_user_create", self.view_user_create, ["POST"]),
            ("/api/m/takserver/admins", "tak_admins", self.view_admins, ["POST"]),
            ("/api/m/takserver/purge", "tak_purge", self.view_purge, ["POST"]),
            ("/api/m/takserver/logs", "tak_logs", self.view_logs, ["GET"]),
            ("/m/takserver/download/<what>", "tak_download", self.view_download, ["GET"]),
            ("/m/takserver/package/<user>", "tak_package", self.view_package, ["GET"]),
        ]

    def view_upload(self):
        saved = {}
        updir = _upload_dir()
        for field, suffix in (("package", ".deb"), ("gpg_key", ".key"), ("policy", ".pol")):
            fs = request.files.get(field)
            if not fs or not fs.filename:
                continue
            name = secure_filename(fs.filename)
            if not name.endswith(suffix):
                return jsonify(ok=False, error=f"El archivo de «{field}» debe terminar en {suffix}"), 400
            dest = updir / name
            fs.save(str(dest))
            os.chmod(dest, 0o600)
            saved[field] = str(dest)
        if not saved:
            return jsonify(ok=False, error="No se recibió ningún archivo"), 400
        if "package" in saved:
            info = capture(["dpkg-deb", "-f", saved["package"], "Package", "Version"])
            fields = dict(line.split(": ", 1) for line in info.output.splitlines() if ": " in line)
            if info.ok and fields.get("Package") != "takserver":
                os.unlink(saved["package"])
                return jsonify(ok=False, error="El .deb no es un paquete «takserver»"), 400
            for old in updir.glob("*.deb"):
                if str(old) != saved["package"]:
                    old.unlink()
            self.save_state(package=saved["package"], package_version=fields.get("Version"))
        if "gpg_key" in saved:
            self.save_state(gpg_key=saved["gpg_key"])
        if "policy" in saved:
            self.save_state(policy=saved["policy"])
        return jsonify(ok=True, saved={k: os.path.basename(v) for k, v in saved.items()},
                       version=self.state().get("package_version"))

    def view_admins(self):
        st = self.state()
        p = {"admin_pass": "", "admin_user": st.get("admin_user", "webadmin")}
        try:
            JOBS.start(self.key, "Reaplicar administradores", lambda job: self._admins(job, p, []))
        except Busy as e:
            return jsonify(ok=False, error=str(e)), 409
        return jsonify(ok=True)

    def view_user_create(self):
        f = validate.Form(request.form)
        name = f.text("name", validate.CLIENT_NAME, validate.CLIENT_NAME_MSG)
        group = f.text("group", validate.GROUP, "Grupo: letras, números, espacio, _ y -",
                       required=False)
        st = self.state()
        if not st.get("installed") or not (FILES / "ca.pem").exists():
            f.error("name", "Despliega TAK Server antes de crear usuarios")
        if name.lower() in {"admin", "takserver", (st.get("root_ca") or "").lower(),
                            (self.int_ca() or "").lower()}:
            f.error("name", "Nombre reservado")
        if (FILES / f"{name}.p12").exists():
            f.error("name", "Ya existe un certificado con ese nombre")
        if not f.ok:
            return jsonify(ok=False, errors=f.errors), 400

        def _create(job):
            secrets = [st.get("cert_pass", "")]
            conf = CERTS / ".openssl-tak-console.cnf"
            env = {"OPENSSL_CONF": str(conf)} if conf.exists() else None
            self._tak(["./makeCert.sh", "client", name], job, secrets, env=env)
            if group:
                run(["java", "-jar", str(USERMANAGER), "certmod", "-g", group,
                     str(FILES / f"{name}.pem")], cwd=str(TAK_HOME), log=job.log,
                    check=False, timeout=300)
            users = self.state().get("users", [])
            users.append({"name": name, "group": group, "created": int(time.time())})
            self.save_state(users=users)
            job.ok(f"Certificado de {name} creado. Descarga su paquete de conexión.")

        try:
            JOBS.start(self.key, f"Crear usuario {name}", _create)
        except Busy as e:
            return jsonify(ok=False, error=str(e)), 409
        return jsonify(ok=True)

    def view_logs(self):
        which = request.args.get("file", "messaging")
        path = TAK_LOGS / ("takserver-api.log" if which == "api" else "takserver-messaging.log")
        if not path.exists():
            return jsonify(ok=True, text=f"(no existe {path})")
        with open(path, "rb") as fh:
            fh.seek(0, os.SEEK_END)
            size = fh.tell()
            fh.seek(max(0, size - 64000))
            text = fh.read().decode("utf-8", errors="replace")
        return jsonify(ok=True, text="\n".join(text.splitlines()[-300:]))

    def view_download(self, what):
        int_ca = self.int_ca()
        allowed = {"admin.p12": FILES / "admin.p12", "root-ca.pem": FILES / "root-ca.pem"}
        if int_ca:
            allowed["truststore.p12"] = FILES / f"truststore-{int_ca}.p12"
        path = allowed.get(what)
        if not path or not path.exists():
            abort(404)
        name = path.name if what != "truststore.p12" else f"truststore-{int_ca}.p12"
        return send_file(str(path), as_attachment=True, download_name=name)

    def view_package(self, user):
        if not re.fullmatch(validate.CLIENT_NAME, user):
            abort(404)
        st = self.state()
        # Solo el administrador puede empaquetar cualquier certificado (por ejemplo «admin», que
        # da acceso a la administración de TAK). Los demás, únicamente los usuarios creados
        # desde esta consola.
        if not rbac.allowed(g.get("role", ""), rbac.ADMIN):
            if user.lower() not in {str(u.get("name", "")).lower() for u in st.get("users", [])}:
                abort(404)
        int_ca = self.int_ca()
        user_p12 = FILES / f"{user}.p12"
        trust = FILES / f"truststore-{int_ca}.p12" if int_ca else None
        if not (user_p12.exists() and trust and trust.exists()):
            abort(404)
        host = request.args.get("host", "").strip()
        if not re.fullmatch(r"[A-Za-z0-9.\-:]{1,253}", host or ""):
            abort(400)
        kind = "itak" if request.args.get("kind") == "itak" else "atak"
        desc = (st.get("org") or "TAK").strip() or "TAK"
        data = tf.data_package(user=user, host=host, port=STREAM_PORT, description=desc,
                               truststore_name=trust.name, truststore_bytes=trust.read_bytes(),
                               user_p12_bytes=user_p12.read_bytes(),
                               cert_pass=st.get("cert_pass", "atakatak"), kind=kind)
        return send_file(io.BytesIO(data), mimetype="application/zip", as_attachment=True,
                         download_name=f"{user}-{host}-{kind}.zip")
