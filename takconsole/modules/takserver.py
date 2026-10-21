# SPDX-License-Identifier: Apache-2.0
"""TAK Server (instalación nativa desde el paquete .deb de tak.gov).

Pasos verificados contra los scripts oficiales del repositorio
TAK-Product-Center/Server (makeRootCa.sh, makeCert.sh, cert-metadata.sh,
CoreConfig.example.xml/CoreConfig.xsd) y las dependencias declaradas del .deb
(openjdk-17-jdk, postgresql-15, postgresql-15-postgis-3, openssl).
"""
import glob
import io
import os
import re
import shutil
import time
import urllib.request
from datetime import datetime
from pathlib import Path

from flask import abort, jsonify, request, send_file
from werkzeug.utils import secure_filename

from .. import config
from ..core import system, validate
from ..core.jobs import JOBS, Busy, JobFailed
from ..core.shell import capture, run
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


def _upload_dir() -> Path:
    d = config.UPLOAD_DIR / "takserver"
    d.mkdir(parents=True, exist_ok=True)
    return d


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
        else:
            job.log(f"Descargando llave {PGDG_KEY_URL}")
            PGDG_KEY.parent.mkdir(parents=True, exist_ok=True)
            os.chmod(PGDG_KEY.parent, 0o755)
            with urllib.request.urlopen(PGDG_KEY_URL, timeout=60) as resp:
                PGDG_KEY.write_bytes(resp.read())
            code = system.codename() or "jammy"
            PGDG_LIST.write_text(f"deb [signed-by={PGDG_KEY}] "
                                 f"https://apt.postgresql.org/pub/repos/apt {code}-pgdg main\n")
            # apt verifica las firmas como el usuario _apt: la llave debe ser legible.
            os.chmod(PGDG_KEY, 0o644)
            os.chmod(PGDG_LIST, 0o644)
            job.ok(f"Repositorio PGDG agregado para {code}")
        run(["apt-get", "update", "-o", "DPkg::Lock::Timeout=600"], log=job.log, timeout=900)

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
                 "de PostgreSQL. Bórralos manualmente solo si ya no los necesitas.")

    # ── rutas adicionales ───────────────────────────────────────────────────
    def routes(self):
        return [
            ("/api/m/takserver/upload", "tak_upload", self.view_upload, ["POST"]),
            ("/api/m/takserver/users", "tak_user_create", self.view_user_create, ["POST"]),
            ("/api/m/takserver/admins", "tak_admins", self.view_admins, ["POST"]),
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
