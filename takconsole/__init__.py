# SPDX-License-Identifier: Apache-2.0
"""Consola web: aplicación Flask."""
import time
from datetime import timedelta

from flask import (Flask, abort, jsonify, redirect, render_template, request, send_file,
                   session, url_for)

from . import config
from .core import auth, certs, firewall, settings, system
from .core.jobs import JOBS, Busy

PUBLIC_ENDPOINTS = {"login", "static", "health"}


def create_app():
    config.ensure_dirs()
    app = Flask(__name__)
    app.secret_key = auth.secret_key()
    app.config.update(
        MAX_CONTENT_LENGTH=4 * 1024 ** 3,       # paquetes de TAK Server de varios cientos de MB
        SESSION_COOKIE_SECURE=True,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_NAME="takconsole_session",
        PERMANENT_SESSION_LIFETIME=timedelta(hours=8),
    )

    from .modules import MODULES

    # ── seguridad global: login y CSRF en todas las rutas ───────────────────
    @app.before_request
    def _guard():
        if request.endpoint in PUBLIC_ENDPOINTS:
            if request.method == "POST" and request.endpoint == "login":
                _check_csrf()
            return None
        if not session.get("user"):
            if request.path.startswith("/api/"):
                return jsonify(ok=False, error="Sesión expirada"), 401
            return redirect(url_for("login", next=request.path))
        if time.time() - session.get("seen", 0) > 1800:
            session.clear()
            return redirect(url_for("login"))
        session["seen"] = time.time()
        if request.method in ("POST", "PUT", "DELETE", "PATCH"):
            _check_csrf()
        return None

    def _check_csrf():
        supplied = request.headers.get("X-CSRF-Token") or request.form.get("csrf")
        if not auth.csrf_valid(session, supplied):
            abort(400, description="Token CSRF inválido. Recarga la página.")

    @app.after_request
    def _headers(resp):
        resp.headers.setdefault("X-Content-Type-Options", "nosniff")
        resp.headers.setdefault("X-Frame-Options", "DENY")
        resp.headers.setdefault("Referrer-Policy", "same-origin")
        resp.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; "
            "frame-ancestors 'none'")
        return resp

    @app.context_processor
    def _ctx():
        return {
            "app_name": config.APP_NAME,
            "app_version": config.APP_VERSION,
            "modules": MODULES,
            "csrf_token": auth.csrf_token(session),
            "current_job": JOBS.current(),
        }

    # ── autenticación ───────────────────────────────────────────────────────
    @app.route("/login", methods=["GET", "POST"])
    def login():
        error = None
        ip = request.remote_addr or "?"
        if request.method == "POST":
            wait = auth.locked_out(ip)
            if wait:
                error = f"Demasiados intentos. Espera {wait // 60 + 1} min."
            elif auth.verify(request.form.get("username", ""), request.form.get("password", "")):
                auth.clear_failures(ip)
                session.clear()
                session["user"] = auth.username()
                session["seen"] = time.time()
                session.permanent = True
                nxt = request.args.get("next", "/")
                return redirect(nxt if nxt.startswith("/") and not nxt.startswith("//") else "/")
            else:
                auth.record_failure(ip)
                error = "Usuario o contraseña incorrectos"
        return render_template("login.html", error=error, configured=auth.is_configured())

    @app.route("/logout", methods=["POST"])
    def logout():
        session.clear()
        return redirect(url_for("login"))

    @app.route("/health")
    def health():
        return jsonify(ok=True)

    # ── páginas ─────────────────────────────────────────────────────────────
    @app.route("/")
    def dashboard():
        return render_template("dashboard.html", host=system.summary(),
                               statuses={k: m.status() for k, m in MODULES.items()},
                               fw=firewall.status(), policy=firewall.policy())

    @app.route("/red", methods=["GET"])
    def network():
        planned = []
        for m in MODULES.values():
            if m.installed():
                planned.append({"module": m.name, "ports": m.ports()})
        return render_template("network.html", host=system.summary(), fw=firewall.status(),
                               policy=firewall.policy(), zt_ifaces=firewall.zerotier_ifaces(),
                               planned=planned, ssh_ports=firewall.ssh_ports(),
                               console_port=config.CONSOLE_PORT, last_job=JOBS.get("network"))

    @app.route("/m/<key>")
    def module_page(key):
        m = MODULES.get(key) or abort(404)
        last = JOBS.get(key)
        return render_template(m.template, m=m, status=m.status(), last_job=last,
                               actions=m.actions(), **m.page_context())

    # ── API genérica de módulos ─────────────────────────────────────────────
    @app.route("/api/status")
    def api_status():
        cur = JOBS.current()
        return jsonify(ok=True, modules={k: m.status() for k, m in MODULES.items()},
                       job={"key": cur.key, "title": cur.title} if cur else None)

    @app.route("/api/m/<key>/deploy", methods=["POST"])
    def api_deploy(key):
        m = MODULES.get(key) or abort(404)
        params, errors = m.validate_deploy(request.form)
        if errors:
            return jsonify(ok=False, errors=errors), 400
        return _start(key, f"Desplegar {m.name}", m.deploy, params)

    @app.route("/api/m/<key>/uninstall", methods=["POST"])
    def api_uninstall(key):
        m = MODULES.get(key) or abort(404)
        if not auth.verify(session.get("user", ""), request.form.get("password", "")):
            return jsonify(ok=False, error="Contraseña de la consola incorrecta"), 403
        return _start(key, f"Desinstalar {m.name}", m.uninstall, {})

    @app.route("/api/m/<key>/action/<verb>", methods=["POST"])
    def api_action(key, verb):
        m = MODULES.get(key) or abort(404)
        acts = m.actions()
        if verb not in acts:
            abort(404)
        label, fn = acts[verb]
        return _start(key, f"{m.name}: {label}", fn)

    @app.route("/api/jobs/<key>")
    def api_job(key):
        job = JOBS.get(key)
        if not job:
            return jsonify(ok=True, job=None)
        return jsonify(ok=True, job=job.snapshot(int(request.args.get("offset", 0) or 0)))

    def _start(key, title, fn, *args):
        try:
            JOBS.start(key, title, fn, *args)
        except Busy as e:
            return jsonify(ok=False, error=str(e)), 409
        return jsonify(ok=True)

    # ── red y firewall ──────────────────────────────────────────────────────
    @app.route("/api/red/policy", methods=["POST"])
    def api_policy():
        mode = request.form.get("exposure", "all")
        if mode not in firewall.POLICIES:
            return jsonify(ok=False, errors={"exposure": "Opción inválida"}), 400
        cidr = request.form.get("lan_cidr", "").strip()
        if mode == "zerotier_lan":
            try:
                cidr = firewall.validate_cidr(cidr)
            except ValueError as e:
                return jsonify(ok=False, errors={"lan_cidr": str(e)}), 400
        settings.update_section("network", {"exposure": mode, "lan_cidr": cidr})

        def _apply(job):
            firewall.ensure_base_rules(log=job.log)
            for m in MODULES.values():
                if m.installed():
                    job.log(f"— {m.name}")
                    m.apply_firewall(log=job.log)
            job.ok("Reglas aplicadas según la política")

        return _start("network", "Aplicar política de exposición", _apply)

    @app.route("/api/red/ufw-enable", methods=["POST"])
    def api_ufw_enable():
        return _start("network", "Activar UFW", lambda job: firewall.enable(log=job.log))

    @app.route("/api/red/console-cert", methods=["POST"])
    def api_console_cert():
        def _regen(job):
            hosts = [system.hostname()] + system.candidate_hosts()
            certs.make_console_cert(hosts, log=job.log)
            job.ok("Certificado regenerado. Reinicia la consola para usarlo: "
                   "systemctl restart tak-console")
        return _start("network", "Regenerar certificado de la consola", _regen)

    @app.route("/m/network/console.crt")
    def console_cert_download():
        return send_file(str(config.CONSOLE_CERT), as_attachment=True,
                         download_name="tak-console.crt")

    # ── rutas propias de cada módulo ────────────────────────────────────────
    for m in MODULES.values():
        for rule, endpoint, view, methods in m.routes():
            app.add_url_rule(rule, endpoint=endpoint, view_func=view, methods=methods)

    @app.errorhandler(400)
    def _bad(e):
        if request.path.startswith("/api/"):
            return jsonify(ok=False, error=getattr(e, "description", "Solicitud inválida")), 400
        return render_template("error.html", code=400, message=e.description), 400

    @app.errorhandler(404)
    def _nf(e):
        if request.path.startswith("/api/"):
            return jsonify(ok=False, error="No encontrado"), 404
        return render_template("error.html", code=404, message="Página no encontrada"), 404

    @app.errorhandler(413)
    def _big(e):
        return jsonify(ok=False, error="Archivo demasiado grande"), 413

    @app.template_filter("ago")
    def _ago(ts):
        if not ts:
            return "—"
        d = int(time.time() - ts)
        if d < 60:
            return "hace segundos"
        if d < 3600:
            return f"hace {d // 60} min"
        if d < 86400:
            return f"hace {d // 3600} h"
        return f"hace {d // 86400} d"

    @app.template_filter("datetime")
    def _dt(ts):
        return time.strftime("%Y-%m-%d %H:%M", time.localtime(ts)) if ts else "—"

    return app
