# SPDX-License-Identifier: Apache-2.0
"""Repositorio SFTP (SFTPGo): configuración, despliegue, usuario inicial por la API y página."""
import base64
import json
import re
import stat
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

from takconsole import config
from takconsole.core import docker, settings, system
from takconsole.modules import MODULES, sftp

P = {"http_port": 8085, "tls": False, "admin_user": "admin", "admin_pass": "clave-admin-12",
     "repo_user": "repositorio", "repo_pass": "clave-repo-1234"}


class FakeJob:
    def __init__(self):
        self.lines = []

    def step(self, i, n, title):
        self.lines.append(("step", title))

    def log(self, msg):
        self.lines.append(("log", msg))

    def ok(self, msg):
        self.lines.append(("ok", msg))

    def warn(self, msg):
        self.lines.append(("warn", msg))

    def kinds(self, kind):
        return [m for k, m in self.lines if k == kind]


# ── configuración ───────────────────────────────────────────────────────────
def test_env_con_administrador_inicial_y_puerto():
    env = sftp.env_values(P)
    assert env["SFTPGO_DEFAULT_ADMIN_USERNAME"] == "admin"
    assert env["SFTPGO_DEFAULT_ADMIN_PASSWORD"] == "clave-admin-12"
    assert env["SFTPGO_DATA_PROVIDER__CREATE_DEFAULT_ADMIN"] == "1"
    assert env["SFTPGO_HTTPD__BINDINGS__0__PORT"] == 8085
    assert not any("HTTPS" in k for k in env)


def test_env_con_https():
    env = sftp.env_values({**P, "tls": True})
    assert env["SFTPGO_HTTPD__BINDINGS__0__ENABLE_HTTPS"] == "1"
    assert env["SFTPGO_HTTPD__BINDINGS__0__CERTIFICATE_FILE"] == "/tls/server.crt"
    assert env["SFTPGO_HTTPD__BINDINGS__0__CERTIFICATE_KEY_FILE"] == "/tls/server.key"


def test_compose_red_de_host_y_version_fija():
    svc = sftp.compose_data()["services"]["sftp"]
    assert svc["network_mode"] == "host" and "ports" not in svc
    assert svc["image"] == sftp.IMAGE and not sftp.IMAGE.endswith(":latest")
    assert "./data/srv:/srv/sftpgo" in svc["volumes"] and "./tls:/tls:ro" in svc["volumes"]


def test_los_secretos_no_van_en_el_compose():
    text = json.dumps(sftp.compose_data())
    assert "clave" not in text and "PASSWORD" not in text


# ── validación ──────────────────────────────────────────────────────────────
def test_validacion_valores_por_defecto(data_dir, monkeypatch):
    monkeypatch.setattr(system, "listening_ports", lambda: set())
    p, errs = sftp.Sftp().validate_deploy({})
    assert errs == {}
    assert p["http_port"] == 8085 and p["admin_user"] == "admin" and p["repo_user"] == "repositorio"
    assert len(p["admin_pass"]) == 20 and len(p["repo_pass"]) == 20 and p["tls"] is False


def test_validacion_conserva_claves_anteriores(data_dir, monkeypatch):
    monkeypatch.setattr(system, "listening_ports", lambda: set())
    settings.update_section("sftp", {"installed": True, "params": P})
    p, errs = sftp.Sftp().validate_deploy({})
    assert errs == {} and p["admin_pass"] == P["admin_pass"] and p["repo_pass"] == P["repo_pass"]
    p, _ = sftp.Sftp().validate_deploy({"repo_pass": "otra-clave-9999"})
    assert p["repo_pass"] == "otra-clave-9999" and p["admin_pass"] == P["admin_pass"]


@pytest.mark.parametrize("data,campo", [
    ({"http_port": "80"}, "http_port"),
    ({"http_port": "2022"}, "http_port"),
    ({"http_port": "abc"}, "http_port"),
    ({"admin_user": "a b"}, "admin_user"),
    ({"repo_user": "x"}, "repo_user"),
    ({"admin_pass": "corta"}, "admin_pass"),
    ({"repo_pass": "con 'comilla' 123"}, "repo_pass"),
    ({"admin_user": "mismo", "repo_user": "MISMO"}, "repo_user"),
])
def test_validacion_rechaza(data_dir, monkeypatch, data, campo):
    monkeypatch.setattr(system, "listening_ports", lambda: set())
    _, errs = sftp.Sftp().validate_deploy(data)
    assert campo in errs


def test_validacion_puerto_ocupado_salvo_el_propio(data_dir, monkeypatch):
    monkeypatch.setattr(system, "listening_ports", lambda: {(9000, "tcp")})
    _, errs = sftp.Sftp().validate_deploy({"http_port": "9000"})
    assert "http_port" in errs
    # ya instalado con ese puerto: es el propio servicio, no un conflicto
    settings.update_section("sftp", {"installed": True, "params": {**P, "http_port": 9000}})
    _, errs = sftp.Sftp().validate_deploy({"http_port": "9000"})
    assert errs == {}


# ── despliegue ──────────────────────────────────────────────────────────────
@pytest.fixture()
def fake_docker(monkeypatch):
    calls = []
    monkeypatch.setattr(docker, "available", lambda: True)
    monkeypatch.setattr(docker, "compose", lambda d, *a, **kw: calls.append(a))
    return calls


def test_deploy_escribe_archivos_y_arranca(data_dir, fake_docker, monkeypatch):
    monkeypatch.setattr(sftp, "run", lambda *a, **kw: None)  # chown
    monkeypatch.setattr(sftp.Sftp, "apply_firewall", lambda self, log=None: [])
    job = FakeJob()
    sftp.Sftp().deploy(job, P)
    d = sftp.stack_dir()
    env = d / "sftp.env"
    assert "SFTPGO_DEFAULT_ADMIN_PASSWORD='clave-admin-12'" in env.read_text()
    assert stat.S_IMODE(env.stat().st_mode) == 0o600
    assert (d / "compose.yaml").exists() and (d / "data" / "srv").is_dir()
    assert ("pull",) in fake_docker and ("up", "-d", "--force-recreate") in fake_docker
    assert settings.section("sftp")["installed"] is True
    assert settings.section("sftp")["params"]["repo_user"] == "repositorio"
    assert any("simulación" in m for m in job.kinds("log"))  # DRY_RUN: no habla con la API


def test_deploy_con_https_copia_el_certificado_de_la_consola(data_dir, fake_docker, monkeypatch):
    monkeypatch.setattr(sftp, "run", lambda *a, **kw: None)
    monkeypatch.setattr(sftp.Sftp, "apply_firewall", lambda self, log=None: [])
    config.CONSOLE_CERT.write_text("CERT")
    config.CONSOLE_KEY.write_text("KEY")
    sftp.Sftp().deploy(FakeJob(), {**P, "tls": True})
    tls = sftp.stack_dir() / "tls"
    assert (tls / "server.crt").read_text() == "CERT" and (tls / "server.key").read_text() == "KEY"
    assert stat.S_IMODE((tls / "server.key").stat().st_mode) == 0o600
    # sin HTTPS, la clave copiada se borra
    sftp.Sftp().deploy(FakeJob(), P)
    assert not (tls / "server.key").exists()


def test_deploy_sin_docker_falla_con_mensaje(data_dir, monkeypatch):
    from takconsole.core.jobs import JobFailed
    monkeypatch.setattr(docker, "available", lambda: False)
    with pytest.raises(JobFailed):
        sftp.Sftp().deploy(FakeJob(), P)


# ── API de SFTPGo (servidor simulado) ───────────────────────────────────────
class _Api(BaseHTTPRequestHandler):
    mode = "ok"
    seen = []

    def log_message(self, *a):
        pass

    def _send(self, code, body):
        raw = json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self):
        if self.path == "/web/client/login":
            return self._send(200, {})
        if self.path == "/api/v2/token":
            _Api.seen.append(("GET", self.path, self.headers.get("Authorization")))
            if _Api.mode == "get405":
                return self._send(405, {"message": "no"})
            user_pass = base64.b64decode(self.headers["Authorization"].split()[1]).decode()
            if _Api.mode == "badauth" or user_pass != "admin:clave-admin-12":
                return self._send(401, {"message": "bad"})
            return self._send(200, {"access_token": "TOK", "expires_at": "x"})
        self._send(404, {})

    def do_POST(self):
        n = int(self.headers.get("Content-Length") or 0)
        body = json.loads(self.rfile.read(n) or b"{}")
        if self.path == "/api/v2/token":
            _Api.seen.append(("POST", self.path, self.headers.get("Authorization")))
            return self._send(200, {"access_token": "TOK"})
        if self.path == "/api/v2/users":
            _Api.seen.append(("POST", self.path, self.headers.get("Authorization"), body))
            if self.headers.get("Authorization") != "Bearer TOK":
                return self._send(401, {})
            if _Api.mode == "dup":
                return self._send(409, {"message": "exists"})
            if _Api.mode == "boom":
                return self._send(500, {"message": "falló"})
            return self._send(201, body)
        self._send(404, {})


@pytest.fixture()
def api():
    srv = HTTPServer(("127.0.0.1", 0), _Api)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    _Api.mode, _Api.seen = "ok", []
    yield {**P, "http_port": srv.server_address[1]}
    srv.shutdown()


def test_crea_el_usuario_del_repositorio(api):
    assert sftp.create_repo_user(api) == "creado"
    method, path, auth, body = _Api.seen[-1]
    assert auth == "Bearer TOK" and body["username"] == "repositorio"
    assert body["password"] == "clave-repo-1234" and body["status"] == 1
    assert body["home_dir"] == "/srv/sftpgo/data/repositorio"
    assert body["permissions"] == {"/": ["*"]}


def test_usuario_existente_no_es_error(api):
    _Api.mode = "dup"
    assert sftp.create_repo_user(api) == "existe"


def test_token_por_post_si_el_get_da_405(api):
    _Api.mode = "get405"
    assert sftp.create_repo_user(api) == "creado"
    assert [s[0] for s in _Api.seen if s[1] == "/api/v2/token"] == ["GET", "POST"]


def test_admin_con_otra_clave(api):
    with pytest.raises(RuntimeError, match="otra contraseña"):
        sftp.create_repo_user({**api, "admin_pass": "otra-clave-9999"})


def test_error_de_la_api(api):
    _Api.mode = "boom"
    with pytest.raises(RuntimeError, match="HTTP 500"):
        sftp.create_repo_user(api)


def test_wait_ready_responde_y_se_rinde(api):
    assert sftp.wait_ready(api, seconds=2) is True
    cerrado = {**P, "http_port": 1}  # nada escucha aquí
    assert sftp.wait_ready(cerrado, seconds=0, sleep=lambda s: None) is False


def test_deploy_en_servidor_real_avisa_si_falla_la_api(data_dir, fake_docker, monkeypatch):
    monkeypatch.setattr(config, "DRY_RUN", False)
    monkeypatch.setattr(sftp, "run", lambda *a, **kw: None)
    monkeypatch.setattr(sftp.Sftp, "apply_firewall", lambda self, log=None: [])
    monkeypatch.setattr(sftp, "wait_ready", lambda p: True)

    def falla(p):
        raise RuntimeError("la API no entregó un token (HTTP 500)")

    monkeypatch.setattr(sftp, "create_repo_user", falla)
    job = FakeJob()
    sftp.Sftp().deploy(job, P)  # no lanza: el despliegue sigue
    assert settings.section("sftp")["installed"] is True
    assert any("Administración" in m and "repositorio" in m for m in job.kinds("warn"))
    monkeypatch.setattr(sftp, "create_repo_user", lambda p: "creado")
    job = FakeJob()
    sftp.Sftp().deploy(job, P)
    assert any("creado" in m for m in job.kinds("ok"))


# ── integración con la consola ──────────────────────────────────────────────
def test_registrado_con_puertos_y_actualizaciones(data_dir):
    m = MODULES["sftp"]
    settings.update_section("sftp", {"installed": True, "params": P})
    assert {(p["port"], p["proto"]) for p in m.ports()} == {("2022", "tcp"), ("8085", "tcp")}
    assert m.containers() == {sftp.CONTAINER: sftp.IMAGE}
    up = m.upstream()[0]
    assert up["repo"] == "drakkan/sftpgo" and up["current"] == "v2.7.6"
    assert re.fullmatch(up["pattern"], up["current"])


def test_pagina_y_botones(client, monkeypatch):
    monkeypatch.setattr(system, "candidate_hosts", lambda: ["10.147.17.5"])
    html = client.get("/m/sftp").get_data(as_text=True)
    assert "Repositorio SFTP" in html and "Desplegar repositorio" in html
    settings.update_section("sftp", {"installed": True, "params": {**P, "tls": True}})
    html = client.get("/m/sftp").get_data(as_text=True)
    assert 'data-open-scheme="https"' in html and 'data-open-port="8085"' in html
    assert 'data-open-path="/web/client"' in html and 'data-open-path="/web/admin"' in html
    assert "clave-repo-1234" in html  # el administrador ve las credenciales
    assert "sftp://repositorio@10.147.17.5:2022" in html
    assert "https://10.147.17.5:8085/web/client" in html


def test_deploy_por_la_api_valida(client):
    r = client.post("/api/m/sftp/deploy", headers={"X-CSRF-Token": client.csrf},
                    data={"http_port": "22", "admin_pass": "x"})
    assert r.status_code == 400 and {"http_port", "admin_pass"} <= set(r.get_json()["errors"])


def test_monitor_no_falla_sin_contenedor(client):
    settings.update_section("sftp", {"installed": True, "params": P})
    r = client.get("/api/m/sftp/monitor")
    assert r.status_code == 200 and r.get_json()["ok"] is True


def test_enlace_js_admite_esquema():
    js = (Path(__file__).resolve().parent.parent / "takconsole/static/app.js").read_text(encoding="utf-8")
    assert 'a.dataset.openScheme || "https"' in js
