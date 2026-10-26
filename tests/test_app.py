# SPDX-License-Identifier: Apache-2.0
import time

from takconsole.core.jobs import JOBS


def wait_job(key, timeout=5):
    end = time.time() + timeout
    while time.time() < end:
        j = JOBS.get(key)
        if j and j.status != "running":
            return j
        time.sleep(0.05)
    raise AssertionError("la tarea no terminó")


def test_requires_login(data_dir):
    from takconsole import create_app
    c = create_app().test_client()
    assert c.get("/").status_code == 302
    assert c.get("/api/status").status_code == 401
    assert c.get("/m/takserver/download/admin.p12").status_code == 302


def test_csrf_required_on_post(client):
    r = client.post("/api/m/mumble/deploy", data={})
    assert r.status_code == 400
    assert "CSRF" in r.get_json()["error"]


def test_bad_login_rate_limited(data_dir):
    import re
    from takconsole import create_app
    from takconsole.core import auth
    auth.set_password("una-clave-larga-1")
    c = create_app().test_client()
    tok = re.search(r'name="csrf" value="([^"]+)"', c.get("/login").get_data(as_text=True)).group(1)
    for _ in range(5):
        c.post("/login", data={"username": "admin", "password": "mala", "csrf": tok})
    r = c.post("/login", data={"username": "admin", "password": "una-clave-larga-1", "csrf": tok})
    assert r.status_code == 200 and "Demasiados intentos" in r.get_data(as_text=True)
    auth.clear_failures("127.0.0.1")


def test_pages_render(client):
    for path in ("/", "/red", "/m/zerotier", "/m/takserver", "/m/mediamtx", "/m/mumble"):
        r = client.get(path)
        assert r.status_code == 200, path
        assert b"<html" in r.data
        assert r.headers["Content-Security-Policy"].startswith("default-src 'self'")


def test_takserver_deploy_validation(client):
    r = client.post("/api/m/takserver/deploy", headers={"X-CSRF-Token": client.csrf}, data={
        "country": "Chile", "state": "Región", "city": "Ok", "org": "Org", "ou": "Com",
        "root_ca": "ROOT_CA", "int_ca": "ROOT_CA", "cert_pass": "x", "admin_pass": "corta"})
    errs = r.get_json()["errors"]
    assert r.status_code == 400
    assert {"country", "state", "root_ca", "cert_pass", "admin_pass", "package"} <= set(errs)


def test_mumble_deploy_runs_in_dry_run(client):
    r = client.post("/api/m/mumble/deploy", headers={"X-CSRF-Token": client.csrf},
                    data={"register_name": "Red TAK", "max_users": "50", "server_pass": "clave-segura-1"})
    assert r.get_json()["ok"] is True
    job = wait_job("mumble")
    # Docker no existe en modo prueba → el despliegue se detiene con un mensaje claro
    assert job.status in ("ok", "error")
    text = "\n".join(job.lines)
    assert "clave-segura-1" not in text


def test_uninstall_requires_console_password(client):
    r = client.post("/api/m/mumble/uninstall", headers={"X-CSRF-Token": client.csrf},
                    data={"password": "incorrecta"})
    assert r.status_code == 403


def test_policy_validation(client):
    r = client.post("/api/red/policy", headers={"X-CSRF-Token": client.csrf},
                    data={"exposure": "zerotier_lan", "lan_cidr": "nada"})
    assert r.status_code == 400 and "lan_cidr" in r.get_json()["errors"]


def test_package_route_rejects_bad_names(client):
    assert client.get("/m/takserver/package/..%2Fetc?host=1.2.3.4").status_code == 404
    assert client.get("/m/takserver/download/../../etc/passwd").status_code == 404


def _pagina_mediamtx(client, params):
    from takconsole.core import settings
    settings.update_section("mediamtx", {"installed": True, "params": params})
    r = client.get("/m/mediamtx")
    assert r.status_code == 200
    return r.get_data(as_text=True)


def test_pagina_mediamtx_sin_auth_no_muestra_credenciales(client):
    html = _pagina_mediamtx(client, {"rtsp": True, "srt": True, "rtmp": True, "hls": True,
                                     "auth": False, "publish_user": "", "publish_pass": "",
                                     "read_user": "", "read_pass": ""})
    assert "rtsp://" in html and "CLAVE" not in html
    assert "Credenciales actuales" not in html
    assert "streamid=publish:camara1&amp;pkt_size=1316" in html
    assert 'name="auth"' in html
    assert 'name="auth" value="1" checked' not in html


def test_pagina_mediamtx_instalacion_anterior_conserva_credenciales(client):
    # estado guardado por la versión 0.1.0: sin la clave «auth», con credenciales
    html = _pagina_mediamtx(client, {"rtsp": True, "publish_user": "publicador",
                                     "publish_pass": "pub-pass-123", "anonymous_read": False,
                                     "read_user": "visor", "read_pass": "read-pass-123"})
    assert "rtsp://publicador:CLAVE@" in html
    assert "Credenciales actuales" in html and "pub-pass-123" in html
    assert 'name="auth" value="1" checked' in html
