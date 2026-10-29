# SPDX-License-Identifier: Apache-2.0
"""Usuarios, roles y permisos: cada ruta de la consola frente a cada rol."""
import json
import os
import re
import stat

import pytest

from takconsole import config, create_app
from takconsole.core import audit, auth, rbac, settings, users
from takconsole.modules import takserver

PW = "una-clave-larga-1"


# ── almacén de usuarios ─────────────────────────────────────────────────────
def test_migra_auth_json_como_administrador(data_dir):
    from werkzeug.security import generate_password_hash
    (config.CONFIG_DIR).mkdir(parents=True, exist_ok=True)
    (config.CONFIG_DIR / "auth.json").write_text(json.dumps(
        {"username": "admin", "hash": generate_password_hash(PW), "changed": 1000}))
    assert users.is_configured()
    u = users.authenticate("admin", PW)
    assert u and u["role"] == "admin"
    assert (config.CONFIG_DIR / "users.json").exists()
    assert (config.CONFIG_DIR / "auth.json").exists()      # no se borra nada del usuario


def test_users_json_es_privado(data_dir):
    users.create("ana", PW, "viewer")
    assert stat.S_IMODE(os.stat(config.CONFIG_DIR / "users.json").st_mode) == 0o600
    assert PW not in (config.CONFIG_DIR / "users.json").read_text()


def test_nombres_unicos_sin_distinguir_mayusculas(data_dir):
    users.create("Ana", PW, "viewer")
    with pytest.raises(ValueError):
        users.create("ana", PW, "operator")
    assert users.authenticate("ANA", PW)["username"] == "Ana"


@pytest.mark.parametrize("name", ["", "ab", "a" * 33, "con espacio", "../x", "ñandú", "a/b"])
def test_nombres_invalidos(data_dir, name):
    with pytest.raises(ValueError):
        users.create(name, PW, "viewer")


def test_contrasena_corta_y_rol_invalido(data_dir):
    with pytest.raises(ValueError):
        users.create("ana", "corta", "viewer")
    with pytest.raises(ValueError):
        users.create("ana", PW, "superadmin")


def test_cuenta_desactivada_no_entra(data_dir):
    users.create("ana", PW, "viewer")
    users.set_disabled("ana", True)
    assert users.authenticate("ana", PW) is None
    users.set_disabled("ana", False)
    assert users.authenticate("ana", PW)


def test_siempre_queda_un_administrador_activo(data_dir):
    auth.set_password(PW)                        # admin
    with pytest.raises(ValueError):
        users.set_role("admin", "viewer")
    with pytest.raises(ValueError):
        users.set_disabled("admin", True)
    with pytest.raises(ValueError):
        users.delete("admin")
    users.create("otro", PW, "admin")
    users.set_role("admin", "viewer")            # ahora sí: queda «otro»
    with pytest.raises(ValueError):
        users.delete("otro")


def test_un_admin_desactivado_no_cuenta_como_activo(data_dir):
    auth.set_password(PW)
    users.create("otro", PW, "admin")
    users.set_disabled("otro", True)
    with pytest.raises(ValueError):
        users.set_role("admin", "operator")


def test_recuperacion_reactiva_o_crea(data_dir):
    auth.set_password(PW)
    users.create("otro", PW, "admin")
    users.set_disabled("admin", True)
    auth.set_password("otra-clave-larga-2", "admin")
    assert users.authenticate("admin", "otra-clave-larga-2")
    auth.set_password(PW, "nuevo")
    assert users.get("nuevo")["role"] == "admin"


# ── clasificación de rutas ──────────────────────────────────────────────────
def test_toda_ruta_esta_clasificada_a_proposito(data_dir):
    app = create_app()
    missing = [r.endpoint for r in app.url_map.iter_rules()
               if r.endpoint not in rbac.PUBLIC_ENDPOINTS and r.endpoint not in rbac.ENDPOINT_PERMS]
    assert not missing, f"rutas sin clasificar en core/rbac.py: {missing}"
    stale = [e for e in rbac.ENDPOINT_PERMS if e not in {r.endpoint for r in app.url_map.iter_rules()}]
    assert not stale, f"rutas que ya no existen: {stale}"


def test_ruta_no_listada_exige_admin():
    assert rbac.required("ruta_nueva_olvidada") == rbac.ADMIN
    assert not rbac.allowed("operator", rbac.required("ruta_nueva_olvidada"))


def test_los_roles_son_los_acordados():
    assert rbac.ROLES["operator"]["perms"] == {"view", "monitor", "service_control", "tak_certs", "zerotier_net"}
    assert rbac.ROLES["viewer"]["perms"] == {"view", "monitor"}
    assert rbac.ADMIN in rbac.ROLES["admin"]["perms"] and rbac.ADMIN not in rbac.ROLES["operator"]["perms"]


# ── cliente por rol ─────────────────────────────────────────────────────────
def login(app, name, password=PW):
    c = app.test_client()
    html = c.get("/login").get_data(as_text=True)
    tok = re.search(r'name="csrf" value="([^"]+)"', html).group(1)
    r = c.post("/login", data={"username": name, "password": password, "csrf": tok})
    assert r.status_code == 302, r.get_data(as_text=True)[:200]
    page = c.get("/").get_data(as_text=True)
    c.csrf = re.search(r'name="csrf-token" content="([^"]+)"', page).group(1)
    return c


@pytest.fixture()
def app(data_dir, monkeypatch):
    # TAK Server «instalado»: así se dibujan los paneles que dependen de ello
    monkeypatch.setattr(takserver.TakServer, "package_version", lambda self: "5.8-RELEASE92")
    auth.set_password(PW)                        # admin
    users.create("oper", PW, "operator")
    users.create("mira", PW, "viewer")
    a = create_app()
    a.config["TESTING"] = True
    return a


@pytest.fixture()
def clients(app):
    return {"admin": login(app, "admin"), "operator": login(app, "oper"), "viewer": login(app, "mira")}


# (método, ruta, endpoint, permiso esperado)
SAMPLE = {"key": "mediamtx", "verb": "restart", "what": "root-ca.pem", "user": "alfa-01", "name": "mira"}


def build(app, endpoint):
    rule = next(r for r in app.url_map.iter_rules() if r.endpoint == endpoint)
    path = re.sub(r"<(?:[^:>]+:)?([^>]+)>", lambda m: SAMPLE[m.group(1)], rule.rule)
    method = "POST" if "POST" in rule.methods else "GET"
    return method, path


def test_matriz_de_permisos_por_rol(app, clients):
    """Cada ruta: 403 si el rol no tiene el permiso; si lo tiene, nunca 403 ni 401."""
    for r in app.url_map.iter_rules():
        ep = r.endpoint
        if ep in rbac.PUBLIC_ENDPOINTS or ep == "logout":
            continue
        method, path = build(app, ep)
        need = rbac.required(ep)
        for role, c in clients.items():
            if method == "POST":
                resp = c.post(path, headers={"X-CSRF-Token": c.csrf}, data={})
            else:
                resp = c.get(path)
            allowed = rbac.allowed(role, need)
            denied_by_role = resp.status_code == 403 and "no tiene permiso" in resp.get_data(as_text=True)
            if allowed:
                # puede devolver 400/403 por validación (p. ej. contraseña de confirmación), pero
                # nunca la negativa por rol ni la de sesión
                assert resp.status_code != 401 and not denied_by_role, \
                    f"{role} debería poder {method} {path} ({ep})"
            else:
                assert denied_by_role, f"{role} NO debería poder {method} {path} ({ep}): {resp.status_code}"


def test_operador_no_puede_desplegar_ni_desinstalar(clients):
    c = clients["operator"]
    h = {"X-CSRF-Token": c.csrf}
    assert c.post("/api/m/takserver/deploy", headers=h, data={}).status_code == 403
    assert c.post("/api/m/takserver/uninstall", headers=h, data={"password": PW}).status_code == 403
    assert c.post("/api/m/takserver/purge", headers=h, data={"password": PW, "confirm": "BORRAR DATOS"}).status_code == 403
    assert c.post("/api/red/policy", headers=h, data={"exposure": "all"}).status_code == 403
    assert c.get("/red").status_code == 403 and c.get("/usuarios").status_code == 403


def test_operador_puede_crear_certificados_y_controlar_servicios(clients):
    c = clients["operator"]
    h = {"X-CSRF-Token": c.csrf}
    r = c.post("/api/m/takserver/users", headers=h, data={"name": "alfa-01"})
    assert r.status_code == 400 and "errors" in r.get_json()       # llega a la validación, no al 403
    assert c.post("/api/m/mumble/action/restart", headers=h).status_code != 403


def test_observador_solo_ve(clients):
    c = clients["viewer"]
    h = {"X-CSRF-Token": c.csrf}
    assert c.get("/m/takserver").status_code == 200
    assert c.get("/api/m/takserver/monitor").status_code == 200
    assert c.post("/api/m/mumble/action/restart", headers=h).status_code == 403
    assert c.post("/api/m/takserver/users", headers=h, data={"name": "x"}).status_code == 403
    assert c.post("/api/m/zerotier/join", headers=h, data={"nwid": "0" * 16}).status_code == 403


def test_get_sin_csrf_pero_post_exige_csrf(clients):
    c = clients["admin"]
    assert c.post("/api/usuarios/crear", data={}).status_code == 400


# ── paquetes de TAK: el operador no puede llevarse el certificado de admin ──
def test_operador_solo_empaqueta_usuarios_de_la_consola(app, clients, monkeypatch, tmp_path):
    files = tmp_path / "files"
    files.mkdir()
    for n in ("admin.p12", "alfa-01.p12", "truststore-int.p12"):
        (files / n).write_bytes(b"x")
    monkeypatch.setattr(takserver, "FILES", files)
    monkeypatch.setattr(takserver.TakServer, "int_ca", lambda self: "int")
    settings.replace_section("takserver", {"installed": True, "users": [{"name": "alfa-01"}]})
    q = "?host=10.0.0.1&kind=atak"
    assert clients["operator"].get("/m/takserver/package/admin" + q).status_code == 404
    assert clients["operator"].get("/m/takserver/package/ADMIN" + q).status_code == 404
    assert clients["operator"].get("/m/takserver/package/alfa-01" + q).status_code == 200
    assert clients["admin"].get("/m/takserver/package/admin" + q).status_code == 200
    assert clients["viewer"].get("/m/takserver/package/alfa-01" + q).status_code == 403


# ── secretos ocultos a quien no es administrador ────────────────────────────
def test_los_secretos_solo_los_ve_el_administrador(app, clients):
    settings.replace_section("mediamtx", {"installed": True, "params": {
        "rtsp": True, "auth": True, "publish_user": "pub", "publish_pass": "SECRETO-PUB-1",
        "read_user": "vis", "read_pass": "SECRETO-VIS-1"}})
    settings.replace_section("mumble", {"installed": True, "params": {
        "server_pass": "SECRETO-SRV-1", "superuser_pass": "SECRETO-SU-1"}})
    for role, visible in (("admin", True), ("operator", False), ("viewer", False)):
        for page, secrets_ in (("mediamtx", ["SECRETO-PUB-1", "SECRETO-VIS-1"]),
                               ("mumble", ["SECRETO-SRV-1", "SECRETO-SU-1"])):
            html = clients[role].get(f"/m/{page}").get_data(as_text=True)
            for s in secrets_:
                assert (s in html) is visible, f"{role} {page} {s}"


def test_paginas_ocultan_controles_de_administrador(app, clients):
    html = clients["operator"].get("/m/takserver").get_data(as_text=True)
    assert "Paquete de instalación" not in html and "Desinstalar" not in html
    assert "download/admin.p12" not in html and 'data-api="/api/m/takserver/users"' in html
    html = clients["viewer"].get("/m/takserver").get_data(as_text=True)
    assert 'data-api="/api/m/takserver/users"' not in html
    html = clients["admin"].get("/m/takserver").get_data(as_text=True)
    assert "Paquete de instalación" in html
    nav_operator = clients["operator"].get("/").get_data(as_text=True)
    assert "/usuarios" not in nav_operator and "Red y firewall" not in nav_operator
    assert "/usuarios" in clients["admin"].get("/").get_data(as_text=True)


# ── sesiones ────────────────────────────────────────────────────────────────
def test_desactivar_cierra_la_sesion_de_inmediato(app, clients):
    assert clients["operator"].get("/m/mumble").status_code == 200
    users.set_disabled("oper", True)
    r = clients["operator"].get("/m/mumble")
    assert r.status_code == 302 and "/login" in r.headers["Location"]
    assert clients["operator"].get("/api/m/mumble/monitor").status_code == 401


def test_cambiar_el_rol_surte_efecto_sin_volver_a_entrar(app, clients):
    c = clients["operator"]
    h = {"X-CSRF-Token": c.csrf}
    assert c.post("/api/m/mumble/action/restart", headers=h).status_code != 403
    users.set_role("oper", "viewer")
    assert c.post("/api/m/mumble/action/restart", headers=h).status_code == 403


def test_restablecer_la_contrasena_cierra_sus_sesiones(app, clients):
    users.set_password("oper", "otra-clave-larga-2")
    assert clients["operator"].get("/m/mumble").status_code == 302


# ── administración de usuarios por HTTP ─────────────────────────────────────
def post(c, path, **data):
    return c.post(path, headers={"X-CSRF-Token": c.csrf}, data=data)


def test_crear_usuario_pide_la_contrasena_del_admin(clients):
    a = clients["admin"]
    r = post(a, "/api/usuarios/crear", username="nuevo", password=PW, role="viewer", admin_password="mala")
    assert r.status_code == 403 and "admin_password" in r.get_json()["errors"]
    assert users.get("nuevo") is None
    r = post(a, "/api/usuarios/crear", username="nuevo", password=PW, role="viewer", admin_password=PW)
    assert r.status_code == 200 and users.get("nuevo")["role"] == "viewer"
    r = post(a, "/api/usuarios/crear", username="nuevo", password=PW, role="viewer", admin_password=PW)
    assert r.status_code == 400
    r = post(a, "/api/usuarios/crear", username="otro", password="corta", role="viewer", admin_password=PW)
    assert r.status_code == 400 and "password" in r.get_json()["errors"]


def test_el_admin_no_puede_quitarse_acceso_a_si_mismo(clients):
    a = clients["admin"]
    for path, data in (("/api/usuarios/admin/rol", {"role": "viewer"}),
                       ("/api/usuarios/admin/estado", {"disabled": "1"}),
                       ("/api/usuarios/admin/borrar", {}),
                       ("/api/usuarios/admin/password", {"new_password": "otra-clave-larga-2"})):
        r = post(a, path, admin_password=PW, **data)
        assert r.status_code == 400, path
    assert users.get("admin")["role"] == "admin" and not users.get("admin")["disabled"]


def test_gestion_de_otro_usuario(clients):
    a = clients["admin"]
    assert post(a, "/api/usuarios/oper/rol", role="viewer", admin_password=PW).status_code == 200
    assert users.get("oper")["role"] == "viewer"
    assert post(a, "/api/usuarios/oper/estado", disabled="1", admin_password=PW).status_code == 200
    assert users.get("oper")["disabled"]
    assert post(a, "/api/usuarios/oper/estado", disabled="", admin_password=PW).status_code == 200
    assert not users.get("oper")["disabled"]
    assert post(a, "/api/usuarios/oper/password", new_password="otra-clave-larga-2", admin_password=PW).status_code == 200
    assert users.authenticate("oper", "otra-clave-larga-2")
    assert post(a, "/api/usuarios/oper/borrar", admin_password=PW).status_code == 200
    assert users.get("oper") is None
    assert post(a, "/api/usuarios/no-existe/borrar", admin_password=PW).status_code == 404
    assert post(a, "/api/usuarios/a%20b/borrar", admin_password=PW).status_code == 404


def test_cambiar_la_propia_contrasena(app, clients):
    c = clients["operator"]
    r = post(c, "/api/cuenta/password", current_password="mala", new_password="otra-clave-larga-2",
             repeat_password="otra-clave-larga-2")
    assert r.status_code == 403
    r = post(c, "/api/cuenta/password", current_password=PW, new_password="otra-clave-larga-2", repeat_password="distinta")
    assert r.status_code == 400
    r = post(c, "/api/cuenta/password", current_password=PW, new_password="corta", repeat_password="corta")
    assert r.status_code == 400
    r = post(c, "/api/cuenta/password", current_password=PW, new_password="otra-clave-larga-2",
             repeat_password="otra-clave-larga-2")
    assert r.status_code == 200
    assert c.get("/cuenta").status_code == 200                # esta sesión sigue viva
    assert users.authenticate("oper", "otra-clave-larga-2") and not users.authenticate("oper", PW)


def test_confirmaciones_fallidas_bloquean_por_ip(app, clients):
    a = clients["admin"]
    for _ in range(auth.MAX_FAILS):
        post(a, "/api/usuarios/oper/borrar", admin_password="mala")
    r = post(a, "/api/usuarios/oper/borrar", admin_password=PW)
    assert r.status_code == 403 and "Demasiados" in r.get_json()["errors"]["admin_password"]
    assert users.get("oper") is not None


# ── auditoría ───────────────────────────────────────────────────────────────
def test_auditoria_registra_quien_hizo_que_sin_secretos(app, clients):
    post(clients["admin"], "/api/usuarios/crear", username="nuevo", password="SECRETO-NUEVO-123", role="viewer", admin_password=PW)
    post(clients["viewer"], "/api/m/mumble/action/restart")
    text = (config.LOG_DIR / "audit.log").read_text()
    assert re.search(r"\badmin\s+admin\s+\S+\s+POST_/api/usuarios/crear\s+200", text)
    assert re.search(r"\bmira\s+viewer\s+\S+\s+DENEGADO_POST_/api/m/mumble/action/restart\s+403", text)
    assert "SECRETO-NUEVO-123" not in text and PW not in text
    assert stat.S_IMODE(os.stat(config.LOG_DIR / "audit.log").st_mode) == 0o600


def test_auditoria_registra_accesos_y_fallos(app):
    login(app, "admin")
    c = app.test_client()
    tok = re.search(r'name="csrf" value="([^"]+)"', c.get("/login").get_data(as_text=True)).group(1)
    c.post("/login", data={"username": "admin", "password": "mala", "csrf": tok})
    text = (config.LOG_DIR / "audit.log").read_text()
    assert re.search(r"admin\s+admin\s+\S+\s+LOGIN\s+200", text)
    assert re.search(r"LOGIN_fallido\s+401", text) and "mala" not in text


def test_auditoria_no_deja_falsificar_lineas(data_dir):
    audit.record("x\n2026-01-01  admin  admin  1.1.1.1  LOGIN  200", "-", "1.1.1.1", "a\rb", 200)
    lines = (config.LOG_DIR / "audit.log").read_text().splitlines()
    assert len(lines) == 1


def test_descargas_sensibles_quedan_registradas(app, clients, monkeypatch, tmp_path):
    files = tmp_path / "files"
    files.mkdir()
    (files / "root-ca.pem").write_text("x")
    monkeypatch.setattr(takserver, "FILES", files)
    clients["admin"].get("/m/takserver/download/root-ca.pem")
    assert "GET_/m/takserver/download/root-ca.pem" in (config.LOG_DIR / "audit.log").read_text()


def test_pagina_de_usuarios_muestra_la_actividad(clients):
    post(clients["admin"], "/api/usuarios/crear", username="nuevo", password=PW, role="viewer", admin_password=PW)
    html = clients["admin"].get("/usuarios").get_data(as_text=True)
    assert "POST_/api/usuarios/crear" in html and "nuevo" in html and "(tú)" in html


# ── CLI de recuperación ─────────────────────────────────────────────────────
def test_cli_list_users(data_dir, capsys):
    from takconsole import cli
    auth.set_password(PW)
    users.create("ana", PW, "operator")
    assert cli.main(["list-users"]) == 0
    out = capsys.readouterr().out
    assert "admin" in out and "Administrador" in out and "ana" in out and "Operador" in out
