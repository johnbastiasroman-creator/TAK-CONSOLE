# SPDX-License-Identifier: Apache-2.0
"""Apariencia: logo, icono, nombre y color. Lo subido se valida por contenido."""
import base64
import io
import os
import re
import stat

import pytest

from takconsole import config
from takconsole.core import branding, settings

PNG = base64.b64decode(
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg==")
JPG = b"\xff\xd8\xff\xe0" + b"\x00" * 32
WEBP = b"RIFF\x24\x00\x00\x00WEBPVP8 " + b"\x00" * 16
ICO = b"\x00\x00\x01\x00\x01\x00" + b"\x00" * 32
SVG = b'<svg xmlns="http://www.w3.org/2000/svg" width="10" height="10"><rect width="10" height="10"/></svg>'


# ── validación de imágenes ──────────────────────────────────────────────────
@pytest.mark.parametrize("data,kind,ext", [
    (PNG, "logo", "png"), (JPG, "logo", "jpg"), (WEBP, "logo", "webp"), (SVG, "logo", "svg"),
    (PNG, "favicon", "png"), (ICO, "favicon", "ico"), (SVG, "favicon", "svg")])
def test_formatos_validos(data, kind, ext):
    assert branding.detect(data, kind) == ext


@pytest.mark.parametrize("data,kind", [
    (b"MZ\x90\x00" + b"\x00" * 64, "logo"),          # ejecutable de Windows con extensión .png
    (b"#!/bin/sh\nrm -rf /\n", "logo"),
    (b"<html><script>alert(1)</script></html>", "logo"),
    (b"GIF89a" + b"\x00" * 20, "logo"),               # GIF no está en la lista
    (ICO, "logo"), (JPG, "favicon"), (WEBP, "favicon"),  # válidos, pero no para ese uso
    (b"", "logo")])
def test_formatos_rechazados(data, kind):
    with pytest.raises(ValueError):
        branding.detect(data, kind)


def svg(inner="", root_attrs=""):
    return f'<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" {root_attrs}>{inner}</svg>'.encode()


@pytest.mark.parametrize("bad", [
    svg("<script>alert(1)</script>"),
    svg('<rect onload="alert(1)"/>'),
    svg("", 'onload="alert(1)"'),
    svg('<foreignObject><body xmlns="http://www.w3.org/1999/xhtml"/></foreignObject>'),
    svg('<image href="http://evil.example/x.png"/>'),
    svg('<image xlink:href="https://evil.example/x.png"/>'),
    svg('<a href="javascript:alert(1)"><rect/></a>'),
    svg('<use href="file:///etc/passwd"/>'),
    svg('<style>@import url(http://evil.example/x.css);</style>'),
    svg('<animate attributeName="href" to="javascript:alert(1)"/>'),
    svg('<set attributeName="onmouseover" to="alert(1)"/>'),
    b'<?xml version="1.0"?><!DOCTYPE svg [<!ENTITY a "aaaa"><!ENTITY b "&a;&a;&a;">]><svg xmlns="http://www.w3.org/2000/svg">&b;</svg>',
    b'<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd"><svg xmlns="http://www.w3.org/2000/svg"/>',
    b"<svg xmlns='http://www.w3.org/2000/svg'><rect></svg>",       # mal formado
    b"<not-svg><svg/></not-svg>",
    b"<svg \xff\xfe/>",                                              # no UTF-8
])
def test_svg_peligroso_se_rechaza(bad):
    with pytest.raises(ValueError):
        branding.detect(bad, "logo")


def test_svg_legitimo_con_referencias_internas_y_data_uri():
    ok = svg('<defs><linearGradient id="g"/></defs><rect fill="url(#g)"/><use href="#g"/>'
             '<image href="data:image/png;base64,iVBORw0KGgo="/>')
    assert branding.detect(ok, "logo") == "svg"


# ── color y nombre ──────────────────────────────────────────────────────────
def test_color_se_normaliza_y_valida():
    assert branding.check_accent(" #E9A43C ") == "#e9a43c"
    for bad in ("", "e9a43c", "#fff", "#12345", "#gggggg", "red", "#e9a43c; } body{display:none"):
        with pytest.raises(ValueError):
            branding.check_accent(bad)


def test_color_ilegible_sobre_el_fondo_se_rechaza():
    for dark in ("#000000", "#1c2320", "#202a26", "#222222"):
        with pytest.raises(ValueError):
            branding.check_accent(dark)
    assert branding.check_accent("#ffffff") == "#ffffff"


def test_tinta_del_boton_tiene_contraste_suficiente():
    for color in ("#e9a43c", "#ffffff", "#4ea8ff", "#74c08a", "#ff6a55", "#9b59b6", "#f1c40f"):
        ink = branding.ink_for(color)
        assert branding.contrast(color, ink) >= 4.5, color


@pytest.mark.parametrize("name", ["", "Base Alfa", "TAK-NAV (Chile)", "Centro 1 / Norte", "Ñandú Ops"])
def test_nombres_validos(name):
    assert branding.check_name(name) == name.strip()


@pytest.mark.parametrize("name", ["<script>", "a" * 41, 'x"y', "uno\ndos", "a;b", "{{7*7}}", "<b>x</b>"])
def test_nombres_invalidos(name):
    with pytest.raises(ValueError):
        branding.check_name(name)


# ── almacenamiento ──────────────────────────────────────────────────────────
def test_guardar_reemplazar_y_borrar_archivos(data_dir):
    branding.set_image("logo", PNG)
    assert (config.BRANDING_DIR / "logo.png").is_file()
    assert stat.S_IMODE(os.stat(config.BRANDING_DIR / "logo.png").st_mode) == 0o600
    branding.set_image("logo", SVG)                      # cambia de formato: no queda el viejo
    assert not (config.BRANDING_DIR / "logo.png").exists() and (config.BRANDING_DIR / "logo.svg").is_file()
    assert branding.image("logo")[1] == "image/svg+xml"
    branding.clear_image("logo")
    assert not list(config.BRANDING_DIR.glob("logo.*")) and branding.get()["logo_url"] is None


def test_limite_de_tamano(data_dir):
    with pytest.raises(ValueError):
        branding.set_image("logo", PNG + b"\x00" * branding.MAX_BYTES["logo"])
    with pytest.raises(ValueError):
        branding.set_image("favicon", PNG + b"\x00" * branding.MAX_BYTES["favicon"])
    assert not list(config.BRANDING_DIR.glob("*.*"))


def test_restablecer_deja_todo_como_al_inicio(data_dir):
    branding.set_image("logo", PNG)
    branding.set_image("favicon", ICO)
    branding.set_text("Base Alfa", "#4ea8ff", show_name=False)
    assert branding.get()["customized"]
    branding.reset()
    b = branding.get()
    assert not b["customized"] and b["name"] == config.APP_NAME and b["accent"] is None and b["show_name"]
    assert not list(config.BRANDING_DIR.glob("*.*"))
    assert "sin color" in branding.theme_css()


def test_archivo_borrado_a_mano_no_rompe_las_paginas(data_dir):
    branding.set_image("logo", PNG)
    (config.BRANDING_DIR / "logo.png").unlink()
    assert branding.get()["logo_url"] is None and branding.image("logo") is None


def test_theme_css_solo_contiene_valores_validados(data_dir):
    branding.set_text("", "#4ea8ff")
    css = branding.theme_css()
    assert css.strip() == ":root { --accent: #4ea8ff; --accent-ink: %s; }" % branding.ink_for("#4ea8ff")
    # aunque alguien editara settings.json a mano, el color se vuelve a comprobar al guardar, no al leer:
    # por eso get/theme_css solo emiten lo que pasó check_accent
    assert re.fullmatch(r"#[0-9a-f]{6}", settings.section("branding")["accent"])


# ── HTTP ────────────────────────────────────────────────────────────────────
def upload(client, kind, data, filename="x.png"):
    return client.post(f"/api/apariencia/imagen/{kind}", headers={"X-CSRF-Token": client.csrf},
                       data={"file": (io.BytesIO(data), filename)}, content_type="multipart/form-data")


def post(client, path, **data):
    return client.post(path, headers={"X-CSRF-Token": client.csrf}, data=data)


def test_logo_e_icono_son_publicos_pero_el_resto_no(client):
    assert upload(client, "logo", PNG).status_code == 200
    anon = client.application.test_client()
    r = anon.get("/branding/logo")
    assert r.status_code == 200 and r.mimetype == "image/png" and r.data == PNG
    assert r.headers["X-Content-Type-Options"] == "nosniff"
    assert "sandbox" in r.headers["Content-Security-Policy"] and "default-src 'none'" in r.headers["Content-Security-Policy"]
    assert anon.get("/branding/favicon").status_code == 404       # no hay icono todavía
    assert anon.get("/branding/theme.css").status_code == 200
    for path in ("/apariencia", "/api/apariencia/restablecer"):
        assert anon.get(path).status_code in (302, 401, 405)
    assert anon.post("/api/apariencia/texto", data={"name": "x"}).status_code in (302, 401)


def test_se_decide_por_el_contenido_no_por_el_nombre(client):
    r = upload(client, "logo", b"MZ\x90\x00" + b"\x00" * 100, "logo.png")
    assert r.status_code == 400 and "no reconocido" in r.get_json()["errors"]["file"]
    r = upload(client, "logo", SVG.replace(b"<rect", b"<script>alert(1)</script><rect"), "logo.png")
    assert r.status_code == 400
    assert upload(client, "logo", PNG, "foto.svg").status_code == 200
    assert client.application.test_client().get("/branding/logo").mimetype == "image/png"


def test_svg_servido_directamente_no_puede_ejecutar_nada(client):
    assert upload(client, "logo", SVG, "a.svg").status_code == 200
    r = client.application.test_client().get("/branding/logo")
    assert r.mimetype == "image/svg+xml"
    assert r.headers["Content-Security-Policy"] == "default-src 'none'; style-src 'unsafe-inline'; sandbox"


def test_archivo_demasiado_grande_responde_413_o_400(client):
    big = PNG + b"\x00" * (branding.MAX_BYTES["logo"] + 1024)
    r = upload(client, "logo", big)
    assert r.status_code in (400, 413) and not list(config.BRANDING_DIR.glob("logo.*"))


def test_errores_de_envio(client):
    assert post(client, "/api/apariencia/imagen/logo").status_code == 400            # sin archivo
    assert upload(client, "otro", PNG).status_code == 404                            # tipo inexistente
    assert post(client, "/api/apariencia/imagen/otro/borrar").status_code == 404


def test_texto_y_color_por_http(client):
    r = post(client, "/api/apariencia/texto", name="<b>x</b>", accent="#000000")
    assert r.status_code == 400 and set(r.get_json()["errors"]) == {"name", "accent"}
    assert not branding.get()["customized"]                      # nada se guardó a medias
    r = post(client, "/api/apariencia/texto", name="Base Alfa", accent="#4EA8FF")
    assert r.status_code == 200
    assert branding.get()["name"] == "Base Alfa" and branding.get()["accent"] == "#4ea8ff"
    assert not branding.get()["show_name"]                       # casilla desmarcada = no se envía


def test_las_paginas_usan_nombre_logo_icono_y_color(client):
    upload(client, "logo", PNG)
    upload(client, "favicon", ICO, "f.ico")
    post(client, "/api/apariencia/texto", name="Base Alfa", accent="#4ea8ff", show_name="1")
    page = client.get("/").get_data(as_text=True)
    assert "<title>Panel · Base Alfa</title>" in page or "· Base Alfa</title>" in page
    assert 'class="logo" src="/branding/logo?v=' in page
    assert 'rel="icon" href="/branding/favicon?v=' in page and 'type="image/x-icon"' in page
    assert 'href="/branding/theme.css?v=' in page and "<strong>Base Alfa</strong>" in page
    anon = client.application.test_client().get("/login").get_data(as_text=True)
    assert "Base Alfa" in anon and "/branding/logo?v=" in anon and "/branding/theme.css" in anon


def test_nombre_sin_mostrar_junto_al_logo(client):
    upload(client, "logo", PNG)
    post(client, "/api/apariencia/texto", name="Base Alfa", accent="")      # sin show_name
    page = client.get("/").get_data(as_text=True)
    assert "<strong>Base Alfa</strong>" not in page and 'alt="Base Alfa"' in page
    assert "Base Alfa" in page                                              # sigue en el título
    # sin logo el nombre siempre se muestra, aunque la casilla esté desmarcada
    post(client, "/api/apariencia/imagen/logo/borrar")
    assert "<strong>Base Alfa</strong>" in client.get("/").get_data(as_text=True)


def test_el_nombre_se_escapa_en_html(client, data_dir):
    # aunque se saltaran las validaciones (settings.json editado a mano), Jinja escapa
    settings.replace_section("branding", {"name": "<img src=x onerror=alert(1)>", "rev": 1})
    page = client.get("/").get_data(as_text=True)
    assert "<img src=x" not in page and "&lt;img src=x" in page


def test_pagina_de_apariencia_y_menu_solo_para_admin(client):
    page = client.get("/apariencia").get_data(as_text=True)
    assert "Nombre y color" in page and "Subir logo" in page and "Subir icono" in page
    assert 'href="/apariencia"' in client.get("/").get_data(as_text=True)


def test_operador_y_observador_no_ven_ni_cambian_la_apariencia(data_dir):
    from takconsole import create_app
    from takconsole.core import auth, users
    from tests.test_roles import login, PW
    auth.set_password(PW)
    users.create("oper", PW, "operator")
    users.create("mira", PW, "viewer")
    app = create_app()
    for name in ("oper", "mira"):
        c = login(app, name)
        assert c.get("/apariencia").status_code == 403
        assert 'href="/apariencia"' not in c.get("/").get_data(as_text=True)
        for path in ("/api/apariencia/texto", "/api/apariencia/restablecer", "/api/apariencia/imagen/logo",
                     "/api/apariencia/imagen/logo/borrar"):
            r = c.post(path, headers={"X-CSRF-Token": c.csrf}, data={"name": "x"})
            assert r.status_code == 403, (name, path)
        assert not branding.get()["customized"]


def test_auditoria_registra_el_cambio_sin_el_contenido(client):
    upload(client, "logo", PNG, "secreto-interno.png")
    log = (config.LOG_DIR / "audit.log").read_text()
    assert "POST_/api/apariencia/imagen/logo" in log.replace(" ", "_") or "/api/apariencia/imagen/logo" in log
    assert "secreto-interno" not in log


def test_logo_grande_en_el_panel_principal(client):
    assert 'class="hero-logo"' not in client.get("/").get_data(as_text=True)      # sin logo, nada
    upload(client, "logo", PNG)
    page = client.get("/").get_data(as_text=True)
    assert 'class="hero-logo" src="/branding/logo?v=' in page
    # solo en el panel principal: el menú lateral conserva su logo pequeño
    assert 'class="hero-logo"' not in client.get("/apariencia").get_data(as_text=True)
    assert 'class="logo" src="/branding/logo' in page
    post(client, "/api/apariencia/imagen/logo/borrar")
    assert 'class="hero-logo"' not in client.get("/").get_data(as_text=True)


def test_operador_y_observador_tambien_ven_el_logo_del_panel(data_dir):
    from takconsole import create_app
    from takconsole.core import auth, users
    from tests.test_roles import login, PW
    auth.set_password(PW)
    users.create("mira", PW, "viewer")
    branding.set_image("logo", PNG)
    assert 'class="hero-logo"' in login(create_app(), "mira").get("/").get_data(as_text=True)


# ── logo propio para la pantalla de ingreso ─────────────────────────────────
def test_ingreso_usa_el_logo_del_sitio_si_no_hay_uno_propio(client):
    anon = client.application.test_client()
    assert "/branding/" not in anon.get("/login").get_data(as_text=True).replace("/branding/theme.css", "")
    upload(client, "logo", PNG)
    page = anon.get("/login").get_data(as_text=True)
    assert 'class="logo" src="/branding/logo?v=' in page and "/branding/login" not in page
    assert not branding.get()["has_login_logo"]


def test_logo_de_ingreso_propio_no_cambia_el_del_sitio(client):
    upload(client, "logo", PNG)
    r = upload(client, "login", SVG, "ingreso.svg")
    assert r.status_code == 200 and (config.BRANDING_DIR / "login.svg").is_file()
    assert (config.BRANDING_DIR / "logo.png").is_file()                    # el del sitio sigue intacto
    anon = client.application.test_client()
    login_page = anon.get("/login").get_data(as_text=True)
    assert 'class="logo" src="/branding/login?v=' in login_page and "/branding/logo?v=" not in login_page
    site = client.get("/").get_data(as_text=True)                          # menú y panel: logo del sitio
    assert 'class="logo" src="/branding/logo?v=' in site and 'class="hero-logo" src="/branding/logo?v=' in site
    assert "/branding/login" not in site
    r = anon.get("/branding/login")
    assert r.status_code == 200 and r.mimetype == "image/svg+xml" and "sandbox" in r.headers["Content-Security-Policy"]
    assert anon.get("/branding/logo").mimetype == "image/png"


def test_logo_de_ingreso_se_valida_igual_que_el_del_sitio(client):
    assert upload(client, "login", svg("<script>alert(1)</script>")).status_code == 400
    assert upload(client, "login", b"MZ" + b"\x00" * 80).status_code == 400
    assert upload(client, "login", ICO).status_code == 400                 # ICO no vale para un logo
    assert upload(client, "login", PNG + b"\x00" * branding.MAX_BYTES["login"]).status_code in (400, 413)
    assert not list(config.BRANDING_DIR.glob("login.*"))


def test_quitar_el_logo_de_ingreso_vuelve_al_del_sitio(client):
    upload(client, "logo", PNG)
    upload(client, "login", SVG, "a.svg")
    assert post(client, "/api/apariencia/imagen/login/borrar").status_code == 200
    assert not list(config.BRANDING_DIR.glob("login.*")) and (config.BRANDING_DIR / "logo.png").is_file()
    assert 'src="/branding/logo?v=' in client.application.test_client().get("/login").get_data(as_text=True)


def test_quitar_el_logo_del_sitio_no_toca_el_de_ingreso_y_restablecer_borra_ambos(client):
    upload(client, "logo", PNG)
    upload(client, "login", SVG, "a.svg")
    post(client, "/api/apariencia/imagen/logo/borrar")
    assert (config.BRANDING_DIR / "login.svg").is_file() and not list(config.BRANDING_DIR.glob("logo.*"))
    assert branding.get()["has_login_logo"] and branding.get()["logo_url"] is None
    assert 'class="logo" src="/branding/login?v=' in client.application.test_client().get("/login").get_data(as_text=True)
    post(client, "/api/apariencia/restablecer")
    assert not list(config.BRANDING_DIR.glob("*.*")) and not branding.get()["customized"]


def test_pagina_de_apariencia_ofrece_el_logo_de_ingreso(client):
    page = client.get("/apariencia").get_data(as_text=True)
    assert "Logo de la pantalla de ingreso" in page and 'data-api="/api/apariencia/imagen/login"' in page


def test_ruta_publica_del_logo_de_ingreso_y_permisos(data_dir):
    from takconsole import create_app
    from takconsole.core import auth, users
    from tests.test_roles import login, PW
    auth.set_password(PW)
    users.create("oper", PW, "operator")
    branding.set_image("login", PNG)
    app = create_app()
    assert app.test_client().get("/branding/login").status_code == 200          # público: se ve en el ingreso
    c = login(app, "oper")
    assert c.post("/api/apariencia/imagen/login", headers={"X-CSRF-Token": c.csrf}).status_code == 403
    assert c.post("/api/apariencia/imagen/login/borrar", headers={"X-CSRF-Token": c.csrf}).status_code == 403
