# SPDX-License-Identifier: Apache-2.0
import json
import shutil
import subprocess

import pytest
import yaml
from werkzeug.datastructures import MultiDict

from takconsole.core import docker, system
from takconsole.core.jobs import Job, JobFailed
from takconsole.modules import jitsi

IPS = ["10.147.17.5", "192.168.10.130"]
P = {"host": "10.147.17.5", "https_port": 443, "bind_ips": ["10.147.17.5"], "tz": "America/Santiago",
     "tls": False, "stun": False}


@pytest.fixture
def ips(monkeypatch):
    monkeypatch.setattr(jitsi, "local_ipv4", lambda: list(IPS))
    monkeypatch.setattr(system, "listening_ports", lambda: set())
    return IPS


def form(**kw):
    data = MultiDict(kw.pop("_multi", []))
    for k, v in kw.items():
        data.add(k, v)
    return data


# ── compose ────────────────────────────────────────────────────────────────
def test_compose_publica_solo_en_las_ip_elegidas(data_dir):
    d = jitsi.compose_data(dict(P, bind_ips=IPS))
    assert set(d["services"]) == {"web", "prosody", "jicofo", "jvb"}
    # Docker se salta UFW: nada publicado sin IP explícita (ni en 0.0.0.0 ni «puerto:puerto»)
    for name, svc in d["services"].items():
        for port in svc.get("ports", []):
            ip = port.split(":")[0]
            assert ip in IPS + ["127.0.0.1"], (name, port)
    assert d["services"]["web"]["ports"] == [f"{ip}:443:8443" for ip in IPS]
    assert d["services"]["jvb"]["ports"] == (
        [f"{ip}:10000:10000/udp" for ip in IPS] + ["127.0.0.1:18080:8080"])
    # el XMPP y la API de Jicofo no salen del equipo
    assert "ports" not in d["services"]["prosody"] and "ports" not in d["services"]["jicofo"]


def test_compose_imagenes_fijas_y_nombres_propios(data_dir):
    d = jitsi.compose_data(P)
    for name, svc in d["services"].items():
        assert svc["image"] == f"ghcr.io/jitsi/{name}:{jitsi.RELEASE}"
        assert not svc["image"].endswith((":latest", ":unstable"))
        assert svc["container_name"] == f"tak-console-jitsi-{name}"
    assert d["name"] == "tak-console-jitsi"


def test_compose_no_modifica_el_oficial(data_dir):
    antes = json.dumps(jitsi._upstream(), sort_keys=True)
    jitsi.compose_data(dict(P, bind_ips=IPS))
    assert json.dumps(jitsi._upstream(), sort_keys=True) == antes


def test_compose_oficial_conserva_la_estructura_esperada():
    up = jitsi._upstream()
    # si al actualizar la versión esto cambia, hay que revisar compose_data()
    assert list(up["services"]) == ["web", "prosody", "jicofo", "jvb"]
    assert up["services"]["web"]["ports"] == ["${HTTP_PORT}:8000", "${HTTPS_PORT}:8443"]
    assert any("10000" in p for p in up["services"]["jvb"]["ports"])
    assert up["services"]["prosody"].get("ports") is None
    assert "COLIBRI_REST_ENABLED" in up["services"]["jvb"]["environment"]
    assert "JVB_DISABLE_STUN" in up["services"]["jvb"]["environment"]


@pytest.mark.skipif(not shutil.which("docker"), reason="requiere docker compose")
def test_compose_valido_y_toma_las_variables_del_env(tmp_path, data_dir):
    p = dict(P, bind_ips=IPS, https_port=8445)
    docker.write_compose(tmp_path, jitsi.compose_data(p))
    docker.write_env(tmp_path / ".env", jitsi.env_values(p))
    res = subprocess.run(["docker", "compose", "--project-directory", str(tmp_path), "-f",
                          str(tmp_path / "compose.yaml"), "config", "--format", "json"],
                         capture_output=True, text=True)
    if "Cannot connect" in res.stderr:
        pytest.skip("sin demonio de Docker")
    assert res.returncode == 0, res.stderr
    cfg = json.loads(res.stdout)
    web = cfg["services"]["web"]
    assert web["environment"]["PUBLIC_URL"] == "https://10.147.17.5:8445"
    jvb = cfg["services"]["jvb"]
    assert jvb["environment"]["JVB_ADVERTISE_IPS"] == ",".join(IPS)
    assert jvb["environment"]["COLIBRI_REST_ENABLED"] == "true"
    assert jvb["environment"]["JVB_DISABLE_STUN"] == "true"
    published = [(x["host_ip"], x["published"], x["protocol"]) for x in jvb["ports"]]
    assert ("127.0.0.1", "18080", "tcp") in published and ("10.147.17.5", "10000", "udp") in published
    assert [(x["host_ip"], x["published"]) for x in web["ports"]] == [(ip, "8445") for ip in IPS]
    # los volúmenes salen de CONFIG, no de una ruta de otro usuario
    assert any(str(jitsi.config_dir()) in v["source"] for v in web["volumes"])
    for svc in ("prosody", "jicofo"):
        for secret in ("JICOFO_AUTH_PASSWORD", "JVB_AUTH_PASSWORD"):
            val = cfg["services"][svc]["environment"].get(secret)
            if val is not None:
                assert len(val) == 32


# ── .env ───────────────────────────────────────────────────────────────────
def test_env_values(data_dir):
    env = jitsi.env_values(P)
    assert env["PUBLIC_URL"] == "https://10.147.17.5"
    assert env["JVB_ADVERTISE_IPS"] == "10.147.17.5"
    assert env["JVB_DISABLE_STUN"] == "true"
    assert env["COLIBRI_REST_ENABLED"] == "true"
    for name in jitsi.SECRET_NAMES:
        assert len(env[name]) == 32 and int(env[name], 16) >= 0
    assert len({env[n] for n in jitsi.SECRET_NAMES}) == len(jitsi.SECRET_NAMES)


def test_env_stun_permitido_y_puerto_en_la_url(data_dir):
    env = jitsi.env_values(dict(P, stun=True, https_port=8445, bind_ips=IPS))
    assert "JVB_DISABLE_STUN" not in env
    assert env["PUBLIC_URL"] == "https://10.147.17.5:8445"
    assert env["JVB_ADVERTISE_IPS"] == "10.147.17.5,192.168.10.130"


def test_env_reutiliza_contrasenas(data_dir):
    fijas = {n: "ab" * 16 for n in jitsi.SECRET_NAMES}
    assert jitsi.env_values(P, fijas)["JVB_AUTH_PASSWORD"] == "ab" * 16


# ── validación del formulario ──────────────────────────────────────────────
def test_formulario_valido(data_dir, ips):
    p, errors = jitsi.Jitsi().validate_deploy(form(host="10.147.17.5", https_port="443",
                                                   bind_ip="10.147.17.5", tz="America/Santiago"))
    assert not errors
    assert p["bind_ips"] == ["10.147.17.5"] and p["https_port"] == 443
    assert p["tls"] is False and p["stun"] is False


def test_formulario_varias_ip_y_sin_duplicados(data_dir, ips):
    data = MultiDict([("host", "meet.red.local"), ("bind_ip", IPS[0]), ("bind_ip", IPS[1]),
                      ("bind_ip", IPS[0])])
    p, errors = jitsi.Jitsi().validate_deploy(data)
    assert not errors and p["bind_ips"] == IPS and p["host"] == "meet.red.local"


def test_formulario_acepta_diccionario_simple(data_dir, ips):
    p, errors = jitsi.Jitsi().validate_deploy({"host": IPS[0], "bind_ip": IPS[0]})
    assert not errors and p["bind_ips"] == [IPS[0]]


@pytest.mark.parametrize("host", ["", "999.1.1.1", "a b", "meet;rm -rf", "https://x", "-x.com", "x_y",
                                  "10.0.0", "a" * 300])
def test_formulario_rechaza_direcciones_invalidas(data_dir, ips, host):
    data = MultiDict([("host", host), ("bind_ip", IPS[0])])
    if host == "":
        # vacía: se usa la primera IP del servidor, no es un error
        _, errors = jitsi.Jitsi().validate_deploy(data)
        assert "host" not in errors
    else:
        _, errors = jitsi.Jitsi().validate_deploy(data)
        assert "host" in errors


def test_formulario_exige_ip_del_equipo(data_dir, ips):
    _, errors = jitsi.Jitsi().validate_deploy(form(host=IPS[0]))
    assert "bind_ip" in errors
    _, errors = jitsi.Jitsi().validate_deploy(form(host=IPS[0], bind_ip="8.8.8.8"))
    assert "bind_ip" in errors
    _, errors = jitsi.Jitsi().validate_deploy(form(host=IPS[0], bind_ip="0.0.0.0"))
    assert "bind_ip" in errors


@pytest.mark.parametrize("port,ok", [("443", True), ("8445", True), ("0", False), ("70000", False),
                                     ("abc", False)])
def test_formulario_puerto(data_dir, ips, port, ok):
    _, errors = jitsi.Jitsi().validate_deploy(form(host=IPS[0], bind_ip=IPS[0], https_port=port))
    assert ("https_port" not in errors) is ok


def test_formulario_puerto_ocupado(data_dir, ips, monkeypatch):
    monkeypatch.setattr(system, "listening_ports", lambda: {(443, "tcp")})
    _, errors = jitsi.Jitsi().validate_deploy(form(host=IPS[0], bind_ip=IPS[0]))
    assert "https_port" in errors and "en uso" in errors["https_port"]
    # al reaplicar con el mismo puerto, lo ocupa el propio Jitsi: no es un conflicto
    j = jitsi.Jitsi()
    j.save_state(installed=True, params=P)
    _, errors = j.validate_deploy(form(host=IPS[0], bind_ip=IPS[0]))
    assert "https_port" not in errors
    # pero si cambia a otro puerto que sí está ocupado, se avisa
    monkeypatch.setattr(system, "listening_ports", lambda: {(8445, "tcp")})
    _, errors = j.validate_deploy(form(host=IPS[0], bind_ip=IPS[0], https_port="8445"))
    assert "https_port" in errors


def test_formulario_tls_necesita_la_ca_de_tak(data_dir, ips, monkeypatch):
    monkeypatch.setattr(jitsi.certs, "tak_ca_available", lambda: False)
    _, errors = jitsi.Jitsi().validate_deploy(form(host=IPS[0], bind_ip=IPS[0], tls="1"))
    assert "tls" in errors
    monkeypatch.setattr(jitsi.certs, "tak_ca_available", lambda: True)
    p, errors = jitsi.Jitsi().validate_deploy(form(host=IPS[0], bind_ip=IPS[0], tls="1"))
    assert not errors and p["tls"] is True


def test_formulario_zona_horaria(data_dir, ips):
    _, errors = jitsi.Jitsi().validate_deploy(form(host=IPS[0], bind_ip=IPS[0], tz="UTC; ls"))
    assert "tz" in errors


# ── estado ─────────────────────────────────────────────────────────────────
def test_estado_no_instalado(data_dir):
    st = jitsi.Jitsi().status()
    assert st["installed"] is False and st["level"] == "off"


def _estados(monkeypatch, corriendo):
    def fake(name):
        svc = name.rsplit("-", 1)[-1]
        run = svc in corriendo
        return {"exists": True, "running": run, "status": "running" if run else "exited", "health": None}
    monkeypatch.setattr(docker, "container_state", fake)


def test_estado_segun_contenedores(data_dir, monkeypatch):
    j = jitsi.Jitsi()
    j.save_state(installed=True, params=P)
    _estados(monkeypatch, set(jitsi.SERVICES))
    assert j.status()["level"] == "ok" and j.status()["running"] is True
    _estados(monkeypatch, {"web", "jvb"})
    st = j.status()
    assert st["level"] == "warn" and "2 de 4" in st["label"]
    _estados(monkeypatch, set())
    assert j.status()["level"] == "err"


def test_sin_reglas_de_ufw(data_dir):
    assert jitsi.Jitsi().ports() == []


def test_conectados_con_cifras_del_videopuente(data_dir, monkeypatch):
    monkeypatch.setattr(jitsi, "stats", lambda: {"conferences": 2, "endpoints": 5, "participants": 5})
    t = jitsi.Jitsi().connected()
    assert t["rows"] == [["Conferencias activas", "2"], ["Participantes", "5"]]


def test_conectados_si_el_videopuente_no_responde(data_dir, monkeypatch):
    def boom():
        raise OSError("connection refused")
    monkeypatch.setattr(jitsi, "stats", boom)
    t = jitsi.Jitsi().connected()
    assert t["rows"] == [] and "no respondió" in t["error"]


def test_registros_por_componente(data_dir, monkeypatch):
    pedidos = []
    monkeypatch.setattr(docker, "logs", lambda name, n: pedidos.append(name) or "a\nb")
    j = jitsi.Jitsi()
    assert [i for i, _ in j.log_sources()][0] == "jicofo"
    assert j.log_lines(10, "jvb") == ["a", "b"]
    j.log_lines(10, "inventado")      # fuente desconocida: no se pasa a Docker tal cual
    assert pedidos == ["tak-console-jitsi-jvb", "tak-console-jitsi-jicofo"]


# ── despliegue (sin Docker real) ───────────────────────────────────────────
class FakeDocker:
    def __init__(self, monkeypatch):
        self.calls = []
        monkeypatch.setattr(docker, "available", lambda: True)
        monkeypatch.setattr(docker, "compose", lambda d, *a, **k: self.calls.append(a))


def _job():
    return Job("jitsi", "prueba")


def test_despliegue_sin_docker_falla_con_mensaje(data_dir, monkeypatch):
    monkeypatch.setattr(docker, "available", lambda: False)
    with pytest.raises(JobFailed, match="Docker"):
        jitsi.Jitsi().deploy(_job(), dict(P))


def test_despliegue_escribe_archivos_privados(data_dir, monkeypatch):
    fake = FakeDocker(monkeypatch)
    j = jitsi.Jitsi()
    job = _job()
    j.deploy(job, dict(P, bind_ips=IPS))
    d = jitsi.stack_dir()
    assert oct((d / ".env").stat().st_mode & 0o777) == "0o600"
    assert oct((d / "compose.yaml").stat().st_mode & 0o777) == "0o600"
    data = yaml.safe_load((d / "compose.yaml").read_text())
    assert data["services"]["web"]["ports"] == [f"{ip}:443:8443" for ip in IPS]
    for sub in jitsi.CONFIG_DIRS:
        assert (jitsi.config_dir() / sub).is_dir(), sub
    assert fake.calls == [("pull",), ("up", "-d", "--force-recreate")]
    st = j.state()
    assert st["installed"] is True and st["params"]["bind_ips"] == IPS
    text = "\n".join(job.lines)
    assert "UFW" in text                                   # avisa que el firewall no aplica
    assert (d / ".env").read_text().count("_PASSWORD=") == len(jitsi.SECRET_NAMES)
    for line in (d / ".env").read_text().splitlines():     # contraseñas nunca en el registro
        k, _, v = line.partition("=")
        if k.endswith("_PASSWORD"):
            assert v.strip("'") not in text


def test_redespliegue_conserva_contrasenas(data_dir, monkeypatch):
    FakeDocker(monkeypatch)
    j = jitsi.Jitsi()
    j.deploy(_job(), dict(P))
    antes = (jitsi.stack_dir() / ".env").read_text()
    j.deploy(_job(), dict(P, https_port=8445))
    despues = (jitsi.stack_dir() / ".env").read_text()
    pw = lambda t: {ln.split("=")[0]: ln for ln in t.splitlines() if "_PASSWORD" in ln}  # noqa: E731
    assert pw(antes) == pw(despues) and len(pw(antes)) == 6
    assert "PUBLIC_URL='https://10.147.17.5:8445'" in despues


def test_sin_tls_quita_certificados_anteriores(data_dir, monkeypatch):
    FakeDocker(monkeypatch)
    cfg = jitsi.config_dir()
    for base in (cfg / "web" / "keys", cfg / "storage" / "web" / "keys"):
        base.mkdir(parents=True)
        (base / "cert.crt").write_text("viejo")
        (base / "cert.key").write_text("viejo")
    jitsi.Jitsi().deploy(_job(), dict(P))
    assert not list(cfg.glob("**/cert.*"))


def test_con_tls_firma_con_la_ca_de_tak(data_dir, monkeypatch):
    FakeDocker(monkeypatch)
    llamadas = {}

    def fake_sign(cn, hosts, out_dir, ca_pass, log=None, days=730):
        out_dir.mkdir(parents=True, exist_ok=True)
        (out_dir / "server.crt").write_text("CERT\n")
        (out_dir / "server.key").write_text("KEY\n")
        (out_dir / "chain.pem").write_text("CHAIN\n")
        llamadas.update(cn=cn, hosts=list(hosts))
        return {"cert": out_dir / "server.crt", "key": out_dir / "server.key",
                "chain": out_dir / "chain.pem"}
    monkeypatch.setattr(jitsi.certs, "sign_with_tak_ca", fake_sign)
    jitsi.Jitsi().deploy(_job(), dict(P, tls=True, host="meet.red.local", bind_ips=IPS))
    keys = jitsi.config_dir() / "web" / "keys"
    assert (keys / "cert.crt").read_text() == "CERT\nCHAIN\n"
    assert (keys / "cert.key").read_text() == "KEY\n"
    assert oct((keys / "cert.key").stat().st_mode & 0o777) == "0o600"
    assert llamadas["hosts"] == ["meet.red.local", *IPS]
    assert not (jitsi.stack_dir() / "tls").exists()        # sin restos de la firma


def test_desinstalar_conserva_la_configuracion(data_dir, monkeypatch):
    FakeDocker(monkeypatch)
    j = jitsi.Jitsi()
    j.deploy(_job(), dict(P))
    j.uninstall(_job(), {})
    assert j.state()["installed"] is False
    assert jitsi.config_dir().is_dir()


def test_acciones_de_control(data_dir):
    assert set(jitsi.Jitsi().actions()) == {"start", "stop", "restart"}


# ── diseño de la página de inicio ──────────────────────────────────────────
TP = dict(P, theme=True, app_name="Tactical VCO", subtitle="Sistema de Video Conferencia Tactica")


def test_tema_archivos_solo_ascii_y_con_el_nombre(data_dir):
    files = jitsi.theme_files(TP)
    assert set(files) == set(jitsi.THEME_FILES)
    assert files["web/custom-interface_config.js"].splitlines()[-1] == 'interfaceConfig.APP_NAME = "Tactical VCO";'
    for text in files.values():
        assert text.isascii()
    css = json.loads(files["web/custom-config.js"].split("s.textContent = ")[1].split(";\n")[0])
    assert 'content: "Tactical VCO";' in css
    assert 'content: "Sistema de Video Conferencia Tactica";' in css
    assert "__TITLE__" not in css and "__SUBTITLE__" not in css


def test_tema_escapa_tildes_para_css(data_dir):
    p = dict(TP, subtitle="Videoconferencia Táctica", app_name="Ñandú")
    files = jitsi.theme_files(p)
    css = json.loads(files["web/custom-config.js"].split("s.textContent = ")[1].split(";\n")[0])
    assert 'content: "Videoconferencia T\\E1 ctica";' in css      # \E1 + espacio = «á»
    assert 'content: "\\D1 and\\FA ";' in css
    assert json.loads(files["web/custom-interface_config.js"].split("= ")[1].rstrip(";\n")) == "Ñandú"


def test_tema_css_solo_toca_la_pagina_de_bienvenida():
    import re
    css = jitsi.THEME_CSS.read_text(encoding="utf-8")
    css = re.sub(r"/\*.*?\*/", "", css, flags=re.S)
    selectors = [s.strip() for block in re.findall(r"([^{}]+)\{", css) for s in block.split(",")]
    assert selectors
    # nada fuera de body.welcome-page: la sala de reunión conserva su aspecto
    assert all(s.startswith("body.welcome-page") for s in selectors), \
        [s for s in selectors if not s.startswith("body.welcome-page")]
    # monocromático: ningún color con matiz (cada #rgb/#rrggbb con r=g=b) ni rgba con canales distintos
    for hexv in re.findall(r"#([0-9a-fA-F]{6})\b", css):
        assert hexv[0:2] == hexv[2:4] == hexv[4:6], hexv
    for r, g, b in re.findall(r"rgba?\((\d+),\s*(\d+),\s*(\d+)", css):
        assert r == g == b


@pytest.mark.skipif(not shutil.which("node"), reason="requiere node")
def test_tema_javascript_valido(tmp_path, data_dir):
    for rel, text in jitsi.theme_files(TP).items():
        f = tmp_path / rel.replace("/", "_")
        f.write_text(text)
        res = subprocess.run(["node", "--check", str(f)], capture_output=True, text=True)
        assert res.returncode == 0, res.stderr


@pytest.mark.parametrize("campo", ["app_name", "subtitle"])
@pytest.mark.parametrize("valor", ['a"b', "a'b", "a\\b", "a<b", "a>b", "a;b", "a{b}", "x" * 61, "a\nb",
                                   "</style><script>"])
def test_tema_rechaza_texto_peligroso(data_dir, ips, campo, valor):
    data = form(host=IPS[0], bind_ip=IPS[0], theme="1")
    data[campo] = valor
    _, errors = jitsi.Jitsi().validate_deploy(data)
    assert campo in errors


def test_tema_acepta_tildes_y_signos_simples(data_dir, ips):
    data = form(host=IPS[0], bind_ip=IPS[0], theme="1")
    data["app_name"], data["subtitle"] = "Tactical VCO (Ñ)", "Sistema de Video Conferencia Táctica, 2.0"
    p, errors = jitsi.Jitsi().validate_deploy(data)
    assert not errors and p["theme"] is True and p["app_name"] == "Tactical VCO (Ñ)"


def test_tema_por_defecto_y_sin_tema(data_dir, ips):
    p, errors = jitsi.Jitsi().validate_deploy(form(host=IPS[0], bind_ip=IPS[0], theme="1"))
    assert not errors and (p["app_name"], p["subtitle"]) == (jitsi.DEFAULT_APP_NAME, jitsi.DEFAULT_SUBTITLE)
    p, errors = jitsi.Jitsi().validate_deploy(form(host=IPS[0], bind_ip=IPS[0]))
    assert not errors and p["theme"] is False


def test_despliegue_escribe_y_quita_el_tema(data_dir, monkeypatch):
    FakeDocker(monkeypatch)
    j = jitsi.Jitsi()
    j.deploy(_job(), dict(TP))
    cfg = jitsi.config_dir()
    for rel in jitsi.THEME_FILES:
        assert oct((cfg / rel).stat().st_mode & 0o777) == "0o644"   # no son secretos
        assert (cfg / rel).read_text().isascii()
    assert "Tactical VCO" in (cfg / "web/custom-interface_config.js").read_text()
    j.deploy(_job(), dict(TP, theme=False))
    assert not any((cfg / rel).exists() for rel in jitsi.THEME_FILES)
    j.deploy(_job(), dict(P))                  # parámetros de una instalación anterior, sin claves de tema
    assert not any((cfg / rel).exists() for rel in jitsi.THEME_FILES)


def test_pagina_del_modulo_muestra_el_diseno(client):
    html = client.get("/m/jitsi").get_data(as_text=True)
    assert 'name="theme"' in html and 'name="app_name"' in html and 'name="subtitle"' in html
    assert "Tactical VCO" in html


# ── diagnóstico del diseño ─────────────────────────────────────────────────
class _Res:
    def __init__(self, ok, output=""):
        self.ok, self.output = ok, output


def _diseno(checks):
    return [c for c in checks if c["label"] == "Diseño de la página"]


def test_diagnostico_instalacion_anterior_sin_tema(data_dir, monkeypatch):
    _estados(monkeypatch, set(jitsi.SERVICES))
    monkeypatch.setattr(system, "listening_ports", lambda: set())
    j = jitsi.Jitsi()
    j.save_state(installed=True, params=P)             # sin la clave «theme»
    (c,) = _diseno(j.checks())
    assert c["ok"] is False and "Aplicar configuración" in c["detail"]


def test_diagnostico_tema_desactivado_no_aparece(data_dir, monkeypatch):
    _estados(monkeypatch, set(jitsi.SERVICES))
    monkeypatch.setattr(system, "listening_ports", lambda: set())
    j = jitsi.Jitsi()
    j.save_state(installed=True, params=dict(P, theme=False))
    assert _diseno(j.checks()) == []


def test_diagnostico_tema_en_disco_y_en_el_contenedor(data_dir, monkeypatch):
    _estados(monkeypatch, set(jitsi.SERVICES))
    monkeypatch.setattr(system, "listening_ports", lambda: set())
    j = jitsi.Jitsi()
    j.save_state(installed=True, params=dict(TP))
    (c,) = _diseno(j.checks())                          # sin archivos
    assert c["ok"] is False and "falta custom-config.js" in c["detail"]
    f = jitsi.config_dir() / jitsi.THEME_FILES[1]
    f.parent.mkdir(parents=True)
    f.write_text("x")
    pedidos = []
    monkeypatch.setattr(docker, "exec_", lambda *a, **k: pedidos.append(a) or _Res(True, "0\n"))
    (c,) = _diseno(j.checks())                          # en disco, pero el contenedor no lo cargó
    assert c["ok"] is False and "no lo cargó" in c["detail"]
    assert pedidos[0][0] == "tak-console-jitsi-web" and "/run/web/config/config.js" in pedidos[0]
    monkeypatch.setattr(docker, "exec_", lambda *a, **k: _Res(True, "1\n"))
    (c,) = _diseno(j.checks())
    assert c["ok"] is True


def test_subtitulo_por_defecto_con_tilde():
    assert jitsi.DEFAULT_SUBTITLE == "Sistema de Video Conferencia Táctica"


def test_tema_oculta_el_logotipo_de_jitsi():
    css = jitsi.THEME_CSS.read_text(encoding="utf-8")
    assert "body.welcome-page .welcome .header-watermark-container { display: none; }" in css
