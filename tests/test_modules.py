# SPDX-License-Identifier: Apache-2.0
import os
import shutil
import subprocess

import pytest
import yaml

from takconsole.core import docker
from takconsole.modules import mediamtx, mumble, zerotier

MTX_PARAMS = {"rtsp": True, "rtmp": False, "srt": True, "hls": True, "webrtc": False,
              "publish_user": "publicador", "publish_pass": "pub-pass-123",
              "auth": True, "anonymous_read": False, "read_user": "visor",
              "read_pass": "read-pass-123", "record": True, "record_days": 7, "tls": False}


def test_mediamtx_config_shape():
    cfg = mediamtx.build_config(MTX_PARAMS)
    users = {u["user"]: u for u in cfg["authInternalUsers"] if u["user"] != "any"}
    assert {p["action"] for p in users["publicador"]["permissions"]} == {"publish", "read", "playback"}
    assert {p["action"] for p in users["visor"]["permissions"]} == {"read", "playback"}
    local = [u for u in cfg["authInternalUsers"] if u["user"] == "any"]
    assert local and local[0]["ips"] == ["127.0.0.1", "::1"]
    assert cfg["apiAddress"] == "127.0.0.1:9997"
    assert cfg["rtmp"] is False and cfg["pathDefaults"]["recordDeleteAfter"] == "7d"


NO_AUTH_FORM = {"rtsp": "1", "srt": "1", "hls": "1"}


def test_mediamtx_sin_auth_no_pide_clave_para_publicar_ni_ver():
    cfg = mediamtx.build_config(dict(MTX_PARAMS, auth=False))
    abiertos = [u for u in cfg["authInternalUsers"] if u["ips"] == []]
    assert len(abiertos) == 1
    u = abiertos[0]
    # «any» = cualquier usuario, incluso anónimo; sin contraseña ni restricción de IP
    assert u["user"] == "any" and u["pass"] == ""
    assert {a["action"] for a in u["permissions"]} == {"publish", "read", "playback"}
    # la API, las métricas y pprof siguen limitadas al propio equipo
    local = [x for x in cfg["authInternalUsers"] if x["ips"] == ["127.0.0.1", "::1"]]
    assert len(local) == 1
    assert {a["action"] for a in local[0]["permissions"]} == {"api", "metrics", "pprof"}
    assert not any(x["user"] in ("publicador", "visor") for x in cfg["authInternalUsers"])


def test_mediamtx_sin_clave_en_la_clave_auth_ausente_exige_autenticacion():
    p = dict(MTX_PARAMS)
    del p["auth"]
    cfg = mediamtx.build_config(p)
    assert any(u["user"] == "publicador" for u in cfg["authInternalUsers"])


def test_mediamtx_formulario_por_defecto_es_sin_clave(data_dir):
    p, errors = mediamtx.MediaMTX().validate_deploy(NO_AUTH_FORM)
    assert not errors
    assert p["auth"] is False
    assert p["publish_pass"] == "" and p["read_pass"] == ""
    cfg = mediamtx.build_config(p)
    assert [u["user"] for u in cfg["authInternalUsers"]] == ["any", "any"]


def test_mediamtx_formulario_con_auth_valida_usuarios(data_dir):
    form = dict(NO_AUTH_FORM, auth="1", publish_user="pub", read_user="pub")
    _, errors = mediamtx.MediaMTX().validate_deploy(form)
    assert "read_user" in errors
    form["read_user"] = "visor"
    p, errors = mediamtx.MediaMTX().validate_deploy(form)
    assert not errors and p["auth"] is True and len(p["publish_pass"]) >= 8


@pytest.mark.skipif(not os.environ.get("MEDIAMTX_BIN"), reason="define MEDIAMTX_BIN para validar")
def test_mediamtx_config_validates_with_real_binary(tmp_path):
    for tls in (False, True):
        p = dict(MTX_PARAMS, anonymous_read=tls)
        cfg = mediamtx.build_config(p, tls=tls)
        if tls:
            cfg["rtspServerKey"] = str(tmp_path / "k")
            cfg["rtspServerCert"] = str(tmp_path / "c")
        path = tmp_path / "mediamtx.yml"
        path.write_text(yaml.safe_dump(cfg, sort_keys=False))
        res = subprocess.run([os.environ["MEDIAMTX_BIN"], f"--validate-conf={path}"],
                             capture_output=True, text=True)
        assert res.returncode == 0, res.stdout + res.stderr
    # sin autenticación
    cfg = mediamtx.build_config(dict(MTX_PARAMS, auth=False))
    path = tmp_path / "sin-auth.yml"
    path.write_text(yaml.safe_dump(cfg, sort_keys=False))
    res = subprocess.run([os.environ["MEDIAMTX_BIN"], f"--validate-conf={path}"],
                         capture_output=True, text=True)
    assert res.returncode == 0, res.stdout + res.stderr


def test_mumble_env_quotes_text():
    p = {"superuser_pass": "su-pass-123", "max_users": 20, "register_name": "Red TAK",
         "welcome": "Hola, equipo", "server_pass": "", "tls": True}
    env = mumble.env_values(p, tls=True)
    assert env["MUMBLE_CONFIG_WELCOMETEXT"] == '"Hola, equipo"'
    assert env["MUMBLE_CONFIG_REGISTER_NAME"] == '"Red TAK"'
    assert env["MUMBLE_CONFIG_SSL_CERT"] == "/data/tls/server.crt"


def test_env_file_single_quoted(tmp_path):
    docker.write_env(tmp_path / "x.env", {"A": "1", "B": 'con "comillas" y $dolar'})
    assert (tmp_path / "x.env").read_text() == "A='1'\nB='con \"comillas\" y $dolar'\n"
    assert oct((tmp_path / "x.env").stat().st_mode & 0o777) == "0o600"
    with pytest.raises(ValueError):
        docker.write_env(tmp_path / "y.env", {"A": "it's"})


@pytest.mark.parametrize("mod", [mediamtx, mumble, zerotier])
def test_compose_uses_host_network_or_loopback(mod, data_dir):
    data = mod.compose_data()
    for name, svc in data["services"].items():
        if svc.get("network_mode") == "host":
            assert "ports" not in svc
        else:
            # Docker se salta UFW: lo publicado fuera de host network debe ir a 127.0.0.1
            assert all(p.startswith("127.0.0.1:") for p in svc.get("ports", [])), name
        assert ":" in svc["image"] and not svc["image"].endswith(":latest")


@pytest.mark.skipif(not shutil.which("docker"), reason="requiere docker compose")
@pytest.mark.parametrize("mod,envname,env", [
    (mumble, "mumble.env", {"MUMBLE_CONFIG_WELCOMETEXT": '"Hola, equipo $x"'}),
    (zerotier, "ztnet.env", {"POSTGRES_PASSWORD": "abc"}),
    (mediamtx, None, None),
])
def test_compose_config_is_valid(mod, envname, env, tmp_path, data_dir):
    docker.write_compose(tmp_path, mod.compose_data())
    if envname:
        docker.write_env(tmp_path / envname, env)
    res = subprocess.run(["docker", "compose", "--project-directory", str(tmp_path), "-f",
                          str(tmp_path / "compose.yaml"), "config", "--format", "json"],
                         capture_output=True, text=True)
    if "Cannot connect" in res.stderr:
        pytest.skip("sin demonio de Docker")
    assert res.returncode == 0, res.stderr
    if envname == "mumble.env":
        import json
        cfg = json.loads(res.stdout)
        # compose representa un $ literal como $$ (no se interpoló)
        assert cfg["services"]["mumble"]["environment"]["MUMBLE_CONFIG_WELCOMETEXT"] == '"Hola, equipo $$x"'


def test_zerotier_root_mode():
    assert zerotier.root_mode([{"address": "62f865ae71"}]) == "publicas"
    assert zerotier.root_mode([{"address": "abcdef0123"}]) == "privada"
    assert zerotier.root_mode([]) == "desconocido"


def test_ztnet_env_contains_secrets_and_urls():
    env = zerotier.ztnet_env({"pg_password": "p" * 48, "nextauth_secret": "s" * 64},
                             "https://10.0.0.5:3443")
    assert env["NEXTAUTH_URL"] == "https://10.0.0.5:3443"
    assert env["ZT_ADDR"] == "http://127.0.0.1:9993"
    assert env["HOSTNAME"] == "127.0.0.1"
