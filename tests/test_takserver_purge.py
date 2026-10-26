# SPDX-License-Identifier: Apache-2.0
"""Borrado de los datos que deja TAK Server tras desinstalarlo."""
import os
import stat
import tarfile
from pathlib import Path

import pytest

from takconsole import config
from takconsole.core import settings
from takconsole.core.jobs import JobFailed
from takconsole.core.shell import Result
from takconsole.modules import takserver

import time

from takconsole.core.jobs import JOBS

FIXTURES = Path(__file__).parent / "fixtures"
HDR = lambda c: {"X-CSRF-Token": c.csrf}  # noqa: E731


class FakeJob:
    def __init__(self):
        self.lines = []

    def log(self, msg):
        self.lines.append(("log", msg))

    def step(self, n, total, title):
        self.lines.append(("step", title))

    def ok(self, msg):
        self.lines.append(("ok", msg))

    def warn(self, msg):
        self.lines.append(("warn", msg))

    def texts(self):
        return "\n".join(m for _, m in self.lines)


def wait_job(key, timeout=5):
    end = time.time() + timeout
    while time.time() < end:
        j = JOBS.get(key)
        if j and j.status != "running":
            return j
        time.sleep(0.05)
    raise AssertionError("la tarea no terminó")


def test_coreconfig_db_lee_base_rol_y_puerto():
    info = takserver.coreconfig_db((FIXTURES / "CoreConfig.sample.xml").read_text())
    assert info == {"name": "cot", "role": "martiuser", "port": 5432}


def test_coreconfig_db_otro_puerto_y_nombre():
    xml = '<x><connection url="jdbc:postgresql://127.0.0.1:5433/mi_bd" username="otro" password="p"/></x>'
    assert takserver.coreconfig_db(xml) == {"name": "mi_bd", "role": "otro", "port": 5433}


def test_coreconfig_db_sin_conexion_usa_valores_de_tak():
    assert takserver.coreconfig_db("<x/>") == takserver.DB_DEFAULTS


@pytest.mark.parametrize("info", [
    {"name": "postgres", "role": "martiuser", "port": 5432},
    {"name": "Template1", "role": "martiuser", "port": 5432},
    {"name": 'cot"; DROP DATABASE x; --', "role": "martiuser", "port": 5432},
    {"name": "cot", "role": "postgres", "port": 5432},
    {"name": "cot", "role": "a b", "port": 5432},
    {"name": "cot", "role": "martiuser", "port": 0},
])
def test_check_db_info_rechaza_nombres_peligrosos(info):
    with pytest.raises(ValueError):
        takserver.check_db_info(info)


def test_check_db_info_acepta_los_de_tak():
    takserver.check_db_info(dict(takserver.DB_DEFAULTS))


@pytest.fixture()
def tak(tmp_path, data_dir, monkeypatch):
    """/opt/tak falso, sin PostgreSQL real; registra cada comando ejecutado."""
    home = tmp_path / "opt" / "tak"
    (home / "certs" / "files").mkdir(parents=True)
    (home / "certs" / "files" / "ca.pem").write_text("CA")
    (home / "conf").mkdir()
    (home / "logs").mkdir()
    (home / "logs" / "gordo.log").write_text("x" * 100)
    (home / "CoreConfig.xml").write_text((FIXTURES / "CoreConfig.sample.xml").read_text())
    (home / "CoreConfig.xml.bak").write_text("bak")
    monkeypatch.setattr(takserver, "TAK_HOME", home)
    monkeypatch.setattr(takserver, "CORECONFIG", home / "CoreConfig.xml")
    monkeypatch.setattr(config, "DRY_RUN", False)
    calls = []

    def fake_run(argv, **kw):
        calls.append([str(a) for a in argv])
        return Result(0, "")

    monkeypatch.setattr(takserver, "run", fake_run)
    monkeypatch.setattr(takserver, "which", lambda n: "/usr/bin/" + n)
    monkeypatch.setattr(takserver, "capture", lambda argv, **kw: Result(1, ""))
    monkeypatch.setattr(takserver.system, "listening_ports", lambda: set())
    return home, calls


def test_purge_borra_base_rol_y_archivos_en_orden(tak):
    home, calls = tak
    job = FakeJob()
    takserver.TakServer()._purge(job, backup=False, uploads=False)
    sql = [c[-1] for c in calls if "psql" in c]
    assert sql == ['DROP DATABASE IF EXISTS "cot" WITH (FORCE)', 'DROP ROLE IF EXISTS "martiuser"']
    assert all(c[:4] == ["runuser", "-u", "postgres", "--"] for c in calls)
    assert not home.exists()
    assert not (config.DATA_DIR / "backups").exists()
    assert "Respaldo omitido" in job.texts()


def test_purge_respaldo_privado_y_solo_lo_necesario(tak):
    home, _ = tak
    takserver.TakServer()._purge(FakeJob(), backup=True, uploads=False)
    backups = list((config.DATA_DIR / "backups").glob("takserver-*.tar.gz"))
    assert len(backups) == 1
    assert stat.S_IMODE(os.stat(backups[0]).st_mode) == 0o600
    assert stat.S_IMODE(os.stat(backups[0].parent).st_mode) == 0o700
    with tarfile.open(backups[0]) as tar:
        names = tar.getnames()
    assert "tak/certs/files/ca.pem" in names
    assert "tak/CoreConfig.xml" in names and "tak/CoreConfig.xml.bak" in names
    assert not any("gordo.log" in n for n in names)


def test_purge_no_borra_si_el_respaldo_falla(tak, monkeypatch):
    home, calls = tak

    def boom(self, job):
        raise OSError("disco lleno")

    monkeypatch.setattr(takserver.TakServer, "_backup", boom)
    with pytest.raises(OSError):
        takserver.TakServer()._purge(FakeJob(), backup=True, uploads=False)
    assert home.exists() and not calls


def test_purge_falla_y_conserva_archivos_si_no_se_puede_borrar_la_base(tak, monkeypatch):
    home, _ = tak
    from takconsole.core.shell import CommandError

    def fake_run(argv, **kw):
        if "DROP DATABASE" in str(argv[-1]):
            raise CommandError(argv, 1, "ERROR: permission denied")
        return Result(0, "")

    monkeypatch.setattr(takserver, "run", fake_run)
    with pytest.raises(JobFailed):
        takserver.TakServer()._purge(FakeJob(), backup=False, uploads=False)
    assert home.exists()


def test_purge_fallo_al_borrar_el_rol_solo_avisa(tak, monkeypatch):
    home, _ = tak
    from takconsole.core.shell import CommandError

    def fake_run(argv, **kw):
        if "DROP ROLE" in str(argv[-1]):
            raise CommandError(argv, 1, "role owns objects")
        return Result(0, "")

    monkeypatch.setattr(takserver, "run", fake_run)
    job = FakeJob()
    takserver.TakServer()._purge(job, backup=False, uploads=False)
    assert not home.exists()
    assert any(k == "warn" and "rol" in m for k, m in job.lines)


def test_purge_se_niega_con_base_ajena(tak):
    home, calls = tak
    (home / "CoreConfig.xml").write_text(
        '<c><connection url="jdbc:postgresql://127.0.0.1/postgres" username="martiuser"/></c>')
    with pytest.raises(JobFailed):
        takserver.TakServer()._purge(FakeJob(), backup=False, uploads=False)
    assert home.exists() and not calls


def test_purge_se_niega_si_tak_sigue_instalado(tak, monkeypatch):
    home, calls = tak
    monkeypatch.setattr(takserver.TakServer, "package_version", lambda self: "5.8-RELEASE92")
    with pytest.raises(JobFailed):
        takserver.TakServer()._purge(FakeJob(), backup=False, uploads=False)
    assert home.exists() and not calls


def test_purge_se_niega_si_los_puertos_estan_ocupados(tak, monkeypatch):
    monkeypatch.setattr(takserver.system, "listening_ports", lambda: {(8089, "tcp")})
    assert any("8089" in b for b in takserver.TakServer().purge_blockers())


def test_purge_se_niega_con_enlace_simbolico(tak, tmp_path):
    home, calls = tak
    real = tmp_path / "otro"
    home.rename(real)
    home.symlink_to(real)
    assert takserver.TakServer().purge_blockers()
    with pytest.raises(JobFailed):
        takserver.TakServer()._purge(FakeJob(), backup=False, uploads=False)
    assert real.exists() and not calls


def test_purge_sin_postgresql_solo_avisa(tak, monkeypatch):
    home, calls = tak
    monkeypatch.setattr(takserver, "which", lambda n: None)
    job = FakeJob()
    takserver.TakServer()._purge(job, backup=False, uploads=False)
    assert not home.exists() and not calls
    assert any(k == "warn" and "PostgreSQL" in m for k, m in job.lines)


def test_purge_restablece_estado_y_borra_subidos_solo_si_se_pide(tak, data_dir):
    home, _ = tak
    updir = takserver._upload_dir()
    for n in ("takserver_5.8.deb", "takserver-public-gpg.key", "deb_policy.pol"):
        (updir / n).write_text("x")
    settings.replace_section("takserver", {
        "installed": True, "int_ca": "x", "version": "5.8", "cert_pass": "c", "users": ["u"],
        "package": str(updir / "takserver_5.8.deb"), "gpg_key": str(updir / "takserver-public-gpg.key"),
        "policy": str(updir / "deb_policy.pol"), "org": "Mi Org", "admin_user": "webadmin"})
    takserver.TakServer()._purge(FakeJob(), backup=False, uploads=False)
    st = settings.section("takserver")
    assert st["installed"] is False and "int_ca" not in st and "cert_pass" not in st
    assert st["org"] == "Mi Org" and st["admin_user"] == "webadmin"
    assert st["gpg_key"] and len(list(updir.iterdir())) == 3
    # segunda pasada, ahora también los subidos
    home.mkdir(exist_ok=True)
    takserver.TakServer()._purge(FakeJob(), backup=False, uploads=True)
    st = settings.section("takserver")
    assert "gpg_key" not in st and "policy" not in st and "package" not in st
    assert list(updir.iterdir()) == []


def test_purge_en_dry_run_no_toca_nada(tak, monkeypatch):
    home, calls = tak
    monkeypatch.setattr(config, "DRY_RUN", True)
    takserver.TakServer()._purge(FakeJob(), backup=True, uploads=True)
    assert home.exists() and not calls


# ── ruta HTTP ───────────────────────────────────────────────────────────────
def _post(client, **data):
    return client.post("/api/m/takserver/purge", headers=HDR(client), data=data)


def test_ruta_exige_contrasena(client):
    r = _post(client, password="mala", confirm="BORRAR DATOS")
    assert r.status_code == 403


def test_ruta_exige_la_frase(client):
    r = _post(client, password="una-clave-larga-1", confirm="borrar")
    assert r.status_code == 400 and "BORRAR DATOS" in r.get_json()["error"]


def test_ruta_rechaza_si_tak_esta_instalado(client, monkeypatch):
    monkeypatch.setattr(takserver.TakServer, "package_version", lambda self: "5.8-RELEASE92")
    r = _post(client, password="una-clave-larga-1", confirm="BORRAR DATOS")
    assert r.status_code == 409 and "instalado" in r.get_json()["error"]


def test_ruta_requiere_csrf(client):
    r = client.post("/api/m/takserver/purge",
                    data={"password": "una-clave-larga-1", "confirm": "BORRAR DATOS"})
    assert r.status_code in (400, 403)


def test_ruta_en_dry_run_arranca_la_tarea(client):
    r = _post(client, password="una-clave-larga-1", confirm="BORRAR DATOS", backup="1")
    assert r.status_code == 200 and r.get_json()["ok"]
    job = wait_job("takserver")
    assert "no se borra nada" in "\n".join(job.lines)


# ── página ──────────────────────────────────────────────────────────────────
def test_pagina_muestra_el_boton_solo_si_hay_datos(client, tak, monkeypatch):
    monkeypatch.setattr(takserver.TakServer, "db_exists", lambda self, info: True)
    html = client.get("/m/takserver").get_data(as_text=True)
    assert "dlg-purge" in html and "BORRAR DATOS" in html and "«cot»" in html
    import shutil
    shutil.rmtree(takserver.TAK_HOME)
    monkeypatch.setattr(takserver.TakServer, "db_exists", lambda self, info: False)
    html = client.get("/m/takserver").get_data(as_text=True)
    assert "dlg-purge" not in html


def test_pagina_no_muestra_el_boton_con_tak_instalado(client, tak, monkeypatch):
    monkeypatch.setattr(takserver.TakServer, "package_version", lambda self: "5.8-RELEASE92")
    html = client.get("/m/takserver").get_data(as_text=True)
    assert "dlg-purge" not in html
