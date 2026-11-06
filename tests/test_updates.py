# SPDX-License-Identifier: Apache-2.0
"""Actualizaciones: sistema operativo, consola, módulos en contenedores y TAK Server."""
import re
import time
from pathlib import Path

import pytest

from takconsole import config
from takconsole.core import settings, system, updates
from takconsole.core.jobs import Job, JobFailed
from takconsole.core.shell import Result
from takconsole.modules import MODULES, takserver

# Salida real de `apt-get -s dist-upgrade` (Ubuntu 24.04), con un paquete nuevo y una baja añadidos
APT_SIM = """\
NOTE: This is only a simulation!
Inst liblzma5 [5.6.1+really5.4.5-1ubuntu0.3] (5.6.1+really5.4.5-1ubuntu0.4 Ubuntu:24.04/noble-updates, Ubuntu:24.04/noble-security [amd64])
Conf liblzma5 (5.6.1+really5.4.5-1ubuntu0.4 Ubuntu:24.04/noble-updates, Ubuntu:24.04/noble-security [amd64])
Inst liblzma-dev [5.6.1+really5.4.5-1ubuntu0.3] (5.6.1+really5.4.5-1ubuntu0.4 Ubuntu:24.04/noble-updates, Ubuntu:24.04/noble-security [amd64]) []
Inst tmux [3.4-1ubuntu0.1] (3.4-1ubuntu0.2 Ubuntu:24.04/noble-updates [amd64])
Inst linux-image-6.8.0-90-generic (6.8.0-90.91 Ubuntu:24.04/noble-updates, Ubuntu:24.04/noble-security [amd64])
Remv viejo-paquete [1.0]
"""


def _job():
    return Job("updates", "prueba")


def _ok(out=""):
    return Result(0, out)


# ── apt y versiones ─────────────────────────────────────────────────────────
def test_parse_apt_sim_con_el_formato_real():
    r = updates.parse_apt_sim(APT_SIM)
    names = [p["name"] for p in r["packages"]]
    assert names == ["liblzma5", "liblzma-dev", "tmux", "linux-image-6.8.0-90-generic"]
    lz = r["packages"][0]
    assert lz == {"name": "liblzma5", "old": "5.6.1+really5.4.5-1ubuntu0.3",
                  "new": "5.6.1+really5.4.5-1ubuntu0.4", "security": True}
    assert r["packages"][2]["security"] is False                   # tmux: solo -updates
    assert r["packages"][3]["old"] == "" and r["packages"][3]["security"] is True   # paquete nuevo
    assert r["removals"] == ["viejo-paquete"]


def test_version_key_compara_por_numeros_no_por_texto():
    assert updates.version_key("v1.21.3") > updates.version_key("v1.9.3")
    assert updates.version_key("stable-11248-2") > updates.version_key("stable-11248")
    assert updates.version_key("stable-11248-1") > updates.version_key("stable-11248")
    assert updates.version_key("stable-11248") > updates.version_key("stable-9955")


LS_REMOTE = "\n".join(f"abc123\trefs/tags/{t}" for t in (
    "v1.9.3", "v1.21.2", "v1.21.3", "v1.22.0-rc1", "v1.21.3-beta", "latest", "nightly"))


def test_latest_tag_ignora_prereleases_y_ordena_bien(monkeypatch):
    monkeypatch.setattr(updates, "capture", lambda argv, **k: _ok(LS_REMOTE))
    assert updates.latest_tag("bluenviron/mediamtx", r"v\d+\.\d+\.\d+") == "v1.21.3"


def test_latest_tag_errores(monkeypatch):
    monkeypatch.setattr(updates, "capture", lambda argv, **k: Result(128, ""))
    with pytest.raises(updates.UpdateError, match="no se pudo consultar"):
        updates.latest_tag("a/b", r"v\d+")
    monkeypatch.setattr(updates, "capture", lambda argv, **k: _ok("x\trefs/tags/zzz"))
    with pytest.raises(updates.UpdateError, match="no tiene etiquetas"):
        updates.latest_tag("a/b", r"v\d+")


def test_las_etiquetas_fijadas_coinciden_con_su_patron():
    """Si un patrón no reconoce la etiqueta en uso, la comprobación nunca podría compararla."""
    for key, m in MODULES.items():
        for u in m.upstream():
            assert re.fullmatch(u["pattern"], u["current"]), (key, u)
            assert "/" in u["repo"]


# ── sistema operativo ───────────────────────────────────────────────────────
def test_os_check_cuenta_y_marca_seguridad(monkeypatch):
    monkeypatch.setattr(updates, "apt_update", lambda log=None: True)
    monkeypatch.setattr(updates, "simulate_upgrade", lambda: updates.parse_apt_sim(APT_SIM))
    r = updates.os_check()
    assert (r["count"], r["security"], r["removals"], r["error"]) == (4, 3, ["viejo-paquete"], "")
    monkeypatch.setattr(updates, "apt_update", lambda log=None: False)
    assert "lista de paquetes" in updates.os_check()["warn"]


def _os_env(monkeypatch, sim, takserver_installed=True, held=(), fail_apt=False):
    calls = []

    def fake_run(argv, **k):
        calls.append(list(argv))
        if fail_apt and argv[:2] == ["apt-get", "-y"]:
            from takconsole.core.shell import CommandError
            raise CommandError(argv, 100, "boom")
        return _ok()

    def fake_capture(argv, **k):
        if argv[0] == "dpkg-query":
            return _ok("takserver\n" if takserver_installed else "")
        if argv[0] == "apt-mark":
            return _ok("\n".join(held))
        return Result(1, "")

    monkeypatch.setattr(updates, "run", fake_run)
    monkeypatch.setattr(updates, "capture", fake_capture)
    monkeypatch.setattr(updates, "apt_update", lambda log=None: True)
    monkeypatch.setattr(updates, "simulate_upgrade", lambda: sim)
    monkeypatch.setattr(system, "disk_gb", lambda p="/": {"total": 50, "free": 30})
    return calls


def test_os_apply_retiene_takserver_y_lo_libera(data_dir, monkeypatch):
    sim = {"packages": [{"name": "tmux", "old": "1", "new": "2", "security": False}], "removals": []}
    calls = _os_env(monkeypatch, sim)
    updates.os_apply(_job())
    seq = [c[:3] for c in calls]
    assert ["apt-mark", "hold", "takserver"] in seq
    assert ["apt-mark", "unhold", "takserver"] in seq
    upgrade = next(c for c in calls if "dist-upgrade" in c)
    assert upgrade[:2] == ["apt-get", "-y"] and "Dpkg::Options::=--force-confold" in upgrade
    assert seq.index(["apt-mark", "hold", "takserver"]) < calls.index(upgrade) < \
        seq.index(["apt-mark", "unhold", "takserver"])
    assert updates.state()["history"][-1]["what"] == "Sistema operativo"


def test_os_apply_libera_takserver_aunque_apt_falle(data_dir, monkeypatch):
    sim = {"packages": [{"name": "tmux", "old": "1", "new": "2", "security": False}], "removals": []}
    calls = _os_env(monkeypatch, sim, fail_apt=True)
    with pytest.raises(Exception):
        updates.os_apply(_job())
    assert ["apt-mark", "unhold", "takserver"] in [c[:3] for c in calls]


def test_os_apply_no_toca_un_hold_que_ya_existia(data_dir, monkeypatch):
    sim = {"packages": [{"name": "tmux", "old": "1", "new": "2", "security": False}], "removals": []}
    calls = _os_env(monkeypatch, sim, held=["takserver"])
    updates.os_apply(_job())
    assert not [c for c in calls if c[:2] == ["apt-mark", "hold"] or c[:2] == ["apt-mark", "unhold"]]


def test_os_apply_se_niega_si_quitaria_paquetes(data_dir, monkeypatch):
    sim = {"packages": [{"name": "tmux", "old": "1", "new": "2", "security": False}],
           "removals": ["algo"]}
    calls = _os_env(monkeypatch, sim)
    with pytest.raises(JobFailed, match="quitaría paquetes"):
        updates.os_apply(_job())
    assert not [c for c in calls if "dist-upgrade" in c]


def test_os_apply_sin_pendientes(data_dir, monkeypatch):
    calls = _os_env(monkeypatch, {"packages": [], "removals": []})
    updates.os_apply(_job())
    assert not [c for c in calls if "dist-upgrade" in c]


def test_os_apply_poco_espacio(data_dir, monkeypatch):
    _os_env(monkeypatch, {"packages": [], "removals": []})
    monkeypatch.setattr(system, "disk_gb", lambda p="/": {"total": 50, "free": 1.2})
    with pytest.raises(JobFailed, match="GB libres"):
        updates.os_apply(_job())


# ── consola (git) ───────────────────────────────────────────────────────────
def _fake_git(monkeypatch, tmp_path, *, behind=2, ahead=0, dirty="", fetch_ok=True, upstream=True):
    (tmp_path / ".git").mkdir(exist_ok=True)
    monkeypatch.setattr(config, "BASE_DIR", tmp_path)
    answers = {
        ("describe", "--tags", "--always"): "v0.1.0-5-gabc1234",
        ("rev-parse", "--abbrev-ref", "HEAD"): "main",
        ("rev-parse", "--abbrev-ref", "--symbolic-full-name", "@{u}"): "origin/main" if upstream else None,
        ("rev-list", "--count", "HEAD..@{u}"): str(behind),
        ("rev-list", "--count", "@{u}..HEAD"): str(ahead),
        ("log", "--format=%h %s", "-n", "15", "HEAD..@{u}"): "aaa1111 Uno\nbbb2222 Dos",
        ("describe", "--tags", "--always", "@{u}"): "v0.2.0",
        ("status", "--porcelain", "--untracked-files=no"): dirty,
    }

    def fake_capture(argv, **k):
        sub = tuple(argv[argv.index("-C") + 2:])
        out = answers.get(sub, "?")
        return Result(0, out) if out is not None else Result(1, "")

    monkeypatch.setattr(updates, "capture", fake_capture)
    monkeypatch.setattr(updates, "run", lambda argv, **k: Result(0 if fetch_ok else 1, ""))


def test_console_check_cuenta_cambios_y_usa_safe_directory(monkeypatch, tmp_path):
    _fake_git(monkeypatch, tmp_path)
    r = updates.console_check()
    assert (r["behind"], r["ahead"], r["version"], r["latest"], r["error"]) == \
        (2, 0, "v0.1.0-5-gabc1234", "v0.2.0", "")
    assert r["commits"] == ["aaa1111 Uno", "bbb2222 Dos"]
    assert f"safe.directory={tmp_path}" in updates._git_argv("status")


def test_console_check_errores(monkeypatch, tmp_path):
    _fake_git(monkeypatch, tmp_path, fetch_ok=False)
    assert "sin conexión" in updates.console_check()["error"]
    _fake_git(monkeypatch, tmp_path, upstream=False)
    assert "ninguna rama remota" in updates.console_check()["error"]
    monkeypatch.setattr(config, "BASE_DIR", tmp_path / "otra")
    assert "git" in updates.console_check()["error"]


def test_console_apply_lanza_una_unidad_aparte_con_registro(data_dir, monkeypatch, tmp_path):
    _fake_git(monkeypatch, tmp_path)
    (tmp_path / "scripts").mkdir()
    (tmp_path / "scripts" / "update.sh").write_text("#!/bin/bash\n")
    seen = []
    monkeypatch.setattr(updates, "run", lambda argv, **k: seen.append(list(argv)) or _ok())
    monkeypatch.setattr(updates, "capture",
                        lambda argv, **k: Result(3, "inactive") if "is-active" in argv else
                        _fake_capture_git(argv))
    updates.console_apply(_job())
    cmd = next(c for c in seen if c[0] == "systemd-run")
    assert "--unit" in cmd and updates.UNIT_SELF in cmd and cmd[-2:] == ["/bin/bash", str(tmp_path / "scripts" / "update.sh")]
    log = next(a for a in cmd if a.startswith("--property=StandardOutput=append:")).split(":", 1)[1]
    assert Path(log).parent == config.LOG_DIR
    assert updates.state()["selfupdate"]["log"] == log


def _fake_git_answers():
    return {"describe": "v1", "rev-parse": "origin/main", "rev-list": "2", "log": "a b", "status": ""}


def _fake_capture_git(argv):
    sub = argv[argv.index("-C") + 2:]
    out = _fake_git_answers().get(sub[0], "")
    if sub[0] == "rev-list" and "@{u}..HEAD" in sub:
        out = "0"
    return Result(0, out)


@pytest.mark.parametrize("kw,msg", [({"dirty": " M takconsole/x.py"}, "modificados a mano"),
                                    ({"ahead": 1}, "commits propios"),
                                    ({"behind": 0}, None)])
def test_console_apply_rechazos(data_dir, monkeypatch, tmp_path, kw, msg):
    _fake_git(monkeypatch, tmp_path, **kw)
    seen = []
    base = updates.run
    monkeypatch.setattr(updates, "run", lambda argv, **k: seen.append(list(argv)) or base(argv, **k))
    if msg:
        with pytest.raises(JobFailed, match=msg):
            updates.console_apply(_job())
    else:
        updates.console_apply(_job())               # ya al día: no hace nada
    assert not [c for c in seen if c and c[0] == "systemd-run"]


# ── módulos ─────────────────────────────────────────────────────────────────
def _install(key, **extra):
    MODULES[key].save_state(installed=True, **extra)


def test_modules_check_detecta_version_pendiente_y_novedades(data_dir, monkeypatch):
    _install("mediamtx", params={"tls": False})
    pinned = next(iter(MODULES["mediamtx"].containers().values()))
    monkeypatch.setattr(updates, "running_image", lambda name: "bluenviron/mediamtx:1.20.0")
    monkeypatch.setattr(updates, "latest_tag", lambda repo, pattern, timeout=60: "v1.99.0")
    (row,) = updates.modules_check()
    assert row["key"] == "mediamtx" and row["pending"] is True
    assert row["containers"][0]["pinned"] == pinned and row["containers"][0]["ok"] is False
    assert row["upstream"][0]["newer"] is True and row["upstream"][0]["latest"] == "v1.99.0"
    monkeypatch.setattr(updates, "running_image", lambda name: pinned)
    monkeypatch.setattr(updates, "latest_tag", lambda *a, **k: "v1.21.2")
    (row,) = updates.modules_check()
    assert row["pending"] is False and row["upstream"][0]["newer"] is False


def test_modules_check_ignora_no_instalados_y_tolera_fallos(data_dir, monkeypatch):
    assert updates.modules_check() == []
    _install("mumble", params={})
    monkeypatch.setattr(updates, "running_image", lambda name: None)

    def boom(*a, **k):
        raise updates.UpdateError("sin red")
    monkeypatch.setattr(updates, "latest_tag", boom)
    (row,) = updates.modules_check()
    assert row["pending"] is False                     # sin contenedor: se desconoce, no «pendiente»
    assert row["upstream"][0]["error"] == "sin red"


def test_module_apply_reaplica_con_la_configuracion_guardada(data_dir, monkeypatch):
    params = {"register_name": "Red", "tls": False}
    _install("mumble", params=params)
    seen = []
    monkeypatch.setattr(type(MODULES["mumble"]), "deploy", lambda self, job, p: seen.append(p))
    monkeypatch.setattr(updates, "running_image",
                        lambda name: next(iter(MODULES["mumble"].containers().values())))
    monkeypatch.setattr(updates, "latest_tag", lambda *a, **k: "v1.6.870")
    updates.module_apply(_job(), "mumble")
    assert seen == [params]
    assert updates.state()["history"][-1]["what"] == MODULES["mumble"].name


def test_module_apply_sin_configuracion_guardada(data_dir):
    _install("mumble")
    with pytest.raises(JobFailed, match="configuración guardada"):
        updates.module_apply(_job(), "mumble")


def test_module_apply_rechaza_lo_que_no_es_contenedor(data_dir):
    with pytest.raises(JobFailed):
        updates.module_apply(_job(), "takserver")


def test_zerotier_reaplica_con_su_direccion_publica(data_dir, monkeypatch):
    _install("zerotier", public_host="10.0.0.5")
    seen = []
    monkeypatch.setattr(type(MODULES["zerotier"]), "deploy", lambda self, job, p: seen.append(p))
    MODULES["zerotier"].reapply(_job())
    assert seen == [{"public_host": "10.0.0.5"}]


def test_los_cuatro_modulos_declaran_contenedores_con_imagen_fijada():
    for key in ("zerotier", "mediamtx", "mumble", "jitsi"):
        cs = MODULES[key].containers()
        assert cs and all(re.search(r":[\w.\-]+$", img) for img in cs.values()), key
    assert MODULES["takserver"].containers() == {}


# ── búsqueda completa e insignia ────────────────────────────────────────────
def test_check_all_guarda_resultados_y_cuenta_pendientes(data_dir, monkeypatch):
    monkeypatch.setattr(updates, "os_check", lambda log=None: {"count": 3, "security": 1, "packages": [],
                                                              "removals": [], "error": "", "warn": ""})
    monkeypatch.setattr(updates, "console_check", lambda log=None: {"behind": 2, "error": "", "version": "v1"})
    monkeypatch.setattr(updates, "modules_check",
                        lambda log=None, upstream=True: [{"key": "mumble", "name": "Mumble", "pending": True,
                                                          "containers": [], "upstream": []}])
    monkeypatch.setattr(updates, "takserver_info",
                        lambda: {"installed": "5.8", "staged": "5.9", "newer": True})
    assert updates.pending_count() == 0
    updates.check_all(_job())
    st = updates.state()
    assert st["checked_at"] <= time.time() and updates.pending_count() == 4


def test_scheduler_no_arranca_en_modo_de_prueba():
    assert config.DRY_RUN and updates.start_scheduler() is None


# ── TAK Server ──────────────────────────────────────────────────────────────
class _TakEnv:
    def __init__(self, monkeypatch, tmp_path, current="5.8-RELEASE92", new="5.9-RELEASE10",
                 after=None, newer=True):
        self.calls, self.after = [], after or new
        pkg = tmp_path / "takserver_5.9_all.deb"
        pkg.write_bytes(b"x")
        self.pkg = pkg
        self.versions = [current, self.after]
        monkeypatch.setattr(config, "DRY_RUN", False)
        self.m = takserver.TakServer()
        self.m.save_state(installed=True, package=str(pkg), package_version=new)
        monkeypatch.setattr(takserver.TakServer, "package_version",
                            lambda s: self.versions.pop(0) if len(self.versions) > 1 else self.versions[0])
        monkeypatch.setattr(takserver, "run", lambda argv, **k: self.calls.append(list(argv)) or _ok())
        monkeypatch.setattr(takserver, "capture",
                            lambda argv, **k: _ok("") if argv[0] == "dpkg" and newer else
                            (Result(1, "") if argv[0] == "dpkg" else _ok(new)))
        monkeypatch.setattr(takserver.TakServer, "_backup", lambda s, job: self.calls.append(["backup"]))
        monkeypatch.setattr(takserver.TakServer, "_backup_db", lambda s, job: self.calls.append(["backup-db"]))
        monkeypatch.setattr(takserver.TakServer, "_start_and_wait", lambda s, job, wait=900: self.calls.append(["start"]))
        monkeypatch.setattr(system, "port_listening", lambda *a, **k: True)
        monkeypatch.setattr(system, "disk_gb", lambda p="/": {"total": 100, "free": 50})


def test_takserver_update_orden_y_estado(data_dir, monkeypatch, tmp_path):
    env = _TakEnv(monkeypatch, tmp_path)
    env.m.update(_job(), verify=False)
    kinds = [c[0] if c[0] in ("backup", "backup-db", "start") else " ".join(c[:2]) for c in env.calls]
    assert kinds == ["backup", "backup-db", "systemctl stop", "apt-get install", "start"]
    install = next(c for c in env.calls if c[:2] == ["apt-get", "install"])
    assert install[-1] == str(env.pkg) and "Dpkg::Options::=--force-confold" in install
    st = env.m.state()
    assert st["version"] == "5.9-RELEASE10" and st["package"] is None and not env.pkg.exists()
    assert updates.state()["history"][-1]["what"] == "TAK Server"


def test_takserver_update_rechaza_version_no_mas_nueva(data_dir, monkeypatch, tmp_path):
    env = _TakEnv(monkeypatch, tmp_path, newer=False)
    with pytest.raises(JobFailed, match="no es más nuevo"):
        env.m.update(_job())
    assert not env.calls and env.pkg.exists()


def test_takserver_update_sin_paquete_o_sin_instalar(data_dir, monkeypatch, tmp_path):
    env = _TakEnv(monkeypatch, tmp_path)
    env.pkg.unlink()
    with pytest.raises(JobFailed, match="Sube primero"):
        env.m.update(_job())
    monkeypatch.setattr(takserver.TakServer, "package_version", lambda s: None)
    with pytest.raises(JobFailed, match="no está instalado"):
        env.m.update(_job())


def test_takserver_update_falla_si_dpkg_no_queda_en_la_version(data_dir, monkeypatch, tmp_path):
    env = _TakEnv(monkeypatch, tmp_path, after="5.8-RELEASE92")
    with pytest.raises(JobFailed, match="Tras instalar"):
        env.m.update(_job())
    assert env.pkg.exists()                      # no se borra el paquete si algo salió mal


def test_takserver_update_verifica_firma_si_se_pide(data_dir, monkeypatch, tmp_path):
    env = _TakEnv(monkeypatch, tmp_path)
    seen = []
    monkeypatch.setattr(takserver.TakServer, "_verify", lambda s, job, pkg, wanted: seen.append(wanted))
    env.m.update(_job(), verify=True)
    assert seen == [True]


# ── rutas ───────────────────────────────────────────────────────────────────
def _wait_job():
    from takconsole.core.jobs import JOBS
    for _ in range(100):
        if not JOBS.busy():
            return JOBS.get("updates")
        time.sleep(0.05)
    raise AssertionError("la tarea no terminó")


def test_pagina_y_busqueda_desde_la_consola(client):
    page = client.get("/actualizaciones").get_data(as_text=True)
    assert "Actualizaciones" in page and "Buscar actualizaciones" in page
    r = client.post("/api/updates/check", headers={"X-CSRF-Token": client.csrf})
    assert r.get_json()["ok"] is True
    assert _wait_job().status == "ok"
    assert "Última búsqueda" in client.get("/actualizaciones").get_data(as_text=True)


def test_insignia_del_menu_con_pendientes(client):
    assert 'class="badge"' not in client.get("/").get_data(as_text=True)
    updates.save(os={"count": 5}, checked_at=int(time.time()))
    assert 'class="badge"' in client.get("/").get_data(as_text=True)


def test_la_pagina_muestra_lo_pendiente(client, monkeypatch):
    updates.save(
        checked_at=int(time.time()),
        os={"count": 1, "security": 1, "removals": [], "error": "", "warn": "",
            "packages": [{"name": "openssl", "old": "1", "new": "2", "security": True}]},
        console={"behind": 1, "ahead": 0, "dirty": [], "commits": ["abc1234 Cambio de prueba"],
                 "version": "v1", "latest": "v2", "branch": "main", "error": ""},
        modules=[{"key": "mumble", "name": "Mumble", "pending": True,
                  "containers": [{"name": "c", "running": "a:1", "pinned": "a:2", "ok": False}],
                  "upstream": [{"label": "Mumble", "current": "v1", "latest": "v2", "newer": True,
                                "error": ""}]}])
    html = client.get("/actualizaciones").get_data(as_text=True)
    for needle in ("openssl", "Cambio de prueba", "data-action=\"/api/updates/module/mumble\"",
                   "data-action=\"/api/updates/os\"", "data-restart-wait=\"/api/updates/console\"",
                   "hay <span class=\"mono\">v2</span>"):
        assert needle in html, needle


def test_actualizar_consola_se_bloquea_con_cambios_locales_en_la_pagina(client):
    updates.save(checked_at=1, console={"behind": 1, "ahead": 0, "dirty": ["takconsole/x.py"],
                                        "commits": [], "version": "v1", "latest": "v2", "error": ""})
    html = client.get("/actualizaciones").get_data(as_text=True)
    assert "git checkout -- ." in html and re.search(r'data-restart-wait[^>]*disabled', html)


def test_reiniciar_exige_la_contrasena(client, monkeypatch):
    seen = []
    monkeypatch.setattr(updates, "reboot", lambda log=None: seen.append(1))
    h = {"X-CSRF-Token": client.csrf}
    bad = client.post("/api/updates/reboot", data={"password": "no-es"}, headers=h)
    assert bad.status_code == 403 and not seen
    good = client.post("/api/updates/reboot", data={"password": "una-clave-larga-1"}, headers=h)
    assert good.get_json()["ok"] is True and seen == [1]


def test_reiniciar_programa_el_reinicio_con_systemd(monkeypatch):
    seen = []
    monkeypatch.setattr(updates, "run", lambda argv, **k: seen.append(list(argv)) or _ok())
    updates.reboot()
    assert seen[0][:2] == ["systemd-run", "--unit"] and seen[0][-2:] == ["systemctl", "reboot"]


def test_modulo_que_no_es_contenedor_da_404(client):
    r = client.post("/api/updates/module/takserver", headers={"X-CSRF-Token": client.csrf})
    assert r.status_code == 404


def test_solo_el_administrador_ve_y_usa_actualizaciones(data_dir):
    from tests.test_roles import PW, login
    from takconsole import create_app
    from takconsole.core import auth, users
    auth.set_password(PW)
    users.create("oper", PW, "operator")
    app = create_app()
    app.config["TESTING"] = True
    c = login(app, "oper")
    assert c.get("/actualizaciones").status_code == 403
    for path in ("check", "os", "console", "takserver", "reboot", "module/mumble"):
        assert c.post(f"/api/updates/{path}", headers={"X-CSRF-Token": c.csrf}).status_code == 403, path
    assert "Actualizaciones" not in c.get("/").get_data(as_text=True)
