# SPDX-License-Identifier: Apache-2.0
"""Repositorio PGDG: la llave debe existir y ser legible por «_apt».

Caso real: el servicio corre con UMask=0077, así que /usr/share/postgresql-common se
creaba con modo 0700 y apt fallaba con NO_PUBKEY aunque la llave fuera correcta."""
import os
import stat
from pathlib import Path

import pytest

from takconsole.core.jobs import JobFailed
from takconsole.modules import takserver

KEY = b"-----BEGIN PGP PUBLIC KEY BLOCK-----\n\nabc\n-----END PGP PUBLIC KEY BLOCK-----\n"


class FakeJob:
    def __init__(self):
        self.lines = []

    def log(self, msg):
        self.lines.append(("log", msg))

    def ok(self, msg):
        self.lines.append(("ok", msg))

    def warn(self, msg):
        self.lines.append(("warn", msg))


@pytest.fixture()
def apt_tree(tmp_path, monkeypatch):
    root = tmp_path / "usr" / "share"
    root.mkdir(parents=True)
    monkeypatch.setattr(takserver, "APT_SAFE_ROOTS", (root,))
    pgdg = root / "postgresql-common" / "pgdg"
    return root, pgdg, pgdg / "apt.postgresql.org.asc"


def mode(path):
    return stat.S_IMODE(path.stat().st_mode)


def test_signed_by_path_una_linea_y_deb822():
    one = "deb [signed-by=/usr/share/postgresql-common/pgdg/apt.postgresql.org.asc] https://x jammy-pgdg main"
    assert takserver.signed_by_path(one) == Path("/usr/share/postgresql-common/pgdg/apt.postgresql.org.asc")
    deb822 = "Types: deb\nURIs: https://x\nSigned-By: /etc/apt/keyrings/pg.asc\n"
    assert takserver.signed_by_path(deb822) == Path("/etc/apt/keyrings/pg.asc")
    assert takserver.signed_by_path("deb https://x jammy-pgdg main") is None
    # una huella no es una ruta
    assert takserver.signed_by_path("deb [signed-by=B97B0AFCAA1A47F0] https://x") is None


def test_make_apt_readable_abre_el_directorio_padre_0700(apt_tree):
    root, pgdg, key = apt_tree
    pgdg.mkdir(parents=True)
    key.write_bytes(KEY)
    os.chmod(key, 0o600)
    os.chmod(pgdg, 0o755)
    os.chmod(pgdg.parent, 0o700)          # el estado que dejaba UMask=0077
    root_mode = mode(root)
    changed = takserver.make_apt_readable(key)
    assert pgdg.parent in changed
    assert mode(pgdg.parent) == 0o755
    assert mode(key) & 0o044 == 0o044
    assert root not in changed and mode(root) == root_mode   # no toca la raíz


def test_make_apt_readable_no_quita_permisos_ni_toca_fuera_de_las_raices(apt_tree, tmp_path):
    root, pgdg, key = apt_tree
    pgdg.mkdir(parents=True)
    key.write_bytes(KEY)
    os.chmod(pgdg.parent, 0o775)
    takserver.make_apt_readable(key)
    assert mode(pgdg.parent) == 0o775     # ya era legible: no cambia
    outside = tmp_path / "otro" / "llave.asc"
    outside.parent.mkdir()
    os.chmod(outside.parent, 0o700)
    outside.write_bytes(KEY)
    assert takserver.make_apt_readable(outside) == []
    assert mode(outside.parent) == 0o700


def test_key_is_present(tmp_path):
    good, empty, html = tmp_path / "a.asc", tmp_path / "b.asc", tmp_path / "c.asc"
    good.write_bytes(KEY)
    empty.write_bytes(b"")
    html.write_bytes(b"<html>error</html>")
    assert takserver.key_is_present(good)
    assert not takserver.key_is_present(empty)
    assert not takserver.key_is_present(html)
    assert takserver.key_is_present(html, armored=False)       # llave binaria de otro origen
    assert not takserver.key_is_present(tmp_path / "no-existe.asc")


def test_pgdg_ya_presente_pero_sin_llave_la_descarga_y_corrige_permisos(apt_tree, monkeypatch):
    """pgdg.list «ya presente» + llave ausente + directorio 0700 (el fallo real)."""
    root, pgdg, key = apt_tree
    pgdg.mkdir(parents=True)
    os.chmod(pgdg.parent, 0o700)
    monkeypatch.setattr(takserver, "PGDG_KEY", key)
    descargas = []
    monkeypatch.setattr(takserver, "fetch_pgdg_key",
                        lambda dest: (descargas.append(dest), dest.write_bytes(KEY)))
    monkeypatch.setattr(takserver, "apt_can_read", lambda p: True)
    job = FakeJob()
    takserver.TakServer()._pgdg_key_ready(job, key)
    assert descargas == [key]
    assert mode(pgdg.parent) == 0o755
    assert any(k == "warn" for k, _ in job.lines)
    assert any("Permisos corregidos" in m for _, m in job.lines)


def test_pgdg_falla_claro_si_apt_sigue_sin_poder_leer(apt_tree, monkeypatch):
    root, pgdg, key = apt_tree
    pgdg.mkdir(parents=True)
    key.write_bytes(KEY)
    monkeypatch.setattr(takserver, "PGDG_KEY", key)
    monkeypatch.setattr(takserver, "apt_can_read", lambda p: False)
    with pytest.raises(JobFailed, match="_apt"):
        takserver.TakServer()._pgdg_key_ready(FakeJob(), key)


def test_pgdg_llave_ajena_ausente_no_se_sobrescribe(apt_tree, monkeypatch):
    root, pgdg, _ = apt_tree
    otra = root / "keyrings" / "postgresql.gpg"
    monkeypatch.setattr(takserver, "fetch_pgdg_key",
                        lambda dest: pytest.fail("no debe descargar sobre una llave ajena"))
    with pytest.raises(JobFailed, match="no existe"):
        takserver.TakServer()._pgdg_key_ready(FakeJob(), otra)


def test_pgdg_completo_con_lista_existente_repara_y_actualiza(apt_tree, tmp_path, monkeypatch):
    """Reproduce el despliegue fallido: pgdg.list existe, la llave no, el padre es 0700."""
    root, pgdg, key = apt_tree
    pgdg.mkdir(parents=True)
    os.chmod(pgdg.parent, 0o700)
    lista = tmp_path / "pgdg.list"
    lista.write_text(f"deb [signed-by={key}] https://apt.postgresql.org/pub/repos/apt jammy-pgdg main\n")
    monkeypatch.setattr(takserver, "PGDG_KEY", key)
    monkeypatch.setattr(takserver.glob, "glob", lambda pattern: [str(lista)])
    monkeypatch.setattr(takserver, "fetch_pgdg_key", lambda dest: dest.write_bytes(KEY))
    monkeypatch.setattr(takserver, "apt_can_read", lambda p: mode(pgdg.parent) & 0o005 == 0o005)
    comandos = []
    monkeypatch.setattr(takserver, "run", lambda argv, **kw: comandos.append(argv))
    takserver.TakServer()._pgdg(FakeJob())
    assert mode(pgdg.parent) == 0o755
    assert key.read_bytes() == KEY
    assert comandos and comandos[0][:2] == ["apt-get", "update"]
