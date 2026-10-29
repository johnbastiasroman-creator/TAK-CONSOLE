# SPDX-License-Identifier: Apache-2.0
import os
import re
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture()
def data_dir(tmp_path, monkeypatch):
    from takconsole import config
    monkeypatch.setattr(config, "DATA_DIR", tmp_path)
    monkeypatch.setattr(config, "CONFIG_DIR", tmp_path / "config")
    monkeypatch.setattr(config, "LOG_DIR", tmp_path / "logs")
    monkeypatch.setattr(config, "UPLOAD_DIR", tmp_path / "uploads")
    monkeypatch.setattr(config, "STACKS_DIR", tmp_path / "stacks")
    monkeypatch.setattr(config, "CERTS_DIR", tmp_path / "certs")
    monkeypatch.setattr(config, "CONSOLE_CERT", tmp_path / "certs" / "console.crt")
    monkeypatch.setattr(config, "CONSOLE_KEY", tmp_path / "certs" / "console.key")
    monkeypatch.setattr(config, "DRY_RUN", True)
    config.ensure_dirs()
    return tmp_path


@pytest.fixture(autouse=True)
def _reset_lockout():
    """El bloqueo por IP vive en memoria del proceso: que una prueba no afecte a la siguiente."""
    from takconsole.core import auth
    auth._FAILS.clear()
    yield
    auth._FAILS.clear()


@pytest.fixture()
def client(data_dir):
    from takconsole import create_app
    from takconsole.core import auth
    auth.set_password("una-clave-larga-1")
    app = create_app()
    app.config["TESTING"] = True
    c = app.test_client()
    html = c.get("/login").get_data(as_text=True)
    tok = re.search(r'name="csrf" value="([^"]+)"', html).group(1)
    r = c.post("/login", data={"username": "admin", "password": "una-clave-larga-1", "csrf": tok})
    assert r.status_code == 302
    # el inicio de sesión renueva la sesión (y su token CSRF)
    page = c.get("/").get_data(as_text=True)
    c.csrf = re.search(r'name="csrf-token" content="([^"]+)"', page).group(1)
    return c


def pytest_configure(config):
    os.environ.setdefault("TAKCONSOLE_DRY_RUN", "1")
