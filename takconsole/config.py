# SPDX-License-Identifier: Apache-2.0
"""Rutas y constantes globales de la consola."""
import os
from pathlib import Path

APP_NAME = "TAK-CONSOLE"
APP_SLUG = "takconsole"
APP_VERSION = "0.1.0"

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = Path(os.environ.get("TAKCONSOLE_DATA_DIR", str(BASE_DIR / "data")))

CONFIG_DIR = DATA_DIR / "config"      # settings.json, auth.json, secret_key
LOG_DIR = DATA_DIR / "logs"           # un archivo por tarea ejecutada
UPLOAD_DIR = DATA_DIR / "uploads"     # paquetes subidos (TAK Server .deb, planet, etc.)
STACKS_DIR = DATA_DIR / "stacks"      # docker compose + volúmenes por módulo
CERTS_DIR = DATA_DIR / "certs"        # certificado HTTPS de la consola

CONSOLE_PORT = int(os.environ.get("TAKCONSOLE_PORT", "5001"))
CONSOLE_CERT = CERTS_DIR / "console.crt"
CONSOLE_KEY = CERTS_DIR / "console.key"

# Comentario que identifica las reglas de UFW creadas por la consola.
FW_TAG = "tak-console"

# Prueba / desarrollo: no ejecuta comandos privilegiados reales.
DRY_RUN = os.environ.get("TAKCONSOLE_DRY_RUN") == "1"


def ensure_dirs():
    for d in (DATA_DIR, CONFIG_DIR, LOG_DIR, UPLOAD_DIR, STACKS_DIR, CERTS_DIR):
        d.mkdir(parents=True, exist_ok=True)
    for d in (DATA_DIR, CONFIG_DIR, CERTS_DIR):
        try:
            os.chmod(d, 0o700)
        except OSError:
            pass
