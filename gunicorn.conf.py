# SPDX-License-Identifier: Apache-2.0
# Un solo proceso: las tareas en segundo plano y su registro viven en memoria.
# Hilos para atender subidas grandes (paquete de TAK Server) sin bloquear la consola.
import os

_data = os.environ.get("TAKCONSOLE_DATA_DIR", os.path.join(os.path.dirname(__file__), "data"))
_port = os.environ.get("TAKCONSOLE_PORT", "5001")

bind = f"0.0.0.0:{_port}"
workers = 1
worker_class = "gthread"
threads = 8
timeout = 120
graceful_timeout = 30
certfile = os.path.join(_data, "certs", "console.crt")
keyfile = os.path.join(_data, "certs", "console.key")
accesslog = "-"
errorlog = "-"
loglevel = "info"
# No registrar la cadena de consulta (puede contener direcciones o nombres de usuario).
access_log_format = '%(h)s "%(m)s %(U)s" %(s)s %(b)s %(L)ss'
