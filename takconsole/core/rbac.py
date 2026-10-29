# SPDX-License-Identifier: Apache-2.0
"""Roles y permisos de la consola.

Tres roles fijos. Cada ruta exige un permiso; lo que no figura en ENDPOINT_PERMS exige
«admin» (denegación por defecto), así que una ruta nueva olvidada queda cerrada, no abierta.
Las pruebas (tests/test_roles.py) exigen además que toda ruta esté clasificada a propósito.
"""

# Permisos
VIEW = "view"                    # páginas, estado de los servicios, registro de tareas
MONITOR = "monitor"              # consolas de estado y actividad, registros
SERVICE_CONTROL = "service_control"  # iniciar, detener y reiniciar servicios ya desplegados
TAK_CERTS = "tak_certs"          # TAK Server: crear certificados y bajar paquetes de conexión
ZEROTIER_NET = "zerotier_net"    # ZeroTier: unir o sacar este servidor de redes
ADMIN = "admin"                  # todo lo demás

ROLES = {
    "admin": {"label": "Administrador",
              "perms": {VIEW, MONITOR, SERVICE_CONTROL, TAK_CERTS, ZEROTIER_NET, ADMIN},
              "about": "Todo: desplegar, desinstalar, borrar datos, firewall, secretos y usuarios."},
    "operator": {"label": "Operador",
                 "perms": {VIEW, MONITOR, SERVICE_CONTROL, TAK_CERTS, ZEROTIER_NET},
                 "about": "Ve el estado y las consolas, inicia/detiene/reinicia servicios, crea "
                          "certificados TAK y une el servidor a redes ZeroTier. No ve secretos."},
    "viewer": {"label": "Observador",
               "perms": {VIEW, MONITOR},
               "about": "Solo ve el estado y las consolas de actividad. No ve secretos."},
}
ROLE_ORDER = ("admin", "operator", "viewer")

# Rutas abiertas (login) o sin permiso propio (cualquier sesión válida): ver app.py.
PUBLIC_ENDPOINTS = {"login", "static", "health"}

# endpoint de Flask → permiso exigido. Lo no listado exige ADMIN.
ENDPOINT_PERMS = {
    # cualquier usuario con sesión
    "dashboard": VIEW, "module_page": VIEW, "api_status": VIEW, "api_job": VIEW,
    "logout": VIEW, "account_page": VIEW, "api_account_password": VIEW,
    # consolas de estado y actividad, y lectura de registros
    "api_monitor": MONITOR, "mtx_paths": MONITOR, "mtx_logs": MONITOR, "mumble_logs": MONITOR,
    "tak_logs": MONITOR, "zt_logs": MONITOR,
    # control de servicios ya desplegados
    "api_action": SERVICE_CONTROL,
    # TAK Server: certificados y paquetes de usuarios
    "tak_user_create": TAK_CERTS, "tak_package": TAK_CERTS,
    # ZeroTier: unir / salir de redes
    "zt_join": ZEROTIER_NET, "zt_leave": ZEROTIER_NET,
    # solo administrador (listado a propósito)
    "api_deploy": ADMIN, "api_uninstall": ADMIN,
    "network": ADMIN, "api_policy": ADMIN, "api_ufw_enable": ADMIN, "api_console_cert": ADMIN,
    "console_cert_download": ADMIN,
    "tak_upload": ADMIN, "tak_admins": ADMIN, "tak_purge": ADMIN, "tak_download": ADMIN,
    "zt_planet_upload": ADMIN, "zt_planet_reset": ADMIN, "zt_planet_download": ADMIN,
    "users_page": ADMIN, "users_create": ADMIN, "users_role": ADMIN, "users_password": ADMIN,
    "users_state": ADMIN, "users_delete": ADMIN,
}


def required(endpoint: str) -> str:
    return ENDPOINT_PERMS.get(endpoint, ADMIN)


def allowed(role: str, perm: str) -> bool:
    spec = ROLES.get(role)
    return bool(spec and perm in spec["perms"])


def label(role: str) -> str:
    return ROLES.get(role, {}).get("label", role or "—")
