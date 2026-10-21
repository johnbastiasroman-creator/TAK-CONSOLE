# SPDX-License-Identifier: Apache-2.0
"""Contrato de un módulo de servicio.

Un módulo despliega, controla y retira un servicio. La consola genera para cada
módulo una página (/m/<key>) y las rutas genéricas:

  POST /api/m/<key>/deploy      → validate_deploy() + deploy() en segundo plano
  POST /api/m/<key>/action/<v>  → acción de control (start/stop/restart/...)
  POST /api/m/<key>/uninstall   → uninstall() en segundo plano
  GET  /api/jobs/<key>          → registro en vivo de la última tarea

Rutas adicionales se declaran en routes(); todas pasan por el login y CSRF
globales de la aplicación, no hay forma de registrar una ruta sin autenticación.
"""
from ..core import firewall, settings


class Module:
    key = ""
    name = ""
    summary = ""
    order = 100
    template = None

    # ── estado ──────────────────────────────────────────────────────────────
    def state(self) -> dict:
        return settings.section(self.key)

    def save_state(self, **values):
        return settings.update_section(self.key, values)

    def installed(self) -> bool:
        return bool(self.state().get("installed"))

    def status(self) -> dict:
        """{'installed', 'running', 'level': ok|warn|err|off, 'label', 'endpoints'}"""
        raise NotImplementedError

    def ports(self) -> list:
        """Puertos públicos [{'port': '8089', 'proto': 'tcp', 'label': '...'}]."""
        return []

    # ── ciclo de vida ───────────────────────────────────────────────────────
    def validate_deploy(self, data):
        """Devuelve (params, errores_por_campo)."""
        return {}, {}

    def deploy(self, job, params):
        raise NotImplementedError

    def uninstall(self, job, params):
        raise NotImplementedError

    def actions(self) -> dict:
        """{'restart': ('Reiniciar', callable(job))}"""
        return {}

    def routes(self) -> list:
        """[(regla, nombre, vista, métodos)]"""
        return []

    def page_context(self) -> dict:
        return {}

    # ── firewall ────────────────────────────────────────────────────────────
    def apply_firewall(self, log=None):
        return firewall.apply_rules(self.ports(), self.key, log=log)

    def remove_firewall(self, log=None):
        firewall.remove_rules(self.key, log=log)
