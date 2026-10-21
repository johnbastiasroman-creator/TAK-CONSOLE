# SPDX-License-Identifier: Apache-2.0
"""Firewall (UFW) con política de exposición.

Cada regla creada por la consola lleva el comentario `tak-console:<módulo>`, lo que
permite quitar y volver a aplicar las reglas de un módulo sin tocar las del
operador.

Políticas de exposición para los puertos de servicio (TAK, video, voz, ZTNET):
  all          → cualquier interfaz
  zerotier     → solo interfaces ZeroTier (zt*)
  zerotier_lan → interfaces ZeroTier + una red local (CIDR)

El transporte de ZeroTier (9993/udp), SSH y la consola se abren siempre.

Nota: Docker publica puertos saltándose UFW. Por eso todos los contenedores
de la consola usan network_mode: host (o publican solo en 127.0.0.1).
"""
import ipaddress
import re

from .. import config
from . import settings, system
from .shell import capture, run

POLICIES = ("all", "zerotier", "zerotier_lan")
_NUMBERED = re.compile(r"^\[\s*(\d+)\]\s.*#\s*(\S+)\s*$")


def tag(module_key: str) -> str:
    return f"{config.FW_TAG}:{module_key}"


def available() -> bool:
    return bool(capture(["which", "ufw"]).ok)


def status() -> dict:
    res = capture(["ufw", "status"])
    if not res.ok and "Status" not in res.output:
        return {"installed": available(), "active": False}
    active = "Status: active" in res.output
    return {"installed": True, "active": active}


def policy() -> dict:
    net = settings.section("network")
    mode = net.get("exposure", "all")
    if mode not in POLICIES:
        mode = "all"
    return {"exposure": mode, "lan_cidr": net.get("lan_cidr", "")}


def validate_cidr(value: str) -> str:
    try:
        return str(ipaddress.ip_network(value.strip(), strict=False))
    except ValueError:
        raise ValueError("Red local inválida; usa formato CIDR, por ejemplo 192.168.1.0/24")


def zerotier_ifaces() -> list:
    names = {i["name"] for i in system.interfaces() if i["kind"] == "zerotier"}
    names.update(settings.section("network").get("zt_ifaces", []))
    return sorted(n for n in names if re.fullmatch(r"zt[0-9a-z]{1,13}", n))


def ssh_ports() -> list:
    ports = []
    try:
        with open("/etc/ssh/sshd_config", encoding="utf-8") as fh:
            for line in fh:
                m = re.match(r"^\s*Port\s+(\d+)", line)
                if m:
                    ports.append(m.group(1))
    except OSError:
        pass
    return ports or ["22"]


def _rule_cmds(spec, module_key, pol, ifaces):
    port, proto = str(spec["port"]), spec["proto"]
    t = tag(module_key)
    if spec.get("always") or pol["exposure"] == "all":
        return [["ufw", "allow", "proto", proto, "to", "any", "port", port, "comment", t]]
    cmds = [["ufw", "allow", "in", "on", i, "proto", proto, "to", "any", "port", port,
             "comment", t] for i in ifaces]
    if pol["exposure"] == "zerotier_lan" and pol["lan_cidr"]:
        cmds.append(["ufw", "allow", "proto", proto, "from", pol["lan_cidr"], "to", "any",
                     "port", port, "comment", t])
    return cmds


def planned_rules(ports, module_key):
    pol = policy()
    ifaces = zerotier_ifaces()
    cmds = []
    for spec in ports:
        cmds.extend(_rule_cmds(spec, module_key, pol, ifaces))
    return cmds


def remove_rules(module_key, log=None):
    if not available():
        return
    res = capture(["ufw", "status", "numbered"])
    nums = []
    for line in res.output.splitlines():
        m = _NUMBERED.match(line.strip())
        if m and m.group(2) == tag(module_key):
            nums.append(int(m.group(1)))
    for n in sorted(nums, reverse=True):
        run(["ufw", "--force", "delete", str(n)], log=log, check=False)


def apply_rules(ports, module_key, log=None):
    """Quita las reglas previas del módulo y aplica las de la política actual."""
    if not available():
        if log:
            log("⚠ UFW no está instalado; no se configuró el firewall")
        return []
    remove_rules(module_key, log=log)
    cmds = planned_rules(ports, module_key)
    for c in cmds:
        run(c, log=log, check=False)
    pol = policy()
    if pol["exposure"] != "all" and not zerotier_ifaces():
        if log:
            log("⚠ La política limita a ZeroTier, pero aún no hay interfaces ZeroTier: "
                "únete a una red y vuelve a aplicar el firewall")
    return cmds


def ensure_base_rules(log=None):
    """SSH, consola y transporte ZeroTier: siempre abiertos en todas las interfaces."""
    base = [{"port": p, "proto": "tcp", "always": True} for p in ssh_ports()]
    base.append({"port": str(config.CONSOLE_PORT), "proto": "tcp", "always": True})
    return apply_rules(base, "core", log=log)


def enable(log=None):
    ensure_base_rules(log=log)
    run(["ufw", "--force", "enable"], log=log)
