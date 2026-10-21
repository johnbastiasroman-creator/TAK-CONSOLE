# SPDX-License-Identifier: Apache-2.0
"""Información del equipo: sistema operativo, interfaces, recursos y puertos."""
import json
import os
import re
import shutil
import socket

from .shell import capture

SKIP_IFACE = re.compile(r"^(lo|docker\d*|br-[0-9a-f]+|veth.*|virbr\d*|cni.*|flannel.*)$")


def os_release() -> dict:
    data = {}
    try:
        with open("/etc/os-release", encoding="utf-8") as fh:
            for line in fh:
                if "=" in line:
                    k, v = line.rstrip("\n").split("=", 1)
                    data[k] = v.strip().strip('"')
    except OSError:
        pass
    return data


def os_label() -> str:
    r = os_release()
    return r.get("PRETTY_NAME") or "Desconocido"


def is_ubuntu_2204() -> bool:
    r = os_release()
    return r.get("ID") == "ubuntu" and r.get("VERSION_ID") == "22.04"


def codename() -> str:
    return os_release().get("VERSION_CODENAME", "")


def hostname() -> str:
    return socket.gethostname()


def interfaces() -> list:
    """[{name, kind: lan|zerotier, addresses:[ipv4...]}] sin loopback ni docker."""
    res = capture(["ip", "-j", "addr", "show"])
    out = []
    if not res.ok:
        return out
    try:
        data = json.loads(res.output)
    except ValueError:
        return out
    for itf in data:
        name = itf.get("ifname", "")
        if SKIP_IFACE.match(name):
            continue
        addrs = [a["local"] for a in itf.get("addr_info", [])
                 if a.get("family") == "inet" and a.get("local")]
        if not addrs:
            continue
        kind = "zerotier" if name.startswith("zt") else "lan"
        out.append({"name": name, "kind": kind, "addresses": addrs,
                    "up": "UP" in itf.get("flags", [])})
    return out


def addresses(kind=None) -> list:
    ips = []
    for itf in interfaces():
        if kind and itf["kind"] != kind:
            continue
        ips.extend(itf["addresses"])
    return ips


def primary_ip() -> str:
    """IP de la ruta por defecto (o la primera LAN disponible)."""
    res = capture(["ip", "-j", "route", "get", "1.1.1.1"])
    if res.ok:
        try:
            info = json.loads(res.output)
            if info and info[0].get("prefsrc"):
                return info[0]["prefsrc"]
        except ValueError:
            pass
    lan = addresses("lan")
    return lan[0] if lan else "127.0.0.1"


def candidate_hosts() -> list:
    """Direcciones que se ofrecen para paquetes de conexión: ZeroTier primero."""
    seen, out = set(), []
    for ip in addresses("zerotier") + addresses("lan"):
        if ip not in seen:
            seen.add(ip)
            out.append(ip)
    return out


def memory_mb() -> dict:
    info = {}
    try:
        with open("/proc/meminfo", encoding="utf-8") as fh:
            for line in fh:
                k, v = line.split(":", 1)
                info[k] = int(v.strip().split()[0]) // 1024
    except (OSError, ValueError):
        return {"total": 0, "available": 0}
    return {"total": info.get("MemTotal", 0), "available": info.get("MemAvailable", 0)}


def disk_gb(path="/") -> dict:
    try:
        du = shutil.disk_usage(path)
    except OSError:
        return {"total": 0, "free": 0}
    return {"total": round(du.total / 1e9, 1), "free": round(du.free / 1e9, 1)}


def cpu_count() -> int:
    return os.cpu_count() or 1


def load_avg():
    try:
        return [round(x, 2) for x in os.getloadavg()]
    except OSError:
        return [0, 0, 0]


def listening_ports() -> set:
    """{(puerto, 'tcp'|'udp')} en escucha."""
    res = capture(["ss", "-H", "-lntu"])
    ports = set()
    if not res.ok:
        return ports
    for line in res.output.splitlines():
        parts = line.split()
        if len(parts) < 5:
            continue
        proto = "udp" if parts[0].startswith("udp") else "tcp"
        local = parts[4]
        port = local.rsplit(":", 1)[-1]
        if port.isdigit():
            ports.add((int(port), proto))
    return ports


def port_listening(port: int, proto="tcp") -> bool:
    return (int(port), proto) in listening_ports()


def summary() -> dict:
    return {
        "hostname": hostname(),
        "os": os_label(),
        "supported": is_ubuntu_2204(),
        "cpus": cpu_count(),
        "load": load_avg(),
        "memory": memory_mb(),
        "disk": disk_gb("/"),
        "interfaces": interfaces(),
        "primary_ip": primary_ip(),
    }
