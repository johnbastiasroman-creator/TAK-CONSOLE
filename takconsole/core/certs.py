# SPDX-License-Identifier: Apache-2.0
"""Certificados: HTTPS de la consola y certificados de servicio firmados por la CA de TAK.

Firmar Mumble o MediaMTX con la CA de TAK permite que los clientes que ya
confían en esa CA (truststore entregado en el paquete de conexión) validen
también la voz y el video.
"""
import ipaddress
import os
import secrets
import tempfile
from pathlib import Path

from .. import config
from .jobs import JobFailed
from .shell import run

TAK_CERT_DIR = Path("/opt/tak/certs/files")


def _san_entries(hosts):
    out = []
    for h in hosts:
        h = h.strip()
        if not h:
            continue
        try:
            ipaddress.ip_address(h)
            out.append(f"IP:{h}")
        except ValueError:
            out.append(f"DNS:{h}")
    return out


def make_console_cert(hosts, log=None, days=825):
    """Certificado autofirmado para la consola (y el proxy HTTPS de ZTNET)."""
    config.CERTS_DIR.mkdir(parents=True, exist_ok=True)
    hosts = [h for h in hosts if h] or ["localhost"]
    san = ",".join(_san_entries(hosts + ["localhost", "127.0.0.1"]))
    run(["openssl", "req", "-x509", "-newkey", "rsa:3072", "-nodes", "-sha256",
         "-days", str(days), "-keyout", str(config.CONSOLE_KEY),
         "-out", str(config.CONSOLE_CERT), "-subj", f"/CN={hosts[0]}",
         "-addext", f"subjectAltName={san}"], log=log)
    os.chmod(config.CONSOLE_KEY, 0o600)
    os.chmod(config.CONSOLE_CERT, 0o644)


def tak_ca_available() -> bool:
    return (TAK_CERT_DIR / "ca.pem").exists() and (TAK_CERT_DIR / "ca-do-not-share.key").exists()


def sign_with_tak_ca(cn, hosts, out_dir: Path, ca_pass, log=None, days=730):
    """Genera server.key / server.crt / chain.pem en out_dir, firmados por la CA de TAK.

    La clave de la CA se descifra con -passin env: para que la contraseña no
    aparezca en la lista de procesos.
    """
    if not tak_ca_available():
        raise JobFailed("No se encontró la CA de TAK Server (despliega TAK Server primero)")
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    key, csr, crt = out_dir / "server.key", out_dir / "server.csr", out_dir / "server.crt"
    san = ",".join(_san_entries(list(hosts) + [cn]))
    env = {"TAKCONSOLE_CAPASS": ca_pass}
    with tempfile.NamedTemporaryFile("w", suffix=".ext", delete=False) as ext:
        ext.write("basicConstraints=CA:FALSE\n"
                  "keyUsage=critical,digitalSignature,keyEncipherment\n"
                  "extendedKeyUsage=serverAuth\n"
                  f"subjectAltName={san}\n")
        ext_path = ext.name
    try:
        run(["openssl", "genrsa", "-out", str(key), "2048"], log=log)
        os.chmod(key, 0o600)
        run(["openssl", "req", "-new", "-key", str(key), "-out", str(csr),
             "-subj", f"/CN={cn}"], log=log)
        run(["openssl", "x509", "-req", "-sha256", "-days", str(days),
             "-in", str(csr), "-CA", str(TAK_CERT_DIR / "ca.pem"),
             "-CAkey", str(TAK_CERT_DIR / "ca-do-not-share.key"),
             "-passin", "env:TAKCONSOLE_CAPASS",
             "-set_serial", "0x" + secrets.token_hex(8),
             "-extfile", ext_path, "-out", str(crt)], log=log, env=env)
    finally:
        os.unlink(ext_path)
        if csr.exists():
            csr.unlink()
    chain = (TAK_CERT_DIR / "ca.pem").read_text()
    root = TAK_CERT_DIR / "root-ca.pem"
    if root.exists() and root.read_text().strip() != chain.strip():
        chain = chain.rstrip() + "\n" + root.read_text()
    (out_dir / "chain.pem").write_text(chain)
    return {"key": key, "cert": crt, "chain": out_dir / "chain.pem"}
