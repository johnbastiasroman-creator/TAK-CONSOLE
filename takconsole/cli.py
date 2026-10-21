# SPDX-License-Identifier: Apache-2.0
"""Herramientas de línea de comandos usadas por install.sh y los scripts de soporte.

  python -m takconsole.cli set-password            pide la contraseña por teclado
  python -m takconsole.cli set-password --random   genera una y la muestra una vez
  python -m takconsole.cli console-cert            genera el certificado HTTPS de la consola
"""
import argparse
import getpass
import sys

from . import config
from .core import auth, certs, system, validate


def cmd_set_password(args):
    config.ensure_dirs()
    if args.random:
        pw = validate.random_password(20)
        auth.set_password(pw)
        print(pw)
        return 0
    while True:
        pw = getpass.getpass(f"Contraseña para la consola (mínimo {auth.MIN_PASSWORD} caracteres): ")
        if len(pw) < auth.MIN_PASSWORD:
            print("Demasiado corta.", file=sys.stderr)
            continue
        if getpass.getpass("Repite la contraseña: ") != pw:
            print("No coinciden.", file=sys.stderr)
            continue
        auth.set_password(pw)
        print("Contraseña guardada.")
        return 0


def cmd_console_cert(args):
    config.ensure_dirs()
    if config.CONSOLE_CERT.exists() and not args.force:
        print(f"Ya existe {config.CONSOLE_CERT} (usa --force para regenerar)")
        return 0
    hosts = [system.hostname()] + system.candidate_hosts()
    certs.make_console_cert(hosts, log=print)
    print(f"Certificado: {config.CONSOLE_CERT}")
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(prog="takconsole")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sp = sub.add_parser("set-password")
    sp.add_argument("--random", action="store_true")
    sp.set_defaults(fn=cmd_set_password)
    sc = sub.add_parser("console-cert")
    sc.add_argument("--force", action="store_true")
    sc.set_defaults(fn=cmd_console_cert)
    args = ap.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
