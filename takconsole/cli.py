# SPDX-License-Identifier: Apache-2.0
"""Herramientas de línea de comandos usadas por install.sh y los scripts de soporte.

  python -m takconsole.cli set-password            pide la contraseña por teclado (usuario admin)
  python -m takconsole.cli set-password --random   genera una y la muestra una vez
  python -m takconsole.cli set-password --user ana restablece a «ana» (la reactiva; si no existe,
                                                   la crea como administrador)
  python -m takconsole.cli list-users              lista usuarios, roles y estado
  python -m takconsole.cli console-cert            genera el certificado HTTPS de la consola
"""
import argparse
import getpass
import sys

from . import config
from .core import auth, certs, rbac, system, users, validate


def cmd_set_password(args):
    config.ensure_dirs()
    user = args.user
    if args.random:
        pw = validate.random_password(20)
        auth.set_password(pw, user)
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
        auth.set_password(pw, user)
        print(f"Contraseña guardada para {user}.")
        return 0


def cmd_list_users(args):
    config.ensure_dirs()
    for u in users.list_users():
        print(f"{u['username']:<20} {rbac.label(u['role']):<14} {'DESACTIVADO' if u['disabled'] else 'activo'}")
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
    sp.add_argument("--user", default="admin", help="usuario de la consola (por defecto admin)")
    sp.set_defaults(fn=cmd_set_password)
    sl = sub.add_parser("list-users")
    sl.set_defaults(fn=cmd_list_users)
    sc = sub.add_parser("console-cert")
    sc.add_argument("--force", action="store_true")
    sc.set_defaults(fn=cmd_console_cert)
    args = ap.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
