#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Cambia la contraseña de un usuario de la consola desde el servidor (acceso de recuperación).
#   sudo scripts/reset-password.sh                       pide la nueva contraseña de «admin»
#   sudo scripts/reset-password.sh --random              genera una para «admin» y la muestra
#   sudo scripts/reset-password.sh --user ana [--random] lo mismo para «ana» (la reactiva; si no
#                                                        existe, la crea como administrador)
#   sudo scripts/reset-password.sh --list                lista los usuarios y su estado
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "Ejecuta con sudo" >&2; exit 1; }
BASE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export TAKCONSOLE_DATA_DIR="${TAKCONSOLE_DATA_DIR:-$BASE/data}"
cd "$BASE"
if [[ "${1:-}" == "--list" ]]; then
  exec "$BASE/.venv/bin/python" -m takconsole.cli list-users
fi
USERNAME=admin
ARGS=("$@")
for ((i = 0; i < ${#ARGS[@]}; i++)); do
  [[ "${ARGS[i]}" == "--user" ]] && USERNAME="${ARGS[i + 1]:-admin}"
done
if [[ " $* " == *" --random "* ]]; then
  echo "Nueva contraseña para $USERNAME: $("$BASE/.venv/bin/python" -m takconsole.cli set-password "$@")"
else
  "$BASE/.venv/bin/python" -m takconsole.cli set-password "$@"
fi
