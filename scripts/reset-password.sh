#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Cambia la contraseña de la consola desde el servidor (acceso de recuperación).
#   sudo scripts/reset-password.sh            pide la nueva contraseña
#   sudo scripts/reset-password.sh --random   genera una y la muestra
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "Ejecuta con sudo" >&2; exit 1; }
BASE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export TAKCONSOLE_DATA_DIR="${TAKCONSOLE_DATA_DIR:-$BASE/data}"
cd "$BASE"
if [[ "${1:-}" == "--random" ]]; then
  echo "Nueva contraseña para admin: $("$BASE/.venv/bin/python" -m takconsole.cli set-password --random)"
else
  "$BASE/.venv/bin/python" -m takconsole.cli set-password
fi
