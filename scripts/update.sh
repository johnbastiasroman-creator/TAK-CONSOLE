#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Actualiza la consola desde git y reinicia el servicio. Los datos (data/) no se tocan.
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "Ejecuta con sudo" >&2; exit 1; }
BASE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$BASE"
# La consola corre como root sobre una copia que suele ser de otro usuario: sin esto git
# se niega a trabajar («dubious ownership»).
git -c safe.directory="$BASE" fetch --tags origin
git -c safe.directory="$BASE" pull --ff-only
"$BASE/.venv/bin/pip" install --quiet -r requirements.txt
systemctl restart tak-console
echo "Consola actualizada a $(git describe --tags --always)"
