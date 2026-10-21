#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Instalador de la consola TAK-CONSOLE para Ubuntu 22.04 LTS.
# Idempotente: se puede volver a ejecutar para reparar o actualizar.
#
#   sudo ./install.sh                 instala o actualiza
#   sudo ./install.sh --random-pass   genera la contraseña de la consola y la muestra una vez
#
set -euo pipefail

SERVICE="tak-console"
PORT="${TAKCONSOLE_PORT:-5001}"
BASE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DATA="${TAKCONSOLE_DATA_DIR:-$BASE/data}"
VENV="$BASE/.venv"
RANDOM_PASS=0

for arg in "$@"; do
  case "$arg" in
    --random-pass) RANDOM_PASS=1 ;;
    -h|--help) sed -n '3,9p' "$0"; exit 0 ;;
    *) echo "Opción desconocida: $arg" >&2; exit 2 ;;
  esac
done

say()  { printf '\n\033[1;33m==> %s\033[0m\n' "$*"; }
ok()   { printf '    \033[32m✓\033[0m %s\n' "$*"; }
warn() { printf '    \033[33m⚠\033[0m %s\n' "$*"; }
die()  { printf '\n\033[31m✗ %s\033[0m\n' "$*" >&2; exit 1; }

[[ $EUID -eq 0 ]] || die "Ejecuta con sudo: sudo ./install.sh"

# ── Sistema operativo ───────────────────────────────────────────────────────
say "Sistema operativo"
# shellcheck disable=SC1091
. /etc/os-release
if [[ "${ID:-}" == "ubuntu" && "${VERSION_ID:-}" == "22.04" ]]; then
  ok "$PRETTY_NAME"
elif [[ "${ID_LIKE:-} ${ID:-}" == *debian* || "${ID:-}" == "ubuntu" ]]; then
  warn "$PRETTY_NAME: la consola está probada en Ubuntu 22.04 LTS. Se continúa."
else
  die "Sistema no soportado: ${PRETTY_NAME:-desconocido}. Usa Ubuntu 22.04 LTS."
fi

APT=(apt-get -y -o DPkg::Lock::Timeout=600)
export DEBIAN_FRONTEND=noninteractive

# ── Paquetes base ───────────────────────────────────────────────────────────
say "Paquetes base"
"${APT[@]}" update
"${APT[@]}" install python3 python3-venv python3-pip ca-certificates curl gnupg \
  openssl ufw iproute2 git
ok "python3, openssl, ufw, iproute2, git"

# ── Docker ──────────────────────────────────────────────────────────────────
say "Docker"
if command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; then
  ok "Ya instalado: $(docker --version)"
else
  # Repositorio oficial de Docker (docs.docker.com/engine/install/ubuntu)
  install -m 0755 -d /etc/apt/keyrings
  curl -fsSL "https://download.docker.com/linux/ubuntu/gpg" -o /etc/apt/keyrings/docker.asc
  chmod a+r /etc/apt/keyrings/docker.asc
  echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu ${VERSION_CODENAME} stable" \
    > /etc/apt/sources.list.d/docker.list
  "${APT[@]}" update
  "${APT[@]}" install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
  ok "Instalado: $(docker --version)"
fi
systemctl enable --now docker >/dev/null
ok "Servicio docker activo"

# ── Entorno de Python ───────────────────────────────────────────────────────
say "Entorno de Python"
if [[ ! -x "$VENV/bin/python" ]]; then
  python3 -m venv "$VENV"
fi
"$VENV/bin/pip" install --quiet --upgrade pip
"$VENV/bin/pip" install --quiet -r "$BASE/requirements.txt"
ok "Dependencias instaladas en $VENV"

# ── Datos, contraseña y certificado ─────────────────────────────────────────
say "Configuración de la consola"
mkdir -p "$DATA"
chmod 700 "$DATA"
export TAKCONSOLE_DATA_DIR="$DATA"
cd "$BASE"
if [[ -f "$DATA/config/auth.json" ]]; then
  ok "Contraseña ya definida (cámbiala con scripts/reset-password.sh)"
elif [[ $RANDOM_PASS -eq 1 || ! -t 0 ]]; then
  PASS="$("$VENV/bin/python" -m takconsole.cli set-password --random)"
  ok "Contraseña generada para el usuario admin: $PASS"
  warn "Guárdala ahora: no se vuelve a mostrar."
else
  "$VENV/bin/python" -m takconsole.cli set-password
fi
"$VENV/bin/python" -m takconsole.cli console-cert

# ── Firewall ────────────────────────────────────────────────────────────────
say "Firewall"
SSH_PORTS="$(awk 'tolower($1)=="port"{print $2}' /etc/ssh/sshd_config 2>/dev/null || true)"
for p in ${SSH_PORTS:-22}; do
  ufw allow proto tcp to any port "$p" comment "tak-console:core" >/dev/null
done
ufw allow proto tcp to any port "$PORT" comment "tak-console:core" >/dev/null
if ufw status | grep -q "Status: active"; then
  ok "UFW activo; SSH y consola ($PORT) permitidos"
else
  ok "Reglas para SSH y consola agregadas. UFW sigue inactivo: actívalo desde la consola (Red y firewall)."
fi

# ── Servicio ────────────────────────────────────────────────────────────────
say "Servicio $SERVICE"
cat > "/etc/systemd/system/$SERVICE.service" <<EOF
[Unit]
Description=TAK-CONSOLE - consola de despliegue (TAK Server, MediaMTX, Mumble, ZeroTier)
After=network-online.target docker.service
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=$BASE
Environment=TAKCONSOLE_DATA_DIR=$DATA
Environment=TAKCONSOLE_PORT=$PORT
Environment=PYTHONUNBUFFERED=1
ExecStart=$VENV/bin/gunicorn -c $BASE/gunicorn.conf.py wsgi:app
Restart=always
RestartSec=5
UMask=0077

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable "$SERVICE" >/dev/null
systemctl restart "$SERVICE"
sleep 2
if systemctl is-active --quiet "$SERVICE"; then
  ok "Servicio activo"
else
  journalctl -u "$SERVICE" -n 30 --no-pager || true
  die "El servicio no arrancó; revisa el registro anterior"
fi

IP="$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src"){print $(i+1); exit}}')"
printf '\n\033[1;32mListo.\033[0m Abre https://%s:%s (usuario admin)\n' "${IP:-<ip-del-servidor>}" "$PORT"
printf 'El certificado es autofirmado: el navegador pedirá confirmar la excepción.\n\n'
