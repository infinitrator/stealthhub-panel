#!/usr/bin/env bash
# Idempotent bare-metal installer for the Infiproxy panel.
#
# This script installs the release binary, systemd units, web-editable config
# directories, starting core configs and the SSH manager without enabling proxy
# core services before their verified binaries are installed.
set -euo pipefail
umask 027

APP_USER="${INFIPROXY_USER:-${STEALTHHUB_USER:-infiproxy}}"
APP_GROUP="${INFIPROXY_GROUP:-${STEALTHHUB_GROUP:-$APP_USER}}"
INSTALL_BIN="${INFIPROXY_INSTALL_BIN:-${STEALTHHUB_INSTALL_BIN:-/usr/local/bin/infiproxy}}"
MANAGER_BIN="${INFIPROXY_MANAGER_BIN:-/usr/local/sbin/infiproxy-manager}"
UPDATE_BIN="${INFIPROXY_UPDATE_BIN:-/usr/local/sbin/infiproxy-panel-update}"
CONFIG_DIR="${INFIPROXY_CONFIG_DIR:-${STEALTHHUB_CONFIG_DIR:-/etc/infiproxy}}"
STATE_DIR="${INFIPROXY_STATE_DIR:-${STEALTHHUB_STATE_DIR:-/var/lib/infiproxy}}"
CORE_DIR="${INFIPROXY_CORE_DIR:-${STEALTHHUB_CORE_DIR:-/opt/infiproxy/cores}}"
CORE_CONFIG_DIR="${INFIPROXY_CORE_CONFIG_DIR:-${STEALTHHUB_CORE_CONFIG_DIR:-/etc/infiproxy-cores}}"
CORE_LOG_DIR="${INFIPROXY_CORE_LOG_DIR:-${STEALTHHUB_CORE_LOG_DIR:-/var/log/infiproxy-cores}}"
SERVICE_FILE="${INFIPROXY_SERVICE_FILE:-${STEALTHHUB_SERVICE_FILE:-/etc/systemd/system/infiproxy.service}}"
UPDATE_SERVICE_FILE="${INFIPROXY_UPDATE_SERVICE_FILE:-/etc/systemd/system/infiproxy-panel-update.service}"
UPDATE_TIMER_FILE="${INFIPROXY_UPDATE_TIMER_FILE:-/etc/systemd/system/infiproxy-panel-update.timer}"
UPDATE_PATH_FILE="${INFIPROXY_UPDATE_PATH_FILE:-/etc/systemd/system/infiproxy-panel-update.path}"
ENV_FILE="${CONFIG_DIR}/infiproxy.env"
NGINX_AVAILABLE="${INFIPROXY_NGINX_AVAILABLE:-/etc/nginx/sites-available/infiproxy.conf}"
NGINX_ENABLED="${INFIPROXY_NGINX_ENABLED:-/etc/nginx/sites-enabled/infiproxy.conf}"

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RELEASE_BIN="${ROOT_DIR}/target/release/stealthhub-panel"

usage() {
    cat <<'USAGE'
Usage: sudo bash deploy/install.sh [--build] [--force-env] [--with-nginx] [--check]

Installs Infiproxy for bare-metal systemd deployment.

Options:
  --build       Build target/release/stealthhub-panel before installing.
  --force-env   Overwrite /etc/infiproxy/infiproxy.env.
  --with-nginx  Install nginx site template and enable it when nginx exists.
  --check       Print install plan and validate inputs without changing files.
USAGE
}

BUILD=0
FORCE_ENV=0
WITH_NGINX=0
CHECK_ONLY=0

while [[ $# -gt 0 ]]; do
    case "$1" in
        --build)
            BUILD=1
            shift
            ;;
        --force-env)
            FORCE_ENV=1
            shift
            ;;
        --with-nginx)
            WITH_NGINX=1
            shift
            ;;
        --check)
            CHECK_ONLY=1
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "Unknown argument: $1" >&2
            usage >&2
            exit 2
            ;;
    esac
done

if [[ "$(id -u)" -ne 0 && "$CHECK_ONLY" -eq 0 ]]; then
    echo "Run as root: sudo bash deploy/install.sh" >&2
    exit 1
fi

need_cmd() {
    if ! command -v "$1" >/dev/null 2>&1; then
        echo "Missing required command: $1" >&2
        exit 1
    fi
}

if [[ "$CHECK_ONLY" -eq 1 ]]; then
    echo "Preflight commands:"
    for cmd in getent groupadd id install systemctl useradd; do
        if command -v "$cmd" >/dev/null 2>&1; then
            echo "  $cmd: found"
        else
            echo "  $cmd: missing"
        fi
    done
else
    need_cmd getent
    need_cmd groupadd
    need_cmd id
    need_cmd install
    need_cmd systemctl
    need_cmd useradd
fi

if [[ ! -f "${ROOT_DIR}/deploy/infiproxy-manager.sh" ]]; then
    echo "Manager script not found: ${ROOT_DIR}/deploy/infiproxy-manager.sh" >&2
    exit 1
fi
if [[ ! -f "${ROOT_DIR}/deploy/panel-update.sh" ]]; then
    echo "Panel updater script not found: ${ROOT_DIR}/deploy/panel-update.sh" >&2
    exit 1
fi

if [[ "$BUILD" -eq 1 ]]; then
    if ! command -v cargo >/dev/null 2>&1; then
        echo "cargo is required for --build" >&2
        exit 1
    fi
    cargo build --release -p stealthhub-panel --manifest-path "${ROOT_DIR}/Cargo.toml"
fi

if [[ ! -x "$RELEASE_BIN" && "$CHECK_ONLY" -eq 0 ]]; then
    echo "Release binary not found: $RELEASE_BIN" >&2
    echo "Run: cargo build --release -p stealthhub-panel" >&2
    exit 1
fi

cat <<EOF
Infiproxy install plan:
  binary:        $INSTALL_BIN
  manager:       $MANAGER_BIN
  updater:       $UPDATE_BIN
  release bin:   $RELEASE_BIN
  config:        $ENV_FILE
  state:         $STATE_DIR
  core binaries: $CORE_DIR
  core configs:  $CORE_CONFIG_DIR
  headscale cfg: /etc/headscale
  core logs:     $CORE_LOG_DIR
  service:       $SERVICE_FILE
  updater units: $UPDATE_SERVICE_FILE, $UPDATE_TIMER_FILE, $UPDATE_PATH_FILE
  nginx:         $WITH_NGINX
  web config:    /etc/infiproxy and /etc/infiproxy-cores are group-writable by $APP_GROUP
EOF

if [[ "$CHECK_ONLY" -eq 1 ]]; then
    echo "Check complete. No changes were made."
    exit 0
fi

if ! getent group "$APP_GROUP" >/dev/null 2>&1; then
    groupadd --system "$APP_GROUP"
fi

if ! id -u "$APP_USER" >/dev/null 2>&1; then
    useradd --system --home "$STATE_DIR" --shell /usr/sbin/nologin --gid "$APP_GROUP" "$APP_USER"
fi

install -d -o root -g "$APP_GROUP" -m 0770 "$CONFIG_DIR"
install -d -o root -g "$APP_GROUP" -m 0770 /etc/headscale
install -d -o "$APP_USER" -g "$APP_GROUP" -m 0750 "$STATE_DIR"
install -d -o root -g root -m 0755 "$(dirname "$INSTALL_BIN")"
install -d -o root -g root -m 0755 "$(dirname "$MANAGER_BIN")"
install -d -o root -g root -m 0755 "$(dirname "$UPDATE_BIN")"
install -d -o root -g root -m 0755 "$CORE_DIR"
install -d -o root -g "$APP_GROUP" -m 0770 "$CORE_CONFIG_DIR"
install -d -o "$APP_USER" -g "$APP_GROUP" -m 0750 "$CORE_LOG_DIR"

install -m 0755 "$RELEASE_BIN" "$INSTALL_BIN"
install -m 0755 "${ROOT_DIR}/deploy/infiproxy-manager.sh" "$MANAGER_BIN"
install -m 0755 "${ROOT_DIR}/deploy/panel-update.sh" "$UPDATE_BIN"

if [[ ! -f "$ENV_FILE" || "$FORCE_ENV" -eq 1 ]]; then
    if [[ -f "$ENV_FILE" ]]; then
        cp -a "$ENV_FILE" "${ENV_FILE}.bak.$(date +%Y%m%d%H%M%S)"
    fi
    install -m 0660 -o root -g "$APP_GROUP" "${ROOT_DIR}/deploy/infiproxy.env.example" "$ENV_FILE"
else
    echo "Keeping existing env file: $ENV_FILE"
fi
chown root:"$APP_GROUP" "$ENV_FILE"
chmod 0660 "$ENV_FILE"

install -m 0644 "${ROOT_DIR}/deploy/infiproxy.service" "$SERVICE_FILE"
install -m 0644 "${ROOT_DIR}/deploy/infiproxy-panel-update.service" "$UPDATE_SERVICE_FILE"
install -m 0644 "${ROOT_DIR}/deploy/infiproxy-panel-update.timer" "$UPDATE_TIMER_FILE"
install -m 0644 "${ROOT_DIR}/deploy/infiproxy-panel-update.path" "$UPDATE_PATH_FILE"

for service in "${ROOT_DIR}"/deploy/cores/systemd/*.service; do
    install -m 0644 "$service" "/etc/systemd/system/$(basename "$service")"
done

install -d -o root -g "$APP_GROUP" -m 0770 "$CORE_CONFIG_DIR/xray"
install -d -o root -g "$APP_GROUP" -m 0770 "$CORE_CONFIG_DIR/sing-box"
install -d -o root -g "$APP_GROUP" -m 0770 "$CORE_CONFIG_DIR/hysteria"
install -d -o root -g "$APP_GROUP" -m 0770 "$CORE_CONFIG_DIR/tuic"
install -d -o root -g "$APP_GROUP" -m 0770 "$CORE_CONFIG_DIR/mtproto"
install -d -o root -g "$APP_GROUP" -m 0770 "$CORE_CONFIG_DIR/tls"

if [[ ! -f "$CORE_CONFIG_DIR/xray/config.json" ]]; then
    install -m 0660 -o root -g "$APP_GROUP" "${ROOT_DIR}/deploy/cores/configs/xray.config.example.json" "$CORE_CONFIG_DIR/xray/config.json"
fi
if [[ ! -f "$CORE_CONFIG_DIR/sing-box/config.json" ]]; then
    install -m 0660 -o root -g "$APP_GROUP" "${ROOT_DIR}/deploy/cores/configs/sing-box.config.example.json" "$CORE_CONFIG_DIR/sing-box/config.json"
fi
if [[ ! -f "$CORE_CONFIG_DIR/hysteria/config.yaml" ]]; then
    install -m 0660 -o root -g "$APP_GROUP" "${ROOT_DIR}/deploy/cores/configs/hysteria.config.example.yaml" "$CORE_CONFIG_DIR/hysteria/config.yaml"
fi
if [[ ! -f "$CORE_CONFIG_DIR/tuic/config.json" ]]; then
    install -m 0660 -o root -g "$APP_GROUP" "${ROOT_DIR}/deploy/cores/configs/tuic.config.example.json" "$CORE_CONFIG_DIR/tuic/config.json"
fi
if [[ ! -f "$CORE_CONFIG_DIR/mtproto/mtproto.env" ]]; then
    install -m 0660 -o root -g "$APP_GROUP" "${ROOT_DIR}/deploy/cores/configs/mtproto.env.example" "$CORE_CONFIG_DIR/mtproto/mtproto.env"
fi
for config in \
    "$CORE_CONFIG_DIR/xray/config.json" \
    "$CORE_CONFIG_DIR/sing-box/config.json" \
    "$CORE_CONFIG_DIR/hysteria/config.yaml" \
    "$CORE_CONFIG_DIR/tuic/config.json" \
    "$CORE_CONFIG_DIR/mtproto/mtproto.env"
do
    chown root:"$APP_GROUP" "$config"
    chmod 0660 "$config"
done

if [[ "$WITH_NGINX" -eq 1 ]]; then
    if command -v nginx >/dev/null 2>&1; then
        install -d -o root -g root -m 0755 "$(dirname "$NGINX_AVAILABLE")"
        install -m 0644 "${ROOT_DIR}/deploy/nginx-infiproxy.conf.example" "$NGINX_AVAILABLE"
        if [[ -d "$(dirname "$NGINX_ENABLED")" && ! -e "$NGINX_ENABLED" ]]; then
            ln -s "$NGINX_AVAILABLE" "$NGINX_ENABLED"
        fi
        nginx -t || echo "Nginx template installed but validation failed; edit $NGINX_AVAILABLE before reload." >&2
    else
        echo "Nginx requested but nginx command was not found; skipping nginx site install." >&2
    fi
fi

systemctl daemon-reload
systemctl enable --now infiproxy.service
systemctl enable --now infiproxy-panel-update.timer
systemctl enable --now infiproxy-panel-update.path

echo "Infiproxy installed."
echo "Status: systemctl status infiproxy.service"
echo "Updater: systemctl list-timers infiproxy-panel-update.timer"
echo "Manager: sudo infiproxy-manager"
echo "HTTPS:  sudo infiproxy-manager  # choose HTTPS / Cloudflare setup"
echo "Health: curl http://127.0.0.1:8080/health"
echo "Ready:  curl http://127.0.0.1:8080/ready"
echo "Config: $ENV_FILE"
if [[ "$WITH_NGINX" -eq 1 ]]; then
    echo "Nginx:  $NGINX_AVAILABLE"
fi
echo "Core services are installed but not enabled until core binaries and final configs are ready."
