#!/usr/bin/env bash
set -euo pipefail

APP_USER="${INFIPROXY_USER:-${STEALTHHUB_USER:-infiproxy}}"
APP_GROUP="${INFIPROXY_GROUP:-${STEALTHHUB_GROUP:-$APP_USER}}"
INSTALL_BIN="${INFIPROXY_INSTALL_BIN:-${STEALTHHUB_INSTALL_BIN:-/usr/local/bin/infiproxy}}"
CONFIG_DIR="${INFIPROXY_CONFIG_DIR:-${STEALTHHUB_CONFIG_DIR:-/etc/infiproxy}}"
STATE_DIR="${INFIPROXY_STATE_DIR:-${STEALTHHUB_STATE_DIR:-/var/lib/infiproxy}}"
CORE_DIR="${INFIPROXY_CORE_DIR:-${STEALTHHUB_CORE_DIR:-/opt/infiproxy/cores}}"
CORE_CONFIG_DIR="${INFIPROXY_CORE_CONFIG_DIR:-${STEALTHHUB_CORE_CONFIG_DIR:-/etc/infiproxy-cores}}"
CORE_LOG_DIR="${INFIPROXY_CORE_LOG_DIR:-${STEALTHHUB_CORE_LOG_DIR:-/var/log/infiproxy-cores}}"
SERVICE_FILE="${INFIPROXY_SERVICE_FILE:-${STEALTHHUB_SERVICE_FILE:-/etc/systemd/system/infiproxy.service}}"
ENV_FILE="${CONFIG_DIR}/infiproxy.env"

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RELEASE_BIN="${ROOT_DIR}/target/release/stealthhub-panel"

usage() {
    cat <<'USAGE'
Usage: sudo bash deploy/install.sh [--build] [--force-env]

Installs Infiproxy for bare-metal systemd deployment.

Options:
  --build       Build target/release/stealthhub-panel before installing.
  --force-env   Overwrite /etc/infiproxy/infiproxy.env.
USAGE
}

BUILD=0
FORCE_ENV=0

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

if [[ "$(id -u)" -ne 0 ]]; then
    echo "Run as root: sudo bash deploy/install.sh" >&2
    exit 1
fi

if [[ "$BUILD" -eq 1 ]]; then
    if ! command -v cargo >/dev/null 2>&1; then
        echo "cargo is required for --build" >&2
        exit 1
    fi
    cargo build --release -p stealthhub-panel --manifest-path "${ROOT_DIR}/Cargo.toml"
fi

if [[ ! -x "$RELEASE_BIN" ]]; then
    echo "Release binary not found: $RELEASE_BIN" >&2
    echo "Run: cargo build --release -p stealthhub-panel" >&2
    exit 1
fi

if ! getent group "$APP_GROUP" >/dev/null 2>&1; then
    groupadd --system "$APP_GROUP"
fi

if ! id -u "$APP_USER" >/dev/null 2>&1; then
    useradd --system --home "$STATE_DIR" --shell /usr/sbin/nologin --gid "$APP_GROUP" "$APP_USER"
fi

install -d -o root -g root -m 0755 "$CONFIG_DIR"
install -d -o "$APP_USER" -g "$APP_GROUP" -m 0750 "$STATE_DIR"
install -d -o root -g root -m 0755 "$(dirname "$INSTALL_BIN")"
install -d -o root -g root -m 0755 "$CORE_DIR"
install -d -o root -g root -m 0755 "$CORE_CONFIG_DIR"
install -d -o "$APP_USER" -g "$APP_GROUP" -m 0750 "$CORE_LOG_DIR"

install -m 0755 "$RELEASE_BIN" "$INSTALL_BIN"

if [[ ! -f "$ENV_FILE" || "$FORCE_ENV" -eq 1 ]]; then
    install -m 0640 -o root -g "$APP_GROUP" "${ROOT_DIR}/deploy/infiproxy.env.example" "$ENV_FILE"
else
    echo "Keeping existing env file: $ENV_FILE"
fi

install -m 0644 "${ROOT_DIR}/deploy/infiproxy.service" "$SERVICE_FILE"

for service in "${ROOT_DIR}"/deploy/cores/systemd/*.service; do
    install -m 0644 "$service" "/etc/systemd/system/$(basename "$service")"
done

install -d -o root -g "$APP_GROUP" -m 0750 "$CORE_CONFIG_DIR/xray"
install -d -o root -g "$APP_GROUP" -m 0750 "$CORE_CONFIG_DIR/sing-box"
install -d -o root -g "$APP_GROUP" -m 0750 "$CORE_CONFIG_DIR/hysteria"
install -d -o root -g "$APP_GROUP" -m 0750 "$CORE_CONFIG_DIR/tuic"
install -d -o root -g "$APP_GROUP" -m 0750 "$CORE_CONFIG_DIR/tls"

if [[ ! -f "$CORE_CONFIG_DIR/xray/config.json" ]]; then
    install -m 0640 -o root -g "$APP_GROUP" "${ROOT_DIR}/deploy/cores/configs/xray.config.example.json" "$CORE_CONFIG_DIR/xray/config.json"
fi
if [[ ! -f "$CORE_CONFIG_DIR/sing-box/config.json" ]]; then
    install -m 0640 -o root -g "$APP_GROUP" "${ROOT_DIR}/deploy/cores/configs/sing-box.config.example.json" "$CORE_CONFIG_DIR/sing-box/config.json"
fi
if [[ ! -f "$CORE_CONFIG_DIR/hysteria/config.yaml" ]]; then
    install -m 0640 -o root -g "$APP_GROUP" "${ROOT_DIR}/deploy/cores/configs/hysteria.config.example.yaml" "$CORE_CONFIG_DIR/hysteria/config.yaml"
fi
if [[ ! -f "$CORE_CONFIG_DIR/tuic/config.json" ]]; then
    install -m 0640 -o root -g "$APP_GROUP" "${ROOT_DIR}/deploy/cores/configs/tuic.config.example.json" "$CORE_CONFIG_DIR/tuic/config.json"
fi

systemctl daemon-reload
systemctl enable --now infiproxy.service

echo "Infiproxy installed."
echo "Status: systemctl status infiproxy.service"
echo "Health: curl http://127.0.0.1:8080/health"
echo "Config: $ENV_FILE"
echo "Core services are installed but not enabled until core binaries and final configs are ready."
