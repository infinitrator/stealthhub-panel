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
MODULE_UPDATE_BIN="${INFIPROXY_MODULE_UPDATE_BIN:-/usr/local/sbin/infiproxy-module-update}"
MODULE_MANIFEST_HELPER="${INFIPROXY_MODULE_MANIFEST_HELPER:-/usr/local/libexec/infiproxy-module-manifest}"
HEADSCALE_CONTROL_HELPER="${INFIPROXY_HEADSCALE_CONTROL_HELPER:-/usr/local/libexec/infiproxy-headscale-control}"
CORE_INSTALL_BIN="${INFIPROXY_CORE_INSTALL_BIN:-/usr/local/sbin/infiproxy-core-install}"
CONFIG_DIR="${INFIPROXY_CONFIG_DIR:-${STEALTHHUB_CONFIG_DIR:-/etc/infiproxy}}"
STATE_DIR="${INFIPROXY_STATE_DIR:-${STEALTHHUB_STATE_DIR:-/var/lib/infiproxy}}"
ROOT_STATE_DIR="${INFIPROXY_ROOT_STATE_DIR:-/var/lib/infiproxy-maintenance}"
MODULE_MANIFEST_DIR="${INFIPROXY_MODULE_MANIFEST_DIR:-/etc/infiproxy-modules.d}"
MODULE_AVAILABLE_DIR="${INFIPROXY_MODULE_AVAILABLE_DIR:-/etc/infiproxy-modules.available.d}"
CORE_DIR="${INFIPROXY_CORE_DIR:-${STEALTHHUB_CORE_DIR:-/opt/infiproxy/cores}}"
CORE_CONFIG_DIR="${INFIPROXY_CORE_CONFIG_DIR:-${STEALTHHUB_CORE_CONFIG_DIR:-/etc/infiproxy-cores}}"
CORE_LOG_DIR="${INFIPROXY_CORE_LOG_DIR:-${STEALTHHUB_CORE_LOG_DIR:-/var/log/infiproxy-cores}}"
SERVICE_FILE="${INFIPROXY_SERVICE_FILE:-${STEALTHHUB_SERVICE_FILE:-/etc/systemd/system/infiproxy.service}}"
UPDATE_SERVICE_FILE="${INFIPROXY_UPDATE_SERVICE_FILE:-/etc/systemd/system/infiproxy-panel-update.service}"
UPDATE_TIMER_FILE="${INFIPROXY_UPDATE_TIMER_FILE:-/etc/systemd/system/infiproxy-panel-update.timer}"
UPDATE_PATH_FILE="${INFIPROXY_UPDATE_PATH_FILE:-/etc/systemd/system/infiproxy-panel-update.path}"
MODULE_UPDATE_SERVICE_FILE="${INFIPROXY_MODULE_UPDATE_SERVICE_FILE:-/etc/systemd/system/infiproxy-module-update.service}"
MODULE_UPDATE_TIMER_FILE="${INFIPROXY_MODULE_UPDATE_TIMER_FILE:-/etc/systemd/system/infiproxy-module-update.timer}"
MODULE_UPDATE_PATH_FILE="${INFIPROXY_MODULE_UPDATE_PATH_FILE:-/etc/systemd/system/infiproxy-module-update.path}"
PROFILE_FILE="${INFIPROXY_PROFILE_FILE:-/etc/profile.d/infiproxy-manager.sh}"
UPDATE_CONFIG_FILE="${INFIPROXY_UPDATE_CONFIG_FILE:-/etc/infiproxy-update.conf}"
ENV_FILE="${CONFIG_DIR}/infiproxy.env"
NGINX_AVAILABLE="${INFIPROXY_NGINX_AVAILABLE:-/etc/nginx/sites-available/infiproxy.conf}"
NGINX_ENABLED="${INFIPROXY_NGINX_ENABLED:-/etc/nginx/sites-enabled/infiproxy.conf}"

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RELEASE_BIN="${ROOT_DIR}/target/release/stealthhub-panel"
RELEASE_MANIFEST_HELPER="${ROOT_DIR}/target/release/infiproxy-module-manifest"
RELEASE_HEADSCALE_HELPER="${ROOT_DIR}/target/release/infiproxy-headscale-control"

normalize_github_repo() {
    local value="$1"
    value="${value#https://github.com/}"
    value="${value#http://github.com/}"
    value="${value#git@github.com:}"
    value="${value%.git}"
    [[ "$value" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]] || return 1
    printf '%s' "$value"
}

source_origin="${INFIPROXY_UPDATE_REPO:-$(git -C "$ROOT_DIR" remote get-url origin 2>/dev/null || true)}"
UPDATE_REPO="$(normalize_github_repo "$source_origin")" || {
    echo "Update source must be a GitHub owner/repo or repository URL: $source_origin" >&2
    exit 2
}
UPDATE_REF="${INFIPROXY_UPDATE_REF:-$(git -C "$ROOT_DIR" branch --show-current 2>/dev/null || true)}"
UPDATE_REF="${UPDATE_REF:-main}"
if [[ ! "$UPDATE_REF" =~ ^[A-Za-z0-9_./-]+$ || "$UPDATE_REF" == /* || "$UPDATE_REF" == *..* ]]; then
    echo "Invalid update reference: $UPDATE_REF" >&2
    exit 2
fi

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

required_deploy_files=(
    deploy/infiproxy-manager.sh
    deploy/panel-update.sh
    deploy/module-update.sh
    deploy/cores/install-core.sh
    deploy/infiproxy-profile.sh
    deploy/infiproxy.service
    deploy/infiproxy-panel-update.service
    deploy/infiproxy-panel-update.timer
    deploy/infiproxy-panel-update.path
    deploy/infiproxy-module-update.service
    deploy/infiproxy-module-update.timer
    deploy/infiproxy-module-update.path
)
for relative_path in "${required_deploy_files[@]}"; do
    if [[ ! -f "${ROOT_DIR}/${relative_path}" ]]; then
        echo "Required deployment file not found: ${ROOT_DIR}/${relative_path}" >&2
        exit 1
    fi
done

if [[ "$BUILD" -eq 1 ]]; then
    if ! command -v cargo >/dev/null 2>&1; then
        echo "cargo is required for --build" >&2
        exit 1
    fi
    cargo build --release -p stealthhub-panel --manifest-path "${ROOT_DIR}/Cargo.toml"
fi

shopt -s nullglob
bundled_manifests=("${ROOT_DIR}"/deploy/modules.d/*.module)
shopt -u nullglob
if [[ "${#bundled_manifests[@]}" -eq 0 ]]; then
    echo "No bundled module manifests found in ${ROOT_DIR}/deploy/modules.d" >&2
    exit 1
fi
SOURCE_MANIFEST_HELPER="$RELEASE_MANIFEST_HELPER"
if [[ ! -x "$SOURCE_MANIFEST_HELPER" && -x "${ROOT_DIR}/target/debug/infiproxy-module-manifest" ]]; then
    SOURCE_MANIFEST_HELPER="${ROOT_DIR}/target/debug/infiproxy-module-manifest"
fi
if [[ -x "$SOURCE_MANIFEST_HELPER" ]]; then
    "$SOURCE_MANIFEST_HELPER" list "${ROOT_DIR}/deploy/modules.d" >/dev/null
    echo "  module manifests: validated by $SOURCE_MANIFEST_HELPER"
elif [[ "$CHECK_ONLY" -eq 1 ]]; then
    echo "  module manifests: validation deferred until the Rust helper is built"
else
    echo "Release helper not found: $RELEASE_MANIFEST_HELPER" >&2
    echo "Run: cargo build --release -p stealthhub-panel" >&2
    exit 1
fi
if [[ ! -x "$RELEASE_HEADSCALE_HELPER" && "$CHECK_ONLY" -eq 0 ]]; then
    echo "Release helper not found: $RELEASE_HEADSCALE_HELPER" >&2
    echo "Run: cargo build --release -p stealthhub-panel" >&2
    exit 1
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
  module updater:$MODULE_UPDATE_BIN
  module helper: $MODULE_MANIFEST_HELPER
  Headscale helper:$HEADSCALE_CONTROL_HELPER
  core installer:$CORE_INSTALL_BIN
  release bin:   $RELEASE_BIN
  release helper:$RELEASE_MANIFEST_HELPER
  Headscale release helper:$RELEASE_HEADSCALE_HELPER
  config:        $ENV_FILE
  state:         $STATE_DIR
  root state:    $ROOT_STATE_DIR
  module registry:$MODULE_MANIFEST_DIR
  module catalog: $MODULE_AVAILABLE_DIR
  core binaries: $CORE_DIR
  core configs:  $CORE_CONFIG_DIR
  headscale cfg: /etc/headscale
  core logs:     $CORE_LOG_DIR
  service:       $SERVICE_FILE
  updater units: $UPDATE_SERVICE_FILE, $UPDATE_TIMER_FILE, $UPDATE_PATH_FILE
  module units:  $MODULE_UPDATE_SERVICE_FILE, $MODULE_UPDATE_TIMER_FILE, $MODULE_UPDATE_PATH_FILE
  SSH launcher:  $PROFILE_FILE
  update source: $UPDATE_REPO @ $UPDATE_REF ($UPDATE_CONFIG_FILE)
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
install -d -o root -g root -m 0751 "$ROOT_STATE_DIR"
install -d -o root -g "$APP_GROUP" -m 0750 "$ROOT_STATE_DIR/module-versions"
install -d -o root -g root -m 0750 "$ROOT_STATE_DIR/module-disabled"
install -d -o root -g root -m 0755 "$MODULE_MANIFEST_DIR"
install -d -o root -g root -m 0755 "$MODULE_AVAILABLE_DIR"
install -d -o root -g root -m 0755 "$(dirname "$INSTALL_BIN")"
install -d -o root -g root -m 0755 "$(dirname "$MANAGER_BIN")"
install -d -o root -g root -m 0755 "$(dirname "$UPDATE_BIN")"
install -d -o root -g root -m 0755 "$(dirname "$MODULE_UPDATE_BIN")"
install -d -o root -g root -m 0755 "$(dirname "$MODULE_MANIFEST_HELPER")"
install -d -o root -g root -m 0755 "$(dirname "$HEADSCALE_CONTROL_HELPER")"
install -d -o root -g root -m 0755 "$CORE_DIR"
install -d -o root -g "$APP_GROUP" -m 0770 "$CORE_CONFIG_DIR"
install -d -o "$APP_USER" -g "$APP_GROUP" -m 0750 "$CORE_LOG_DIR"
install -d -o "$APP_USER" -g "$APP_GROUP" -m 0750 "$STATE_DIR/modules"
install -d -o "$APP_USER" -g "$APP_GROUP" -m 0750 "$STATE_DIR/module-requests"
install -d -o "$APP_USER" -g "$APP_GROUP" -m 0750 "$STATE_DIR/headscale-requests"
install -d -o root -g root -m 0700 "$ROOT_STATE_DIR/headscale-processing"

# Recover SQLite files that a previously interrupted root-run install may have
# created before the unprivileged panel service was started.
find "$STATE_DIR" -maxdepth 1 -type f -name 'infiproxy.sqlite*' \
    -exec chown "$APP_USER:$APP_GROUP" {} + \
    -exec chmod 0640 {} +

install -m 0755 "$RELEASE_BIN" "$INSTALL_BIN"
install -m 0755 "${ROOT_DIR}/deploy/infiproxy-manager.sh" "$MANAGER_BIN"
install -m 0755 "${ROOT_DIR}/deploy/panel-update.sh" "$UPDATE_BIN"
install -m 0755 "${ROOT_DIR}/deploy/module-update.sh" "$MODULE_UPDATE_BIN"
install -m 0755 "$RELEASE_MANIFEST_HELPER" "$MODULE_MANIFEST_HELPER"
install -m 0755 "$RELEASE_HEADSCALE_HELPER" "$HEADSCALE_CONTROL_HELPER"
install -m 0755 "${ROOT_DIR}/deploy/cores/install-core.sh" "$CORE_INSTALL_BIN"
install -m 0644 "${ROOT_DIR}/deploy/infiproxy-profile.sh" "$PROFILE_FILE"
if [[ ! -f "$STATE_DIR/headscale-state.json" ]]; then
    printf '{"updated_at":"","status":"waiting for first maintenance refresh","users":"","nodes":"","last_result":"","result_is_secret":false}\n' \
        | install -m 0640 -o root -g "$APP_GROUP" /dev/stdin "$STATE_DIR/headscale-state.json"
else
    chown root:"$APP_GROUP" "$STATE_DIR/headscale-state.json"
    chmod 0640 "$STATE_DIR/headscale-state.json"
fi
install -m 0644 -o root -g root /dev/stdin "$UPDATE_CONFIG_FILE" <<EOF
REPO=${UPDATE_REPO}
REF=${UPDATE_REF}
EOF

for manifest in "${bundled_manifests[@]}"; do
    module_id="$(basename "$manifest" .module)"
    install -m 0644 -o root -g root "$manifest" "$MODULE_AVAILABLE_DIR/${module_id}.module"
    if [[ ! -e "$ROOT_STATE_DIR/module-disabled/${module_id}" \
        && ! -e "$MODULE_MANIFEST_DIR/${module_id}.module" ]]; then
        install -m 0644 -o root -g root "$manifest" "$MODULE_MANIFEST_DIR/${module_id}.module"
    fi
done

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
install -m 0644 "${ROOT_DIR}/deploy/infiproxy-module-update.service" "$MODULE_UPDATE_SERVICE_FILE"
install -m 0644 "${ROOT_DIR}/deploy/infiproxy-module-update.timer" "$MODULE_UPDATE_TIMER_FILE"
install -m 0644 "${ROOT_DIR}/deploy/infiproxy-module-update.path" "$MODULE_UPDATE_PATH_FILE"

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
        if [[ ! -e "$NGINX_AVAILABLE" ]]; then
            install -m 0644 "${ROOT_DIR}/deploy/nginx-infiproxy.conf.example" "$NGINX_AVAILABLE"
        else
            echo "Keeping existing Nginx config: $NGINX_AVAILABLE"
        fi
        if [[ -d "$(dirname "$NGINX_ENABLED")" && ! -e "$NGINX_ENABLED" ]]; then
            ln -s "$NGINX_AVAILABLE" "$NGINX_ENABLED"
        fi
        nginx -t || echo "Nginx template installed but validation failed; edit $NGINX_AVAILABLE before reload." >&2
    else
        echo "Nginx requested but nginx command was not found; skipping nginx site install." >&2
    fi
fi

systemctl daemon-reload
systemctl enable infiproxy.service
systemctl restart infiproxy.service
systemctl enable --now infiproxy-panel-update.timer
systemctl enable --now infiproxy-panel-update.path
systemctl enable --now infiproxy-module-update.timer
systemctl enable --now infiproxy-module-update.path

echo "Infiproxy installed."
echo "Status: systemctl status infiproxy.service"
echo "Updater: systemctl list-timers infiproxy-panel-update.timer"
echo "Modules: systemctl list-timers infiproxy-module-update.timer"
echo "Manager: sudo infiproxy-manager"
echo "HTTPS:  sudo infiproxy-manager  # choose HTTPS / Cloudflare setup"
echo "Health: curl http://127.0.0.1:8080/health"
echo "Ready:  curl http://127.0.0.1:8080/ready"
echo "Config: $ENV_FILE"
if [[ "$WITH_NGINX" -eq 1 ]]; then
    echo "Nginx:  $NGINX_AVAILABLE"
fi
echo "Core services are installed but not enabled until core binaries and final configs are ready."
