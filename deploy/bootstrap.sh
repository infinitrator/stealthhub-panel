#!/usr/bin/env bash
# One-command Infiproxy bootstrapper for fresh VPS hosts.
#
# Installs OS build dependencies, ensures Rust is available, syncs the source
# checkout and delegates the idempotent filesystem/systemd setup to install.sh.
set -euo pipefail
umask 027

REPO_URL="${STEALTHHUB_REPO:-https://github.com/infinitrator/stealthhub-panel.git}"
REF="${STEALTHHUB_REF:-main}"
SRC_DIR="${INFIPROXY_SRC_DIR:-${STEALTHHUB_SRC_DIR:-/opt/infiproxy/source}}"
WITH_NGINX=0
FORCE_ENV=0
CHECK_ONLY=0

usage() {
    cat <<'USAGE'
Usage: curl -fsSL https://raw.githubusercontent.com/infinitrator/stealthhub-panel/main/deploy/bootstrap.sh | sudo bash

Options:
  --repo <url>       Git repository URL. Default: https://github.com/infinitrator/stealthhub-panel.git
  --ref <ref>        Git branch, tag, or commit to install. Default: main
  --src-dir <path>   Source checkout directory. Default: /opt/infiproxy/source
  --with-nginx       Install nginx package together with build dependencies.
  --force-env        Replace /etc/infiproxy/infiproxy.env.
  --check            Validate source/dependencies and print install plan.
USAGE
}

require_value() {
    local flag="$1"
    local value="${2:-}"
    if [[ -z "$value" || "$value" == --* ]]; then
        echo "Missing value for $flag" >&2
        usage >&2
        exit 2
    fi
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --repo)
            require_value "$1" "${2:-}"
            REPO_URL="${2:-}"
            shift 2
            ;;
        --ref)
            require_value "$1" "${2:-}"
            REF="${2:-}"
            shift 2
            ;;
        --src-dir)
            require_value "$1" "${2:-}"
            SRC_DIR="${2:-}"
            shift 2
            ;;
        --with-nginx)
            WITH_NGINX=1
            shift
            ;;
        --force-env)
            FORCE_ENV=1
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
    echo "Run as root: curl -fsSL <bootstrap-url> | sudo bash" >&2
    exit 1
fi

echo "Infiproxy bootstrap:"
echo "  repo:      $REPO_URL"
echo "  ref:       $REF"
echo "  source:    $SRC_DIR"
echo "  nginx:     $WITH_NGINX"
echo "  force env: $FORCE_ENV"

need_cmd() {
    if ! command -v "$1" >/dev/null 2>&1; then
        echo "Missing command after dependency install: $1" >&2
        exit 1
    fi
}

if [[ "$CHECK_ONLY" -eq 1 ]]; then
    echo "Preflight:"
    for cmd in git cargo systemctl; do
        if command -v "$cmd" >/dev/null 2>&1; then
            echo "  $cmd: found"
        else
            echo "  $cmd: missing"
        fi
    done
    if [[ -x "${SRC_DIR}/deploy/install.sh" ]]; then
        bash "${SRC_DIR}/deploy/install.sh" --check
    else
        echo "  install plan: source checkout not found at ${SRC_DIR}"
    fi
    exit 0
fi

install_deps() {
    if command -v apt-get >/dev/null 2>&1; then
        local packages=(
            build-essential
            ca-certificates
            curl
            git
            libssl-dev
            pkg-config
            sqlite3
            unzip
            xz-utils
        )
        if [[ "$WITH_NGINX" -eq 1 ]]; then
            packages+=(nginx)
        fi
        export DEBIAN_FRONTEND=noninteractive
        apt-get update
        apt-get install -y "${packages[@]}"
    elif command -v dnf >/dev/null 2>&1; then
        local packages=(
            ca-certificates
            curl
            gcc
            gcc-c++
            git
            make
            openssl-devel
            pkgconf-pkg-config
            sqlite
            unzip
            xz
        )
        if [[ "$WITH_NGINX" -eq 1 ]]; then
            packages+=(nginx)
        fi
        dnf install -y "${packages[@]}"
    else
        echo "Unsupported package manager. Install git, curl, Rust, OpenSSL headers, pkg-config, SQLite, and build tools manually." >&2
        exit 1
    fi
}

ensure_rust() {
    if command -v cargo >/dev/null 2>&1; then
        return
    fi

    echo "Installing Rust stable toolchain with rustup..."
    local tmp_dir
    tmp_dir="$(mktemp -d)"
    trap 'rm -rf "$tmp_dir"' EXIT
    curl --proto '=https' --tlsv1.2 --fail --silent --show-error \
        https://sh.rustup.rs \
        --output "${tmp_dir}/rustup-init.sh"
    sh "${tmp_dir}/rustup-init.sh" -y --profile minimal --default-toolchain stable
    export PATH="/root/.cargo/bin:${PATH}"
}

sync_source() {
    install -d -m 0755 "$(dirname "$SRC_DIR")"

    if [[ -d "${SRC_DIR}/.git" ]]; then
        git -C "$SRC_DIR" remote set-url origin "$REPO_URL"
        git -C "$SRC_DIR" fetch --tags --prune origin
    elif [[ -e "$SRC_DIR" ]]; then
        echo "Source directory exists but is not a git checkout: $SRC_DIR" >&2
        exit 1
    else
        git clone "$REPO_URL" "$SRC_DIR"
    fi

    git -C "$SRC_DIR" checkout --force "$REF" 2>/dev/null \
        || git -C "$SRC_DIR" checkout --force "origin/$REF"
}

install_deps
ensure_rust
need_cmd cargo
need_cmd git
need_cmd systemctl

sync_source

cargo build --release -p stealthhub-panel --manifest-path "${SRC_DIR}/Cargo.toml"

install_args=()
if [[ "$FORCE_ENV" -eq 1 ]]; then
    install_args+=(--force-env)
fi
if [[ "$WITH_NGINX" -eq 1 ]]; then
    install_args+=(--with-nginx)
fi

bash "${SRC_DIR}/deploy/install.sh" "${install_args[@]}"

cat <<EOF

Infiproxy is installed.

Service:
  systemctl status infiproxy.service
  sudo infiproxy-manager

HTTPS:
  sudo infiproxy-manager
  Choose "HTTPS / Cloudflare setup" and follow the guided DNS + certificate flow.

Local health checks:
  curl http://127.0.0.1:8080/health
  curl http://127.0.0.1:8080/ready

First admin setup:
  Open https://<your-domain>/admin/setup after configuring HTTPS reverse proxy.
  Or use an SSH tunnel first: ssh -L 8080:127.0.0.1:8080 root@<server>

Source:
  ${SRC_DIR}
EOF
