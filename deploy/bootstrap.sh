#!/usr/bin/env bash
set -euo pipefail

REPO_URL="${STEALTHHUB_REPO:-https://github.com/infinitrator/stealthhub-panel.git}"
REF="${STEALTHHUB_REF:-main}"
SRC_DIR="${STEALTHHUB_SRC_DIR:-/opt/stealthhub-panel/source}"
WITH_NGINX=0
FORCE_ENV=0

usage() {
    cat <<'USAGE'
Usage: curl -fsSL https://raw.githubusercontent.com/infinitrator/stealthhub-panel/main/deploy/bootstrap.sh | sudo bash

Options:
  --repo <url>       Git repository URL. Default: https://github.com/infinitrator/stealthhub-panel.git
  --ref <ref>        Git branch, tag, or commit to install. Default: main
  --src-dir <path>   Source checkout directory. Default: /opt/stealthhub-panel/source
  --with-nginx       Install nginx package together with build dependencies.
  --force-env        Replace /etc/stealthhub-panel/stealthhub-panel.env.
USAGE
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --repo)
            REPO_URL="${2:-}"
            shift 2
            ;;
        --ref)
            REF="${2:-}"
            shift 2
            ;;
        --src-dir)
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
    echo "Run as root: curl -fsSL <bootstrap-url> | sudo bash" >&2
    exit 1
fi

need_cmd() {
    if ! command -v "$1" >/dev/null 2>&1; then
        echo "Missing command after dependency install: $1" >&2
        exit 1
    fi
}

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

bash "${SRC_DIR}/deploy/install.sh" "${install_args[@]}"

cat <<EOF

StealthHub Panel is installed.

Service:
  systemctl status stealthhub-panel.service

Local health checks:
  curl http://127.0.0.1:8080/health
  curl http://127.0.0.1:8080/ready

First admin setup:
  Open https://<your-domain>/admin/setup after configuring HTTPS reverse proxy.

Source:
  ${SRC_DIR}
EOF
