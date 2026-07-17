#!/usr/bin/env bash
# Verified proxy-core installer.
#
# Downloads or reads a release archive, verifies SHA256, installs it into a
# versioned core directory and atomically updates the `current` symlink. Optional
# service restart is restricted to the expected Infiproxy core unit.
set -euo pipefail

CORE_ROOT="${INFIPROXY_CORE_ROOT:-${STEALTHHUB_CORE_ROOT:-/opt/infiproxy/cores}}"
STAGING_ROOT="${INFIPROXY_CORE_STAGING:-${STEALTHHUB_CORE_STAGING:-/var/lib/infiproxy-maintenance/core-updates}}"

CORE=""
VERSION=""
URL=""
SHA256=""
BINARY=""
ARCHIVE=""
RESTART_SERVICE=""

usage() {
    cat <<'USAGE'
Usage:
  sudo deploy/cores/install-core.sh --core <module-id> \
    --version <version> --url <release-url> --sha256 <sha256> --binary <binary-name> \
    [--restart <systemd-service>]

  sudo deploy/cores/install-core.sh --core <name> --version <version> \
    --archive ./release.tar.gz --sha256 <sha256> --binary <binary-name>

The script stages the archive, verifies SHA256, installs into a versioned
directory, then atomically switches the current symlink.
USAGE
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --core)
            CORE="${2:-}"
            shift 2
            ;;
        --version)
            VERSION="${2:-}"
            shift 2
            ;;
        --url)
            URL="${2:-}"
            shift 2
            ;;
        --sha256)
            SHA256="${2:-}"
            shift 2
            ;;
        --binary)
            BINARY="${2:-}"
            shift 2
            ;;
        --archive)
            ARCHIVE="${2:-}"
            shift 2
            ;;
        --restart)
            RESTART_SERVICE="${2:-}"
            shift 2
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
    echo "Run as root: sudo deploy/cores/install-core.sh ..." >&2
    exit 1
fi

if [[ ! "$CORE" =~ ^[a-z][a-z0-9-]{0,31}$ ]]; then
    echo "Invalid core ID: $CORE" >&2
    usage >&2
    exit 2
fi

if [[ -z "$VERSION" || -z "$SHA256" || -z "$BINARY" ]]; then
    echo "--version, --sha256 and --binary are required" >&2
    usage >&2
    exit 2
fi

if [[ ! "$VERSION" =~ ^[A-Za-z0-9._+-]+$ ]]; then
    echo "Invalid version. Use only letters, digits, dot, underscore, plus, and dash." >&2
    exit 2
fi

if [[ ! "$BINARY" =~ ^[A-Za-z0-9._+-]+$ ]]; then
    echo "Invalid binary name. Use only letters, digits, dot, underscore, plus, and dash." >&2
    exit 2
fi

if [[ ! "$SHA256" =~ ^[A-Fa-f0-9]{64}$ ]]; then
    echo "Invalid SHA256. Expected 64 hexadecimal characters." >&2
    exit 2
fi

expected_service() {
    echo "infiproxy-${CORE}.service"
}

if [[ -n "$RESTART_SERVICE" && "$RESTART_SERVICE" != "$(expected_service)" ]]; then
    echo "Refusing to restart unrelated service: $RESTART_SERVICE" >&2
    echo "Expected for $CORE: $(expected_service)" >&2
    exit 2
fi

if [[ -n "$URL" && -n "$ARCHIVE" ]]; then
    echo "Use either --url or --archive, not both" >&2
    exit 2
fi

if [[ -z "$URL" && -z "$ARCHIVE" ]]; then
    echo "Either --url or --archive is required" >&2
    exit 2
fi

need_cmd() {
    if ! command -v "$1" >/dev/null 2>&1; then
        echo "Missing command: $1" >&2
        exit 1
    fi
}

need_cmd sha256sum
need_cmd find
need_cmd install

STAGING_DIR="${STAGING_ROOT}/${CORE}/${VERSION}"
TARGET_DIR="${CORE_ROOT}/${CORE}/${VERSION}"
CURRENT_LINK="${CORE_ROOT}/${CORE}/current"
NEXT_LINK="${CORE_ROOT}/${CORE}/.current.${VERSION}.next"

rm -rf "$STAGING_DIR"
install -d -m 0750 "$STAGING_DIR"
install -d -m 0755 "${CORE_ROOT}/${CORE}"

if [[ -n "$URL" ]]; then
    need_cmd curl
    ARCHIVE_NAME="${URL##*/}"
    ARCHIVE_PATH="${STAGING_DIR}/${ARCHIVE_NAME}"
    curl --fail --location --show-error --output "$ARCHIVE_PATH" "$URL"
else
    ARCHIVE_PATH="${STAGING_DIR}/${ARCHIVE##*/}"
    install -m 0644 "$ARCHIVE" "$ARCHIVE_PATH"
fi

printf '%s  %s\n' "$SHA256" "$ARCHIVE_PATH" | sha256sum -c -

EXTRACT_DIR="${STAGING_DIR}/extract"
install -d -m 0750 "$EXTRACT_DIR"

validate_member_names() {
    local member
    while IFS= read -r member; do
        case "$member" in
            ""|/*|../*|*/../*|*/..|*\\*)
                echo "Unsafe archive member: $member" >&2
                return 1
                ;;
        esac
    done
}

case "$ARCHIVE_PATH" in
    *.tar.gz|*.tgz)
        need_cmd tar
        tar -tzf "$ARCHIVE_PATH" | validate_member_names
        tar -tvzf "$ARCHIVE_PATH" | awk 'substr($1, 1, 1) ~ /[lh]/ { exit 1 }' \
            || { echo "Archive links are not allowed" >&2; exit 1; }
        tar --no-same-owner --no-same-permissions -xzf "$ARCHIVE_PATH" -C "$EXTRACT_DIR"
        ;;
    *.tar.xz|*.txz)
        need_cmd tar
        tar -tJf "$ARCHIVE_PATH" | validate_member_names
        tar -tvJf "$ARCHIVE_PATH" | awk 'substr($1, 1, 1) ~ /[lh]/ { exit 1 }' \
            || { echo "Archive links are not allowed" >&2; exit 1; }
        tar --no-same-owner --no-same-permissions -xJf "$ARCHIVE_PATH" -C "$EXTRACT_DIR"
        ;;
    *.zip)
        need_cmd unzip
        need_cmd zipinfo
        unzip -Z -1 "$ARCHIVE_PATH" | validate_member_names
        zipinfo -l "$ARCHIVE_PATH" | awk '$1 ~ /^l/ { exit 1 }' \
            || { echo "Archive links are not allowed" >&2; exit 1; }
        unzip -q "$ARCHIVE_PATH" -d "$EXTRACT_DIR"
        ;;
    *)
        install -m 0755 "$ARCHIVE_PATH" "${EXTRACT_DIR}/${BINARY}"
        ;;
esac

FOUND_BINARY="$(find "$EXTRACT_DIR" -type f -name "$BINARY" -perm -u+x -print -quit)"
if [[ -z "$FOUND_BINARY" ]]; then
    FOUND_BINARY="$(find "$EXTRACT_DIR" -type f -name "$BINARY" -print -quit)"
fi

if [[ -z "$FOUND_BINARY" ]]; then
    echo "Binary not found in archive: $BINARY" >&2
    exit 1
fi

rm -rf "$TARGET_DIR"
install -d -m 0755 "$TARGET_DIR"
install -m 0755 "$FOUND_BINARY" "${TARGET_DIR}/${BINARY}"

smoke_test_binary() {
    local binary_path="$1"

    case "$CORE" in
        mtproto)
            ("$binary_path" --help 2>&1 || true) | grep -Eiq 'mtproto|proxy|usage' \
                || ("$binary_path" -h 2>&1 || true) | grep -Eiq 'mtproto|proxy|usage'
            ;;
        *)
            "$binary_path" --version >/dev/null 2>&1
            ;;
    esac
}

smoke_test_binary "${TARGET_DIR}/${BINARY}" || {
    echo "${BINARY} smoke test failed; current symlink was not changed." >&2
    exit 1
}

ln -sfn "$TARGET_DIR" "$NEXT_LINK"
mv -Tf "$NEXT_LINK" "$CURRENT_LINK"

if [[ -n "$RESTART_SERVICE" ]]; then
    systemctl enable "$RESTART_SERVICE"
    systemctl restart "$RESTART_SERVICE"
    systemctl --no-pager --full status "$RESTART_SERVICE"
fi

echo "Installed ${CORE} ${VERSION}: ${CURRENT_LINK} -> ${TARGET_DIR}"
