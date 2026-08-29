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
MAX_ARCHIVE_BYTES=536870912
MAX_EXTRACTED_BYTES=1073741824
MAX_ARCHIVE_MEMBERS=4096

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

if [[ -n "$URL" && ! "$URL" =~ ^https:// ]]; then
    echo "Release URL must use HTTPS: $URL" >&2
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
PREVIOUS_TARGET="$(readlink -f "$CURRENT_LINK" 2>/dev/null || true)"
WAS_ENABLED=0
WAS_ACTIVE=0
ACTIVATION_FAILED=0

if [[ -n "$RESTART_SERVICE" ]]; then
    need_cmd systemctl
    systemctl is-enabled --quiet "$RESTART_SERVICE" 2>/dev/null && WAS_ENABLED=1
    systemctl is-active --quiet "$RESTART_SERVICE" 2>/dev/null && WAS_ACTIVE=1
fi

rm -rf "$STAGING_DIR"
install -d -m 0750 "$STAGING_DIR"
install -d -m 0755 "${CORE_ROOT}/${CORE}"

if [[ -n "$URL" ]]; then
    need_cmd curl
    ARCHIVE_NAME="${URL##*/}"
    ARCHIVE_PATH="${STAGING_DIR}/${ARCHIVE_NAME}"
    curl --fail --location --show-error \
        --proto '=https' --proto-redir '=https' --tlsv1.2 \
        --connect-timeout 15 --max-time 900 \
        --max-filesize "$MAX_ARCHIVE_BYTES" \
        --retry 3 --retry-delay 2 --retry-connrefused \
        --output "$ARCHIVE_PATH" "$URL"
else
    ARCHIVE_PATH="${STAGING_DIR}/${ARCHIVE##*/}"
    install -m 0644 "$ARCHIVE" "$ARCHIVE_PATH"
fi

ARCHIVE_SIZE="$(wc -c <"$ARCHIVE_PATH" | tr -d '[:space:]')"
if [[ ! "$ARCHIVE_SIZE" =~ ^[0-9]+$ ]] || ((ARCHIVE_SIZE > MAX_ARCHIVE_BYTES)); then
    echo "Release archive exceeds the ${MAX_ARCHIVE_BYTES}-byte safety limit" >&2
    exit 1
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

validate_tar_limits() {
    local archive="$1" compression="$2"
    LC_ALL=C tar --numeric-owner "-${compression}tvf" "$archive" | awk \
        -v max_bytes="$MAX_EXTRACTED_BYTES" -v max_members="$MAX_ARCHIVE_MEMBERS" '
        function is_date(value) {
            return value ~ /^[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]$/ \
                || value ~ /^(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)$/
        }
        {
            size = ""
            for (field_no = 2; field_no <= NF; field_no++) {
                if (is_date($field_no) && field_no > 2) {
                    size = $(field_no - 1)
                    break
                }
            }
            if (size !~ /^[0-9]+$/) exit 2
            total += size
            members += 1
            if (total > max_bytes || members > max_members) exit 1
        }
        END {
            if (members == 0) exit 3
        }
    '
}

validate_zip_limits() {
    local archive="$1"
    LC_ALL=C zipinfo -l "$archive" | awk \
        -v max_bytes="$MAX_EXTRACTED_BYTES" -v max_members="$MAX_ARCHIVE_MEMBERS" '
        $1 ~ /^[-d]/ {
            if ($4 !~ /^[0-9]+$/) exit 2
            total += $4
            members += 1
            if (total > max_bytes || members > max_members) exit 1
        }
        END {
            if (members == 0) exit 3
        }
    '
}

case "$ARCHIVE_PATH" in
    *.tar.gz|*.tgz)
        need_cmd tar
        tar -tzf "$ARCHIVE_PATH" | validate_member_names
        validate_tar_limits "$ARCHIVE_PATH" z \
            || { echo "Archive exceeds extraction safety limits" >&2; exit 1; }
        tar -tvzf "$ARCHIVE_PATH" | awk 'substr($1, 1, 1) !~ /[-d]/ { exit 1 }' \
            || { echo "Only regular files and directories are allowed in archives" >&2; exit 1; }
        tar --no-same-owner --no-same-permissions -xzf "$ARCHIVE_PATH" -C "$EXTRACT_DIR"
        ;;
    *.tar.xz|*.txz)
        need_cmd tar
        tar -tJf "$ARCHIVE_PATH" | validate_member_names
        validate_tar_limits "$ARCHIVE_PATH" J \
            || { echo "Archive exceeds extraction safety limits" >&2; exit 1; }
        tar -tvJf "$ARCHIVE_PATH" | awk 'substr($1, 1, 1) !~ /[-d]/ { exit 1 }' \
            || { echo "Only regular files and directories are allowed in archives" >&2; exit 1; }
        tar --no-same-owner --no-same-permissions -xJf "$ARCHIVE_PATH" -C "$EXTRACT_DIR"
        ;;
    *.zip)
        need_cmd unzip
        need_cmd zipinfo
        unzip -Z -1 "$ARCHIVE_PATH" | validate_member_names
        validate_zip_limits "$ARCHIVE_PATH" \
            || { echo "Archive exceeds extraction safety limits" >&2; exit 1; }
        zipinfo -l "$ARCHIVE_PATH" | awk 'NR > 3 && $1 ~ /^[bclps]/ { exit 1 }' \
            || { echo "Archive links and special files are not allowed" >&2; exit 1; }
        unzip -q "$ARCHIVE_PATH" -d "$EXTRACT_DIR"
        ;;
    *.gz)
        need_cmd dd
        need_cmd gzip
        # Read at most one MiB beyond the configured ceiling. This bounds a
        # gzip bomb before its output can consume unbounded disk space.
        gzip -cd -- "$ARCHIVE_PATH" \
            | dd bs=1048576 count=1025 of="${EXTRACT_DIR}/${BINARY}" 2>/dev/null
        extracted_size="$(wc -c <"${EXTRACT_DIR}/${BINARY}" | tr -d '[:space:]')"
        if [[ ! "$extracted_size" =~ ^[0-9]+$ ]] \
            || ((extracted_size > MAX_EXTRACTED_BYTES)); then
            echo "Compressed binary exceeds extraction safety limits" >&2
            exit 1
        fi
        chmod 0755 "${EXTRACT_DIR}/${BINARY}"
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
        mihomo)
            "$binary_path" -v >/dev/null 2>&1
            ;;
        sing-box|hysteria)
            "$binary_path" version >/dev/null 2>&1
            ;;
        xray)
            "$binary_path" version >/dev/null 2>&1 \
                || "$binary_path" --version >/dev/null 2>&1
            ;;
        tuic)
            "$binary_path" --version >/dev/null 2>&1
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
    if ! systemctl enable "$RESTART_SERVICE" \
        || ! systemctl restart "$RESTART_SERVICE"; then
        ACTIVATION_FAILED=1
    fi
    if [[ "$ACTIVATION_FAILED" -eq 0 ]]; then
        sleep 2
        systemctl is-active --quiet "$RESTART_SERVICE" || ACTIVATION_FAILED=1
    fi
    if [[ "$ACTIVATION_FAILED" -eq 1 ]]; then
        if [[ -n "$PREVIOUS_TARGET" && -d "$PREVIOUS_TARGET" ]]; then
            ROLLBACK_LINK="${CORE_ROOT}/${CORE}/.current.rollback.$$"
            rm -f -- "$ROLLBACK_LINK"
            if ! ln -s "$PREVIOUS_TARGET" "$ROLLBACK_LINK" \
                || ! mv -Tf "$ROLLBACK_LINK" "$CURRENT_LINK"; then
                rm -f -- "$ROLLBACK_LINK"
                echo "Failed to restore previous runtime link: ${PREVIOUS_TARGET}" >&2
            fi
        else
            rm -f -- "$CURRENT_LINK"
        fi
        if [[ "$WAS_ENABLED" -eq 1 ]]; then
            systemctl enable "$RESTART_SERVICE" >/dev/null 2>&1 || true
        else
            systemctl disable "$RESTART_SERVICE" >/dev/null 2>&1 || true
        fi
        if [[ "$WAS_ACTIVE" -eq 1 && -n "$PREVIOUS_TARGET" ]]; then
            systemctl restart "$RESTART_SERVICE" >/dev/null 2>&1 || true
        else
            systemctl stop "$RESTART_SERVICE" >/dev/null 2>&1 || true
        fi
        echo "${RESTART_SERVICE} failed after activation; previous runtime state was restored." >&2
        exit 1
    fi
    systemctl --no-pager --full status "$RESTART_SERVICE"
fi

echo "Installed ${CORE} ${VERSION}: ${CURRENT_LINK} -> ${TARGET_DIR}"
