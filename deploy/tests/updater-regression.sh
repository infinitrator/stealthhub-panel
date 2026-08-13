#!/usr/bin/env bash
# Offline regression tests for release downloads, smoke tests and update backups.
# shellcheck disable=SC2030,SC2031
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TMP_DIR="$(mktemp -d)"
TMP_DIR="$(cd "$TMP_DIR" && pwd -P)"
trap 'rm -rf "$TMP_DIR"' EXIT

fail() {
    echo "FAIL: $*" >&2
    exit 1
}

assert_file_contains() {
    local file="$1" expected="$2"
    grep -Fqx -- "$expected" "$file" \
        || fail "${file} does not contain exact line: ${expected}"
}

FAKE_BIN="${TMP_DIR}/bin"
mkdir -p "$FAKE_BIN"
cat >"${FAKE_BIN}/id" <<'EOF'
#!/usr/bin/env bash
if [[ "${1:-}" == "-u" ]]; then
    echo 0
else
    exec /usr/bin/id "$@"
fi
EOF
chmod +x "${FAKE_BIN}/id"
cat >"${FAKE_BIN}/mv" <<'EOF'
#!/usr/bin/env bash
# Darwin lacks GNU mv -T; emulate only the atomic-link test invocation locally.
if [[ "${1:-}" == "-Tf" && $# -eq 3 ]]; then
    rm -f -- "$3"
    exec /bin/mv -f -- "$2" "$3"
fi
exec /bin/mv "$@"
EOF
chmod +x "${FAKE_BIN}/mv"
cat >"${FAKE_BIN}/install" <<'EOF'
#!/usr/bin/env bash
args=()
while [[ $# -gt 0 ]]; do
    if [[ "$1" == "-o" || "$1" == "-g" ]]; then
        shift 2
    else
        args+=("$1")
        shift
    fi
done
exec /usr/bin/install "${args[@]}"
EOF
chmod +x "${FAKE_BIN}/install"

make_fake_core() {
    local target="$1"
    cat >"$target" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' "$*" >>"$SMOKE_ARGS_FILE"
if [[ "$*" == "$SMOKE_ACCEPT" ]]; then
    echo "usage: test proxy"
    exit 0
fi
exit 1
EOF
    chmod +x "$target"
}

install_fake_core() {
    local core="$1" expected="$2" root="$3" version="test-1"
    local archive="${TMP_DIR}/${core}-release" checksum args_file
    args_file="${TMP_DIR}/${core}-smoke.args"
    : >"$args_file"
    make_fake_core "$archive"
    checksum="$(sha256sum "$archive" | awk '{print $1}')"
    PATH="${FAKE_BIN}:${PATH}" \
        INFIPROXY_CORE_ROOT="$root" \
        INFIPROXY_CORE_STAGING="${TMP_DIR}/staging-${core}" \
        SMOKE_ARGS_FILE="$args_file" \
        SMOKE_ACCEPT="$expected" \
        bash "${ROOT_DIR}/deploy/cores/install-core.sh" \
            --core "$core" --version "$version" --archive "$archive" \
            --sha256 "$checksum" --binary "$core" >/dev/null
    assert_file_contains "$args_file" "$expected"
    [[ "$(readlink "${root}/${core}/current")" == "${root}/${core}/${version}" ]] \
        || fail "${core} current symlink was not switched after a successful smoke test"
}

CORE_ROOT="${TMP_DIR}/cores"
install_fake_core sing-box version "$CORE_ROOT"
install_fake_core hysteria version "$CORE_ROOT"
install_fake_core tuic --version "$CORE_ROOT"
install_fake_core mtproto --help "$CORE_ROOT"
install_fake_core custom --version "$CORE_ROOT"

install_fake_core xray --version "$CORE_ROOT"
assert_file_contains "${TMP_DIR}/xray-smoke.args" version
assert_file_contains "${TMP_DIR}/xray-smoke.args" --version
[[ "$(sed -n '1p' "${TMP_DIR}/xray-smoke.args")" == "version" \
    && "$(sed -n '2p' "${TMP_DIR}/xray-smoke.args")" == "--version" ]] \
    || fail "Xray did not use the version/--version compatibility order"

FAIL_ROOT="${TMP_DIR}/failed-smoke"
mkdir -p "${FAIL_ROOT}/sing-box/old"
ln -s "${FAIL_ROOT}/sing-box/old" "${FAIL_ROOT}/sing-box/current"
FAIL_ARCHIVE="${TMP_DIR}/failed-release"
FAIL_ARGS="${TMP_DIR}/failed-smoke.args"
: >"$FAIL_ARGS"
make_fake_core "$FAIL_ARCHIVE"
FAIL_SHA="$(sha256sum "$FAIL_ARCHIVE" | awk '{print $1}')"
if PATH="${FAKE_BIN}:${PATH}" \
    INFIPROXY_CORE_ROOT="$FAIL_ROOT" \
    INFIPROXY_CORE_STAGING="${TMP_DIR}/failed-staging" \
    SMOKE_ARGS_FILE="$FAIL_ARGS" SMOKE_ACCEPT="never" \
    bash "${ROOT_DIR}/deploy/cores/install-core.sh" \
        --core sing-box --version broken --archive "$FAIL_ARCHIVE" \
        --sha256 "$FAIL_SHA" --binary sing-box >/dev/null 2>&1
then
    fail "failed smoke test unexpectedly succeeded"
fi
[[ "$(readlink "${FAIL_ROOT}/sing-box/current")" == "${FAIL_ROOT}/sing-box/old" ]] \
    || fail "failed smoke test changed the current symlink"

cat >"${FAKE_BIN}/curl" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' "$@" >"$CURL_ARGS_FILE"
output=""
while [[ $# -gt 0 ]]; do
    if [[ "$1" == "--output" ]]; then
        output="$2"
        shift 2
    else
        shift
    fi
done
[[ -n "$output" ]] && printf 'download fixture\n' >"$output"
EOF
chmod +x "${FAKE_BIN}/curl"

(
    export PATH="${FAKE_BIN}:${PATH}"
    export INFIPROXY_STATE_DIR="${TMP_DIR}/module-state"
    export INFIPROXY_ROOT_STATE_DIR="${TMP_DIR}/module-root-state"
    export INFIPROXY_MODULE_UPDATE_LOG="${TMP_DIR}/module-update.log"
    export CURL_ARGS_FILE="${TMP_DIR}/curl.args"
    # shellcheck source=deploy/module-update.sh
    source "${ROOT_DIR}/deploy/module-update.sh"
    M_REPO="owner/repo"
    download_release_asset "${TMP_DIR}/release.bin" \
        "https://github.com/owner/repo/releases/download/v1/release.bin"
    for argument in --retry 3 --retry-all-errors --connect-timeout 15 --max-time 600; do
        assert_file_contains "$CURL_ARGS_FILE" "$argument"
    done
    if grep -Fqx -- --ipv4 "$CURL_ARGS_FILE"; then
        fail "IPv4 was forced without INFIPROXY_FORCE_IPV4=true"
    fi
    INFIPROXY_FORCE_IPV4=true download_release_asset "${TMP_DIR}/release-v4.bin" \
        "https://github.com/owner/repo/releases/download/v1/release.bin"
    assert_file_contains "$CURL_ARGS_FILE" --ipv4
    if (download_release_asset "${TMP_DIR}/untrusted" \
        "https://example.com/owner/repo/release.bin" >/dev/null 2>&1); then
        fail "untrusted release URL was accepted"
    fi
    if (resolve_checksum release.bin "" "" >/dev/null 2>&1); then
        fail "missing digest and checksum did not fail closed"
    fi

    M_ID="sing-box"
    M_ROOT="cores"
    M_CONFIG="${TMP_DIR}/configs/sing-box/config.json"
    mkdir -p "$(dirname "$M_CONFIG")"
    printf '{"preserved":true}\n' >"$M_CONFIG"
    backup_module_config 1 1
    grep -Fq '"preserved":true' "$M_CONFIG" \
        || fail "module config changed while it was being backed up"
    MODULE_ARCHIVE="$(find "$MODULE_BACKUP_ROOT/sing-box" -name config.tar.gz -print -quit)"
    [[ -f "$MODULE_ARCHIVE" ]] || fail "module config backup was not created"
    tar -tzf "$MODULE_ARCHIVE" | grep -Fq "${M_CONFIG#/}" \
        || fail "module config backup does not contain the config"
)

cat >"${FAKE_BIN}/sqlite3" <<'EOF'
#!/usr/bin/env bash
[[ "${SQLITE_FAIL:-false}" == "true" ]] && exit 1
database="$1"
command="$2"
target="$(printf '%s\n' "$command" | sed -n "s/^\\.backup '\(.*\)'$/\1/p")"
[[ -n "$target" ]] || exit 1
cp "$database" "$target"
EOF
chmod +x "${FAKE_BIN}/sqlite3"

cat >"${FAKE_BIN}/systemctl" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' "$*" >>"${SYSTEMCTL_LOG:-/dev/null}"
exit 0
EOF
chmod +x "${FAKE_BIN}/systemctl"

(
    export PATH="${FAKE_BIN}:${PATH}"
    export INFIPROXY_STATE_DIR="${TMP_DIR}/headscale-panel-state"
    export INFIPROXY_ROOT_STATE_DIR="${TMP_DIR}/headscale-root-state"
    export INFIPROXY_MODULE_ROOT="${TMP_DIR}/headscale-modules"
    export INFIPROXY_HEADSCALE_DATA_DIR="${TMP_DIR}/headscale-data"
    export INFIPROXY_HEADSCALE_LINK="${TMP_DIR}/headscale-link"
    export SYSTEMCTL_LOG="${TMP_DIR}/headscale-systemctl.log"
    # shellcheck source=deploy/module-update.sh
    source "${ROOT_DIR}/deploy/module-update.sh"
    M_ID="headscale"
    M_DRIVER="headscale"
    M_ROOT="modules"
    M_BINARY="headscale"
    M_SERVICE="headscale.service"
    M_CONFIG="${TMP_DIR}/headscale-config/config.yaml"
    mkdir -p "$(dirname "$M_CONFIG")" "$HEADSCALE_DATA_DIR" \
        "$(runtime_root)/old"
    printf 'server_url: https://hs.example.test\n' >"$M_CONFIG"
    printf 'consistent database\n' >"${HEADSCALE_DATA_DIR}/db.sqlite"
    printf 'transient wal\n' >"${HEADSCALE_DATA_DIR}/db.sqlite-wal"
    cat >"$(runtime_root)/old/headscale" <<'EOF'
#!/usr/bin/env bash
echo 'headscale version v0.28.2 (audit fixture)'
EOF
    chmod +x "$(runtime_root)/old/headscale"
    ln -s "$(runtime_root)/old" "$(runtime_root)/current"
    [[ "$(installed_version headscale)" == "v0.28.2" ]] \
        || fail "Headscale binary version fallback did not return one version line"

    backup_module_config 1 1
    [[ -n "$LAST_MODULE_BACKUP" ]] || fail "Headscale backup path was not recorded"
    tar -tzf "${LAST_MODULE_BACKUP}/config.tar.gz" \
        | grep -Fq "${HEADSCALE_DATA_DIR#/}/db.sqlite" \
        || fail "Headscale SQLite snapshot is missing from the backup"
    if tar -tzf "${LAST_MODULE_BACKUP}/config.tar.gz" \
        | grep -Fq "${HEADSCALE_DATA_DIR#/}/db.sqlite-wal"; then
        fail "Headscale WAL leaked into the consistent backup"
    fi

    NEW_HEADSCALE="${TMP_DIR}/headscale-candidate"
    cat >"$NEW_HEADSCALE" <<'EOF'
#!/usr/bin/env bash
if [[ "${1:-}" == "version" ]]; then
    exit 0
fi
printf 'migrated database\n' >"$HEADSCALE_TEST_DB"
exit 1
EOF
    chmod +x "$NEW_HEADSCALE"
    export HEADSCALE_TEST_DB="${HEADSCALE_DATA_DIR}/db.sqlite"
    ensure_headscale_unit() { :; }
    if (install_headscale_binary v0.29.3 "$NEW_HEADSCALE" 1 1); then
        fail "failed Headscale config canary unexpectedly succeeded"
    fi
    [[ "$(readlink "$(runtime_root)/current")" == "$(runtime_root)/old" ]] \
        || fail "Headscale canary failure did not restore the previous symlink"
    assert_file_contains "${HEADSCALE_DATA_DIR}/db.sqlite" "consistent database"
    grep -Fq 'restart headscale.service' "$SYSTEMCTL_LOG" \
        || fail "Headscale rollback did not restore the active service"
)

(
    export INFIPROXY_HEADSCALE_CONFIG="${TMP_DIR}/generated-headscale/config.yaml"
    export INFIPROXY_HEADSCALE_STATE_DIR="${TMP_DIR}/generated-headscale/state"
    INFIPROXY_GROUP="$(id -gn)"
    export INFIPROXY_GROUP
    # shellcheck source=deploy/infiproxy-manager.sh
    source "${ROOT_DIR}/deploy/infiproxy-manager.sh"
    require_cmd() { :; }
    secure_headscale_paths() {
        mkdir -p "$(dirname "$HEADSCALE_CONFIG")" "$HEADSCALE_STATE_DIR"
    }
    headscale_configtest() { [[ -f "${1:-}" ]]; }
    publish_staged_file() {
        chmod "$5" "$1"
        mv -f -- "$1" "$2"
    }

    write_headscale_config \
        "https://hs.example.test" "tailnet.example.test" >/dev/null
    assert_file_contains "$HEADSCALE_CONFIG" "prefixes:"
    assert_file_contains "$HEADSCALE_CONFIG" "  allocation: sequential"
    if grep -Fqx 'allocation: sequential' "$HEADSCALE_CONFIG"; then
        fail "Headscale allocation escaped the prefixes mapping"
    fi
)

(
    export INFIPROXY_MODULE_REQUEST_DIR="${TMP_DIR}/manager-module-requests"
    INFIPROXY_USER="$(id -un)"
    INFIPROXY_GROUP="$(id -gn)"
    export INFIPROXY_USER INFIPROXY_GROUP
    # shellcheck source=deploy/infiproxy-manager.sh
    source "${ROOT_DIR}/deploy/infiproxy-manager.sh"

    write_module_request "sing-box" remove
    [[ -f "${MODULE_REQUEST_DIR}/sing-box.remove" ]] \
        || fail "manager did not atomically publish the module request"
    grep -Eq '^requested_at=[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$' \
        "${MODULE_REQUEST_DIR}/sing-box.remove" \
        || fail "manager module request has malformed content"
    if find "$MODULE_REQUEST_DIR" -name '.*.remove.*' -print -quit | grep -q .; then
        fail "manager left a staged module request behind"
    fi
)

(
    export PATH="${FAKE_BIN}:${PATH}"
    export INFIPROXY_STATE_DIR="${TMP_DIR}/panel-state"
    export INFIPROXY_ROOT_STATE_DIR="${TMP_DIR}/panel-root-state"
    export INFIPROXY_DATABASE_FILE="${TMP_DIR}/panel-state/infiproxy.sqlite"
    export INFIPROXY_CONFIG_DIR="${TMP_DIR}/etc/infiproxy"
    export INFIPROXY_CORE_CONFIG_DIR="${TMP_DIR}/etc/infiproxy-cores"
    export INFIPROXY_HEADSCALE_CONFIG_DIR="${TMP_DIR}/etc/headscale"
    export INFIPROXY_UPDATE_CONFIG_FILE="${TMP_DIR}/etc/infiproxy-update.conf"
    export INFIPROXY_MODULE_MANIFEST_DIR="${TMP_DIR}/etc/modules.d"
    export INFIPROXY_MODULE_AVAILABLE_DIR="${TMP_DIR}/etc/modules.available.d"
    export INFIPROXY_NGINX_AVAILABLE="${TMP_DIR}/etc/nginx/infiproxy.conf"
    export INFIPROXY_NGINX_HEADSCALE_AVAILABLE="${TMP_DIR}/etc/nginx/headscale.conf"
    export INFIPROXY_SRC_DIR="${TMP_DIR}/panel-source"
    export INFIPROXY_PANEL_BINARY="${TMP_DIR}/installed/infiproxy"
    export INFIPROXY_MANIFEST_HELPER_BINARY="${TMP_DIR}/installed/infiproxy-module-manifest"
    export INFIPROXY_HEADSCALE_HELPER_BINARY="${TMP_DIR}/installed/infiproxy-headscale-control"
    # shellcheck source=deploy/panel-update.sh
    source "${ROOT_DIR}/deploy/panel-update.sh"
    mkdir -p "$SOURCE_DIR"
    git -C "$SOURCE_DIR" init -q
    git -C "$SOURCE_DIR" config user.name "Infiproxy audit"
    git -C "$SOURCE_DIR" config user.email "audit@example.test"
    printf 'first\n' >"${SOURCE_DIR}/history"
    git -C "$SOURCE_DIR" add history
    git -C "$SOURCE_DIR" commit -qm first
    FIRST_COMMIT="$(git -C "$SOURCE_DIR" rev-parse HEAD)"
    printf 'second\n' >"${SOURCE_DIR}/history"
    git -C "$SOURCE_DIR" commit -qam second
    SECOND_COMMIT="$(git -C "$SOURCE_DIR" rev-parse HEAD)"
    is_safe_update_target "$FIRST_COMMIT" "$SECOND_COMMIT" \
        || fail "panel updater rejected a fast-forward commit"
    if is_safe_update_target "$SECOND_COMMIT" "$FIRST_COMMIT"; then
        fail "panel updater accepted a non-fast-forward rollback"
    fi
    INFIPROXY_ALLOW_NON_FAST_FORWARD=true \
        is_safe_update_target "$SECOND_COMMIT" "$FIRST_COMMIT" \
        || fail "reviewed non-fast-forward recovery override was ignored"
    mkdir -p "$CONFIG_DIR" "$(dirname "$DATABASE_FILE")"
    printf 'settings\n' >"${CONFIG_DIR}/infiproxy.env"
    printf 'users and settings fixture\n' >"$DATABASE_FILE"
    mkdir -p "$(dirname "$PANEL_BINARY")"
    printf 'old panel\n' >"$PANEL_BINARY"
    printf 'old manifest helper\n' >"$MANIFEST_HELPER_BINARY"
    printf 'old Headscale helper\n' >"$HEADSCALE_HELPER_BINARY"
    chmod 0755 "$PANEL_BINARY" "$MANIFEST_HELPER_BINARY" "$HEADSCALE_HELPER_BINARY"
    PANEL_BACKUP="${TMP_DIR}/panel-backup"
    mkdir -p "$PANEL_BACKUP"
    backup_control_binaries "$PANEL_BACKUP"
    printf 'new panel\n' >"$PANEL_BINARY"
    printf 'new manifest helper\n' >"$MANIFEST_HELPER_BINARY"
    printf 'new Headscale helper\n' >"$HEADSCALE_HELPER_BINARY"
    restore_control_binaries "$PANEL_BACKUP"
    assert_file_contains "$PANEL_BINARY" "old panel"
    assert_file_contains "$MANIFEST_HELPER_BINARY" "old manifest helper"
    assert_file_contains "$HEADSCALE_HELPER_BINARY" "old Headscale helper"
    backup_database "$PANEL_BACKUP"
    backup_system_configs "$PANEL_BACKUP"
    if SQLITE_FAIL=true backup_database "${TMP_DIR}/failed-panel-backup"; then
        fail "failed SQLite backup was reported as successful"
    fi
    cmp "$DATABASE_FILE" "${PANEL_BACKUP}/infiproxy.sqlite" \
        || fail "panel database backup differs from its source"
    tar -tzf "${PANEL_BACKUP}/system-configs.tar.gz" \
        | grep -Fq "${CONFIG_DIR#/}/infiproxy.env" \
        || fail "panel config backup does not contain infiproxy.env"
)

echo "Updater regression tests passed."
