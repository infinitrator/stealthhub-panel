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

file_mode() {
    stat -c '%a' "$1" 2>/dev/null || stat -f '%Lp' "$1"
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
cat >"${FAKE_BIN}/dd" <<'EOF'
#!/usr/bin/env perl
use strict;
use warnings;

my ($fullblock, $block_size, $count, $output) = (0, 512, 0, q{});
for my $argument (@ARGV) {
    if ($argument eq 'iflag=fullblock') {
        $fullblock = 1;
    } elsif ($argument =~ /^bs=([0-9]+)$/) {
        $block_size = $1;
    } elsif ($argument =~ /^count=([0-9]+)$/) {
        $count = $1;
    } elsif ($argument =~ /^of=(.+)$/) {
        $output = $1;
    } else {
        exit 2;
    }
}
exit 2 if $block_size < 1 || $count < 1 || $output eq q{};

binmode STDIN;
open my $target, '>:raw', $output or die "open output: $!";
if (($ENV{FAKE_DD_FORCE_OVERSIZE} // 'false') eq 'true') {
    my $buffer;
    1 while sysread(STDIN, $buffer, 4096);
    truncate $target, 1_073_741_825 or die "truncate output: $!";
    close $target or die "close output: $!";
    exit 0;
}

my $records = 0;
my $eof = 0;
while ($records < $count && !$eof) {
    my $record_bytes = 0;
    while ($record_bytes < $block_size) {
        my $remaining = $block_size - $record_bytes;
        my $read_size = $remaining < 4096 ? $remaining : 4096;
        my $buffer;
        my $read = sysread(STDIN, $buffer, $read_size);
        die "read input: $!" unless defined $read;
        if ($read == 0) {
            $eof = 1;
            last;
        }
        my $offset = 0;
        while ($offset < $read) {
            my $written = syswrite($target, $buffer, $read - $offset, $offset);
            die "write output: $!" unless defined $written && $written > 0;
            $offset += $written;
        }
        $record_bytes += $read;
        last unless $fullblock;
    }
    $records++ if $record_bytes > 0;
}
close $target or die "close output: $!";
EOF
chmod +x "${FAKE_BIN}/dd"
cat >"${FAKE_BIN}/gzip" <<'EOF'
#!/usr/bin/env bash
if [[ "${FAKE_GZIP_SHORT_WRITES:-false}" != "true" ]]; then
    exec /usr/bin/gzip "$@"
fi
/usr/bin/gzip "$@" | /usr/bin/perl -e '
    use strict;
    use warnings;
    binmode STDIN;
    binmode STDOUT;
    while (1) {
        my $buffer;
        my $read = sysread(STDIN, $buffer, 4096);
        die "read decompressor: $!" unless defined $read;
        last if $read == 0;
        my $offset = 0;
        while ($offset < $read) {
            my $written = syswrite(STDOUT, $buffer, $read - $offset, $offset);
            die "write decompressor: $!" unless defined $written && $written > 0;
            $offset += $written;
        }
    }
'
EOF
chmod +x "${FAKE_BIN}/gzip"

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
install_fake_core mihomo -v "$CORE_ROOT"
install_fake_core custom --version "$CORE_ROOT"

MIHOMO_GZIP_SOURCE="${TMP_DIR}/mihomo-gzip-source"
MIHOMO_GZIP_ARCHIVE="${TMP_DIR}/mihomo-linux-amd64-v1.19.30.gz"
MIHOMO_GZIP_ARGS="${TMP_DIR}/mihomo-gzip-smoke.args"
: >"$MIHOMO_GZIP_ARGS"
make_fake_core "$MIHOMO_GZIP_SOURCE"
awk 'BEGIN { for (i = 0; i < 300000; i++) print "# short-read fixture" }' \
    >>"$MIHOMO_GZIP_SOURCE"
gzip -c "$MIHOMO_GZIP_SOURCE" >"$MIHOMO_GZIP_ARCHIVE"
MIHOMO_GZIP_SHA="$(sha256sum "$MIHOMO_GZIP_ARCHIVE" | awk '{print $1}')"

BINARY_STREAM_SOURCE="${TMP_DIR}/short-read-binary-source"
BINARY_STREAM_ARCHIVE="${TMP_DIR}/short-read-binary.gz"
OLD_DD_OUTPUT="${TMP_DIR}/short-read-old-output"
FULLBLOCK_DD_OUTPUT="${TMP_DIR}/short-read-fullblock-output"
/usr/bin/perl -e 'binmode STDOUT; print pack("C*", 0 .. 255) x 24576' \
    >"$BINARY_STREAM_SOURCE"
gzip -c "$BINARY_STREAM_SOURCE" >"$BINARY_STREAM_ARCHIVE"
if FAKE_GZIP_SHORT_WRITES=true "${FAKE_BIN}/gzip" -cd "$BINARY_STREAM_ARCHIVE" \
    | "${FAKE_BIN}/dd" bs=1048576 count=1025 of="$OLD_DD_OUTPUT" 2>/dev/null; then
    :
fi
OLD_DD_SIZE="$(wc -c <"$OLD_DD_OUTPUT" | tr -d '[:space:]')"
[[ "$OLD_DD_SIZE" == "$((4096 * 1025))" ]] \
    || fail "dd without fullblock did not consume one count per short read"
if cmp -s "$BINARY_STREAM_SOURCE" "$OLD_DD_OUTPUT"; then
    fail "dd without fullblock unexpectedly preserved the short-read stream"
fi
FAKE_GZIP_SHORT_WRITES=true "${FAKE_BIN}/gzip" -cd "$BINARY_STREAM_ARCHIVE" \
    | "${FAKE_BIN}/dd" iflag=fullblock bs=1048576 count=1025 \
        of="$FULLBLOCK_DD_OUTPUT" 2>/dev/null
cmp -s "$BINARY_STREAM_SOURCE" "$FULLBLOCK_DD_OUTPUT" \
    || fail "dd with fullblock truncated the binary short-read stream"

PATH="${FAKE_BIN}:${PATH}" \
    FAKE_GZIP_SHORT_WRITES=true \
    INFIPROXY_CORE_ROOT="${TMP_DIR}/gzip-cores" \
    INFIPROXY_CORE_STAGING="${TMP_DIR}/gzip-staging" \
    SMOKE_ARGS_FILE="$MIHOMO_GZIP_ARGS" SMOKE_ACCEPT="-v" \
    bash "${ROOT_DIR}/deploy/cores/install-core.sh" \
        --core mihomo --version test-gzip --archive "$MIHOMO_GZIP_ARCHIVE" \
        --sha256 "$MIHOMO_GZIP_SHA" --binary mihomo >/dev/null
assert_file_contains "$MIHOMO_GZIP_ARGS" -v
MIHOMO_GZIP_BINARY="${TMP_DIR}/gzip-cores/mihomo/test-gzip/mihomo"
[[ -x "$MIHOMO_GZIP_BINARY" ]] \
    || fail "large Mihomo gzip did not install an executable binary"
[[ "$(file_mode "$MIHOMO_GZIP_BINARY")" == 755 ]] \
    || fail "installed Mihomo gzip binary mode is not 0755"
gzip -cd "$MIHOMO_GZIP_ARCHIVE" | cmp -s - "$MIHOMO_GZIP_BINARY" \
    || fail "large Mihomo gzip was truncated during extraction"

OVERSIZE_ROOT="${TMP_DIR}/oversize-gzip-cores"
if PATH="${FAKE_BIN}:${PATH}" \
    FAKE_DD_FORCE_OVERSIZE=true \
    INFIPROXY_CORE_ROOT="$OVERSIZE_ROOT" \
    INFIPROXY_CORE_STAGING="${TMP_DIR}/oversize-gzip-staging" \
    SMOKE_ARGS_FILE="${TMP_DIR}/oversize-gzip-smoke.args" SMOKE_ACCEPT="-v" \
    bash "${ROOT_DIR}/deploy/cores/install-core.sh" \
        --core mihomo --version too-large --archive "$MIHOMO_GZIP_ARCHIVE" \
        --sha256 "$MIHOMO_GZIP_SHA" --binary mihomo >/dev/null 2>&1
then
    fail "gzip output larger than 1 GiB unexpectedly installed"
fi
[[ ! -e "${OVERSIZE_ROOT}/mihomo/current" \
    && ! -e "${OVERSIZE_ROOT}/mihomo/too-large" ]] \
    || fail "oversize gzip published a binary or current symlink"

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
    export INFIPROXY_MODULE_MANIFEST_HELPER="${ROOT_DIR}/target/debug/infiproxy-module-manifest"
    export INFIPROXY_CORE_ROOT="${TMP_DIR}/module-cores"
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

    github_json() {
        local tag="v1.1.0"
        [[ "$1" == */releases/tags/v1.0.0 ]] && tag="v1.0.0"
        printf '{"tag_name":"%s","draft":false,"prerelease":false,"assets":[{"name":"demo-%s-amd64","browser_download_url":"https://github.com/owner/repo/releases/download/%s/demo-%s-amd64","digest":"sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"},{"name":"demo-%s-arm64","browser_download_url":"https://github.com/owner/repo/releases/download/%s/demo-%s-arm64","digest":"sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"}]}' \
            "$tag" "${tag#v}" "$tag" "${tag#v}" "${tag#v}" "$tag" "${tag#v}"
    }
    M_ID="demo"
    M_REPO="owner/repo"
    M_UPSTREAM="pinned-release"
    M_REF="v1.0.0"
    M_ROOT="cores"
    M_BINARY="demo"
    M_ASSET_AMD64='demo-{version}-amd64'
    M_ASSET_ARM64='demo-{version}-arm64'
    [[ "$(release_metadata amd64 | cut -d'|' -f1)" == "v1.0.0" ]] \
        || fail "pinned release did not resolve the exact tag"
    [[ "$(upstream_latest_version)" == "v1.1.0" ]] \
        || fail "pinned release check did not observe newer upstream metadata"

    mkdir -p "${MODULE_VERSION_DIR}" "${INFIPROXY_CORE_ROOT}/demo/current"
    printf 'v1.1.0\n' >"${MODULE_VERSION_DIR}/demo.version"
    printf '#!/usr/bin/env bash\nexit 0\n' >"${INFIPROXY_CORE_ROOT}/demo/current/demo"
    chmod +x "${INFIPROXY_CORE_ROOT}/demo/current/demo"
    install_release_module false
    [[ "$(cat "${MODULE_VERSION_DIR}/demo.version")" == "v1.1.0" ]] \
        || fail "automatic pinned update downgraded a newer installed runtime"

    load_module() {
        [[ "$1" == sing-box ]] || return 1
        M_ID="sing-box"
        M_REPO="SagerNet/sing-box"
        M_UPSTREAM="pinned-release"
        M_REF="v1.13.20"
        M_DRIVER="release"
        M_ROOT="cores"
        M_BINARY="sing-box"
        M_SERVICE="infiproxy-sing-box.service"
        M_CONFIG="${TMP_DIR}/configs/sing-box/config.json"
        M_ASSET_AMD64='sing-box-{version}-linux-amd64.tar.gz'
        M_ASSET_ARM64='sing-box-{version}-linux-arm64.tar.gz'
    }
    github_json() {
        local tag="v1.14.0"
        [[ "$1" == */releases/tags/v1.13.20 ]] && tag="v1.13.20"
        printf '{"tag_name":"%s","draft":false,"prerelease":false,"assets":[{"name":"sing-box-%s-linux-amd64.tar.gz","browser_download_url":"https://github.com/SagerNet/sing-box/releases/download/%s/sing-box-%s-linux-amd64.tar.gz","digest":"sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"},{"name":"sing-box-%s-linux-arm64.tar.gz","browser_download_url":"https://github.com/SagerNet/sing-box/releases/download/%s/sing-box-%s-linux-arm64.tar.gz","digest":"sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"}]}' \
            "$tag" "${tag#v}" "$tag" "${tag#v}" "${tag#v}" "$tag" "${tag#v}"
    }
    mkdir -p "${INFIPROXY_CORE_ROOT}/sing-box/current"
    printf 'v1.14.0\n' >"${MODULE_VERSION_DIR}/sing-box.version"
    printf '#!/usr/bin/env bash\nexit 0\n' \
        >"${INFIPROXY_CORE_ROOT}/sing-box/current/sing-box"
    chmod +x "${INFIPROXY_CORE_ROOT}/sing-box/current/sing-box"
    sing_box_status="$(check_module sing-box)"
    [[ "$sing_box_status" == *'latest=v1.13.20'* \
        && "$sing_box_status" == *'installed version outside validated contract'* ]] \
        || fail "production sing-box pin did not report a newer installed version safely"
    rm -rf "${INFIPROXY_CORE_ROOT}/sing-box/current"
    mkdir -p "${INFIPROXY_CORE_ROOT}/sing-box/1.14.0"
    printf '#!/usr/bin/env bash\nexit 0\n' \
        >"${INFIPROXY_CORE_ROOT}/sing-box/1.14.0/sing-box"
    chmod +x "${INFIPROXY_CORE_ROOT}/sing-box/1.14.0/sing-box"
    ln -s "${INFIPROXY_CORE_ROOT}/sing-box/1.14.0" \
        "${INFIPROXY_CORE_ROOT}/sing-box/current"
    printf 'v1.13.20\n' >"${MODULE_VERSION_DIR}/sing-box.version"
    load_module sing-box
    [[ "$(installed_version sing-box)" == "1.14.0" ]] \
        || fail "stale marker concealed the installed sing-box symlink version"
    sing_box_status="$(check_module sing-box)"
    [[ "$sing_box_status" == *'installed=1.14.0'* \
        && "$sing_box_status" == *'installed version outside validated contract'* ]] \
        || fail "sing-box marker/binary mismatch was not visible"
    install_release_module() {
        printf '%s\n' "$1" >"${TMP_DIR}/sing-box-allow-downgrade"
    }
    update_module sing-box true
    assert_file_contains "${TMP_DIR}/sing-box-allow-downgrade" true

    M_ID="mihomo"
    M_REPO="MetaCubeX/mihomo"
    M_UPSTREAM="pinned-release"
    M_REF="v1.19.30"
    M_ASSET_AMD64='mihomo-linux-amd64-v{version}.gz'
    github_json() {
        printf '{"tag_name":"v1.19.30","draft":false,"prerelease":false,"assets":[{"name":"mihomo-linux-amd64-v1.19.30.gz","browser_download_url":"https://github.com/MetaCubeX/mihomo/releases/download/v1.19.30/mihomo-linux-amd64-v1.19.30.gz","digest":"sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"}]}'
    }
    [[ "$(release_metadata amd64 | cut -d'|' -f1-2)" \
        == 'v1.19.30|mihomo-linux-amd64-v1.19.30.gz' ]] \
        || fail "production Mihomo pin did not resolve its gzip release asset"

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
    export INFIPROXY_STATE_DIR="${TMP_DIR}/lifecycle-state"
    export INFIPROXY_ROOT_STATE_DIR="${TMP_DIR}/lifecycle-root-state"
    export SYSTEMCTL_LOG="${TMP_DIR}/lifecycle-systemctl.log"
    mkdir -p "${INFIPROXY_STATE_DIR}/module-requests" "${TMP_DIR}/lifecycle-runtime"
    chmod 0750 "${INFIPROXY_STATE_DIR}/module-requests"
    printf '#!/usr/bin/env bash\nexit 0\n' >"${TMP_DIR}/lifecycle-runtime/runtime"
    chmod +x "${TMP_DIR}/lifecycle-runtime/runtime"
    printf 'requested_at=test\n' \
        >"${INFIPROXY_STATE_DIR}/module-requests/demo.restart"
    chmod 0640 "${INFIPROXY_STATE_DIR}/module-requests/demo.restart"
    # shellcheck source=deploy/module-update.sh
    source "${ROOT_DIR}/deploy/module-update.sh"
    safe_request_file() {
        [[ -f "$1" && ! -L "$1" ]]
    }
    load_module() {
        [[ "$1" == "demo" ]] || return 1
        M_ID="demo"
        M_SERVICE="infiproxy-demo.service"
    }
    module_binary() {
        printf '%s' "${TMP_DIR}/lifecycle-runtime/runtime"
    }
    lifecycle_requested
    grep -Fq 'restart infiproxy-demo.service' "$SYSTEMCTL_LOG" \
        || fail "typed lifecycle request did not use the manifest service"
    [[ ! -e "${REQUEST_DIR}/demo.restart" ]] \
        || fail "successful lifecycle request was not consumed"
)

(
    export PATH="${FAKE_BIN}:${PATH}"
    export INFIPROXY_STATE_DIR="${TMP_DIR}/retired-panel-state"
    export INFIPROXY_ROOT_STATE_DIR="${TMP_DIR}/retired-root-state"
    # shellcheck source=deploy/module-update.sh
    source "${ROOT_DIR}/deploy/module-update.sh"
    module_is_retired headscale || fail "Headscale is not retired"
    module_is_retired mtproto || fail "MTProto is not retired"
    if (require_active_product_module headscale >/dev/null 2>&1); then
        fail "Headscale entered an active updater path"
    fi
    if (require_active_product_module mtproto >/dev/null 2>&1); then
        fail "MTProto entered an active updater path"
    fi
    [[ ! -e "${ROOT_DIR}/deploy/modules.d/headscale.module" ]] \
        || fail "installer still bundles Headscale"
    [[ ! -e "${ROOT_DIR}/deploy/modules.d/mtproto.module" ]] \
        || fail "installer still bundles MTProto"
    if [[ "$(grep -ci 'headscale' "${ROOT_DIR}/deploy/install.sh")" -ne 1 ]] \
        || ! grep -Fq 'retire_legacy_module headscale headscale.service' \
            "${ROOT_DIR}/deploy/install.sh"; then
        fail "installer has a non-retirement Headscale path"
    fi
    if [[ "$(grep -ci 'mtproto' "${ROOT_DIR}/deploy/install.sh")" -ne 1 ]] \
        || ! grep -Fq 'retire_legacy_module mtproto infiproxy-mtproto.service' \
            "${ROOT_DIR}/deploy/install.sh"; then
        fail "installer has a non-retirement MTProto path"
    fi
    ! grep -Fq 'infiproxy-mtproto.service' "${ROOT_DIR}/deploy/infiproxy-manager.sh" \
        || fail "normal TUI still exposes MTProto"
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
    export INFIPROXY_NGINX_SUBSCRIPTION_AVAILABLE="${TMP_DIR}/etc/nginx/subscription.conf"
    export INFIPROXY_NGINX_HEADSCALE_AVAILABLE="${TMP_DIR}/etc/nginx/headscale.conf"
    export INFIPROXY_PANEL_APPLIED_SHA="${TMP_DIR}/panel-root-state/panel-last-applied.sha"
    export INFIPROXY_SRC_DIR="${TMP_DIR}/panel-source"
    export INFIPROXY_PANEL_BINARY="${TMP_DIR}/installed/infiproxy"
    export INFIPROXY_TUI_BIN="${TMP_DIR}/installed/infiproxy-tui"
    export INFIPROXY_MANAGER_BIN="${TMP_DIR}/installed/infiproxy-manager"
    export INFIPROXY_MANAGER_OPERATIONS="${TMP_DIR}/installed/infiproxy-manager-operations.sh"
    export INFIPROXY_MANIFEST_HELPER_BINARY="${TMP_DIR}/installed/infiproxy-module-manifest"
    export INFIPROXY_RECONCILE_HELPER_BINARY="${TMP_DIR}/installed/infiproxy-reconcile"
    # shellcheck source=deploy/panel-update.sh
    source "${ROOT_DIR}/deploy/panel-update.sh"
    mkdir -p "$(dirname "$CONFIG_FILE")" "$(dirname "$STATE_FILE")"
    printf 'REPO=infinitrator/stealthhub-panel\nREF=main\n' >"$CONFIG_FILE"
    printf "AUTO_ENABLED=true\nSCHEDULE_TIME='00:00'\nREPO=untrusted/example\nREF=feature/unreviewed\n" \
        >"$STATE_FILE"

    assert_pinned_update_source() {
        [[ "$(read_config REPO)" == "infinitrator/stealthhub-panel" \
            && "$(read_config REF)" == "main" ]] \
            || fail "panel updater did not use the root-pinned source"
    }

    : >"$REQUEST_FILE"
    should_update_now "2222222222222222222222222222222222222222" \
        "1111111111111111111111111111111111111111" \
        || fail "manual update request was not recognized"
    assert_pinned_update_source
    rm -f "$REQUEST_FILE"
    should_update_now "2222222222222222222222222222222222222222" \
        "1111111111111111111111111111111111111111" \
        || fail "scheduled update policy was not recognized"
    assert_pinned_update_source
    valid_ref "some-reviewed-ref" || fail "safe reviewed ref was rejected"
    for unsafe_ref in "../escape" "/absolute" "-option" "bad ref"; do
        if valid_ref "$unsafe_ref"; then
            fail "unsafe panel update ref was accepted: ${unsafe_ref}"
        fi
    done

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
    mkdir -p "${SOURCE_DIR}/deploy"
    cat >"${SOURCE_DIR}/deploy/build-control-plane.sh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf 'target-owned\n' >"${TARGET_BUILD_MARKER:?}"
EOF
    chmod 0755 "${SOURCE_DIR}/deploy/build-control-plane.sh"
    cat >"${SOURCE_DIR}/deploy/control-plane-artifacts" <<'EOF'
future-helper|infiproxy-future-helper|/usr/local/libexec/infiproxy-future-helper
EOF
    git -C "$SOURCE_DIR" add deploy
    git -C "$SOURCE_DIR" commit -qm 'add target build contract'
    TARGET_COMMIT="$(git -C "$SOURCE_DIR" rev-parse HEAD)"
    TARGET_BUILD_MARKER="${TMP_DIR}/target-build.marker" build_target_control_plane
    assert_file_contains "${TMP_DIR}/target-build.marker" "target-owned"
    printf '#!/usr/bin/env bash\nexit 1\n' >"${SOURCE_DIR}/deploy/build-control-plane.sh"
    chmod 0755 "${SOURCE_DIR}/deploy/build-control-plane.sh"
    if build_target_control_plane; then
        fail "failed target build contract was reported as successful"
    fi
    mkdir -p "$(dirname "$APPLIED_SHA_FILE")"
    printf '%s\n' "$FIRST_COMMIT" >"$APPLIED_SHA_FILE"
    # Invoked indirectly by publish_verified_update_commit.
    # shellcheck disable=SC2317,SC2329
    wait_panel_ready() { return 1; }
    if publish_verified_update_commit "$SECOND_COMMIT"; then
        fail "failed updater readiness unexpectedly published the target commit"
    fi
    [[ "$(cat "$APPLIED_SHA_FILE")" == "$FIRST_COMMIT" ]] \
        || fail "failed updater rollback changed the applied commit marker"
    mkdir -p "$CONFIG_DIR" "$(dirname "$DATABASE_FILE")"
    printf 'settings\n' >"${CONFIG_DIR}/infiproxy.env"
    printf 'users and settings fixture\n' >"$DATABASE_FILE"
    mkdir -p "$(dirname "$PANEL_BINARY")"
    printf 'old panel\n' >"$PANEL_BINARY"
    printf 'old manifest helper\n' >"$MANIFEST_HELPER_BINARY"
    printf 'old reconcile helper\n' >"$RECONCILE_HELPER_BINARY"
    printf 'old TUI\n' >"$TUI_BINARY"
    printf 'old manager wrapper\n' >"$MANAGER_BINARY"
    printf 'old manager operations\n' >"$MANAGER_OPERATIONS"
    chmod 0755 "$TUI_BINARY" "$MANAGER_BINARY" "$MANAGER_OPERATIONS"
    chmod 0755 "$PANEL_BINARY" "$MANIFEST_HELPER_BINARY" "$RECONCILE_HELPER_BINARY"
    PANEL_BACKUP="${TMP_DIR}/panel-backup"
    mkdir -p "$PANEL_BACKUP"
    backup_control_binaries "$PANEL_BACKUP"
    export INFIPROXY_CONTROL_ARTIFACT_ROOT="${TMP_DIR}/artifact-root"
    CONTROL_ARTIFACT_ROOT="$INFIPROXY_CONTROL_ARTIFACT_ROOT"
    backup_forward_artifacts "$PANEL_BACKUP" "$TARGET_COMMIT"
    mkdir -p "${CONTROL_ARTIFACT_ROOT}/usr/local/libexec"
    printf 'new future helper\n' \
        >"${CONTROL_ARTIFACT_ROOT}/usr/local/libexec/infiproxy-future-helper"
    chmod 0755 "${CONTROL_ARTIFACT_ROOT}/usr/local/libexec/infiproxy-future-helper"
    printf 'new panel\n' >"$PANEL_BINARY"
    printf 'new manifest helper\n' >"$MANIFEST_HELPER_BINARY"
    printf 'new reconcile helper\n' >"$RECONCILE_HELPER_BINARY"
    printf 'new TUI\n' >"$TUI_BINARY"
    printf 'new manager wrapper\n' >"$MANAGER_BINARY"
    printf 'new manager operations\n' >"$MANAGER_OPERATIONS"
    restore_control_binaries "$PANEL_BACKUP"
    restore_forward_artifacts "$PANEL_BACKUP"
    assert_file_contains "$PANEL_BINARY" "old panel"
    assert_file_contains "$MANIFEST_HELPER_BINARY" "old manifest helper"
    assert_file_contains "$RECONCILE_HELPER_BINARY" "old reconcile helper"
    assert_file_contains "$TUI_BINARY" "old TUI"
    assert_file_contains "$MANAGER_BINARY" "old manager wrapper"
    assert_file_contains "$MANAGER_OPERATIONS" "old manager operations"
    [[ ! -e "${CONTROL_ARTIFACT_ROOT}/usr/local/libexec/infiproxy-future-helper" ]] \
        || fail "rollback retained a forward artifact absent from the old release"
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
