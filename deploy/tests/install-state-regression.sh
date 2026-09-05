#!/usr/bin/env bash
# Offline regression coverage for setup-token and applied-SHA lifecycle.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

# shellcheck source=deploy/lib/install-state.sh
. "${ROOT_DIR}/deploy/lib/install-state.sh"
# shellcheck source=deploy/lib/runtime-tls.sh
. "${ROOT_DIR}/deploy/lib/runtime-tls.sh"

owner="$(id -un)"
group="$(id -gn)"
env_file="${TMP_DIR}/infiproxy.env"
marker="${TMP_DIR}/maintenance/panel-last-applied.sha"
old_sha="1111111111111111111111111111111111111111"
new_sha="ABCDEFABCDEFABCDEFABCDEFABCDEFABCDEFABCD"

printf 'INFIPROXY_SETUP_TOKEN=%064d\n' 0 >"$env_file"
before="$(cat "$env_file")"
ensure_setup_token "$env_file" "$owner" "$group"
[[ "$(cat "$env_file")" == "$before" ]] \
    || { echo 'valid setup token was unexpectedly replaced' >&2; exit 1; }

printf 'INFIPROXY_BIND=127.0.0.1:8080\n' >"$env_file"
ensure_setup_token "$env_file" "$owner" "$group"
missing_generated="$(awk -F= '$1 == "INFIPROXY_SETUP_TOKEN" { print $2 }' "$env_file")"
[[ "${#missing_generated}" -ge 32 ]] \
    || { echo 'missing setup token was not generated' >&2; exit 1; }

printf 'INFIPROXY_SETUP_TOKEN=short\n' >"$env_file"
ensure_setup_token "$env_file" "$owner" "$group"
short_replaced="$(awk -F= '$1 == "INFIPROXY_SETUP_TOKEN" { print $2 }' "$env_file")"
[[ "${#short_replaced}" -ge 32 && "$short_replaced" != short ]] \
    || { echo 'short setup token was not replaced' >&2; exit 1; }

printf 'INFIPROXY_SETUP_TOKEN=%064d\nINFIPROXY_SETUP_TOKEN=duplicate\n' 0 >"$env_file"
ensure_setup_token "$env_file" "$owner" "$group"
[[ "$(grep -c '^INFIPROXY_SETUP_TOKEN=' "$env_file")" -eq 1 ]] \
    || { echo 'duplicate setup token entries were not normalized' >&2; exit 1; }

ready() { return 0; }
not_ready() { return 1; }

publish_applied_sha "$marker" "$old_sha" "$owner" "$group"
if verify_and_publish_applied_sha "$marker" "$new_sha" "$owner" "$group" not_ready; then
    echo 'failed readiness unexpectedly published an applied SHA' >&2
    exit 1
fi
[[ "$(cat "$marker")" == "$old_sha" ]] \
    || { echo 'failed install changed the applied SHA' >&2; exit 1; }

verify_and_publish_applied_sha "$marker" "$new_sha" "$owner" "$group" ready
normalized_new_sha="$(normalized_commit_sha "$new_sha")"
[[ "$(cat "$marker")" == "$normalized_new_sha" && "$(wc -l <"$marker")" -eq 1 ]] \
    || { echo 'verified install did not publish one exact SHA' >&2; exit 1; }

if publish_applied_sha "$marker" invalid "$owner" "$group" 2>/dev/null; then
    echo 'invalid applied SHA was accepted' >&2
    exit 1
fi
[[ "$(cat "$marker")" == "$normalized_new_sha" ]] \
    || { echo 'invalid publication changed the marker' >&2; exit 1; }

printf '%s\n\n' "$old_sha" >"$marker"
if read_applied_sha "$marker" >/dev/null; then
    echo 'applied marker with extra lines was accepted' >&2
    exit 1
fi

tls_dir="${TMP_DIR}/tls"
tls_chown_log="${TMP_DIR}/tls-chown.log"
tls_fake_bin="${TMP_DIR}/tls-bin"
mkdir -p "$tls_dir" "$tls_fake_bin"
file_mode() {
    stat -c '%a' "$1" 2>/dev/null || stat -f '%Lp' "$1"
}
cat >"${tls_fake_bin}/chown" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' "$*" >>"$TLS_CHOWN_LOG"
EOF
chmod +x "${tls_fake_bin}/chown"

certificate="$tls_dir/fullchain.pem"
private_key="$tls_dir/privkey.pem"
printf 'certificate bytes stay unchanged\n' >"$certificate"
printf 'private key bytes stay unchanged\n' >"$private_key"
chmod 0640 "$certificate" "$private_key"
certificate_before="$(cat "$certificate")"
private_key_before="$(cat "$private_key")"

PATH="${tls_fake_bin}:${PATH}" TLS_CHOWN_LOG="$tls_chown_log" \
    normalize_runtime_tls_file "$certificate" infiproxy-runtime
PATH="${tls_fake_bin}:${PATH}" TLS_CHOWN_LOG="$tls_chown_log" \
    normalize_runtime_tls_file "$private_key" infiproxy-runtime
[[ "$(cat "$certificate")" == "$certificate_before" \
    && "$(cat "$private_key")" == "$private_key_before" ]] \
    || { echo 'TLS normalization changed file contents' >&2; exit 1; }
[[ "$(file_mode "$certificate")" == 640 \
    && "$(file_mode "$private_key")" == 640 ]] \
    || { echo 'TLS normalization did not enforce mode 0640' >&2; exit 1; }
grep -Fqx -- "-h root:infiproxy-runtime -- $certificate" "$tls_chown_log" \
    || { echo 'certificate was not assigned to the runtime group' >&2; exit 1; }
grep -Fqx -- "-h root:infiproxy-runtime -- $private_key" "$tls_chown_log" \
    || { echo 'private key was not assigned to the runtime group' >&2; exit 1; }

first_log="$(cat "$tls_chown_log")"
PATH="${tls_fake_bin}:${PATH}" TLS_CHOWN_LOG="$tls_chown_log" \
    normalize_runtime_tls_file "$certificate" infiproxy-runtime
PATH="${tls_fake_bin}:${PATH}" TLS_CHOWN_LOG="$tls_chown_log" \
    normalize_runtime_tls_file "$private_key" infiproxy-runtime
[[ "$(tail -n 2 "$tls_chown_log")" == "$first_log" ]] \
    || { echo 'TLS normalization is not idempotent' >&2; exit 1; }
[[ "$(cat "$certificate")" == "$certificate_before" \
    && "$(cat "$private_key")" == "$private_key_before" ]] \
    || { echo 'repeated TLS normalization changed contents' >&2; exit 1; }

symlink_target="$tls_dir/acme-target.pem"
symlink_path="$tls_dir/acme-link.pem"
printf 'external ACME bytes\n' >"$symlink_target"
chmod 0600 "$symlink_target"
ln -s "$symlink_target" "$symlink_path"
log_before_symlink="$(cat "$tls_chown_log")"
PATH="${tls_fake_bin}:${PATH}" TLS_CHOWN_LOG="$tls_chown_log" \
    normalize_runtime_tls_file "$symlink_path" infiproxy-runtime
[[ -L "$symlink_path" && "$(cat "$symlink_target")" == 'external ACME bytes' \
    && "$(file_mode "$symlink_target")" == 600 \
    && "$(cat "$tls_chown_log")" == "$log_before_symlink" ]] \
    || { echo 'TLS symlink target was changed' >&2; exit 1; }

absent="$tls_dir/absent.pem"
normalize_runtime_tls_file "$absent" infiproxy-runtime
[[ ! -e "$absent" && ! -L "$absent" ]] \
    || { echo 'absent TLS file was created' >&2; exit 1; }

installer_checkout="${TMP_DIR}/installer-checkout"
installer_fake_bin="${TMP_DIR}/installer-bin"
mkdir -p "$installer_fake_bin"
git clone -q "$ROOT_DIR" "$installer_checkout"
git -C "$installer_checkout" checkout -qb feature/update-source-regression
git -C "$installer_checkout" remote set-url origin \
    https://github.com/infinitrator/stealthhub-panel.git
cp "${ROOT_DIR}/deploy/install.sh" "${installer_checkout}/deploy/install.sh"
cp "${ROOT_DIR}/deploy/lib/manager-operations.sh" "${installer_checkout}/deploy/lib/manager-operations.sh"
mkdir -p "${installer_checkout}/target/release"
for binary in stealthhub-panel infiproxy-module-manifest infiproxy-reconcile infiproxy-tui; do
    cat >"${installer_checkout}/target/release/${binary}" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF
    chmod +x "${installer_checkout}/target/release/${binary}"
done

cat >"${installer_fake_bin}/id" <<'EOF'
#!/usr/bin/env bash
if [[ "$#" -eq 1 && "$1" == "-u" ]]; then
    printf '0\n'
else
    exec /usr/bin/id "$@"
fi
EOF
cat >"${installer_fake_bin}/install" <<'EOF'
#!/usr/bin/env bash
args=()
while [[ "$#" -gt 0 ]]; do
    if [[ "$1" == "-o" || "$1" == "-g" ]]; then
        shift 2
    else
        args+=("$1")
        shift
    fi
done
destination="${args[${#args[@]}-1]}"
[[ "$destination" == /etc/systemd/system/* ]] && exit 0
exec /usr/bin/install "${args[@]}"
EOF
for command in chown flock getent groupadd systemctl useradd; do
    cat >"${installer_fake_bin}/${command}" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF
done
chmod +x "${installer_fake_bin}"/*

run_installer_case() {
    local scenario="$1" update_config="$2" reviewed_ref="${3:-}"
    mkdir -p "$scenario/systemd" "$scenario/profile"
    (
        export PATH="${installer_fake_bin}:${PATH}"
        export INFIPROXY_USER="$owner" INFIPROXY_GROUP="$group"
        export INFIPROXY_RUNTIME_USER="$owner" INFIPROXY_RUNTIME_GROUP="$group"
        export INFIPROXY_INSTALL_BIN="${scenario}/bin/infiproxy"
        export INFIPROXY_MANAGER_BIN="${scenario}/sbin/infiproxy-manager"
        export INFIPROXY_TUI_BIN="${scenario}/libexec/infiproxy-tui"
        export INFIPROXY_MANAGER_OPERATIONS="${scenario}/libexec/infiproxy-manager-operations.sh"
        export INFIPROXY_UPDATE_BIN="${scenario}/sbin/infiproxy-panel-update"
        export INFIPROXY_MODULE_UPDATE_BIN="${scenario}/sbin/infiproxy-module-update"
        export INFIPROXY_MODULE_MANIFEST_HELPER="${scenario}/libexec/infiproxy-module-manifest"
        export INFIPROXY_RECONCILE_HELPER="${scenario}/libexec/infiproxy-reconcile"
        export INFIPROXY_INSTALL_STATE_LIB="${scenario}/libexec/infiproxy-install-state"
        export INFIPROXY_CORE_INSTALL_BIN="${scenario}/sbin/infiproxy-core-install"
        export INFIPROXY_CONFIG_DIR="${scenario}/etc/infiproxy"
        export INFIPROXY_STATE_DIR="${scenario}/state"
        export INFIPROXY_ROOT_STATE_DIR="${scenario}/root-state"
        export INFIPROXY_MODULE_MANIFEST_DIR="${scenario}/etc/modules.d"
        export INFIPROXY_MODULE_AVAILABLE_DIR="${scenario}/etc/modules.available.d"
        export INFIPROXY_LEGACY_MODULE_DIR="${scenario}/legacy-modules"
        export INFIPROXY_CORE_DIR="${scenario}/cores"
        export INFIPROXY_CORE_CONFIG_DIR="${scenario}/etc/cores"
        export INFIPROXY_CORE_LOG_DIR="${scenario}/logs"
        export INFIPROXY_SERVICE_FILE="${scenario}/systemd/infiproxy.service"
        export INFIPROXY_UPDATE_SERVICE_FILE="${scenario}/systemd/panel-update.service"
        export INFIPROXY_UPDATE_TIMER_FILE="${scenario}/systemd/panel-update.timer"
        export INFIPROXY_UPDATE_PATH_FILE="${scenario}/systemd/panel-update.path"
        export INFIPROXY_MODULE_UPDATE_SERVICE_FILE="${scenario}/systemd/module-update.service"
        export INFIPROXY_MODULE_UPDATE_TIMER_FILE="${scenario}/systemd/module-update.timer"
        export INFIPROXY_MODULE_UPDATE_PATH_FILE="${scenario}/systemd/module-update.path"
        export INFIPROXY_RECONCILE_SERVICE_FILE="${scenario}/systemd/reconcile.service"
        export INFIPROXY_RECONCILE_TIMER_FILE="${scenario}/systemd/reconcile.timer"
        export INFIPROXY_RECONCILE_PATH_FILE="${scenario}/systemd/reconcile.path"
        export INFIPROXY_PROFILE_FILE="${scenario}/profile/infiproxy-manager.sh"
        export INFIPROXY_UPDATE_CONFIG_FILE="$update_config"
        export INFIPROXY_PANEL_APPLIED_SHA="${scenario}/root-state/panel-last-applied.sha"
        export INFIPROXY_DEFER_APPLIED_SHA=true
        unset INFIPROXY_UPDATE_REF
        [[ -n "$reviewed_ref" ]] && export INFIPROXY_UPDATE_REF="$reviewed_ref"
        bash "${installer_checkout}/deploy/install.sh" >/dev/null
    )
}

assert_update_config() {
    local config="$1" expected_ref="$2"
    grep -Fqx 'REPO=infinitrator/stealthhub-panel' "$config" \
        && grep -Fqx "REF=${expected_ref}" "$config"
}

feature_config="${TMP_DIR}/feature-install/update.conf"
run_installer_case "${TMP_DIR}/feature-install" "$feature_config"
assert_update_config "$feature_config" main \
    || { echo 'feature checkout changed the default update ref' >&2; exit 1; }

git -C "$installer_checkout" checkout --detach -q
cp "${ROOT_DIR}/deploy/install.sh" "${installer_checkout}/deploy/install.sh"
detached_config="${TMP_DIR}/detached-install/update.conf"
run_installer_case "${TMP_DIR}/detached-install" "$detached_config"
assert_update_config "$detached_config" main \
    || { echo 'detached checkout changed the default update ref' >&2; exit 1; }

override_config="${TMP_DIR}/override-install/update.conf"
run_installer_case "${TMP_DIR}/override-install" "$override_config" some-reviewed-ref
assert_update_config "$override_config" some-reviewed-ref \
    || { echo 'explicit reviewed update ref was not preserved' >&2; exit 1; }

if INFIPROXY_UPDATE_REPO=infinitrator/stealthhub-panel \
    INFIPROXY_UPDATE_REF='../unsafe' \
    bash "${installer_checkout}/deploy/install.sh" --check >/dev/null 2>&1; then
    echo 'installer accepted an unsafe update ref' >&2
    exit 1
fi

echo 'Install state regression tests passed.'
