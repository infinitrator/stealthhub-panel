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

echo 'Install state regression tests passed.'
