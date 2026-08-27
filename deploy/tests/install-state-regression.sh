#!/usr/bin/env bash
# Offline regression coverage for setup-token and applied-SHA lifecycle.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

# shellcheck source=deploy/lib/install-state.sh
. "${ROOT_DIR}/deploy/lib/install-state.sh"

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

echo 'Install state regression tests passed.'
