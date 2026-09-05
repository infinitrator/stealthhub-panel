#!/usr/bin/env bash
# Exercise the finite root-operation contract with functions substituted in a
# disposable process. No service, network, credential or production file access.
set -euo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT
# shellcheck source=deploy/infiproxy-manager.sh
source "$ROOT_DIR/deploy/infiproxy-manager.sh"
# shellcheck source=deploy/lib/manager-operations.sh
source "$ROOT_DIR/deploy/lib/manager-operations.sh"

# These functions are intentionally invoked indirectly by manager_operation.
# shellcheck disable=SC2317,SC2329
need_root() { :; }
# shellcheck disable=SC2317,SC2329
registered_services() { printf '%s\n' infiproxy-mihomo.service; }
# shellcheck disable=SC2317,SC2329
systemctl() { printf '%s\n' "$*" >>"$TMP_DIR/calls"; }
# shellcheck disable=SC2317,SC2329
journalctl() { printf '%s\n' "$*" >>"$TMP_DIR/calls"; }
# shellcheck disable=SC2317,SC2329
store_privileged_secret() { local value; IFS= read -r value; printf '%s' "$value" >"$TMP_DIR/secret"; }

for operation in shell exec bash reboot; do
  if manager_operation "$operation" 'wrong' >/dev/null 2>&1; then echo 'unsafe operation accepted' >&2; exit 1; fi
done
if manager_operation logs 'ssh.service;reboot' >/dev/null 2>&1; then exit 1; fi
if manager_operation panel-restart WRONG >/dev/null 2>&1; then exit 1; fi
if manager_operation secret-store .. STORE </dev/null >/dev/null 2>&1; then exit 1; fi
[[ ! -f "$TMP_DIR/calls" ]] || { echo 'invalid operation crossed command boundary' >&2; exit 1; }
manager_operation logs infiproxy-mihomo.service
grep -Fq -- '-u infiproxy-mihomo.service -n 120 --no-pager' "$TMP_DIR/calls"
manager_operation panel-restart APPLY
grep -Fxq 'restart infiproxy.service' "$TMP_DIR/calls"
printf 'hidden-fixture\n' | manager_operation secret-store reality.private STORE >"$TMP_DIR/output"
[[ ! -s "$TMP_DIR/output" && "$(cat "$TMP_DIR/secret")" == hidden-fixture ]]
manager_operation uninstall-preview full >"$TMP_DIR/plan"
grep -Fq '/usr/local/libexec/infiproxy-tui' "$TMP_DIR/plan"
grep -Fq '/usr/local/libexec/infiproxy-manager-operations.sh' "$TMP_DIR/plan"
echo 'Manager operation regression tests passed.'
