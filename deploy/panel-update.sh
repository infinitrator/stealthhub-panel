#!/usr/bin/env bash
# Root-side Infiproxy panel updater.
#
# The web panel only writes a small state/request file. This script performs the
# privileged git/build/install cycle from systemd so update permissions stay out
# of the HTTP process.
set -euo pipefail
umask 027

STATE_DIR="${INFIPROXY_STATE_DIR:-/var/lib/infiproxy}"
SOURCE_DIR="${INFIPROXY_SRC_DIR:-/opt/infiproxy/source}"
STATE_FILE="${INFIPROXY_PANEL_UPDATE_STATE:-${STATE_DIR}/panel-update-state.env}"
REQUEST_FILE="${INFIPROXY_PANEL_UPDATE_REQUEST:-${STATE_DIR}/panel-update-now.request}"
RUN_LOG="${INFIPROXY_PANEL_UPDATE_LOG:-${STATE_DIR}/panel-update-run.log}"
LOCK_DIR="${INFIPROXY_PANEL_UPDATE_LOCK:-/run/infiproxy-panel-update.lock}"

log() {
    local line
    line="$(date -u '+%Y-%m-%dT%H:%M:%SZ') $*"
    echo "$line"
    install -d -m 0750 "$STATE_DIR"
    printf '%s\n' "$line" >>"$RUN_LOG"
}

cleanup() {
    rmdir "$LOCK_DIR" 2>/dev/null || true
}

read_state() {
    local key="$1"
    local value
    [[ -f "$STATE_FILE" ]] || return 1
    value="$(grep -E "^${key}=" "$STATE_FILE" 2>/dev/null | tail -n 1 | cut -d= -f2- || true)"
    value="${value#\'}"
    value="${value%\'}"
    value="${value//\'\"\'\"\'/\'}"
    printf '%s' "$value"
}

valid_repo() {
    [[ "$1" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]]
}

valid_ref() {
    [[ "$1" =~ ^[A-Za-z0-9_./-]+$ ]] && [[ "$1" != /* ]] && [[ "$1" != *..* ]]
}

should_update_now() {
    if [[ -f "$REQUEST_FILE" ]]; then
        return 0
    fi

    local enabled available scheduled_hour current_hour
    enabled="$(read_state AUTO_ENABLED || true)"
    available="$(read_state UPDATE_AVAILABLE || true)"
    scheduled_hour="$(read_state SCHEDULE_HOUR || true)"
    current_hour="$(date -u '+%-H')"

    [[ "$enabled" == "true" ]] || return 1
    [[ "$available" == "true" ]] || return 1
    [[ "$scheduled_hour" =~ ^[0-9]+$ ]] || return 1
    [[ "$scheduled_hour" -ge 0 && "$scheduled_hour" -le 23 ]] || return 1
    [[ "$current_hour" -eq "$scheduled_hour" ]]
}

main() {
    if [[ "$(id -u)" -ne 0 ]]; then
        echo "Run as root: sudo infiproxy-panel-update" >&2
        exit 1
    fi

    if ! mkdir "$LOCK_DIR" 2>/dev/null; then
        log "another updater instance is already running"
        exit 0
    fi
    trap cleanup EXIT

    if ! should_update_now; then
        log "no panel update due"
        exit 0
    fi

    local repo ref repo_url
    repo="$(read_state REPO || true)"
    ref="$(read_state REF || true)"
    repo="${repo:-infinitrator/stealthhub-panel}"
    ref="${ref:-main}"

    valid_repo "$repo" || { log "invalid repo in state: $repo"; exit 1; }
    valid_ref "$ref" || { log "invalid git ref in state: $ref"; exit 1; }

    repo_url="https://github.com/${repo}.git"
    log "starting panel update from ${repo}@${ref}"

    if [[ ! -d "${SOURCE_DIR}/.git" ]]; then
        install -d -m 0755 "$(dirname "$SOURCE_DIR")"
        git clone "$repo_url" "$SOURCE_DIR"
    fi

    git -C "$SOURCE_DIR" remote set-url origin "$repo_url"
    git -C "$SOURCE_DIR" fetch --tags --prune origin
    git -C "$SOURCE_DIR" checkout --force "$ref" 2>/dev/null \
        || git -C "$SOURCE_DIR" checkout --force "origin/$ref"
    git -C "$SOURCE_DIR" reset --hard "origin/$ref" 2>/dev/null || true

    bash "${SOURCE_DIR}/deploy/bootstrap.sh" --repo "$repo_url" --ref "$ref" --src-dir "$SOURCE_DIR" --with-nginx
    rm -f "$REQUEST_FILE"
    log "panel update completed"
}

main "$@"
