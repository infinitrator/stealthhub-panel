#!/usr/bin/env bash
# Root-side Infiproxy panel updater.
#
# The web panel only writes a small state/request file. This script performs the
# privileged git/build/install cycle from systemd so update permissions stay out
# of the HTTP process.
set -euo pipefail
umask 027

STATE_DIR="${INFIPROXY_STATE_DIR:-/var/lib/infiproxy}"
ROOT_STATE_DIR="${INFIPROXY_ROOT_STATE_DIR:-/var/lib/infiproxy-maintenance}"
SOURCE_DIR="${INFIPROXY_SRC_DIR:-/opt/infiproxy/source}"
STATE_FILE="${INFIPROXY_PANEL_UPDATE_STATE:-${STATE_DIR}/panel-update-state.env}"
REQUEST_FILE="${INFIPROXY_PANEL_UPDATE_REQUEST:-${STATE_DIR}/panel-update-now.request}"
RUN_LOG="${INFIPROXY_PANEL_UPDATE_LOG:-${ROOT_STATE_DIR}/panel-update-run.log}"
LOCK_DIR="${INFIPROXY_PANEL_UPDATE_LOCK:-/run/infiproxy-panel-update.lock}"
CONFIG_FILE="${INFIPROXY_UPDATE_CONFIG_FILE:-/etc/infiproxy-update.conf}"
APPLIED_SHA_FILE="${INFIPROXY_PANEL_APPLIED_SHA:-${ROOT_STATE_DIR}/panel-last-applied.sha}"

log() {
    local line
    line="$(date -u '+%Y-%m-%dT%H:%M:%SZ') $*"
    echo "$line"
    install -d -o root -g root -m 0751 "$ROOT_STATE_DIR"
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

read_config() {
    local key="$1"
    [[ -f "$CONFIG_FILE" ]] || return 1
    awk -F= -v key="$key" '$1 == key { sub("^[^=]*=", ""); print; exit }' "$CONFIG_FILE"
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

    local enabled available latest_sha applied_sha scheduled_time scheduled_hour scheduled_minute
    local current_hour current_minute scheduled_total current_total
    enabled="$(read_state AUTO_ENABLED || true)"
    available="$(read_state UPDATE_AVAILABLE || true)"
    latest_sha="$(read_state LATEST_SHA || true)"
    applied_sha="$(cat "$APPLIED_SHA_FILE" 2>/dev/null || true)"
    scheduled_time="$(read_state SCHEDULE_TIME || true)"
    scheduled_time="${scheduled_time:-05:00}"
    current_hour="$(date '+%-H')"
    current_minute="$(date '+%-M')"

    [[ "$enabled" == "true" ]] || return 1
    [[ "$available" == "true" ]] || return 1
    [[ -z "$latest_sha" || "$latest_sha" != "$applied_sha" ]] || return 1
    [[ "$scheduled_time" =~ ^([01][0-9]|2[0-3]):[0-5][0-9]$ ]] || return 1
    scheduled_hour="${scheduled_time%%:*}"
    scheduled_minute="${scheduled_time##*:}"
    scheduled_total=$((10#$scheduled_hour * 60 + 10#$scheduled_minute))
    current_total=$((10#$current_hour * 60 + 10#$current_minute))
    [[ "$current_total" -ge "$scheduled_total" ]]
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

    local repo ref repo_url previous_commit backup_dir backup_binary latest_sha applied_tmp
    repo="$(read_config REPO || true)"
    ref="$(read_config REF || true)"
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
    previous_commit="$(git -C "$SOURCE_DIR" rev-parse HEAD 2>/dev/null || true)"
    backup_dir="${ROOT_STATE_DIR}/update-backups/$(date '+%Y%m%d-%H%M%S')"
    backup_binary="${backup_dir}/infiproxy"
    install -d -m 0750 "$backup_dir"
    if [[ -x /usr/local/bin/infiproxy ]]; then
        cp -a /usr/local/bin/infiproxy "$backup_binary"
    fi
    if command -v sqlite3 >/dev/null 2>&1 && [[ -f "${STATE_DIR}/infiproxy.sqlite" ]]; then
        sqlite3 "${STATE_DIR}/infiproxy.sqlite" ".backup '${backup_dir}/infiproxy.sqlite'" \
            || log "warning: pre-update SQLite backup failed"
    fi
    git -C "$SOURCE_DIR" checkout --force "$ref" 2>/dev/null \
        || git -C "$SOURCE_DIR" checkout --force "origin/$ref"
    git -C "$SOURCE_DIR" reset --hard "origin/$ref" 2>/dev/null || true

    if ! bash "${SOURCE_DIR}/deploy/bootstrap.sh" --repo "$repo_url" --ref "$ref" --src-dir "$SOURCE_DIR" --with-nginx; then
        log "panel update failed; restoring previous binary and source revision"
        if [[ -n "$previous_commit" ]]; then
            git -C "$SOURCE_DIR" checkout --force --detach "$previous_commit" || true
        fi
        if [[ -f "$backup_binary" ]]; then
            install -m 0755 "$backup_binary" /usr/local/bin/infiproxy
            systemctl restart infiproxy.service || true
        fi
        exit 1
    fi
    rm -f "$REQUEST_FILE"
    latest_sha="$(read_state LATEST_SHA || true)"
    if [[ "$latest_sha" =~ ^[A-Fa-f0-9]{40}$ ]]; then
        applied_tmp="${APPLIED_SHA_FILE}.tmp.$$"
        printf '%s\n' "$latest_sha" >"$applied_tmp"
        chmod 0640 "$applied_tmp"
        mv -f "$applied_tmp" "$APPLIED_SHA_FILE"
    fi
    log "panel update completed"
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    main "$@"
fi
