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
LOCK_FILE="${INFIPROXY_PANEL_UPDATE_LOCK_FILE:-/run/lock/infiproxy-panel-update.lock}"
CONFIG_FILE="${INFIPROXY_UPDATE_CONFIG_FILE:-/etc/infiproxy-update.conf}"
APPLIED_SHA_FILE="${INFIPROXY_PANEL_APPLIED_SHA:-${ROOT_STATE_DIR}/panel-last-applied.sha}"
APP_USER="${INFIPROXY_USER:-infiproxy}"
APP_GROUP="${INFIPROXY_GROUP:-$APP_USER}"
DATABASE_FILE="${INFIPROXY_DATABASE_FILE:-${STATE_DIR}/infiproxy.sqlite}"
CONFIG_DIR="${INFIPROXY_CONFIG_DIR:-/etc/infiproxy}"
CORE_CONFIG_DIR="${INFIPROXY_CORE_CONFIG_DIR:-/etc/infiproxy-cores}"
HEADSCALE_CONFIG_DIR="${INFIPROXY_HEADSCALE_CONFIG_DIR:-/etc/headscale}"
MODULE_MANIFEST_DIR="${INFIPROXY_MODULE_MANIFEST_DIR:-/etc/infiproxy-modules.d}"
MODULE_AVAILABLE_DIR="${INFIPROXY_MODULE_AVAILABLE_DIR:-/etc/infiproxy-modules.available.d}"
NGINX_AVAILABLE="${INFIPROXY_NGINX_AVAILABLE:-/etc/nginx/sites-available/infiproxy.conf}"
NGINX_HEADSCALE_AVAILABLE="${INFIPROXY_NGINX_HEADSCALE_AVAILABLE:-/etc/nginx/sites-available/infiproxy-headscale.conf}"
PANEL_BINARY="${INFIPROXY_PANEL_BINARY:-/usr/local/bin/infiproxy}"
MANIFEST_HELPER_BINARY="${INFIPROXY_MANIFEST_HELPER_BINARY:-/usr/local/libexec/infiproxy-module-manifest}"
HEADSCALE_HELPER_BINARY="${INFIPROXY_HEADSCALE_HELPER_BINARY:-/usr/local/libexec/infiproxy-headscale-control}"
BACKUP_RETENTION_DAYS="${INFIPROXY_BACKUP_RETENTION_DAYS:-30}"
MAX_LOG_BYTES="${INFIPROXY_UPDATE_LOG_MAX_BYTES:-5242880}"

log() {
    local line
    line="$(date -u '+%Y-%m-%dT%H:%M:%SZ') $*"
    echo "$line"
    install -d -o root -g root -m 0751 "$ROOT_STATE_DIR"
    if [[ "$MAX_LOG_BYTES" =~ ^[0-9]{4,9}$ && -f "$RUN_LOG" ]] \
        && [[ "$(wc -c <"$RUN_LOG")" -ge "$MAX_LOG_BYTES" ]]; then
        mv -f "$RUN_LOG" "${RUN_LOG}.1"
    fi
    printf '%s\n' "$line" >>"$RUN_LOG"
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
    [[ "$1" =~ ^[A-Za-z0-9_./-]+$ ]] \
        && [[ "$1" != /* ]] && [[ "$1" != -* ]] && [[ "$1" != *..* ]]
}

resolve_target_commit() {
    local ref="$1" candidate target
    for candidate in "refs/remotes/origin/${ref}" "refs/tags/${ref}" "$ref"; do
        if target="$(git -C "$SOURCE_DIR" rev-parse --verify "${candidate}^{commit}" 2>/dev/null)"; then
            printf '%s' "$target"
            return 0
        fi
    done
    git -C "$SOURCE_DIR" fetch --force origin "$ref" || return 1
    git -C "$SOURCE_DIR" rev-parse --verify 'FETCH_HEAD^{commit}'
}

is_safe_update_target() {
    local previous_commit="$1" target_commit="$2"
    [[ -z "$previous_commit" || "${INFIPROXY_ALLOW_NON_FAST_FORWARD:-false}" == "true" ]] \
        && return 0
    git -C "$SOURCE_DIR" merge-base --is-ancestor "$previous_commit" "$target_commit"
}

backup_system_configs() {
    local backup_dir="$1" path
    local -a relative_paths=()
    for path in \
        "$CONFIG_DIR" \
        "$CORE_CONFIG_DIR" \
        "$HEADSCALE_CONFIG_DIR" \
        "$CONFIG_FILE" \
        "$MODULE_MANIFEST_DIR" \
        "$MODULE_AVAILABLE_DIR" \
        "$NGINX_AVAILABLE" \
        "$NGINX_HEADSCALE_AVAILABLE"
    do
        [[ "$path" == /* && "$path" != *$'\n'* ]] \
            || { log "unsafe backup path: $path"; return 1; }
        [[ -e "$path" || -L "$path" ]] && relative_paths+=("${path#/}")
    done
    if [[ "${#relative_paths[@]}" -eq 0 ]]; then
        log "no system configs found for pre-update backup"
        return 0
    fi
    tar -C / -czf "${backup_dir}/system-configs.tar.gz" -- "${relative_paths[@]}" \
        || return 1
    chmod 0600 "${backup_dir}/system-configs.tar.gz" || return 1
}

backup_database() {
    local backup_dir="$1"
    [[ -f "$DATABASE_FILE" ]] || return 0
    [[ "$DATABASE_FILE" == /* && "$DATABASE_FILE" != *"'"* && "$backup_dir" != *"'"* ]] || {
        log "unsafe database backup path"
        return 1
    }
    command -v sqlite3 >/dev/null 2>&1 || {
        log "sqlite3 is required to protect the existing panel database"
        return 1
    }
    sqlite3 "$DATABASE_FILE" ".backup '${backup_dir}/infiproxy.sqlite'" || return 1
    chmod 0600 "${backup_dir}/infiproxy.sqlite" || return 1
}

backup_control_binaries() {
    local backup_dir="$1" entry name source
    local -a binaries=(
        "infiproxy:${PANEL_BINARY}"
        "infiproxy-module-manifest:${MANIFEST_HELPER_BINARY}"
        "infiproxy-headscale-control:${HEADSCALE_HELPER_BINARY}"
    )
    install -d -o root -g root -m 0700 "${backup_dir}/control-binaries"
    for entry in "${binaries[@]}"; do
        name="${entry%%:*}"
        source="${entry#*:}"
        if [[ -x "$source" && ! -L "$source" ]]; then
            install -m 0700 -o root -g root "$source" \
                "${backup_dir}/control-binaries/${name}"
        else
            install -m 0600 -o root -g root /dev/null \
                "${backup_dir}/control-binaries/${name}.absent"
        fi
    done
    [[ -f "${backup_dir}/control-binaries/infiproxy" ]] || {
        log "installed panel binary is missing or unsafe: ${PANEL_BINARY}"
        return 1
    }
}

restore_control_binaries() {
    local backup_dir="$1" entry name destination target_name backup
    local -a binaries=(
        "infiproxy:${PANEL_BINARY}:stealthhub-panel"
        "infiproxy-module-manifest:${MANIFEST_HELPER_BINARY}:infiproxy-module-manifest"
        "infiproxy-headscale-control:${HEADSCALE_HELPER_BINARY}:infiproxy-headscale-control"
    )
    install -d -m 0755 "${SOURCE_DIR}/target/release"
    for entry in "${binaries[@]}"; do
        name="${entry%%:*}"
        entry="${entry#*:}"
        destination="${entry%%:*}"
        target_name="${entry##*:}"
        backup="${backup_dir}/control-binaries/${name}"
        if [[ -f "$backup" ]]; then
            install -d -m 0755 "$(dirname "$destination")"
            install -m 0755 "$backup" "$destination"
            install -m 0755 "$backup" "${SOURCE_DIR}/target/release/${target_name}"
        elif [[ -f "${backup}.absent" ]]; then
            rm -f -- "$destination" "${SOURCE_DIR}/target/release/${target_name}"
        else
            log "control binary backup is incomplete: ${name}"
            return 1
        fi
    done
}

restore_update_backup() {
    local backup_dir="$1" database_was_present="$2"
    systemctl stop infiproxy.service 2>/dev/null || true
    if [[ -f "${backup_dir}/system-configs.tar.gz" ]]; then
        tar -C / -xzf "${backup_dir}/system-configs.tar.gz" || return 1
    fi
    rm -f "${DATABASE_FILE}-wal" "${DATABASE_FILE}-shm" || return 1
    if [[ -f "${backup_dir}/infiproxy.sqlite" ]]; then
        install -d -o "$APP_USER" -g "$APP_GROUP" -m 0750 \
            "$(dirname "$DATABASE_FILE")" || return 1
        install -m 0640 -o "$APP_USER" -g "$APP_GROUP" \
            "${backup_dir}/infiproxy.sqlite" "$DATABASE_FILE" || return 1
    elif [[ "$database_was_present" -eq 0 ]]; then
        rm -f "$DATABASE_FILE" || return 1
    fi
}

wait_panel_ready() {
    local bind host port attempts=15
    bind="$(awk -F= '$1 == "INFIPROXY_BIND" { sub("^[^=]*=", ""); print; exit }' \
        "${CONFIG_DIR}/infiproxy.env" 2>/dev/null || true)"
    bind="${bind:-127.0.0.1:8080}"
    host="${bind%:*}"
    port="${bind##*:}"
    [[ "$port" =~ ^[0-9]{1,5}$ && "$port" -ge 1 && "$port" -le 65535 ]] || {
        log "invalid panel bind port after update"
        return 1
    }
    case "$host" in
        127.0.0.1|localhost) ;;
        0.0.0.0) host="127.0.0.1" ;;
        "[::1]") ;;
        "[::]") host="[::1]" ;;
        *)
            log "refusing readiness request to non-local panel bind: $host"
            return 1
            ;;
    esac
    while [[ "$attempts" -gt 0 ]]; do
        if systemctl is-active --quiet infiproxy.service \
            && curl --fail --silent --show-error --max-time 3 \
                "http://${host}:${port}/ready" >/dev/null; then
            return 0
        fi
        attempts=$((attempts - 1))
        sleep 2
    done
    log "updated panel did not become ready"
    return 1
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

    command -v flock >/dev/null 2>&1 || { log "flock is required"; exit 1; }
    install -d -o root -g root -m 0755 "$(dirname "$LOCK_FILE")"
    exec 9>"$LOCK_FILE"
    if ! flock -n 9; then
        log "another updater instance is already running"
        exit 0
    fi

    if ! should_update_now; then
        log "no panel update due"
        exit 0
    fi

    local repo ref repo_url previous_commit target_commit installed_commit applied_commit
    local backup_dir applied_tmp
    local database_was_present=0
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
    git -C "$SOURCE_DIR" fetch --force --prune --tags origin \
        '+refs/heads/*:refs/remotes/origin/*'
    target_commit="$(resolve_target_commit "$ref")"
    [[ "$target_commit" =~ ^[A-Fa-f0-9]{40}$ ]] \
        || { log "unable to resolve target commit for $ref"; exit 1; }
    previous_commit="$(git -C "$SOURCE_DIR" rev-parse HEAD 2>/dev/null || true)"
    if ! is_safe_update_target "$previous_commit" "$target_commit"; then
        log "refusing non-fast-forward update from ${previous_commit:0:12} to ${target_commit:0:12}"
        log "set INFIPROXY_ALLOW_NON_FAST_FORWARD=true only for a reviewed recovery"
        exit 1
    fi
    installed_commit="$(awk -F= '$1 == "INFIPROXY_CURRENT_COMMIT" { sub("^[^=]*=", ""); print; exit }' \
        "${CONFIG_DIR}/infiproxy.env" 2>/dev/null || true)"
    applied_commit="$(cat "$APPLIED_SHA_FILE" 2>/dev/null || true)"
    if [[ "$target_commit" == "$installed_commit" || "$target_commit" == "$applied_commit" ]]; then
        rm -f "$REQUEST_FILE"
        log "panel is already current at ${target_commit:0:12}"
        exit 0
    fi
    backup_dir="${ROOT_STATE_DIR}/update-backups/$(date '+%Y%m%d-%H%M%S')-$$"
    [[ "$BACKUP_RETENTION_DAYS" =~ ^[0-9]{1,3}$ ]] \
        || { log "invalid backup retention: $BACKUP_RETENTION_DAYS"; exit 1; }
    install -d -o root -g root -m 0700 "$backup_dir"
    backup_control_binaries "$backup_dir" \
        || { log "panel update aborted: control binary backup failed"; exit 1; }
    [[ -f "$DATABASE_FILE" ]] && database_was_present=1
    backup_database "$backup_dir" \
        || { log "panel update aborted: database backup failed"; exit 1; }
    backup_system_configs "$backup_dir" \
        || { log "panel update aborted: config backup failed"; exit 1; }
    {
        printf 'created_at=%s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
        printf 'previous_commit=%s\n' "$previous_commit"
        printf 'target_commit=%s\n' "$target_commit"
        printf 'database_was_present=%s\n' "$database_was_present"
    } >"${backup_dir}/metadata.env"
    chmod 0600 "${backup_dir}/metadata.env"
    find "${ROOT_STATE_DIR}/update-backups" -mindepth 1 -maxdepth 1 -type d \
        -mtime "+${BACKUP_RETENTION_DAYS}" -exec rm -rf -- {} +
    git -C "$SOURCE_DIR" checkout --force --detach "$target_commit"
    git -C "$SOURCE_DIR" clean -fdx -e target/

    export PATH="/root/.cargo/bin:$PATH"
    if ! cargo build --locked --release -p stealthhub-panel \
            --jobs "${INFIPROXY_BUILD_JOBS:-2}" \
            --manifest-path "${SOURCE_DIR}/Cargo.toml" \
        || ! INFIPROXY_UPDATE_REPO="$repo" INFIPROXY_UPDATE_REF="$ref" \
            INFIPROXY_INSTALL_COMMIT="$target_commit" \
            bash "${SOURCE_DIR}/deploy/install.sh" --with-nginx \
        || ! wait_panel_ready; then
        log "panel update failed; restoring previous control plane and source revision"
        restore_update_backup "$backup_dir" "$database_was_present" \
            || log "warning: automatic data/config restore was incomplete"
        if [[ -n "$previous_commit" ]]; then
            git -C "$SOURCE_DIR" checkout --force --detach "$previous_commit" || true
        fi
        if restore_control_binaries "$backup_dir"; then
            INFIPROXY_UPDATE_REPO="$repo" INFIPROXY_UPDATE_REF="$ref" \
                bash "${SOURCE_DIR}/deploy/install.sh" --with-nginx \
                || log "warning: previous installer could not fully repair the control plane"
            systemctl restart infiproxy.service || true
        else
            log "warning: previous control binaries could not be fully restored"
        fi
        exit 1
    fi
    rm -f "$REQUEST_FILE"
    applied_tmp="${APPLIED_SHA_FILE}.tmp.$$"
    printf '%s\n' "$target_commit" >"$applied_tmp"
    chmod 0640 "$applied_tmp"
    mv -f "$applied_tmp" "$APPLIED_SHA_FILE"
    log "panel update completed at ${target_commit:0:12}"
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    main "$@"
fi
