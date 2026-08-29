#!/usr/bin/env bash
# Root worker for independently managed Infiproxy module manifests.
set -Eeuo pipefail
umask 027

STATE_DIR="${INFIPROXY_STATE_DIR:-/var/lib/infiproxy}"
ROOT_STATE_DIR="${INFIPROXY_ROOT_STATE_DIR:-/var/lib/infiproxy-maintenance}"
MANIFEST_DIR="${INFIPROXY_MODULE_MANIFEST_DIR:-/etc/infiproxy-modules.d}"
AVAILABLE_DIR="${INFIPROXY_MODULE_AVAILABLE_DIR:-/etc/infiproxy-modules.available.d}"
MODULE_STATE_DIR="${STATE_DIR}/modules"
MODULE_VERSION_DIR="${INFIPROXY_MODULE_VERSION_DIR:-${ROOT_STATE_DIR}/module-versions}"
REQUEST_DIR="${STATE_DIR}/module-requests"
DISABLED_DIR="${ROOT_STATE_DIR}/module-disabled"
MODULE_BACKUP_ROOT="${INFIPROXY_MODULE_BACKUP_ROOT:-${ROOT_STATE_DIR}/module-backups}"
BACKUP_RETENTION_DAYS="${INFIPROXY_BACKUP_RETENTION_DAYS:-30}"
MAX_LOG_BYTES="${INFIPROXY_UPDATE_LOG_MAX_BYTES:-5242880}"
MAX_DOWNLOAD_BYTES="${INFIPROXY_MODULE_MAX_DOWNLOAD_BYTES:-536870912}"
CORE_ROOT="${INFIPROXY_CORE_ROOT:-/opt/infiproxy/cores}"
MODULE_ROOT="${INFIPROXY_MODULE_ROOT:-/opt/infiproxy/modules}"
CORE_INSTALLER="${INFIPROXY_CORE_INSTALLER:-/usr/local/sbin/infiproxy-core-install}"
MANIFEST_HELPER="${INFIPROXY_MODULE_MANIFEST_HELPER:-/usr/local/libexec/infiproxy-module-manifest}"
PANEL_STATE="${STATE_DIR}/panel-update-state.env"
RUN_LOG="${ROOT_STATE_DIR}/module-update.log"
LOCK_FILE="${INFIPROXY_MODULE_UPDATE_LOCK_FILE:-/run/lock/infiproxy-module-update.lock}"
GITHUB_API="https://api.github.com/repos"
APP_USER="${INFIPROXY_USER:-infiproxy}"
APP_GROUP="${INFIPROXY_GROUP:-infiproxy}"
RUNTIME_GROUP="${INFIPROXY_RUNTIME_GROUP:-infiproxy-runtime}"
RECONCILE_APPLIED_FILE="${INFIPROXY_RECONCILE_APPLIED_FILE:-${ROOT_STATE_DIR}/reconcile/applied.json}"

module_is_retired() {
  [[ "$1" == "headscale" || "$1" == "mtproto" ]]
}

require_active_product_module() {
  module_is_retired "$1" && die "retired module supports removal only: $1"
  valid_id "$1" || die "invalid module ID"
}

log() {
  local line
  line="$(date '+%Y-%m-%dT%H:%M:%S%z') $*"
  printf '%s\n' "$line"
  install -d -o root -g root -m 0751 "$ROOT_STATE_DIR"
  if [[ "$MAX_LOG_BYTES" =~ ^[0-9]{4,9}$ && -f "$RUN_LOG" ]] \
    && [[ "$(wc -c <"$RUN_LOG")" -ge "$MAX_LOG_BYTES" ]]; then
    mv -f "$RUN_LOG" "${RUN_LOG}.1"
  fi
  printf '%s\n' "$line" >>"$RUN_LOG"
}

die() {
  log "ERROR: $*"
  exit 1
}

need_root() {
  if [[ "$(id -u)" -ne 0 ]]; then
    printf '%s\n' "Run as root: sudo infiproxy-module-update" >&2
    exit 1
  fi
}

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "missing command: $1"
}

prepare_request_dir() {
  local expected_uid actual_uid mode
  expected_uid="$(id -u "$APP_USER")" || die "missing service user: ${APP_USER}"
  if [[ ! -e "$REQUEST_DIR" && ! -L "$REQUEST_DIR" ]]; then
    install -d -o "$APP_USER" -g "$APP_GROUP" -m 0750 "$REQUEST_DIR"
  fi
  [[ -d "$REQUEST_DIR" && ! -L "$REQUEST_DIR" ]] \
    || die "module request path must be a real directory"
  actual_uid="$(stat -c '%u' "$REQUEST_DIR")"
  mode="$(stat -c '%a' "$REQUEST_DIR")"
  [[ "$actual_uid" == "$expected_uid" ]] \
    || die "module request directory must be owned by ${APP_USER}"
  (( (8#$mode & 0022) == 0 )) \
    || die "module request directory must not be group/world-writable"
}

safe_request_file() {
  local request="$1" directory_uid request_uid mode size
  [[ -f "$request" && ! -L "$request" ]] || return 1
  directory_uid="$(stat -c '%u' "$REQUEST_DIR")" || return 1
  request_uid="$(stat -c '%u' "$request")" || return 1
  mode="$(stat -c '%a' "$request")" || return 1
  size="$(stat -c '%s' "$request")" || return 1
  [[ "$request_uid" == "$directory_uid" && "$size" -le 4096 ]] || return 1
  (( (8#$mode & 0022) == 0 ))
}

discard_unsafe_request() {
  log "discarding unsafe module request: $(basename "$1")"
  rm -f -- "$1"
}

valid_id() {
  [[ "$1" =~ ^[a-z][a-z0-9-]{0,31}$ ]]
}

manifest_file() {
  printf '%s/%s.module' "$MANIFEST_DIR" "$1"
}

module_ids() {
  "$MANIFEST_HELPER" list "$MANIFEST_DIR" --root-owned
}

load_module() {
  local id="$1" record
  valid_id "$id" || return 1
  record="$("$MANIFEST_HELPER" read "$(manifest_file "$id")" --root-owned)" || return 1
  IFS='|' read -r M_ID _ _ _ M_REPO M_UPSTREAM M_REF M_DRIVER \
    M_ROOT M_BINARY M_SERVICE M_CONFIG M_ASSET_AMD64 M_ASSET_ARM64 <<<"$record"
  [[ "$M_ID" == "$id" ]]
}

host_arch() {
  case "$(uname -m)" in
    x86_64|amd64) echo "amd64" ;;
    aarch64|arm64) echo "arm64" ;;
    *) die "unsupported architecture: $(uname -m)" ;;
  esac
}

runtime_root() {
  if [[ "$M_ROOT" == "cores" ]]; then
    printf '%s/%s' "$CORE_ROOT" "$M_ID"
  else
    printf '%s/%s' "$MODULE_ROOT" "$M_ID"
  fi
}

module_binary() {
  printf '%s/current/%s' "$(runtime_root)" "$M_BINARY"
}

state_value() {
  local file="$1" key="$2" value
  [[ -f "$file" ]] || return 1
  value="$(awk -F= -v key="$key" '$1 == key { sub("^[^=]*=", ""); print; exit }' "$file")"
  value="${value#\'}"
  value="${value%\'}"
  printf '%s' "$value"
}

installed_version() {
  local file="${MODULE_VERSION_DIR}/$1.version"
  if [[ -s "$file" ]]; then
    tr -d '[:space:]' <"$file"
  else
    echo "unknown"
  fi
}

normalize_version() {
  local value="$1"
  value="${value#app/v}"
  value="${value#tuic-server-}"
  value="${value#v}"
  printf '%s' "$value"
}

github_json() {
  local curl_config="${INFIPROXY_GITHUB_CURL_CONFIG:-/root/.config/infiproxy/github-api.curl}"
  local -a auth_args=()

  if [[ -r "$curl_config" ]]; then
    auth_args=(--config "$curl_config")
  fi

  curl "${auth_args[@]}" \
    --fail --silent --show-error --location \
    --proto '=https' --proto-redir '=https' --tlsv1.2 \
    --connect-timeout 15 --max-time 30 --retry 2 \
    -H 'Accept: application/vnd.github+json' \
    -H 'X-GitHub-Api-Version: 2022-11-28' \
    -H 'User-Agent: Infiproxy-module-updater' "$1"
}

download_release_asset() {
  local output="$1" url="$2"
  local -a args=(
    --fail
    --location
    --show-error
    --proto '=https'
    --proto-redir '=https'
    --tlsv1.2
    --retry 3
    --retry-all-errors
    --connect-timeout 15
    --max-time 600
    --max-filesize "$MAX_DOWNLOAD_BYTES"
  )
  [[ "$MAX_DOWNLOAD_BYTES" =~ ^[0-9]{6,10}$ ]] \
    || die "invalid module download limit"
  [[ -n "${M_REPO:-}" && "$url" == "https://github.com/${M_REPO}/releases/download/"* ]] \
    || die "refusing untrusted release download URL"
  if [[ "${INFIPROXY_FORCE_IPV4:-false}" == "true" ]]; then
    args+=(--ipv4)
  fi
  curl "${args[@]}" --output "$output" "$url"
}

# Prints: tag|asset-name|asset-url|sha256-or-empty|checksum-url-or-empty
asset_pattern() {
  local arch="$1"
  if [[ "$arch" == "amd64" ]]; then
    printf '%s' "$M_ASSET_AMD64"
  else
    printf '%s' "$M_ASSET_ARM64"
  fi
}

release_metadata() {
  local arch="$1" pattern api_url api_json metadata tag
  pattern="$(asset_pattern "$arch")"
  if [[ "$M_UPSTREAM" == "pinned-release" ]]; then
    api_url="${GITHUB_API}/${M_REPO}/releases/tags/${M_REF}"
  else
    api_url="${GITHUB_API}/${M_REPO}/releases/latest"
  fi
  api_json="$(github_json "$api_url")"
  metadata="$("$MANIFEST_HELPER" release-metadata "$pattern" <<<"$api_json")"
  if [[ "$M_UPSTREAM" == "pinned-release" ]]; then
    tag="${metadata%%|*}"
    [[ "$tag" == "$M_REF" ]] || die "pinned release tag mismatch for ${M_ID}"
  fi
  printf '%s\n' "$metadata"
}

upstream_latest_version() {
  local pattern api_json
  pattern="$(asset_pattern "$(host_arch)")"
  api_json="$(github_json "${GITHUB_API}/${M_REPO}/releases/latest")"
  "$MANIFEST_HELPER" release-metadata "$pattern" <<<"$api_json" | cut -d'|' -f1
}

compare_versions() {
  "$MANIFEST_HELPER" compare-versions "$1" "$2"
}

resolve_checksum() {
  local expected_asset="$1" digest="$2" checksum_url="$3" checksum_file checksum
  if [[ "$digest" =~ ^[A-Fa-f0-9]{64}$ ]]; then
    printf '%s' "$digest" | tr 'A-F' 'a-f'
    return
  fi
  [[ "$checksum_url" == "https://github.com/${M_REPO}/releases/download/"* ]] \
    || die "no trusted checksum is available for ${expected_asset}"
  checksum_file="$(mktemp)"
  if ! download_release_asset "$checksum_file" "$checksum_url"; then
    rm -f "$checksum_file"
    die "failed to download official checksum for ${expected_asset}"
  fi
  checksum="$(awk -v name="$expected_asset" '
    length($1) == 64 {
      file = $2
      sub(/^\*/, "", file)
      if (NF == 1 || file == name) { print $1; exit }
    }
  ' "$checksum_file")"
  rm -f "$checksum_file"
  [[ "$checksum" =~ ^[A-Fa-f0-9]{64}$ ]] \
    || die "official checksum file does not contain ${expected_asset}"
  printf '%s' "$checksum" | tr 'A-F' 'a-f'
}

remember_version() {
  local target temporary
  install -d -o root -g "$APP_GROUP" -m 0750 "$MODULE_VERSION_DIR"
  target="${MODULE_VERSION_DIR}/$1.version"
  temporary="$(mktemp "${MODULE_VERSION_DIR}/.$1.version.XXXXXX")"
  printf '%s\n' "$2" >"$temporary"
  chown root:"$APP_GROUP" "$temporary" 2>/dev/null || true
  chmod 0640 "$temporary"
  mv -f -- "$temporary" "$target"
}

backup_module_config() {
  local was_enabled="$1" was_active="$2"
  local module_dir backup_dir current_target timestamp
  local -a backup_paths=()
  if [[ -e "$M_CONFIG" || -L "$M_CONFIG" ]]; then
    [[ -f "$M_CONFIG" && ! -L "$M_CONFIG" ]] \
      || die "refusing to back up unsafe module config: ${M_CONFIG}"
    backup_paths+=("${M_CONFIG#/}")
  fi
  [[ "${#backup_paths[@]}" -gt 0 ]] || {
    log "no existing config to back up for ${M_ID}: ${M_CONFIG}"
    return
  }
  [[ "$BACKUP_RETENTION_DAYS" =~ ^[0-9]{1,3}$ ]] \
    || die "invalid backup retention: ${BACKUP_RETENTION_DAYS}"

  timestamp="$(date '+%Y%m%d-%H%M%S')-$$"
  module_dir="${MODULE_BACKUP_ROOT}/${M_ID}"
  backup_dir="${module_dir}/${timestamp}"
  current_target="$(readlink -f "$(runtime_root)/current" 2>/dev/null || true)"
  install -d -o root -g root -m 0700 "$backup_dir" \
    || die "failed to create module backup directory"
  if ! tar -C / -czf "${backup_dir}/config.tar.gz" -- "${backup_paths[@]}"; then
    rm -rf -- "$backup_dir"
    die "failed to back up ${M_ID} config"
  fi
  chmod 0600 "${backup_dir}/config.tar.gz" \
    || die "failed to protect ${M_ID} config backup"
  {
    printf 'module=%s\n' "$M_ID"
    printf 'config=%s\n' "$M_CONFIG"
    printf 'installed_version=%s\n' "$(installed_version "$M_ID")"
    printf 'current_target=%s\n' "$current_target"
    printf 'service_enabled=%s\n' "$was_enabled"
    printf 'service_active=%s\n' "$was_active"
  } >"${backup_dir}/metadata.env" || die "failed to write module backup metadata"
  chmod 0600 "${backup_dir}/metadata.env" \
    || die "failed to protect module backup metadata"
  find "$module_dir" -mindepth 1 -maxdepth 1 -type d \
    -mtime "+${BACKUP_RETENTION_DAYS}" -exec rm -rf -- {} + \
    || die "failed to prune old module backups"
  log "backed up ${M_ID} config and state to ${backup_dir}"
}

restore_service_state() {
  local service="$1" was_enabled="$2" was_active="$3"
  systemctl daemon-reload || return 1
  if [[ "$was_enabled" -eq 1 ]]; then
    systemctl enable "$service" >/dev/null || return 1
  fi
  if [[ "$was_active" -eq 1 ]]; then
    systemctl restart "$service" || return 1
    sleep 2
    systemctl is-active --quiet "$service" || return 1
  fi
}

rollback_symlink() {
  local current_link="$1" previous_target="$2" service="$3" was_active="$4" next
  [[ -n "$previous_target" && -d "$previous_target" ]] || return 1
  next="${current_link}.rollback.$$"
  ln -s "$previous_target" "$next" || return 1
  mv -Tf "$next" "$current_link" || {
    rm -f "$next"
    return 1
  }
  if [[ "$was_active" -eq 1 ]]; then
    systemctl restart "$service" || return 1
    sleep 2
    systemctl is-active --quiet "$service" || return 1
  fi
  log "rolled back ${service} to ${previous_target}"
}

install_release_module() {
  local allow_downgrade="${1:-false}"
  local metadata tag asset url digest checksum_url checksum tmp normalized current ordering
  local was_enabled=0 was_active=0 current_link previous_target
  metadata="$(release_metadata "$(host_arch)")"
  IFS='|' read -r tag asset url digest checksum_url <<<"$metadata"
  [[ "$url" == "https://github.com/${M_REPO}/releases/download/"* ]] \
    || die "refusing unexpected release URL for ${M_ID}"
  checksum="$(resolve_checksum "$asset" "$digest" "$checksum_url")"
  normalized="$(normalize_version "$tag")"
  current="$(installed_version "$M_ID")"

  if [[ -x "$(module_binary)" ]] \
    && { [[ "$current" == "$tag" ]] || [[ "$current" == "$normalized" ]]; }; then
    log "${M_ID} is already current (${tag})"
    return
  fi
  if [[ "$M_UPSTREAM" == "pinned-release" && "$current" != "unknown" ]]; then
    ordering="$(compare_versions "$current" "$tag")"
    if [[ "$ordering" -gt 0 && "$allow_downgrade" != "true" ]]; then
      log "${M_ID} ${current} is newer than validated pin ${tag}; automatic downgrade refused"
      return
    fi
  fi

  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"; trap - RETURN' RETURN
  download_release_asset "${tmp}/${asset}" "$url" \
    || die "failed to download ${asset}"
  printf '%s  %s\n' "$checksum" "${tmp}/${asset}" | sha256sum -c - \
    || die "checksum verification failed for ${asset}"
  systemctl is-enabled --quiet "$M_SERVICE" 2>/dev/null && was_enabled=1
  systemctl is-active --quiet "$M_SERVICE" 2>/dev/null && was_active=1
  backup_module_config "$was_enabled" "$was_active"

  [[ "$M_DRIVER" == "release" && "$M_ROOT" == "cores" ]] \
    || die "unsupported generic release contract for ${M_ID}"
  current_link="$(runtime_root)/current"
  previous_target="$(readlink -f "$current_link" 2>/dev/null || true)"
  "$CORE_INSTALLER" --core "$M_ID" --version "$normalized" \
    --archive "${tmp}/${asset}" --sha256 "$checksum" --binary "$M_BINARY"
  if ! restore_service_state "$M_SERVICE" "$was_enabled" "$was_active"; then
    if rollback_symlink "$current_link" "$previous_target" "$M_SERVICE" "$was_active"; then
      die "${M_SERVICE} failed after update; previous binary and service were restored"
    fi
    die "${M_SERVICE} failed after update and automatic rollback was incomplete"
  fi
  remember_version "$M_ID" "$tag"
  log "updated ${M_ID}: ${tag}"
}

latest_version() {
  [[ "$M_UPSTREAM" == "release" || "$M_UPSTREAM" == "pinned-release" ]] \
    || die "retired source modules support removal only"
  release_metadata "$(host_arch)" | cut -d'|' -f1
}

check_module() {
  local module="$1" current latest state ordering upstream_latest
  load_module "$module" || die "unknown or invalid module: $module"
  current="$(installed_version "$module")"
  latest="$(latest_version)"
  if [[ ! -x "$(module_binary)" ]]; then
    if [[ "$M_UPSTREAM" == "pinned-release" ]]; then
      state="pinned version not installed"
    else
      state="not installed"
    fi
  elif [[ "$M_UPSTREAM" == "pinned-release" ]]; then
    ordering="$(compare_versions "$current" "$latest")"
    if [[ "$ordering" -gt 0 ]]; then
      state="installed version outside validated contract"
    elif [[ "$ordering" -lt 0 ]]; then
      state="pinned version not installed"
    else
      upstream_latest="$(upstream_latest_version)"
      if [[ "$(compare_versions "$upstream_latest" "$latest")" -gt 0 ]]; then
        state="current; newer upstream intentionally not selected"
      else
        state="current"
      fi
    fi
  else
    state="update available"
    [[ "$(normalize_version "$current")" == "$(normalize_version "$latest")" ]] \
      && state="current"
  fi
  printf '%-20s installed=%-18s latest=%-18s %s\n' \
    "$module" "${current:0:18}" "${latest:0:18}" "$state"
}

update_module() {
  local module="$1" allow_downgrade="${2:-false}"
  load_module "$module" || die "unknown or invalid module: $module"
  log "checking ${module}"
  [[ "$M_UPSTREAM" == "release" || "$M_UPSTREAM" == "pinned-release" ]] \
    || die "retired source modules support removal only"
  install_release_module "$allow_downgrade"
}

register_requested() {
  local request id source target failed=0
  install -d -o root -g root -m 0755 "$MANIFEST_DIR"
  install -d -o root -g root -m 0755 "$AVAILABLE_DIR"
  install -d -o root -g root -m 0750 "$DISABLED_DIR"
  shopt -s nullglob
  for request in "$REQUEST_DIR"/*.register; do
    if ! safe_request_file "$request"; then
      discard_unsafe_request "$request"
      failed=1
      continue
    fi
    id="$(basename "$request" .register)"
    source="${AVAILABLE_DIR}/${id}.module"
    target="$(manifest_file "$id")"
    if ! module_is_retired "$id" && valid_id "$id" \
      && [[ ! -e "$target" ]] \
      && "$MANIFEST_HELPER" validate "$source" --root-owned; then
      install -o root -g root -m 0644 "$source" "$target"
      rm -f "${DISABLED_DIR}/${id}" "${request}.failed"
      load_module "$id" || die "installed manifest could not be reloaded: ${id}"
      install -d -o root -g "$RUNTIME_GROUP" -m 0750 "$(dirname "$M_CONFIG")"
      if (update_module "$id" true); then
        rm -f "$request"
      else
        mv -f "$target" "${target}.failed"
        mv -f "$request" "${request}.failed"
        log "registration install failed for ${id}"
        failed=1
      fi
    else
      mv -f "$request" "${request}.failed"
      log "registration rejected for ${id}"
      failed=1
    fi
  done
  shopt -u nullglob
  return "$failed"
}

remove_requested() {
  local request id legacy_dir failed=0
  install -d -o root -g root -m 0750 "$DISABLED_DIR"
  install -d -o root -g root -m 0755 "$AVAILABLE_DIR"
  shopt -s nullglob
  for request in "$REQUEST_DIR"/*.remove; do
    if ! safe_request_file "$request"; then
      discard_unsafe_request "$request"
      failed=1
      continue
    fi
    id="$(basename "$request" .remove)"
    if load_module "$id"; then
      if [[ -f "$RECONCILE_APPLIED_FILE" && ! -L "$RECONCILE_APPLIED_FILE" ]] \
          && grep -Eq '"active_core_ids"[[:space:]]*:[[:space:]]*\[[^]]*"'"$id"'"' \
              "$RECONCILE_APPLIED_FILE"; then
        mv -f "$request" "${request}.failed"
        log "removal blocked for active desired-state adapter ${id}"
        failed=1
        continue
      fi
      if module_is_retired "$id"; then
        legacy_dir="${ROOT_STATE_DIR}/legacy-modules/${id}"
        install -d -o root -g root -m 0700 "$legacy_dir"
        install -o root -g root -m 0600 "$(manifest_file "$id")" \
          "${legacy_dir}/removed.module"
        rm -f -- "${AVAILABLE_DIR}/${id}.module"
      elif [[ ! -e "${AVAILABLE_DIR}/${id}.module" ]]; then
        install -o root -g root -m 0644 "$(manifest_file "$id")" "${AVAILABLE_DIR}/${id}.module"
      fi
      systemctl disable --now "$M_SERVICE" 2>/dev/null || true
      rm -rf "$(runtime_root)"
      rm -f "$(manifest_file "$id")" "${MODULE_VERSION_DIR}/${id}.version" \
        "${MODULE_STATE_DIR}/${id}.env" "$request" "${request}.failed"
      install -o root -g root -m 0644 /dev/null "${DISABLED_DIR}/${id}"
      systemctl daemon-reload || true
      log "removed ${id}; configuration preserved at ${M_CONFIG}"
    else
      mv -f "$request" "${request}.failed"
      failed=1
    fi
  done
  shopt -u nullglob
  return "$failed"
}

run_requested() {
  local module request failed=0
  while IFS= read -r module; do
    request="${REQUEST_DIR}/${module}.request"
    [[ -f "$request" ]] || continue
    if module_is_retired "$module"; then
      mv -f "$request" "${request}.failed"
      log "update rejected for retired module ${module}; remove it instead"
      failed=1
      continue
    fi
    if ! safe_request_file "$request"; then
      discard_unsafe_request "$request"
      failed=1
      continue
    fi
    if (update_module "$module" true); then
      rm -f "$request" "${request}.failed"
    else
      mv -f "$request" "${request}.failed"
      log "request failed for ${module}; details retained in ${request}.failed"
      failed=1
    fi
  done < <(module_ids)
  return "$failed"
}

lifecycle_requested() {
  local action request id failed=0
  for action in start stop restart; do
    shopt -s nullglob
    for request in "$REQUEST_DIR"/*."$action"; do
      if ! safe_request_file "$request"; then
        discard_unsafe_request "$request"
        failed=1
        continue
      fi
      id="$(basename "$request" ".${action}")"
      if module_is_retired "$id"; then
        mv -f "$request" "${request}.failed"
        log "${action} rejected for retired module ${id}"
        failed=1
        continue
      fi
      if ! load_module "$id" || [[ ! -x "$(module_binary)" ]]; then
        mv -f "$request" "${request}.failed"
        log "${action} rejected for unavailable runtime ${id}"
        failed=1
        continue
      fi
      if systemctl "$action" "$M_SERVICE"; then
        rm -f "$request" "${request}.failed"
        log "${action} completed for ${id}"
      else
        mv -f "$request" "${request}.failed"
        log "${action} failed for ${id}"
        failed=1
      fi
    done
    shopt -u nullglob
  done
  return "$failed"
}

run_automatic() {
  local schedule_time hour minute current_hour current_minute schedule_total current_total
  local today marker marker_tmp module state_file enabled installed failed=0
  schedule_time="$(state_value "$PANEL_STATE" SCHEDULE_TIME || true)"
  schedule_time="${schedule_time:-05:00}"
  [[ "$schedule_time" =~ ^([01][0-9]|2[0-3]):[0-5][0-9]$ ]] \
    || die "invalid maintenance time: $schedule_time"
  hour="${schedule_time%%:*}"
  minute="${schedule_time##*:}"
  current_hour="$(date '+%-H')"
  current_minute="$(date '+%-M')"
  schedule_total=$((10#$hour * 60 + 10#$minute))
  current_total=$((10#$current_hour * 60 + 10#$current_minute))
  [[ "$current_total" -ge "$schedule_total" ]] || return 0
  today="$(date '+%F')"
  marker="${ROOT_STATE_DIR}/module-last-auto-date"
  [[ "$(cat "$marker" 2>/dev/null || true)" != "$today" ]] || return 0

  while IFS= read -r module; do
    module_is_retired "$module" && continue
    state_file="${MODULE_STATE_DIR}/${module}.env"
    enabled="$(state_value "$state_file" AUTO_ENABLED || true)"
    installed="$(state_value "$state_file" INSTALLED || true)"
    [[ "$enabled" == "true" && "$installed" == "true" ]] || continue
    if ! (update_module "$module" false); then
      log "automatic update failed for ${module}; the scheduler will retry"
      failed=1
    fi
  done < <(module_ids)
  [[ "$failed" -eq 0 ]] || return 1
  install -d -o root -g root -m 0751 "$ROOT_STATE_DIR"
  marker_tmp="$(mktemp "${ROOT_STATE_DIR}/.module-last-auto-date.XXXXXX")"
  printf '%s\n' "$today" >"$marker_tmp"
  chmod 0640 "$marker_tmp"
  mv -f -- "$marker_tmp" "$marker"
}

run_due() {
  local failed=0
  register_requested || failed=1
  remove_requested || failed=1
  lifecycle_requested || failed=1
  run_requested || failed=1
  run_automatic || failed=1
  return "$failed"
}

with_lock() {
  install -d -o root -g root -m 0755 "$(dirname "$LOCK_FILE")"
  exec 9>"$LOCK_FILE"
  if ! flock -n 9; then
    log "another module updater is already running"
    return 0
  fi
  "$@"
}

usage() {
  cat <<'EOF'
Usage: sudo infiproxy-module-update <command> [module]

Commands:
  --check <module>   Compare installed and latest upstream version.
  --check-all        Compare all registered modules.
  --update <module>  Install or update one module now.
  --run-due          Process registration, removal, update and automatic jobs.
EOF
}

main() {
  need_root
  need_cmd curl
  need_cmd flock
  need_cmd sha256sum
  need_cmd tar
  prepare_request_dir
  [[ -x "$MANIFEST_HELPER" ]] || die "module manifest helper is missing"
  "$MANIFEST_HELPER" list "$MANIFEST_DIR" --root-owned >/dev/null \
    || die "module registry validation failed"
  case "${1:-}" in
    --check)
      require_active_product_module "${2:-}"
      check_module "$2"
      ;;
    --check-all)
      local module
      while IFS= read -r module; do
        module_is_retired "$module" || check_module "$module"
      done < <(module_ids)
      ;;
    --update)
      require_active_product_module "${2:-}"
      with_lock update_module "$2" true
      ;;
    --run-due) with_lock run_due ;;
    -h|--help) usage ;;
    *) usage >&2; exit 2 ;;
  esac
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  main "$@"
fi
