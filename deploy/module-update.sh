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
BUILD_DIR="${ROOT_STATE_DIR}/module-build"
MODULE_BACKUP_ROOT="${INFIPROXY_MODULE_BACKUP_ROOT:-${ROOT_STATE_DIR}/module-backups}"
BACKUP_RETENTION_DAYS="${INFIPROXY_BACKUP_RETENTION_DAYS:-30}"
CORE_ROOT="${INFIPROXY_CORE_ROOT:-/opt/infiproxy/cores}"
MODULE_ROOT="${INFIPROXY_MODULE_ROOT:-/opt/infiproxy/modules}"
CORE_INSTALLER="${INFIPROXY_CORE_INSTALLER:-/usr/local/sbin/infiproxy-core-install}"
MANIFEST_HELPER="${INFIPROXY_MODULE_MANIFEST_HELPER:-/usr/local/libexec/infiproxy-module-manifest}"
HEADSCALE_CONTROL_HELPER="${INFIPROXY_HEADSCALE_CONTROL_HELPER:-/usr/local/libexec/infiproxy-headscale-control}"
PANEL_STATE="${STATE_DIR}/panel-update-state.env"
RUN_LOG="${ROOT_STATE_DIR}/module-update.log"
LOCK_DIR="${INFIPROXY_MODULE_UPDATE_LOCK:-/run/infiproxy-module-update.lock}"
GITHUB_API="https://api.github.com/repos"
APP_GROUP="${INFIPROXY_GROUP:-infiproxy}"

log() {
  local line
  line="$(date '+%Y-%m-%dT%H:%M:%S%z') $*"
  printf '%s\n' "$line"
  install -d -o root -g root -m 0751 "$ROOT_STATE_DIR"
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
  curl --fail --silent --show-error --location --max-time 30 \
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
    --retry 3
    --retry-all-errors
    --connect-timeout 15
    --max-time 600
  )
  [[ -n "${M_REPO:-}" && "$url" == "https://github.com/${M_REPO}/releases/download/"* ]] \
    || die "refusing untrusted release download URL"
  if [[ "${INFIPROXY_FORCE_IPV4:-false}" == "true" ]]; then
    args+=(--ipv4)
  fi
  curl "${args[@]}" --output "$output" "$url"
}

# Prints: tag|asset-name|asset-url|sha256-or-empty|checksum-url-or-empty
release_metadata() {
  local arch="$1" pattern api_json
  if [[ "$arch" == "amd64" ]]; then
    pattern="$M_ASSET_AMD64"
  else
    pattern="$M_ASSET_ARM64"
  fi
  api_json="$(github_json "${GITHUB_API}/${M_REPO}/releases/latest")"
  "$MANIFEST_HELPER" release-metadata "$pattern" <<<"$api_json"
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
  install -d -o root -g "$APP_GROUP" -m 0750 "$MODULE_VERSION_DIR"
  printf '%s\n' "$2" >"${MODULE_VERSION_DIR}/$1.version"
  chown root:"$APP_GROUP" "${MODULE_VERSION_DIR}/$1.version" 2>/dev/null || true
  chmod 0640 "${MODULE_VERSION_DIR}/$1.version"
}

backup_module_config() {
  local was_enabled="$1" was_active="$2"
  local module_dir backup_dir current_target timestamp
  [[ -e "$M_CONFIG" ]] || {
    log "no existing config to back up for ${M_ID}: ${M_CONFIG}"
    return
  }
  [[ -f "$M_CONFIG" && ! -L "$M_CONFIG" ]] \
    || die "refusing to back up unsafe module config: ${M_CONFIG}"
  [[ "$BACKUP_RETENTION_DAYS" =~ ^[0-9]{1,3}$ ]] \
    || die "invalid backup retention: ${BACKUP_RETENTION_DAYS}"

  timestamp="$(date '+%Y%m%d-%H%M%S')"
  module_dir="${MODULE_BACKUP_ROOT}/${M_ID}"
  backup_dir="${module_dir}/${timestamp}"
  current_target="$(readlink -f "$(runtime_root)/current" 2>/dev/null || true)"
  install -d -o root -g root -m 0700 "$backup_dir" \
    || die "failed to create module backup directory"
  if ! tar -C / -czf "${backup_dir}/config.tar.gz" -- "${M_CONFIG#/}"; then
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
  log "backed up ${M_ID} config to ${backup_dir}"
}

restore_service_state() {
  local service="$1" was_enabled="$2" was_active="$3"
  systemctl daemon-reload || return 1
  if [[ "$was_enabled" -eq 1 ]]; then
    systemctl enable "$service" >/dev/null || return 1
  fi
  if [[ "$was_active" -eq 1 ]]; then
    systemctl restart "$service" || return 1
    systemctl is-active --quiet "$service" || return 1
  fi
}

rollback_symlink() {
  local current_link="$1" previous_target="$2" service="$3" was_active="$4"
  [[ -n "$previous_target" && -d "$previous_target" ]] || return 1
  ln -sfn "$previous_target" "$current_link"
  if [[ "$was_active" -eq 1 ]]; then
    systemctl restart "$service" || true
  fi
  log "rolled back ${service} to ${previous_target}"
}

ensure_headscale_unit() {
  if ! id -u headscale >/dev/null 2>&1; then
    useradd --system --home-dir /var/lib/headscale --create-home \
      --shell /usr/sbin/nologin headscale
  fi
  install -d -o headscale -g headscale -m 0750 /var/lib/headscale
  if ! systemctl cat "$M_SERVICE" >/dev/null 2>&1; then
    [[ "$M_ID" == "headscale" && "$M_SERVICE" == "headscale.service" ]] \
      || die "service unit is missing for ${M_ID}: ${M_SERVICE}"
    install -d -m 0755 /etc/systemd/system
    install -m 0644 /dev/stdin /etc/systemd/system/headscale.service <<'EOF'
[Unit]
Description=Headscale coordination server
Wants=network-online.target
After=network-online.target

[Service]
Type=simple
User=headscale
Group=headscale
ExecStart=/opt/infiproxy/modules/headscale/current/headscale serve -c /etc/headscale/config.yaml
Restart=on-failure
RestartSec=5
NoNewPrivileges=true
PrivateTmp=true
ProtectHome=true
ProtectSystem=strict
ReadWritePaths=/etc/headscale /var/lib/headscale
RuntimeDirectory=headscale

[Install]
WantedBy=multi-user.target
EOF
  fi
}

install_headscale_binary() {
  local version="$1" archive="$2" was_enabled="$3" was_active="$4"
  local normalized target next current_link previous_target
  normalized="$(normalize_version "$version")"
  target="$(runtime_root)/${normalized}"
  next="$(runtime_root)/.current.${normalized}.next"
  current_link="$(runtime_root)/current"
  previous_target="$(readlink -f "$current_link" 2>/dev/null || true)"
  install -d -m 0755 "$target"
  install -m 0755 "$archive" "${target}/${M_BINARY}"
  "${target}/${M_BINARY}" version >/dev/null
  ln -sfn "$target" "$next"
  mv -Tf "$next" "$current_link"
  ln -sfn "${current_link}/${M_BINARY}" /usr/local/bin/headscale
  ensure_headscale_unit
  if ! restore_service_state "$M_SERVICE" "$was_enabled" "$was_active"; then
    rollback_symlink "$current_link" "$previous_target" "$M_SERVICE" "$was_active" || true
    die "${M_SERVICE} failed after update; previous binary was restored"
  fi
}

install_release_module() {
  local metadata tag asset url digest checksum_url checksum tmp normalized
  local was_enabled=0 was_active=0 current_link previous_target
  metadata="$(release_metadata "$(host_arch)")"
  IFS='|' read -r tag asset url digest checksum_url <<<"$metadata"
  [[ "$url" == "https://github.com/${M_REPO}/releases/download/"* ]] \
    || die "refusing unexpected release URL for ${M_ID}"
  checksum="$(resolve_checksum "$asset" "$digest" "$checksum_url")"
  normalized="$(normalize_version "$tag")"

  if [[ -x "$(module_binary)" ]] \
    && { [[ "$(installed_version "$M_ID")" == "$tag" ]] \
      || [[ "$(installed_version "$M_ID")" == "$normalized" ]]; }; then
    log "${M_ID} is already current (${tag})"
    return
  fi

  systemctl is-enabled --quiet "$M_SERVICE" 2>/dev/null && was_enabled=1
  systemctl is-active --quiet "$M_SERVICE" 2>/dev/null && was_active=1
  backup_module_config "$was_enabled" "$was_active"
  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"; trap - RETURN' RETURN
  download_release_asset "${tmp}/${asset}" "$url" \
    || die "failed to download ${asset}"
  printf '%s  %s\n' "$checksum" "${tmp}/${asset}" | sha256sum -c - \
    || die "checksum verification failed for ${asset}"

  if [[ "$M_DRIVER" == "headscale" ]]; then
    install_headscale_binary "$tag" "${tmp}/${asset}" "$was_enabled" "$was_active"
  else
    [[ "$M_DRIVER" == "release" && "$M_ROOT" == "cores" ]] \
      || die "unsupported generic release contract for ${M_ID}"
    current_link="$(runtime_root)/current"
    previous_target="$(readlink -f "$current_link" 2>/dev/null || true)"
    "$CORE_INSTALLER" --core "$M_ID" --version "$normalized" \
      --archive "${tmp}/${asset}" --sha256 "$checksum" --binary "$M_BINARY"
    if ! restore_service_state "$M_SERVICE" "$was_enabled" "$was_active"; then
      rollback_symlink "$current_link" "$previous_target" "$M_SERVICE" "$was_active" || true
      die "${M_SERVICE} failed after update; previous binary was restored"
    fi
  fi
  remember_version "$M_ID" "$tag"
  log "updated ${M_ID}: ${tag}"
}

latest_commit() {
  github_json "${GITHUB_API}/${M_REPO}/commits/${M_REF}" \
    | "$MANIFEST_HELPER" commit-sha
}

install_source_module() {
  local commit source binary checksum current_link previous_target
  local was_enabled=0 was_active=0
  [[ "$M_DRIVER" == "mtproto-source" ]] || die "unsupported source driver"
  commit="$(latest_commit)"
  [[ "$commit" =~ ^[A-Fa-f0-9]{40}$ ]] || die "invalid commit returned by GitHub"
  if [[ -x "$(module_binary)" && "$(installed_version "$M_ID")" == "$commit" ]]; then
    log "${M_ID} is already current (${commit:0:12})"
    return
  fi
  need_cmd git
  need_cmd make
  source="${BUILD_DIR}/${M_ID}/source"
  install -d -m 0750 "$(dirname "$source")"
  if [[ -d "${source}/.git" ]]; then
    git -C "$source" remote set-url origin "https://github.com/${M_REPO}.git"
    git -C "$source" fetch --force --prune origin "$M_REF"
  else
    git clone --filter=blob:none "https://github.com/${M_REPO}.git" "$source"
  fi
  git -C "$source" checkout --force --detach "$commit"
  git -C "$source" clean -fdx
  make -C "$source" -j"$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 1)"
  binary="${source}/objs/bin/${M_BINARY}"
  [[ -x "$binary" ]] || die "source build did not produce ${binary}"
  checksum="$(sha256sum "$binary" | awk '{print $1}')"
  systemctl is-enabled --quiet "$M_SERVICE" 2>/dev/null && was_enabled=1
  systemctl is-active --quiet "$M_SERVICE" 2>/dev/null && was_active=1
  backup_module_config "$was_enabled" "$was_active"
  current_link="$(runtime_root)/current"
  previous_target="$(readlink -f "$current_link" 2>/dev/null || true)"
  "$CORE_INSTALLER" --core "$M_ID" --version "$commit" --archive "$binary" \
    --sha256 "$checksum" --binary "$M_BINARY"
  if ! restore_service_state "$M_SERVICE" "$was_enabled" "$was_active"; then
    rollback_symlink "$current_link" "$previous_target" "$M_SERVICE" "$was_active" || true
    die "${M_SERVICE} failed after update; previous binary was restored"
  fi
  remember_version "$M_ID" "$commit"
  log "updated ${M_ID}: ${commit:0:12}"
}

latest_version() {
  if [[ "$M_UPSTREAM" == "commit" ]]; then
    latest_commit
  else
    release_metadata "$(host_arch)" | cut -d'|' -f1
  fi
}

check_module() {
  local module="$1" current latest state
  load_module "$module" || die "unknown or invalid module: $module"
  current="$(installed_version "$module")"
  latest="$(latest_version)"
  state="update available"
  [[ "$(normalize_version "$current")" == "$(normalize_version "$latest")" ]] && state="current"
  [[ ! -x "$(module_binary)" ]] && state="not installed"
  printf '%-20s installed=%-18s latest=%-18s %s\n' \
    "$module" "${current:0:18}" "${latest:0:18}" "$state"
}

update_module() {
  local module="$1"
  load_module "$module" || die "unknown or invalid module: $module"
  log "checking ${module}"
  if [[ "$M_UPSTREAM" == "commit" ]]; then
    install_source_module
  else
    install_release_module
  fi
}

register_requested() {
  local request id source target failed=0
  install -d -o root -g root -m 0755 "$MANIFEST_DIR"
  install -d -o root -g root -m 0755 "$AVAILABLE_DIR"
  install -d -o root -g root -m 0750 "$DISABLED_DIR"
  shopt -s nullglob
  for request in "$REQUEST_DIR"/*.register; do
    id="$(basename "$request" .register)"
    source="${AVAILABLE_DIR}/${id}.module"
    target="$(manifest_file "$id")"
    if valid_id "$id" \
      && [[ ! -e "$target" ]] \
      && "$MANIFEST_HELPER" validate "$source" --root-owned; then
      install -o root -g root -m 0644 "$source" "$target"
      rm -f "${DISABLED_DIR}/${id}" "${request}.failed"
      load_module "$id" || die "installed manifest could not be reloaded: ${id}"
      install -d -o root -g "$APP_GROUP" -m 0770 "$(dirname "$M_CONFIG")"
      if (update_module "$id"); then
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
  local request id failed=0
  install -d -o root -g root -m 0750 "$DISABLED_DIR"
  install -d -o root -g root -m 0755 "$AVAILABLE_DIR"
  shopt -s nullglob
  for request in "$REQUEST_DIR"/*.remove; do
    id="$(basename "$request" .remove)"
    if load_module "$id"; then
      if [[ ! -e "${AVAILABLE_DIR}/${id}.module" ]]; then
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
  install -d -m 0750 "$REQUEST_DIR"
  while IFS= read -r module; do
    request="${REQUEST_DIR}/${module}.request"
    [[ -f "$request" ]] || continue
    if (update_module "$module"); then
      rm -f "$request" "${request}.failed"
    else
      mv -f "$request" "${request}.failed"
      log "request failed for ${module}; details retained in ${request}.failed"
      failed=1
    fi
  done < <(module_ids)
  return "$failed"
}

run_automatic() {
  local schedule_time hour minute current_hour current_minute schedule_total current_total
  local today marker module state_file enabled installed failed=0
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
    state_file="${MODULE_STATE_DIR}/${module}.env"
    enabled="$(state_value "$state_file" AUTO_ENABLED || true)"
    installed="$(state_value "$state_file" INSTALLED || true)"
    [[ "$enabled" == "true" && "$installed" == "true" ]] || continue
    if ! (update_module "$module"); then
      log "automatic update failed for ${module}; the scheduler will retry"
      failed=1
    fi
  done < <(module_ids)
  [[ "$failed" -eq 0 ]] || return 1
  printf '%s\n' "$today" >"$marker"
  chmod 0640 "$marker"
}

run_due() {
  local failed=0
  if [[ -x "$HEADSCALE_CONTROL_HELPER" ]]; then
    "$HEADSCALE_CONTROL_HELPER" --process || failed=1
  fi
  register_requested || true
  remove_requested || true
  run_requested || true
  run_automatic || failed=1
  return "$failed"
}

with_lock() {
  if ! mkdir "$LOCK_DIR" 2>/dev/null; then
    log "another module updater is already running"
    return 0
  fi
  trap 'rmdir "$LOCK_DIR" 2>/dev/null || true' EXIT
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
  need_cmd sha256sum
  need_cmd tar
  [[ -x "$MANIFEST_HELPER" ]] || die "module manifest helper is missing"
  "$MANIFEST_HELPER" list "$MANIFEST_DIR" --root-owned >/dev/null \
    || die "module registry validation failed"
  case "${1:-}" in
    --check) check_module "${2:-}" ;;
    --check-all)
      local module
      while IFS= read -r module; do check_module "$module"; done < <(module_ids)
      ;;
    --update) with_lock update_module "${2:-}" ;;
    --run-due) with_lock run_due ;;
    -h|--help) usage ;;
    *) usage >&2; exit 2 ;;
  esac
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  main "$@"
fi
