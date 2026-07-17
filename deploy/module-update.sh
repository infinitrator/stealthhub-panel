#!/usr/bin/env bash
# Independent updater for Infiproxy runtime modules.
#
# Release modules are downloaded only from fixed upstream GitHub repositories
# and verified with GitHub's SHA-256 digest or an official checksum sidecar.
# MTProxy is built from an exact commit in Telegram's official repository.
set -Eeuo pipefail
umask 027

STATE_DIR="${INFIPROXY_STATE_DIR:-/var/lib/infiproxy}"
ROOT_STATE_DIR="${INFIPROXY_ROOT_STATE_DIR:-/var/lib/infiproxy-maintenance}"
MODULE_STATE_DIR="${STATE_DIR}/modules"
MODULE_VERSION_DIR="${INFIPROXY_MODULE_VERSION_DIR:-${ROOT_STATE_DIR}/module-versions}"
REQUEST_DIR="${STATE_DIR}/module-requests"
BUILD_DIR="${ROOT_STATE_DIR}/module-build"
CORE_ROOT="${INFIPROXY_CORE_ROOT:-/opt/infiproxy/cores}"
MODULE_ROOT="${INFIPROXY_MODULE_ROOT:-/opt/infiproxy/modules}"
CORE_INSTALLER="${INFIPROXY_CORE_INSTALLER:-/usr/local/sbin/infiproxy-core-install}"
PANEL_STATE="${STATE_DIR}/panel-update-state.env"
RUN_LOG="${ROOT_STATE_DIR}/module-update.log"
LOCK_DIR="${INFIPROXY_MODULE_UPDATE_LOCK:-/run/infiproxy-module-update.lock}"
GITHUB_API="https://api.github.com/repos"
MODULES=(xray sing-box hysteria tuic mtproto headscale)
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

valid_module() {
  case "$1" in
    xray|sing-box|hysteria|tuic|mtproto|headscale) return 0 ;;
    *) return 1 ;;
  esac
}

module_repo() {
  case "$1" in
    xray) echo "XTLS/Xray-core" ;;
    sing-box) echo "SagerNet/sing-box" ;;
    hysteria) echo "apernet/hysteria" ;;
    tuic) echo "tuic-protocol/tuic" ;;
    mtproto) echo "TelegramMessenger/MTProxy" ;;
    headscale) echo "juanfont/headscale" ;;
  esac
}

module_service() {
  case "$1" in
    xray) echo "infiproxy-xray.service" ;;
    sing-box) echo "infiproxy-sing-box.service" ;;
    hysteria) echo "infiproxy-hysteria.service" ;;
    tuic) echo "infiproxy-tuic.service" ;;
    mtproto) echo "infiproxy-mtproto.service" ;;
    headscale) echo "headscale.service" ;;
  esac
}

module_binary() {
  case "$1" in
    xray) echo "${CORE_ROOT}/xray/current/xray" ;;
    sing-box) echo "${CORE_ROOT}/sing-box/current/sing-box" ;;
    hysteria) echo "${CORE_ROOT}/hysteria/current/hysteria" ;;
    tuic) echo "${CORE_ROOT}/tuic/current/tuic-server" ;;
    mtproto) echo "${CORE_ROOT}/mtproto/current/mtproto-proxy" ;;
    headscale) echo "${MODULE_ROOT}/headscale/current/headscale" ;;
  esac
}

host_arch() {
  case "$(uname -m)" in
    x86_64|amd64) echo "amd64" ;;
    aarch64|arm64) echo "arm64" ;;
    *) die "unsupported architecture: $(uname -m)" ;;
  esac
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
  [[ -s "$file" ]] && tr -d '[:space:]' <"$file" || echo "unknown"
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

# Prints: tag|asset-name|asset-url|sha256-or-empty|checksum-url-or-empty
release_metadata() {
  local module="$1" arch="$2" repo api_json
  repo="$(module_repo "$module")"
  api_json="$(github_json "${GITHUB_API}/${repo}/releases/latest")"
  python3 -c '
import json, sys
module, arch = sys.argv[1:3]
d = json.load(sys.stdin)
tag = d["tag_name"]
version = tag.removeprefix("app/v").removeprefix("tuic-server-").removeprefix("v")
names = {
    ("xray", "amd64"): "Xray-linux-64.zip",
    ("xray", "arm64"): "Xray-linux-arm64-v8a.zip",
    ("sing-box", "amd64"): f"sing-box-{version}-linux-amd64.tar.gz",
    ("sing-box", "arm64"): f"sing-box-{version}-linux-arm64.tar.gz",
    ("hysteria", "amd64"): "hysteria-linux-amd64",
    ("hysteria", "arm64"): "hysteria-linux-arm64",
    ("tuic", "amd64"): f"tuic-server-{version}-x86_64-unknown-linux-gnu",
    ("tuic", "arm64"): f"tuic-server-{version}-aarch64-unknown-linux-gnu",
    ("headscale", "amd64"): f"headscale_{version}_linux_amd64",
    ("headscale", "arm64"): f"headscale_{version}_linux_arm64",
}
name = names[(module, arch)]
assets = {asset["name"]: asset for asset in d.get("assets", [])}
asset = assets.get(name)
if not asset:
    raise SystemExit(f"release asset not found: {name}")
digest = (asset.get("digest") or "").removeprefix("sha256:")
sidecars = [name + ".dgst", name + ".sha256sum", "hashes.txt", "checksums.txt"]
checksum_url = next((assets[n]["browser_download_url"] for n in sidecars if n in assets), "")
print("|".join((tag, name, asset["browser_download_url"], digest, checksum_url)))
' "$module" "$arch" <<<"$api_json"
}

resolve_checksum() {
  local expected_asset="$1" digest="$2" checksum_url="$3" checksum_file checksum
  if [[ "$digest" =~ ^[A-Fa-f0-9]{64}$ ]]; then
    printf '%s' "$digest" | tr 'A-F' 'a-f'
    return
  fi
  [[ "$checksum_url" == https://github.com/*/releases/download/* ]] \
    || die "no trusted checksum is available for ${expected_asset}"
  checksum_file="$(mktemp)"
  curl --fail --silent --show-error --location --max-time 60 \
    --output "$checksum_file" "$checksum_url"
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

install_release_module() {
  local module="$1" arch repo metadata tag asset url digest checksum_url checksum tmp
  local service was_enabled=0 was_active=0 normalized current_link previous_target
  arch="$(host_arch)"
  repo="$(module_repo "$module")"
  metadata="$(release_metadata "$module" "$arch")"
  IFS='|' read -r tag asset url digest checksum_url <<<"$metadata"
  [[ "$url" == "https://github.com/${repo}/releases/download/"* ]] \
    || die "refusing unexpected release URL for ${module}"
  checksum="$(resolve_checksum "$asset" "$digest" "$checksum_url")"
  normalized="$(normalize_version "$tag")"

  if [[ -x "$(module_binary "$module")" ]] \
    && { [[ "$(installed_version "$module")" == "$tag" ]] \
      || [[ "$(installed_version "$module")" == "$normalized" ]]; }; then
    log "${module} is already current (${tag})"
    return
  fi

  service="$(module_service "$module")"
  systemctl is-enabled --quiet "$service" 2>/dev/null && was_enabled=1
  systemctl is-active --quiet "$service" 2>/dev/null && was_active=1
  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"; trap - RETURN' RETURN
  curl --fail --location --show-error --max-time 300 --output "${tmp}/${asset}" "$url"
  printf '%s  %s\n' "$checksum" "${tmp}/${asset}" | sha256sum -c -

  if [[ "$module" == "headscale" ]]; then
    install_headscale_binary "$tag" "${tmp}/${asset}" "$was_enabled" "$was_active"
  else
    current_link="${CORE_ROOT}/${module}/current"
    previous_target="$(readlink -f "$current_link" 2>/dev/null || true)"
    "$CORE_INSTALLER" --core "$module" --version "$normalized" \
      --archive "${tmp}/${asset}" --sha256 "$checksum" --binary "$(basename "$(module_binary "$module")")"
    if ! restore_service_state "$service" "$was_enabled" "$was_active"; then
      rollback_symlink "$current_link" "$previous_target" "$service" "$was_active" || true
      die "${service} failed after update; previous binary was restored"
    fi
  fi
  remember_version "$module" "$tag"
  log "updated ${module}: ${tag}"
}

ensure_headscale_unit() {
  if ! id -u headscale >/dev/null 2>&1; then
    useradd --system --home-dir /var/lib/headscale --create-home \
      --shell /usr/sbin/nologin headscale
  fi
  install -d -o headscale -g headscale -m 0750 /var/lib/headscale
  if ! systemctl cat headscale.service >/dev/null 2>&1; then
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
ReadWritePaths=/var/lib/headscale
RuntimeDirectory=headscale

[Install]
WantedBy=multi-user.target
EOF
  else
    install -d -m 0755 /etc/systemd/system/headscale.service.d
    install -m 0644 /dev/stdin /etc/systemd/system/headscale.service.d/infiproxy-module.conf <<'EOF'
[Service]
ExecStart=
ExecStart=/opt/infiproxy/modules/headscale/current/headscale serve -c /etc/headscale/config.yaml
EOF
  fi
}

install_headscale_binary() {
  local version="$1" archive="$2" was_enabled="$3" was_active="$4"
  local normalized target next current_link previous_target
  normalized="$(normalize_version "$version")"
  target="${MODULE_ROOT}/headscale/${normalized}"
  next="${MODULE_ROOT}/headscale/.current.${normalized}.next"
  current_link="${MODULE_ROOT}/headscale/current"
  previous_target="$(readlink -f "$current_link" 2>/dev/null || true)"
  install -d -m 0755 "$target"
  install -m 0755 "$archive" "${target}/headscale"
  "${target}/headscale" version >/dev/null
  ln -sfn "$target" "$next"
  mv -Tf "$next" "$current_link"
  ln -sfn "${MODULE_ROOT}/headscale/current/headscale" /usr/local/bin/headscale
  ensure_headscale_unit
  if ! restore_service_state headscale.service "$was_enabled" "$was_active"; then
    rollback_symlink "$current_link" "$previous_target" headscale.service "$was_active" || true
    die "headscale.service failed after update; previous binary was restored"
  fi
}

latest_mtproto_commit() {
  github_json "${GITHUB_API}/TelegramMessenger/MTProxy/commits/master" \
    | python3 -c 'import json,sys; print(json.load(sys.stdin)["sha"])'
}

install_mtproto_commit() {
  local commit source binary checksum service current_link previous_target
  local was_enabled=0 was_active=0
  commit="$(latest_mtproto_commit)"
  [[ "$commit" =~ ^[A-Fa-f0-9]{40}$ ]] || die "invalid MTProxy commit returned by GitHub"
  if [[ -x "$(module_binary mtproto)" && "$(installed_version mtproto)" == "$commit" ]]; then
    log "mtproto is already current (${commit:0:12})"
    return
  fi
  need_cmd git
  need_cmd make
  source="${BUILD_DIR}/mtproto/source"
  install -d -m 0750 "$(dirname "$source")"
  if [[ -d "${source}/.git" ]]; then
    git -C "$source" remote set-url origin https://github.com/TelegramMessenger/MTProxy.git
    git -C "$source" fetch --force --prune origin master
  else
    git clone --filter=blob:none https://github.com/TelegramMessenger/MTProxy.git "$source"
  fi
  git -C "$source" checkout --force --detach "$commit"
  git -C "$source" clean -fdx
  make -C "$source" -j"$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 1)"
  binary="${source}/objs/bin/mtproto-proxy"
  [[ -x "$binary" ]] || die "MTProxy build did not produce ${binary}"
  checksum="$(sha256sum "$binary" | awk '{print $1}')"
  service="$(module_service mtproto)"
  systemctl is-enabled --quiet "$service" 2>/dev/null && was_enabled=1
  systemctl is-active --quiet "$service" 2>/dev/null && was_active=1
  current_link="${CORE_ROOT}/mtproto/current"
  previous_target="$(readlink -f "$current_link" 2>/dev/null || true)"
  "$CORE_INSTALLER" --core mtproto --version "$commit" --archive "$binary" \
    --sha256 "$checksum" --binary mtproto-proxy
  if ! restore_service_state "$service" "$was_enabled" "$was_active"; then
    rollback_symlink "$current_link" "$previous_target" "$service" "$was_active" || true
    die "${service} failed after update; previous binary was restored"
  fi
  remember_version mtproto "$commit"
  log "updated mtproto: ${commit:0:12}"
}

latest_version() {
  local module="$1"
  if [[ "$module" == "mtproto" ]]; then
    latest_mtproto_commit
  else
    release_metadata "$module" "$(host_arch)" | cut -d'|' -f1
  fi
}

check_module() {
  local module="$1" current latest state
  valid_module "$module" || die "unknown module: $module"
  current="$(installed_version "$module")"
  latest="$(latest_version "$module")"
  state="update available"
  [[ "$(normalize_version "$current")" == "$(normalize_version "$latest")" ]] && state="current"
  [[ ! -x "$(module_binary "$module")" ]] && state="not installed"
  printf '%-12s installed=%-18s latest=%-18s %s\n' \
    "$module" "${current:0:18}" "${latest:0:18}" "$state"
}

update_module() {
  local module="$1"
  valid_module "$module" || die "unknown module: $module"
  log "checking ${module}"
  if [[ "$module" == "mtproto" ]]; then
    install_mtproto_commit
  else
    install_release_module "$module"
  fi
}

run_requested() {
  local module request failed=0
  install -d -m 0750 "$REQUEST_DIR"
  for module in "${MODULES[@]}"; do
    request="${REQUEST_DIR}/${module}.request"
    [[ -f "$request" ]] || continue
    if (update_module "$module"); then
      rm -f "$request" "${request}.failed"
    else
      mv -f "$request" "${request}.failed"
      log "request failed for ${module}; details retained in ${request}.failed"
      failed=1
    fi
  done
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

  for module in "${MODULES[@]}"; do
    state_file="${MODULE_STATE_DIR}/${module}.env"
    enabled="$(state_value "$state_file" AUTO_ENABLED || true)"
    installed="$(state_value "$state_file" INSTALLED || true)"
    [[ "$enabled" == "true" && "$installed" == "true" ]] || continue
    if ! (update_module "$module"); then
      log "automatic update failed for ${module}; the scheduler will retry"
      failed=1
    fi
  done
  [[ "$failed" -eq 0 ]] || return 1
  printf '%s\n' "$today" >"$marker"
  chmod 0640 "$marker"
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
  --check-all        Compare all supported modules.
  --update <module>  Install or update one module now.
  --run-due          Process web requests and the daily automatic window.
EOF
}

main() {
  need_root
  need_cmd curl
  need_cmd python3
  need_cmd sha256sum
  case "${1:-}" in
    --check)
      check_module "${2:-}"
      ;;
    --check-all)
      local module
      for module in "${MODULES[@]}"; do check_module "$module"; done
      ;;
    --update)
      with_lock update_module "${2:-}"
      ;;
    --run-due)
      with_lock run_due
      ;;
    -h|--help)
      usage
      ;;
    *)
      usage >&2
      exit 2
      ;;
  esac
}

run_due() {
  run_requested || true
  run_automatic
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  main "$@"
fi
