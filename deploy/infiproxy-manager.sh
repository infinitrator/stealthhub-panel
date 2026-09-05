#!/usr/bin/env bash
# SSH entry point, finite operation helpers and legacy recovery menus.
#
# The manager intentionally stays dependency-light: plain Bash, systemd, curl,
# certbot and small Rust helpers. Destructive actions require root and explicit
# confirmation; Cloudflare tokens are never echoed back to the terminal.
set -Eeuo pipefail

APP="Infiproxy"
ENV_FILE="${INFIPROXY_ENV_FILE:-/etc/infiproxy/infiproxy.env}"
SOURCE_DIR="${INFIPROXY_SRC_DIR:-/opt/infiproxy/source}"
APP_GROUP="${INFIPROXY_GROUP:-infiproxy}"
APP_USER="${INFIPROXY_USER:-infiproxy}"
PRIVILEGED_SECRET_DIR="${INFIPROXY_SECRET_DIR:-/etc/infiproxy/secrets.d}"
RECONCILE_HELPER="${INFIPROXY_RECONCILE_HELPER:-/usr/local/libexec/infiproxy-reconcile}"
PANEL_SERVICE="infiproxy.service"
MODULE_UPDATE_BIN="${INFIPROXY_MODULE_UPDATE_BIN:-/usr/local/sbin/infiproxy-module-update}"
MODULE_MANIFEST_HELPER="${INFIPROXY_MODULE_MANIFEST_HELPER:-/usr/local/libexec/infiproxy-module-manifest}"
MODULE_MANIFEST_DIR="${INFIPROXY_MODULE_MANIFEST_DIR:-/etc/infiproxy-modules.d}"
MODULE_AVAILABLE_DIR="${INFIPROXY_MODULE_AVAILABLE_DIR:-/etc/infiproxy-modules.available.d}"
MODULE_REQUEST_DIR="${INFIPROXY_MODULE_REQUEST_DIR:-/var/lib/infiproxy/module-requests}"
MODULE_UPDATE_LOG="${INFIPROXY_MODULE_UPDATE_LOG:-/var/lib/infiproxy-maintenance/module-update.log}"
PANEL_UPDATE_REQUEST="${INFIPROXY_PANEL_UPDATE_REQUEST:-/var/lib/infiproxy/panel-update-now.request}"
PANEL_UPDATE_STATUS="${INFIPROXY_PANEL_UPDATE_STATUS:-/var/lib/infiproxy-maintenance/panel-update-status.env}"
NGINX_SITE="${INFIPROXY_NGINX_SITE:-/etc/nginx/sites-available/infiproxy.conf}"
NGINX_ENABLED="${INFIPROXY_NGINX_ENABLED:-/etc/nginx/sites-enabled/infiproxy.conf}"
CLOUDFLARE_CREDENTIALS="${INFIPROXY_CF_CREDENTIALS:-/etc/letsencrypt/cloudflare.ini}"
CF_API="https://api.cloudflare.com/client/v4"

green=$'\033[38;5;71m'
soft=$'\033[38;5;250m'
muted=$'\033[38;5;245m'
danger=$'\033[38;5;167m'
reset=$'\033[0m'
bold=$'\033[1m'

export NEWT_COLORS='root=white,black;window=white,black;border=green,black;title=green,black;button=black,green;actbutton=white,green;entry=black,white;checkbox=green,black;actcheckbox=green,black;listbox=white,black;actlistbox=black,green;compactbutton=green,black'

if [[ ! -t 1 || -n "${NO_COLOR:-}" ]]; then
  green=""
  soft=""
  muted=""
  danger=""
  reset=""
  bold=""
fi

need_root() {
  if [[ "${EUID}" -ne 0 ]]; then
    echo "${danger}Run as root: sudo infiproxy-manager${reset}" >&2
    exit 1
  fi
}

pause() {
  echo
  [[ -t 0 ]] || return 0
  read -r -p "${muted}Press Enter to continue...${reset}" _
}

invalid_choice() {
  echo "${danger}Unknown menu item.${reset}"
  pause
}

confirm_yes() {
  local prompt="$1"
  local default="${2:-N}"
  local answer

  if tui_available; then
    if [[ "$default" == "Y" ]]; then
      whiptail --title "Infiproxy Manager" --yesno "$prompt" 10 72
    else
      whiptail --title "Infiproxy Manager" --defaultno --yesno "$prompt" 10 72
    fi
    return
  elif [[ "$default" == "Y" ]]; then
    read -r -p "${prompt} [Y/n]: " answer || return 1
    [[ -z "$answer" || "$answer" =~ ^[Yy]$ ]]
  else
    read -r -p "${prompt} [y/N]: " answer || return 1
    [[ "$answer" =~ ^[Yy]$ ]]
  fi
}

tui_available() {
  have_cmd whiptail && [[ -t 0 && -t 1 ]]
}

tui_menu() {
  local title="$1" prompt="$2"
  shift 2
  if tui_available; then
    whiptail --title "$title" --menu "$prompt" 25 78 15 "$@" 3>&1 1>&2 2>&3
    return
  fi

  header >&2
  echo "${bold}${title}${reset}" >&2
  echo "${muted}${prompt}${reset}" >&2
  echo >&2
  while [[ $# -ge 2 ]]; do
    printf '%s) %s\n' "$1" "$2" >&2
    shift 2
  done
  local selected
  read -r -p "> " selected || return 1
  printf '%s' "$selected"
}

prompt_value() {
  local variable="$1" title="$2" prompt="$3" default="${4:-}" secret="${5:-0}" value
  if tui_available; then
    if [[ "$secret" -eq 1 ]]; then
      value="$(whiptail --title "$title" --passwordbox "$prompt" 11 72 "$default" 3>&1 1>&2 2>&3)" || return 1
    else
      value="$(whiptail --title "$title" --inputbox "$prompt" 11 72 "$default" 3>&1 1>&2 2>&3)" || return 1
    fi
  elif [[ "$secret" -eq 1 ]]; then
    read -r -s -p "${prompt}: " value || return 1
    echo
  else
    read -r -p "${prompt}${default:+ [$default]}: " value || return 1
    value="${value:-$default}"
  fi
  printf -v "$variable" '%s' "$value"
}

registered_module_records() {
  local module
  [[ -x "$MODULE_MANIFEST_HELPER" && -d "$MODULE_MANIFEST_DIR" ]] || return 0
  while IFS= read -r module; do
    "$MODULE_MANIFEST_HELPER" read "$MODULE_MANIFEST_DIR/${module}.module" --root-owned
  done < <("$MODULE_MANIFEST_HELPER" list "$MODULE_MANIFEST_DIR" --root-owned)
}

registered_services() {
  local record service
  while IFS= read -r record; do
    IFS='|' read -r _ _ _ _ _ _ _ _ _ _ service _ _ _ <<<"$record"
    printf '%s\n' "$service"
  done < <(registered_module_records)
}

header() {
  local panel_state host uptime_label module_count service record
  clear 2>/dev/null || true
  host="$(hostname -f 2>/dev/null || hostname)"
  panel_state="$(systemctl is-active "$PANEL_SERVICE" 2>/dev/null || true)"
  uptime_label="$(uptime -p 2>/dev/null | sed 's/^up //' || true)"
  module_count=0
  while IFS= read -r record; do
    IFS='|' read -r _ _ _ _ _ _ _ _ _ _ service _ _ _ <<<"$record"
    if systemctl is-active --quiet "$service" 2>/dev/null; then
      ((module_count += 1))
    fi
  done < <(registered_module_records)
  echo "${green}${bold}+------------------------------------------------------------------+${reset}"
  printf '%s| %-64s |%s\n' "${green}${bold}" "${APP} Manager / ${host}" "${reset}"
  echo "${green}${bold}+------------------------------------------------------------------+${reset}"
  printf "${muted}panel %-10s modules active %-2s    uptime %s${reset}\n" \
    "${panel_state:-unknown}" "$module_count" "${uptime_label:-unknown}"
  echo "${muted}systemd bare-metal / env ${ENV_FILE}${reset}"
  echo
}

main_menu_choice() {
  tui_menu "Infiproxy Manager" "Host: $(hostname)\nSelect an operations area" \
    1 "Overview and service status" \
    2 "Admin access and panel URL" \
    3 "Runtime modules" \
    4 "Restart and reload" \
    5 "Logs and diagnostics" \
    6 "HTTPS and Cloudflare" \
    7 "Panel updates" \
    8 "Panel environment" \
    9 "Guided deployment" \
    10 "Privileged runtime secrets" \
    11 "Advanced tools" \
    12 "Danger zone" \
    0 "Exit to shell"
}

run_cmd() {
  echo "${soft}$ $*${reset}"
  "$@"
}

have_cmd() {
  command -v "$1" >/dev/null 2>&1
}

valid_secret_reference() {
  [[ "$1" =~ ^[A-Za-z0-9._-]{1,128}$ && "$1" != "." && "$1" != ".." ]]
}

store_privileged_secret() {
  local reference value temporary
  if [[ $# -eq 1 ]]; then reference="$1"; else
    prompt_value reference "Privileged secret" "Reference name" "" 0 || return
  fi
  valid_secret_reference "$reference" || {
    echo "${danger}Invalid reference. Use 1-128 letters, digits, dot, underscore or dash.${reset}" >&2
    pause
    return
  }
  if [[ $# -eq 1 ]]; then IFS= read -r value || return 1; else
    prompt_value value "Privileged secret" "Secret value (input is hidden)" "" 1 || return
  fi
  if [[ -z "$value" || "${#value}" -gt 8192 ]]; then
    echo "${danger}Secret must contain 1-8192 bytes.${reset}" >&2
    pause
    return
  fi
  [[ ! -L "$PRIVILEGED_SECRET_DIR" ]] || return 1
  install -d -o root -g root -m 0700 "$PRIVILEGED_SECRET_DIR"
  temporary="$(mktemp "${PRIVILEGED_SECRET_DIR}/.secret.XXXXXX")"
  chmod 0600 "$temporary"
  printf '%s' "$value" >"$temporary"
  sync "$temporary" 2>/dev/null || true
  mv -f "$temporary" "${PRIVILEGED_SECRET_DIR}/${reference}"
  chown root:root "${PRIVILEGED_SECRET_DIR}/${reference}"
  chmod 0600 "${PRIVILEGED_SECRET_DIR}/${reference}"
  unset value
  echo "${green}Stored root-only reference ${reference}.${reset}"
  systemctl start infiproxy-reconcile.service || true
  [[ $# -eq 1 ]] || pause
}

delete_privileged_secret() {
  local reference
  if [[ $# -eq 1 ]]; then reference="$1"; else
    prompt_value reference "Privileged secret" "Reference name to delete" "" 0 || return
  fi
  valid_secret_reference "$reference" || { invalid_choice; return; }
  [[ -f "${PRIVILEGED_SECRET_DIR}/${reference}" \
      && ! -L "${PRIVILEGED_SECRET_DIR}/${reference}" ]] || {
    echo "${muted}Reference is not present.${reset}"
    pause
    return
  }
  if [[ $# -eq 0 ]]; then
    confirm_yes "Delete root-only reference ${reference}? The next reconcile may fail closed." "N" || return
  fi
  rm -f -- "${PRIVILEGED_SECRET_DIR:?}/${reference}"
  systemctl start infiproxy-reconcile.service || true
  [[ $# -eq 1 ]] || pause
}

adopt_legacy_privileged_secret() {
  local reference
  prompt_value reference "Adopt legacy secret" \
    "Server-only reference already used by an enabled profile" "" 0 || return
  valid_secret_reference "$reference" || {
    echo "${danger}Invalid reference. Use 1-128 letters, digits, dot, underscore or dash.${reset}" >&2
    pause
    return
  }
  [[ -x "$RECONCILE_HELPER" ]] || {
    echo "${danger}Reconcile helper is not installed.${reset}" >&2
    pause
    return
  }
  echo "${muted}The value is copied to root-only storage, verified, then removed from SQLite.${reset}"
  run_cmd "$RECONCILE_HELPER" --adopt-server-secret "$reference"
  systemctl start infiproxy-reconcile.service || true
  pause
}

privileged_secrets_menu() {
  local choice
  while true; do
    choice="$(tui_menu "Privileged runtime secrets" \
      "Values remain root-only and are never displayed" \
      1 "List configured reference names" \
      2 "Create or rotate a reference" \
      3 "Delete a reference" \
      4 "Adopt a legacy SQLite server-only reference" \
      0 "Back")" || return
    case "$choice" in
      1)
        header
        echo "${bold}Configured root-only references${reset}"
        find "$PRIVILEGED_SECRET_DIR" -maxdepth 1 -type f -printf '%f\n' 2>/dev/null \
          | grep -E '^[A-Za-z0-9._-]{1,128}$' | sort || true
        pause
        ;;
      2) store_privileged_secret ;;
      3) delete_privileged_secret ;;
      4) adopt_legacy_privileged_secret ;;
      0) return ;;
      *) invalid_choice ;;
    esac
  done
}

require_cmd() {
  if ! have_cmd "$1"; then
    echo "${danger}Missing command: $1${reset}" >&2
    return 1
  fi
}

https_curl() {
  require_cmd curl || return 1
  curl --proto '=https' --proto-redir '=https' --tlsv1.2 \
    --fail --silent --show-error --location \
    --connect-timeout 10 --max-time 30 \
    --retry 3 --retry-all-errors "$@"
}

valid_domain() {
  [[ "$1" =~ ^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$ ]]
}

valid_ipv4() {
  [[ "$1" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]] || return 1
  local a b c d octet
  IFS=. read -r a b c d <<<"$1"
  for octet in "$a" "$b" "$c" "$d"; do
    ((10#$octet <= 255)) || return 1
  done
}

valid_public_host() {
  valid_domain "$1" || valid_ipv4 "$1"
}

valid_port() {
  [[ "$1" =~ ^[0-9]{1,5}$ ]] && ((10#$1 >= 1 && 10#$1 <= 65535))
}

# Publish root-helper requests only after their owner, mode and content are
# complete. The systemd path watcher ignores the hidden staging filename.
write_module_request() {
  local id="$1" suffix="$2" target temp

  [[ "$id" =~ ^[a-z][a-z0-9-]{0,31}$ ]] || return 1
  [[ "$suffix" == "register" || "$suffix" == "remove" ]] || return 1
  install -d -o "$APP_USER" -g "$APP_GROUP" -m 0750 "$MODULE_REQUEST_DIR"
  target="${MODULE_REQUEST_DIR}/${id}.${suffix}"
  temp="$(mktemp "${MODULE_REQUEST_DIR}/.${id}.${suffix}.XXXXXX")"
  if ! printf 'requested_at=%s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" >"$temp" \
    || ! chown "$APP_USER":"$APP_GROUP" "$temp" \
    || ! chmod 0640 "$temp" \
    || ! mv -f -- "$temp" "$target"; then
    rm -f -- "$temp"
    return 1
  fi
}

valid_cloudflare_token() {
  [[ "$1" =~ ^[A-Za-z0-9_-]{20,200}$ ]]
}

public_ip() {
  https_curl --max-time 10 https://api.ipify.org
}

env_value() {
  local file="$1"
  local key="$2"
  awk -F= -v key="$key" '$1 == key { value=$0; sub("^[^=]*=", "", value); print value }' "$file" 2>/dev/null | tail -1
}

cloudflare_token_from_file() {
  awk -F= '/dns_cloudflare_api_token/ { value=$2; sub(/^[[:space:]]+/, "", value); sub(/[[:space:]]+$/, "", value); print value }' "$CLOUDFLARE_CREDENTIALS" 2>/dev/null | tail -1
}

publish_staged_file() {
  local staged="$1" target="$2" owner="$3" group="$4" mode="$5"
  chown "$owner":"$group" "$staged"
  chmod "$mode" "$staged"
  mv -f -- "$staged" "$target"
}

json_first_id() {
  "$MODULE_MANIFEST_HELPER" cloudflare-first-id
}

cloudflare_get() {
  local token="$1"
  local url="$2"
  shift 2
  valid_cloudflare_token "$token" \
    || { echo "${danger}Invalid Cloudflare API token format.${reset}" >&2; return 1; }
  https_curl \
    --config <(printf 'header = "Authorization: Bearer %s"\nheader = "Content-Type: application/json"\n' "$token") \
    --get "$@" "$url"
}

cloudflare_zone_id() {
  local token="$1"
  local zone="$2"
  cloudflare_get "$token" "${CF_API}/zones" --data-urlencode "name=${zone}" | json_first_id
}

cloudflare_record_id() {
  local token="$1"
  local zone_id="$2"
  local record="$3"
  cloudflare_get "$token" "${CF_API}/zones/${zone_id}/dns_records" \
    --data-urlencode "type=A" \
    --data-urlencode "name=${record}" | json_first_id
}

cloudflare_write_a_record() {
  local token="$1"
  local zone="$2"
  local record="$3"
  local ip="$4"
  local proxied="${5:-false}"

  require_cmd curl || return 1
  [[ -x "$MODULE_MANIFEST_HELPER" ]] || return 1
  valid_cloudflare_token "$token" \
    || { echo "${danger}Invalid Cloudflare API token format.${reset}" >&2; return 1; }
  valid_domain "$zone" || { echo "${danger}Invalid zone: $zone${reset}" >&2; return 1; }
  valid_domain "$record" || { echo "${danger}Invalid record: $record${reset}" >&2; return 1; }
  valid_ipv4 "$ip" || { echo "${danger}Invalid IPv4: $ip${reset}" >&2; return 1; }
  [[ "$proxied" == "true" || "$proxied" == "false" ]] \
    || { echo "${danger}Invalid Cloudflare proxy mode.${reset}" >&2; return 1; }

  local zone_id record_id payload method url response
  zone_id="$(cloudflare_zone_id "$token" "$zone")"
  if [[ -z "$zone_id" ]]; then
    echo "${danger}Cloudflare zone not found: $zone${reset}" >&2
    return 1
  fi

  record_id="$(cloudflare_record_id "$token" "$zone_id" "$record")"
  payload="{\"type\":\"A\",\"name\":\"${record}\",\"content\":\"${ip}\",\"ttl\":1,\"proxied\":${proxied}}"
  if [[ -n "$record_id" ]]; then
    method="PUT"
    url="${CF_API}/zones/${zone_id}/dns_records/${record_id}"
  else
    method="POST"
    url="${CF_API}/zones/${zone_id}/dns_records"
  fi

  response="$(https_curl -X "$method" \
    --config <(printf 'header = "Authorization: Bearer %s"\nheader = "Content-Type: application/json"\n' "$token") \
    --data "$payload" \
    "$url")" || return 1
  printf '%s' "$response" | "$MODULE_MANIFEST_HELPER" cloudflare-success || return 1
  echo "${green}Cloudflare A record ready: ${record} -> ${ip}${reset}"
}

pick_editor() {
  if [[ -n "${EDITOR:-}" ]]; then
    echo "$EDITOR"
  elif command -v nano >/dev/null 2>&1; then
    echo "nano"
  else
    echo "vi"
  fi
}

secure_env_file() {
  install -d -m 0770 -o root -g "$APP_GROUP" "$(dirname "$ENV_FILE")"
  touch "$ENV_FILE"
  chown root:"$APP_GROUP" "$ENV_FILE" 2>/dev/null || true
  chmod 0660 "$ENV_FILE" 2>/dev/null || true
}

unit_state() {
  local unit="$1"
  local active enabled
  active="$(systemctl is-active "$unit" 2>/dev/null || true)"
  enabled="$(systemctl is-enabled "$unit" 2>/dev/null || true)"
  printf "%-34s %-12s %-12s\n" "$unit" "${active:-unknown}" "${enabled:-unknown}"
}

service_status() {
  header
  echo "${bold}Services${reset}"
  printf "%-34s %-12s %-12s\n" "unit" "active" "enabled"
  printf "%-34s %-12s %-12s\n" "----" "------" "-------"
  unit_state "$PANEL_SERVICE"
  while IFS= read -r service; do
    unit_state "$service"
  done < <(registered_services)
  echo
  echo "${bold}Local checks${reset}"
  echo "  curl http://127.0.0.1:8080/health"
  echo "  curl http://127.0.0.1:8080/ready"
  echo
  echo "${bold}Next step${reset}"
  echo "  Use HTTPS / Cloudflare setup to publish a protected URL."
  pause
}

restart_menu() {
  choice="$(tui_menu "Restart and reload" "Validated service operations" \
    1 "Restart panel" \
    2 "Validate and reload nginx" \
    3 "Validate and reload SSH" \
    4 "Restart all enabled modules" \
    5 "Reboot server" \
    0 "Back")" || return
  case "$choice" in
    1) need_root; run_cmd systemctl restart "$PANEL_SERVICE" || true ;;
    2)
      need_root
      if command -v nginx >/dev/null 2>&1; then
        if run_cmd nginx -t; then
          run_cmd systemctl reload nginx.service || true
        fi
      else
        echo "${danger}nginx is not installed.${reset}"
      fi
      ;;
    3)
      need_root
      if command -v sshd >/dev/null 2>&1; then
        if run_cmd sshd -t; then
          run_cmd systemctl reload ssh.service || run_cmd systemctl reload sshd.service || true
        fi
      else
        echo "${danger}sshd is not installed.${reset}"
      fi
      ;;
    4)
      need_root
      while IFS= read -r service; do
        if systemctl is-enabled --quiet "$service" 2>/dev/null; then
          run_cmd systemctl restart "$service" || true
        fi
      done < <(registered_services)
      ;;
    5)
      need_root
      read -r -p "Type REBOOT to reboot this server: " confirm
      if [[ "$confirm" == "REBOOT" ]]; then
        run_cmd systemctl reboot || true
      fi
      ;;
    0) return ;;
    *) invalid_choice; return ;;
  esac
  pause
}

edit_env() {
  need_root
  header
  secure_env_file
  "$(pick_editor)" "$ENV_FILE"
  secure_env_file
  run_cmd systemctl restart "$PANEL_SERVICE" || true
  pause
}

install_or_repair() {
  need_root
  header
  if [[ ! -x "${SOURCE_DIR}/deploy/install.sh" ]]; then
    echo "${danger}Installer not found at ${SOURCE_DIR}/deploy/install.sh${reset}"
    echo "Clone or bootstrap the source checkout first."
    pause
    return
  fi
  choice="$(tui_menu "Install or repair" "Use the checked-out release source" \
    1 "Install/repair from current source" \
    2 "Install/repair with nginx template" \
    3 "Force env template rewrite" \
    0 "Back")" || return
  case "$choice" in
    1) run_panel_install_from_source 0 0 || true ;;
    2) run_panel_install_from_source 1 0 || true ;;
    3) run_panel_install_from_source 0 1 || true ;;
    0) return ;;
    *) invalid_choice; return ;;
  esac
  pause
}

# Reuse the same installer entrypoint from both the menu and the guided flow so
# repair, nginx setup and env replacement never drift into separate code paths.
run_panel_install_from_source() {
  local with_nginx="${1:-0}"
  local force_env="${2:-0}"
  local args=(--build)

  if [[ ! -x "${SOURCE_DIR}/deploy/install.sh" ]]; then
    echo "${danger}Installer not found at ${SOURCE_DIR}/deploy/install.sh${reset}"
    echo "Clone or bootstrap the source checkout first."
    return 1
  fi

  [[ "$with_nginx" -eq 1 ]] && args+=(--with-nginx)
  [[ "$force_env" -eq 1 ]] && args+=(--force-env)
  bash "${SOURCE_DIR}/deploy/install.sh" "${args[@]}"
}

select_core_runtime() {
  local record id name root binary_name unit index selected
  local -a ids=() binaries=() services=() menu_items=()
  while IFS= read -r record; do
    IFS='|' read -r id name _ _ _ _ _ _ root binary_name unit _ _ _ <<<"$record"
    [[ "$root" == "cores" ]] || continue
    ids+=("$id")
    binaries+=("$binary_name")
    services+=("$unit")
    menu_items+=("${#ids[@]}" "$name [$id]")
  done < <(registered_module_records)
  if [[ "${#ids[@]}" -eq 0 ]]; then
    echo "No registered core modules."
    return 1
  fi
  menu_items+=(0 "Back")
  choice="$(tui_menu "Select core runtime" "Choose a registered module" "${menu_items[@]}")" || return 1
  [[ "$choice" == "0" ]] && return 2
  [[ "$choice" =~ ^[0-9]+$ ]] || { invalid_choice; return 1; }
  index=$((choice - 1))
  selected="${ids[$index]:-}"
  [[ -n "$selected" ]] || { invalid_choice; return 1; }
  core="$selected"
  binary="${binaries[$index]}"
  service="${services[$index]}"
}

# Import a core archive using the checksum-verifying installer. The TUI only
# gathers operator input; activation and rollback-safe symlink switching remain
# centralized in deploy/cores/install-core.sh.
install_core_from_prompts() {
  if [[ ! -x "${SOURCE_DIR}/deploy/cores/install-core.sh" ]]; then
    echo "${danger}Core installer not found at ${SOURCE_DIR}/deploy/cores/install-core.sh${reset}"
    return 1
  fi

  select_core_runtime || return $?
  prompt_value version "Manual core import" "Version" || return 1
  prompt_value url "Manual core import" "Release archive URL" || return 1
  prompt_value sha256 "Manual core import" "SHA-256 digest" || return 1
  if [[ -z "$version" || -z "$url" || -z "$sha256" ]]; then
    echo "${danger}Version, URL and SHA256 are required.${reset}"
    return 1
  fi
  bash "${SOURCE_DIR}/deploy/cores/install-core.sh" \
    --core "$core" \
    --version "$version" \
    --url "$url" \
    --sha256 "$sha256" \
    --binary "$binary" \
    --restart "$service"
}

core_helper() {
  need_root
  header
  install_core_from_prompts || true
  pause
}

install_https_deps() {
  need_root
  header
  if have_cmd apt-get; then
    export DEBIAN_FRONTEND=noninteractive
    run_cmd apt-get update
    run_cmd apt-get install -y ca-certificates certbot curl nginx python3 python3-certbot-dns-cloudflare
  elif have_cmd dnf; then
    run_cmd dnf install -y ca-certificates certbot curl nginx python3 python3-certbot-dns-cloudflare
  else
    echo "${danger}Unsupported package manager. Install nginx, certbot, python3 and certbot-dns-cloudflare manually.${reset}" >&2
    return 1
  fi
  run_cmd systemctl enable --now nginx.service
}

save_cloudflare_credentials() {
  local token="$1" staged
  valid_cloudflare_token "$token" \
    || { echo "${danger}Invalid Cloudflare API token format.${reset}" >&2; return 1; }
  install -d -m 0700 -o root -g root "$(dirname "$CLOUDFLARE_CREDENTIALS")"
  staged="$(mktemp "$(dirname "$CLOUDFLARE_CREDENTIALS")/.cloudflare.XXXXXX")"
  printf 'dns_cloudflare_api_token = %s\n' "$token" >"$staged"
  publish_staged_file "$staged" "$CLOUDFLARE_CREDENTIALS" root root 0600
}

issue_cloudflare_certificate() {
  local domain="$1"
  local email="$2"

  need_root
  require_cmd certbot || return 1
  valid_domain "$domain" || { echo "${danger}Invalid domain: $domain${reset}" >&2; return 1; }
  [[ "$email" == *@*.* ]] || { echo "${danger}Invalid email: $email${reset}" >&2; return 1; }
  [[ -f "$CLOUDFLARE_CREDENTIALS" ]] || { echo "${danger}Missing Cloudflare credentials: $CLOUDFLARE_CREDENTIALS${reset}" >&2; return 1; }

  run_cmd certbot certonly \
    --dns-cloudflare \
    --dns-cloudflare-credentials "$CLOUDFLARE_CREDENTIALS" \
    --dns-cloudflare-propagation-seconds 60 \
    --cert-name "$domain" \
    -d "$domain" \
    --non-interactive \
    --agree-tos \
    -m "$email"
}

write_nginx_https_config() {
  local domain="$1"
  local backup="" link_created=0

  need_root
  valid_domain "$domain" || { echo "${danger}Invalid domain: $domain${reset}" >&2; return 1; }
  install -d -m 0755 "$(dirname "$NGINX_SITE")"
  if [[ -f "$NGINX_SITE" ]]; then
    backup="${NGINX_SITE}.bak.$(date +%Y%m%d%H%M%S)"
    cp -a "$NGINX_SITE" "$backup"
  fi
  cat >"$NGINX_SITE" <<EOF
server {
    listen 443 ssl http2;
    server_name ${domain};

    ssl_certificate /etc/letsencrypt/live/${domain}/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/${domain}/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_session_tickets off;
    server_tokens off;
    client_max_body_size 1m;
    client_header_timeout 15s;
    client_body_timeout 15s;
    keepalive_timeout 30s;
    send_timeout 60s;
    proxy_connect_timeout 5s;
    proxy_send_timeout 30s;
    proxy_read_timeout 60s;

    add_header X-Frame-Options DENY always;
    add_header X-Content-Type-Options nosniff always;
    add_header Referrer-Policy no-referrer always;
    add_header Strict-Transport-Security "max-age=31536000" always;

    location ^~ /sub/ {
        access_log off;
        proxy_pass http://127.0.0.1:8080;
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$remote_addr;
        proxy_set_header X-Forwarded-Proto https;
    }

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$remote_addr;
        proxy_set_header X-Forwarded-Proto https;
    }
}

server {
    listen 80;
    server_name ${domain};
    return 301 https://\$host\$request_uri;
}
EOF
  install -d -m 0755 "$(dirname "$NGINX_ENABLED")"
  if [[ ! -e "$NGINX_ENABLED" ]]; then
    ln -s "$NGINX_SITE" "$NGINX_ENABLED"
    link_created=1
  fi
  if ! run_cmd nginx -t; then
    if [[ -n "$backup" ]]; then
      cp -a "$backup" "$NGINX_SITE"
    else
      rm -f "$NGINX_SITE"
    fi
    [[ "$link_created" -eq 0 ]] || rm -f "$NGINX_ENABLED"
    echo "${danger}Nginx rejected the panel site; the previous file was restored.${reset}" >&2
    return 1
  fi
  run_cmd systemctl reload nginx.service || return 1
}

guided_https_setup() {
  local zone domain email ip proxy_answer token proxied

  prompt_value zone "HTTPS setup" "Cloudflare zone (example.com)" || return
  prompt_value domain "HTTPS setup" "Panel hostname (panel.example.com)" || return
  prompt_value email "HTTPS setup" "Let's Encrypt email" || return
  prompt_value ip "HTTPS setup" "Public IPv4 (blank: detect automatically)" || return
  if [[ -z "$ip" ]]; then
    ip="$(public_ip || true)"
  fi
  if confirm_yes "Proxy panel traffic through Cloudflare?" "N"; then
    proxy_answer=y
  else
    proxy_answer=n
  fi
  prompt_value token "HTTPS setup" "Cloudflare API token" "" 1 || return
  proxied=false
  [[ "$proxy_answer" =~ ^[Yy]$ ]] && proxied=true

  install_https_deps || return
  cloudflare_write_a_record "$token" "$zone" "$domain" "$ip" "$proxied" || return
  save_cloudflare_credentials "$token" || return
  issue_cloudflare_certificate "$domain" "$email" || return
  write_nginx_https_config "$domain" || return
  echo
  echo "${green}${bold}Secure panel URL: https://${domain}/admin/setup${reset}"
}

https_setup_menu() {
  need_root
  choice="$(tui_menu "HTTPS and Cloudflare" "DNS, certificate and reverse proxy" \
    1 "Install HTTPS dependencies" \
    2 "Upsert Cloudflare A record" \
    3 "Issue certificate with DNS-01" \
    4 "Write nginx HTTPS config" \
    5 "Full guided setup" \
    0 "Back")" || return
  case "$choice" in
    1)
      install_https_deps || true
      ;;
    2)
      read -r -p "Cloudflare zone (example.com): " zone
      read -r -p "Panel hostname (panel.example.com): " domain
      read -r -p "IPv4 [auto]: " ip
      if [[ -z "$ip" ]]; then
        ip="$(public_ip || true)"
      fi
      read -r -p "Proxy through Cloudflare? [y/N]: " proxy_answer
      read -r -s -p "Cloudflare API token: " token
      echo
      proxied=false
      [[ "$proxy_answer" =~ ^[Yy]$ ]] && proxied=true
      cloudflare_write_a_record "$token" "$zone" "$domain" "$ip" "$proxied" || true
      ;;
    3)
      read -r -p "Panel hostname: " domain
      read -r -p "Let's Encrypt email: " email
      read -r -s -p "Cloudflare API token (stored in ${CLOUDFLARE_CREDENTIALS}): " token
      echo
      save_cloudflare_credentials "$token" || true
      issue_cloudflare_certificate "$domain" "$email" || true
      ;;
    4)
      read -r -p "Panel hostname: " domain
      write_nginx_https_config "$domain" || true
      echo "${green}Secure panel URL: https://${domain}/admin/setup${reset}"
      ;;
    5)
      guided_https_setup || true
      ;;
    0) return ;;
    *) invalid_choice; return ;;
  esac
  pause
}

# Commercial-style first-run path: keep the operator in one TUI session and
# offer every optional module in dependency order without hiding verification.
guided_deployment() {
  need_root
  if tui_available; then
    whiptail --title "Infiproxy guided deployment" --msgbox \
      "One installation cycle will:\n\n1. Install or repair the panel\n2. Configure optional HTTPS\n3. Install verified runtime modules\n4. Verify final service state" \
      18 72
  else
    header
    echo "${bold}Guided deployment cycle${reset}"
    echo "Panel, HTTPS, verified modules and final checks."
    echo
  fi

  if confirm_yes "Install or repair the panel from ${SOURCE_DIR} now?" "Y"; then
    local with_nginx=0 force_env=0
    confirm_yes "Install nginx template during panel install?" "Y" && with_nginx=1
    confirm_yes "Overwrite panel env template? Existing env will be backed up." "N" && force_env=1
    run_panel_install_from_source "$with_nginx" "$force_env" || {
      echo "${danger}Panel install/repair failed.${reset}" >&2
      pause
      return 1
    }
  fi

  echo
  if confirm_yes "Configure HTTPS with Cloudflare DNS-01 now?" "N"; then
    guided_https_setup || {
      echo "${danger}HTTPS setup did not complete. You can rerun this guided cycle later.${reset}" >&2
    }
  else
    echo "${muted}HTTPS skipped. Use SSH tunnel until a reverse proxy is configured:${reset}"
    echo "ssh -L 8080:127.0.0.1:8080 root@<server>"
  fi

  echo
  if confirm_yes "Install current verified proxy modules now?" "Y"; then
    local record module name driver root
    while IFS= read -r record; do
      IFS='|' read -r module name _ _ _ _ _ driver root _ _ _ _ _ <<<"$record"
      [[ "$driver" == "release" && "$root" == "cores" ]] || continue
      if confirm_yes "Install or update ${name} [${module}]?" "N"; then
        "$MODULE_UPDATE_BIN" --update "$module" || {
          echo "${danger}${name} installation failed; see ${MODULE_UPDATE_LOG}.${reset}" >&2
        }
      fi
    done < <(registered_module_records)
  fi

  echo
  echo "${green}${bold}Guided deployment cycle complete.${reset}"
  echo "Open the panel:"
  echo "  HTTPS:      https://<your-domain>/admin/setup"
  echo "  SSH tunnel: http://127.0.0.1:8080/admin/setup"
  echo "  Setup token: $(env_value "$ENV_FILE" INFIPROXY_SETUP_TOKEN)"
  echo
  echo "${bold}Service summary${reset}"
  printf "%-34s %-12s %-12s\n" "unit" "active" "enabled"
  printf "%-34s %-12s %-12s\n" "----" "------" "-------"
  unit_state "$PANEL_SERVICE"
  while IFS= read -r service; do
    unit_state "$service"
  done < <(registered_services)
  pause
}

logs_menu() {
  while true; do
    choice="$(tui_menu "Logs and diagnostics" "Bounded local diagnostics" \
      1 "Panel journal" \
      2 "Module updater log" \
      3 "Panel updater log" \
      4 "Nginx journal" \
      5 "Failed systemd units" \
      0 "Back")" || return
    case "$choice" in
      1) run_cmd journalctl -u "$PANEL_SERVICE" -n 120 --no-pager || true; pause ;;
      2) run_cmd tail -n 160 "$MODULE_UPDATE_LOG" || true; pause ;;
      3) run_cmd tail -n 160 /var/lib/infiproxy-maintenance/panel-update-run.log || true; pause ;;
      4) run_cmd journalctl -u nginx.service -n 120 --no-pager || true; pause ;;
      5) run_cmd systemctl --failed --no-pager --full || true; pause ;;
      0) return ;;
      *) invalid_choice ;;
    esac
  done
}

admin_access() {
  local domain setup_token
  header
  domain="$(awk '$1 == "server_name" { gsub(";", "", $2); if ($2 != "_") { print $2; exit } }' "$NGINX_SITE" 2>/dev/null || true)"
  echo "${bold}Web panel${reset}"
  if [[ -n "$domain" ]]; then
    echo "  https://${domain}/admin"
    echo "  first owner: https://${domain}/admin/setup"
  else
    echo "  SSH tunnel: ssh -L 8080:127.0.0.1:8080 root@$(hostname -I 2>/dev/null | awk '{print $1}')"
    echo "  local URL:  http://127.0.0.1:8080/admin"
  fi
  echo
  setup_token="$(env_value "$ENV_FILE" INFIPROXY_SETUP_TOKEN)"
  if [[ -n "$setup_token" ]]; then
    echo "${bold}First-owner setup token${reset}"
    echo "  $setup_token"
    echo "  The token is required only until the first administrator is created."
    echo
  fi
  echo "${bold}Local probes${reset}"
  curl -fsS --max-time 3 http://127.0.0.1:8080/health || true
  echo
  curl -fsS --max-time 3 http://127.0.0.1:8080/ready || true
  echo
  pause
}

select_module_runtime() {
  local record id name index selected
  local -a ids=() menu_items=()
  while IFS= read -r record; do
    IFS='|' read -r id name _ <<<"$record"
    ids+=("$id")
    menu_items+=("${#ids[@]}" "$name [$id]")
  done < <(registered_module_records)
  if [[ "${#ids[@]}" -eq 0 ]]; then
    echo "No registered modules."
    return 1
  fi
  menu_items+=(0 "Back")
  choice="$(tui_menu "Select runtime module" "Choose a registered module" "${menu_items[@]}")" || return 1
  [[ "$choice" == "0" ]] && return 2
  [[ "$choice" =~ ^[0-9]+$ ]] || { invalid_choice; return 1; }
  index=$((choice - 1))
  selected="${ids[$index]:-}"
  [[ -n "$selected" ]] || { invalid_choice; return 1; }
  module="$selected"
}

import_module_manifest() {
  local source id target record root binary service config
  read -r -p "Manifest path: " source
  [[ -f "$source" ]] || { echo "${danger}Manifest not found.${reset}"; return 1; }
  id="$(basename "$source" .module)"
  "$MODULE_MANIFEST_HELPER" validate "$source" --registration || return 1
  record="$("$MODULE_MANIFEST_HELPER" read "$source" --registration)" || return 1
  IFS='|' read -r _ _ _ _ _ _ _ _ root binary service config _ _ <<<"$record"
  install_generic_module_unit "$source" "$id" "$root" "$binary" "$service" || return 1
  target="${MODULE_AVAILABLE_DIR}/${id}.module"
  install -d -o root -g root -m 0755 "$MODULE_AVAILABLE_DIR"
  install -d -o root -g "$APP_GROUP" -m 0770 "$(dirname "$config")"
  install -o root -g root -m 0644 "$source" "$target"
  write_module_request "$id" register || return 1
  run_cmd systemctl start infiproxy-module-update.service || true
}

install_generic_module_unit() {
  local manifest="$1" id="$2" root="$3" binary="$4" service="$5"
  local suggested unit_source expected_binary exec_count
  [[ "$root" == "cores" && "$service" == "infiproxy-${id}.service" ]] || return 1
  systemctl cat "$service" >/dev/null 2>&1 && return 0

  suggested="${manifest%.module}.service"
  read -r -p "Service unit path [${suggested}]: " unit_source
  unit_source="${unit_source:-$suggested}"
  if [[ ! -f "$unit_source" || -L "$unit_source" || "$(wc -c <"$unit_source")" -gt 65536 ]]; then
    echo "${danger}Unit must be a regular non-symlink file no larger than 64 KiB.${reset}" >&2
    return 1
  fi

  expected_binary="/opt/infiproxy/cores/${id}/current/${binary}"
  exec_count="$(grep -Ec '^Exec[A-Za-z]*=' "$unit_source" || true)"
  if [[ "$exec_count" -ne 1 ]] \
    || [[ "$(grep -Ec '^User=' "$unit_source" || true)" -ne 1 ]] \
    || [[ "$(grep -Ec '^Group=' "$unit_source" || true)" -ne 1 ]] \
    || [[ "$(grep -Ec '^NoNewPrivileges=' "$unit_source" || true)" -ne 1 ]] \
    || [[ "$(grep -Ec '^ProtectSystem=' "$unit_source" || true)" -ne 1 ]] \
    || ! awk -F= -v expected="$expected_binary" '
      $1 == "ExecStart" {
        command = $2
        sub(/^[[:space:]]+/, "", command)
        split(command, parts, /[[:space:]]+/)
        if (parts[1] == expected) valid = 1
      }
      END { exit(valid ? 0 : 1) }
    ' "$unit_source" \
    || ! grep -Fxq "User=${APP_USER}" "$unit_source" \
    || ! grep -Fxq "Group=${APP_GROUP}" "$unit_source" \
    || ! grep -Fxq 'NoNewPrivileges=true' "$unit_source" \
    || ! grep -Fxq 'ProtectSystem=strict' "$unit_source"; then
    echo "${danger}Unit rejected: require one fixed ExecStart, infiproxy user/group, NoNewPrivileges and ProtectSystem=strict.${reset}" >&2
    return 1
  fi
  if grep -Eq '^(SupplementaryGroups|PermissionsStartOnly)=' "$unit_source" \
    || grep -E '^(AmbientCapabilities|CapabilityBoundingSet)=' "$unit_source" \
      | grep -Ev '^(AmbientCapabilities|CapabilityBoundingSet)=CAP_NET_BIND_SERVICE$' >/dev/null; then
    echo "${danger}Unit rejected: elevated groups or capabilities are not allowed.${reset}" >&2
    return 1
  fi

  install -o root -g root -m 0644 "$unit_source" "/etc/systemd/system/${service}"
  systemctl daemon-reload
}

module_update_menu() {
  need_root
  while true; do
    choice="$(tui_menu "Runtime modules" "Independent verified module lifecycle" \
      1 "Show installed/latest status" \
      2 "Check one module" \
      3 "Install or update one module" \
      4 "Restart module updater" \
      5 "Show module updater log" \
      6 "Import generic release manifest" \
      7 "Remove registered module" \
      0 "Back")" || return
    case "$choice" in
      1) run_cmd "$MODULE_UPDATE_BIN" --check-all || true; pause ;;
      2)
        select_module_runtime || continue
        run_cmd "$MODULE_UPDATE_BIN" --check "$module" || true
        pause
        ;;
      3)
        select_module_runtime || continue
        run_cmd "$MODULE_UPDATE_BIN" --check "$module" || true
        if confirm_yes "Install the latest verified ${module} version now?" "N"; then
          run_cmd "$MODULE_UPDATE_BIN" --update "$module" || true
        fi
        pause
        ;;
      4)
        run_cmd systemctl daemon-reload
        run_cmd systemctl enable --now infiproxy-module-update.timer infiproxy-module-update.path || true
        pause
        ;;
      5) run_cmd tail -n 160 "$MODULE_UPDATE_LOG" || true; pause ;;
      6) import_module_manifest || true; pause ;;
      7)
        select_module_runtime || continue
        read -r -p "Type ${module} to remove its runtime and preserve config: " confirm
        if [[ "$confirm" == "$module" ]]; then
          write_module_request "$module" remove || return 1
          run_cmd systemctl start infiproxy-module-update.service || true
        fi
        pause
        ;;
      0) return ;;
      *) invalid_choice ;;
    esac
  done
}

panel_update_check() {
  run_cmd /usr/local/sbin/infiproxy-panel-update --check || return 1
  [[ -f "$PANEL_UPDATE_STATUS" ]] || return 1
  awk -F= '
    $1 == "REPO" { print "repository  " $2 }
    $1 == "REF" { print "reference   " $2 }
    $1 == "CURRENT_SHA" { print "installed   " substr($2, 1, 12) }
    $1 == "LATEST_SHA" { print "latest      " substr($2, 1, 12) }
    $1 == "STATUS" { print "status      " $2 }
  ' "$PANEL_UPDATE_STATUS"
}

panel_update_menu() {
  while true; do
    choice="$(tui_menu "Panel updater" "Git-backed control-plane lifecycle" \
      1 "Check GitHub now" \
      2 "Update panel now" \
      3 "Show updater log" \
      4 "Restart timer and path watcher" \
      0 "Back")" || return
    case "$choice" in
      1) panel_update_check || true; pause ;;
      2)
        panel_update_check || true
        if confirm_yes "Apply the latest panel commit now?" "N"; then
          install -m 0640 -o root -g root /dev/null "$PANEL_UPDATE_REQUEST"
          run_cmd systemctl start infiproxy-panel-update.service || true
        fi
        pause
        ;;
      3) run_cmd tail -n 120 /var/lib/infiproxy-maintenance/panel-update-run.log || true; pause ;;
      4)
        run_cmd systemctl daemon-reload
        run_cmd systemctl enable --now infiproxy-panel-update.timer infiproxy-panel-update.path || true
        pause
        ;;
      0) return ;;
      *) invalid_choice ;;
    esac
  done
}

advanced_menu() {
  while true; do
    choice="$(tui_menu "Advanced tools" "Installation and runtime tools" \
      1 "Install or repair panel" \
      2 "Manual verified archive import" \
      0 "Back")" || return
    case "$choice" in
      1) install_or_repair ;;
      2) core_helper ;;
      0) return ;;
      *) invalid_choice ;;
    esac
  done
}

uninstall_commands() {
  case "$1" in
    panel)
      cat <<'EOF'
systemctl disable --now infiproxy.service || true
systemctl disable --now infiproxy-panel-update.timer infiproxy-panel-update.path infiproxy-panel-update.service || true
systemctl disable --now infiproxy-reconcile.timer infiproxy-reconcile.path infiproxy-reconcile.service || true
rm -f /etc/systemd/system/infiproxy.service
rm -f /etc/systemd/system/infiproxy-panel-update.service /etc/systemd/system/infiproxy-panel-update.timer /etc/systemd/system/infiproxy-panel-update.path
rm -f /etc/systemd/system/infiproxy-reconcile.service /etc/systemd/system/infiproxy-reconcile.timer /etc/systemd/system/infiproxy-reconcile.path
systemctl daemon-reload
rm -f /usr/local/bin/infiproxy /usr/local/sbin/infiproxy-panel-update /usr/local/libexec/infiproxy-reconcile /usr/local/libexec/infiproxy-install-state /etc/infiproxy-update.conf
rm -rf /etc/infiproxy /opt/infiproxy/source
rm -f /var/lib/infiproxy/infiproxy.sqlite /var/lib/infiproxy/infiproxy.sqlite-wal /var/lib/infiproxy/infiproxy.sqlite-shm
rm -f /var/lib/infiproxy/panel-update-state.env /var/lib/infiproxy/panel-update-now.request
rm -rf /var/lib/infiproxy-maintenance/update-backups
rm -f /var/lib/infiproxy-maintenance/panel-update-run.log /var/lib/infiproxy-maintenance/panel-last-applied.sha
rm -f /etc/nginx/sites-enabled/infiproxy.conf /etc/nginx/sites-available/infiproxy.conf /etc/nginx/sites-enabled/infiproxy-subscription.conf /etc/nginx/sites-available/infiproxy-subscription.conf
if command -v nginx >/dev/null 2>&1 && nginx -t; then
  systemctl reload nginx.service || true
fi
EOF
      ;;
    full)
      cat <<'EOF'
for manifest in /etc/infiproxy-modules.d/*.module; do
  [ -f "$manifest" ] || continue
  service=$(/usr/local/libexec/infiproxy-module-manifest read "$manifest" --root-owned | cut -d'|' -f11)
  systemctl disable --now "$service" || true
  rm -f "/etc/systemd/system/$service"
done
systemctl disable --now infiproxy.service infiproxy-panel-update.timer infiproxy-panel-update.path infiproxy-panel-update.service infiproxy-module-update.timer infiproxy-module-update.path infiproxy-module-update.service infiproxy-reconcile.timer infiproxy-reconcile.path infiproxy-reconcile.service || true
rm -f /etc/systemd/system/infiproxy.service
rm -f /etc/systemd/system/infiproxy-panel-update.service /etc/systemd/system/infiproxy-panel-update.timer /etc/systemd/system/infiproxy-panel-update.path
rm -f /etc/systemd/system/infiproxy-module-update.service /etc/systemd/system/infiproxy-module-update.timer /etc/systemd/system/infiproxy-module-update.path
rm -f /etc/systemd/system/infiproxy-reconcile.service /etc/systemd/system/infiproxy-reconcile.timer /etc/systemd/system/infiproxy-reconcile.path
rm -f /etc/systemd/system/headscale.service
rm -f /etc/systemd/system/headscale.service.d/infiproxy-module.conf
rmdir /etc/systemd/system/headscale.service.d 2>/dev/null || true
systemctl daemon-reload
rm -f /usr/local/bin/infiproxy /usr/local/bin/headscale /usr/local/sbin/infiproxy-manager /usr/local/sbin/infiproxy-panel-update /usr/local/sbin/infiproxy-module-update /usr/local/sbin/infiproxy-core-install /usr/local/libexec/infiproxy-module-manifest /usr/local/libexec/infiproxy-headscale-control /usr/local/libexec/infiproxy-reconcile /usr/local/libexec/infiproxy-install-state
rm -f /usr/local/libexec/infiproxy-tui /usr/local/libexec/infiproxy-manager-operations.sh
rm -f /etc/profile.d/infiproxy-manager.sh
rm -f /etc/infiproxy-update.conf
rm -rf /etc/infiproxy /etc/infiproxy-modules.d /etc/infiproxy-modules.available.d /var/lib/infiproxy /var/lib/infiproxy-maintenance
rm -rf /etc/infiproxy-cores /opt/infiproxy/cores /opt/infiproxy/modules /var/log/infiproxy-cores
rm -rf /etc/headscale /var/lib/headscale
rm -rf /opt/infiproxy/source
rm -f /etc/nginx/sites-enabled/infiproxy.conf /etc/nginx/sites-available/infiproxy.conf /etc/nginx/sites-enabled/infiproxy-subscription.conf /etc/nginx/sites-available/infiproxy-subscription.conf
rm -f /etc/nginx/sites-enabled/infiproxy-headscale.conf /etc/nginx/sites-available/infiproxy-headscale.conf
if nginx -t; then
  systemctl reload nginx.service || true
fi
userdel infiproxy 2>/dev/null || true
userdel infiproxy-runtime 2>/dev/null || true
groupdel infiproxy 2>/dev/null || true
groupdel infiproxy-runtime 2>/dev/null || true
EOF
      ;;
    factory)
      cat <<'EOF'
for manifest in /etc/infiproxy-modules.d/*.module; do
  [ -f "$manifest" ] || continue
  service=$(/usr/local/libexec/infiproxy-module-manifest read "$manifest" --root-owned | cut -d'|' -f11)
  systemctl disable --now "$service" || true
  rm -f "/etc/systemd/system/$service"
done
systemctl disable --now infiproxy.service infiproxy-panel-update.timer infiproxy-panel-update.path infiproxy-panel-update.service infiproxy-module-update.timer infiproxy-module-update.path infiproxy-module-update.service infiproxy-reconcile.timer infiproxy-reconcile.path infiproxy-reconcile.service || true
rm -f /etc/systemd/system/infiproxy.service
rm -f /etc/systemd/system/infiproxy-panel-update.service /etc/systemd/system/infiproxy-panel-update.timer /etc/systemd/system/infiproxy-panel-update.path
rm -f /etc/systemd/system/infiproxy-module-update.service /etc/systemd/system/infiproxy-module-update.timer /etc/systemd/system/infiproxy-module-update.path
rm -f /etc/systemd/system/infiproxy-reconcile.service /etc/systemd/system/infiproxy-reconcile.timer /etc/systemd/system/infiproxy-reconcile.path
rm -f /etc/systemd/system/headscale.service
rm -f /etc/systemd/system/headscale.service.d/infiproxy-module.conf
rmdir /etc/systemd/system/headscale.service.d 2>/dev/null || true
systemctl daemon-reload
rm -f /usr/local/bin/infiproxy /usr/local/sbin/infiproxy-manager /usr/local/sbin/infiproxy-panel-update /usr/local/sbin/infiproxy-module-update /usr/local/sbin/infiproxy-core-install /usr/local/libexec/infiproxy-module-manifest /usr/local/libexec/infiproxy-headscale-control /usr/local/libexec/infiproxy-reconcile /usr/local/libexec/infiproxy-install-state
rm -f /usr/local/libexec/infiproxy-tui /usr/local/libexec/infiproxy-manager-operations.sh
rm -f /etc/profile.d/infiproxy-manager.sh
rm -f /etc/infiproxy-update.conf
rm -rf /etc/infiproxy /etc/infiproxy-modules.d /etc/infiproxy-modules.available.d /var/lib/infiproxy /var/lib/infiproxy-maintenance
rm -rf /etc/infiproxy-cores /opt/infiproxy /var/log/infiproxy-cores
rm -rf /etc/headscale /var/lib/headscale
rm -f /usr/local/bin/headscale
rm -f /etc/nginx/sites-enabled/infiproxy.conf /etc/nginx/sites-available/infiproxy.conf /etc/nginx/sites-enabled/infiproxy-subscription.conf /etc/nginx/sites-available/infiproxy-subscription.conf
rm -f /etc/nginx/sites-enabled/infiproxy-headscale.conf /etc/nginx/sites-available/infiproxy-headscale.conf
if nginx -t; then
  systemctl reload nginx.service || true
fi
userdel infiproxy 2>/dev/null || true
userdel infiproxy-runtime 2>/dev/null || true
groupdel infiproxy 2>/dev/null || true
groupdel infiproxy-runtime 2>/dev/null || true
EOF
      ;;
    *) return 1 ;;
  esac
}

run_uninstall() {
  need_root
  local mode="${1:-}"
  if [[ -n "$mode" && "$mode" != "panel" && "$mode" != "full" && "$mode" != "factory" ]]; then
    echo "${danger}Unknown uninstall mode: $mode${reset}" >&2
    echo "Use: panel, full, or factory" >&2
    exit 2
  fi
  if [[ -z "$mode" ]]; then
    choice="$(tui_menu "Danger zone" "Review the printed command plan before final confirmation" \
      1 "Panel-only removal" \
      2 "Full Infiproxy footprint removal" \
      3 "Factory footprint cleanup" \
      0 "Back")" || return
    case "$choice" in
      1) mode="panel" ;;
      2) mode="full" ;;
      3) mode="factory" ;;
      0) return ;;
      *) invalid_choice; return ;;
    esac
  fi
  header
  echo "${danger}${bold}About to run ${mode} uninstall.${reset}"
  uninstall_commands "$mode"
  echo
  read -r -p "Type DELETE INFIPROXY to continue: " confirm
  [[ "$confirm" == "DELETE INFIPROXY" ]] || return
  uninstall_commands "$mode" | bash
}

main_menu() {
  local menu_choice
  while true; do
    menu_choice="$(main_menu_choice)" || exit 0
    case "$menu_choice" in
      1) service_status ;;
      2) admin_access ;;
      3) module_update_menu ;;
      4) restart_menu ;;
      5) logs_menu ;;
      6) https_setup_menu ;;
      7) panel_update_menu ;;
      8) edit_env ;;
      9) guided_deployment ;;
      10) privileged_secrets_menu ;;
      11) advanced_menu ;;
      12) run_uninstall ;;
      0) exit 0 ;;
      *) invalid_choice ;;
    esac
  done
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  if [[ "${1:-}" == "--operation" ]]; then
    operations="${INFIPROXY_MANAGER_OPERATIONS:-/usr/local/libexec/infiproxy-manager-operations.sh}"
    # shellcheck source=deploy/lib/manager-operations.sh
    source "$operations"
    shift
    manager_operation "$@"
    exit $?
  fi
  if [[ "${1:-}" != "--legacy" && "${1:-}" != "--uninstall" ]]; then
    tui="${INFIPROXY_TUI_BIN:-/usr/local/libexec/infiproxy-tui}"
    if [[ -x "$tui" ]]; then exec "$tui" "$@"; fi
    if [[ "${1:-}" != "--guided" && -n "${1:-}" && "${1:-}" != "--help" && "${1:-}" != "-h" ]]; then
      echo "Compiled manager unavailable; use --legacy for recovery." >&2
      exit 1
    fi
    echo "Compiled manager unavailable; opening legacy recovery." >&2
  fi
  if [[ "${1:-}" == "--legacy" ]]; then shift; fi
  case "${1:-}" in
    --guided)
      guided_deployment
      ;;
    --uninstall)
      run_uninstall "${2:-}"
      ;;
    --help|-h)
      echo "Usage: sudo infiproxy-manager [--guided] [--uninstall panel|full|factory]"
      ;;
    *)
      main_menu
      ;;
  esac
fi
