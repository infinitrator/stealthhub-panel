#!/usr/bin/env bash
# Minimal SSH control surface for Infiproxy VPS installs.
#
# The manager intentionally stays dependency-light: plain Bash, systemd, curl,
# certbot and Python for tiny JSON parsing. Destructive actions require root and
# explicit confirmation; Cloudflare tokens are never echoed back to the terminal.
set -Eeuo pipefail

APP="Infiproxy"
ENV_FILE="${INFIPROXY_ENV_FILE:-/etc/infiproxy/infiproxy.env}"
SOURCE_DIR="${INFIPROXY_SRC_DIR:-/opt/infiproxy/source}"
APP_GROUP="${INFIPROXY_GROUP:-infiproxy}"
PANEL_SERVICE="infiproxy.service"
MODULE_UPDATE_BIN="${INFIPROXY_MODULE_UPDATE_BIN:-/usr/local/sbin/infiproxy-module-update}"
MODULE_UPDATE_LOG="${INFIPROXY_MODULE_UPDATE_LOG:-/var/lib/infiproxy-maintenance/module-update.log}"
PANEL_UPDATE_REQUEST="${INFIPROXY_PANEL_UPDATE_REQUEST:-/var/lib/infiproxy/panel-update-now.request}"
UPDATE_CONFIG_FILE="${INFIPROXY_UPDATE_CONFIG_FILE:-/etc/infiproxy-update.conf}"
NGINX_SITE="${INFIPROXY_NGINX_SITE:-/etc/nginx/sites-available/infiproxy.conf}"
NGINX_ENABLED="${INFIPROXY_NGINX_ENABLED:-/etc/nginx/sites-enabled/infiproxy.conf}"
CLOUDFLARE_CREDENTIALS="${INFIPROXY_CF_CREDENTIALS:-/etc/letsencrypt/cloudflare.ini}"
CF_API="https://api.cloudflare.com/client/v4"
CORE_SERVICES=(
  "infiproxy-xray.service"
  "infiproxy-sing-box.service"
  "infiproxy-hysteria.service"
  "infiproxy-tuic.service"
  "infiproxy-mtproto.service"
)
MTPROTO_DIR="${INFIPROXY_MTPROTO_DIR:-/etc/infiproxy-cores/mtproto}"
MTPROTO_ENV="${INFIPROXY_MTPROTO_ENV:-${MTPROTO_DIR}/mtproto.env}"
MTPROTO_BINARY="${INFIPROXY_MTPROTO_BINARY:-/opt/infiproxy/cores/mtproto/current/mtproto-proxy}"
MTPROTO_SECRET_URL="https://core.telegram.org/getProxySecret"
MTPROTO_CONFIG_URL="https://core.telegram.org/getProxyConfig"
HEADSCALE_SERVICE="headscale.service"
HEADSCALE_CONFIG="${INFIPROXY_HEADSCALE_CONFIG:-/etc/headscale/config.yaml}"
HEADSCALE_STATE_DIR="${INFIPROXY_HEADSCALE_STATE_DIR:-/var/lib/headscale}"
HEADSCALE_NGINX_SITE="${INFIPROXY_HEADSCALE_NGINX_SITE:-/etc/nginx/sites-available/infiproxy-headscale.conf}"
HEADSCALE_NGINX_ENABLED="${INFIPROXY_HEADSCALE_NGINX_ENABLED:-/etc/nginx/sites-enabled/infiproxy-headscale.conf}"
HEADSCALE_LISTEN_ADDR="${INFIPROXY_HEADSCALE_LISTEN_ADDR:-127.0.0.1:8088}"
HEADSCALE_METRICS_ADDR="${INFIPROXY_HEADSCALE_METRICS_ADDR:-127.0.0.1:9098}"
HEADSCALE_GRPC_ADDR="${INFIPROXY_HEADSCALE_GRPC_ADDR:-127.0.0.1:50443}"
HEADSCALE_LATEST_API="https://api.github.com/repos/juanfont/headscale/releases/latest"

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

read_menu_choice() {
  choice=""
  read -r -p "> " choice || return 1
}

confirm_yes() {
  local prompt="$1"
  local default="${2:-N}"
  local answer

  if [[ "$default" == "Y" ]]; then
    read -r -p "${prompt} [Y/n]: " answer || return 1
    [[ -z "$answer" || "$answer" =~ ^[Yy]$ ]]
  else
    read -r -p "${prompt} [y/N]: " answer || return 1
    [[ "$answer" =~ ^[Yy]$ ]]
  fi
}

header() {
  local panel_state host uptime_label module_count
  clear 2>/dev/null || true
  host="$(hostname -f 2>/dev/null || hostname)"
  panel_state="$(systemctl is-active "$PANEL_SERVICE" 2>/dev/null || true)"
  uptime_label="$(uptime -p 2>/dev/null | sed 's/^up //' || true)"
  module_count=0
  for service in "${CORE_SERVICES[@]}" "$HEADSCALE_SERVICE"; do
    systemctl is-active --quiet "$service" 2>/dev/null && ((module_count += 1)) || true
  done
  echo "${green}${bold}+------------------------------------------------------------------+${reset}"
  printf '%s| %-64s |%s\n' "${green}${bold}" "${APP} Manager / ${host}" "${reset}"
  echo "${green}${bold}+------------------------------------------------------------------+${reset}"
  printf "${muted}panel %-10s modules active %-2s/6  uptime %s${reset}\n" \
    "${panel_state:-unknown}" "$module_count" "${uptime_label:-unknown}"
  echo "${muted}systemd bare-metal / env ${ENV_FILE}${reset}"
  echo
}

main_menu_choice() {
  if have_cmd whiptail && [[ -t 0 && -t 1 ]]; then
    whiptail --title "Infiproxy Manager" \
      --menu "Host: $(hostname)\nSelect an operations area" 25 78 15 \
      1 "Overview and service status" \
      2 "Admin access and panel URL" \
      3 "Runtime modules" \
      4 "Restart and reload" \
      5 "Logs and diagnostics" \
      6 "HTTPS and Cloudflare" \
      7 "Panel updates" \
      8 "Panel environment" \
      9 "Guided deployment" \
      10 "Advanced tools" \
      11 "Danger zone" \
      0 "Exit to shell" 3>&1 1>&2 2>&3
  else
    header >&2
    echo "1) Overview and service status" >&2
    echo "2) Admin access and panel URL" >&2
    echo "3) Runtime modules" >&2
    echo "4) Restart and reload" >&2
    echo "5) Logs and diagnostics" >&2
    echo "6) HTTPS and Cloudflare" >&2
    echo "7) Panel updates" >&2
    echo "8) Panel environment" >&2
    echo "9) Guided deployment" >&2
    echo "10) Advanced tools" >&2
    echo "${danger}11) Danger zone${reset}" >&2
    echo "0) Exit to shell" >&2
    read_menu_choice || return 1
    printf '%s' "$choice"
  fi
}

run_cmd() {
  echo "${soft}$ $*${reset}"
  "$@"
}

have_cmd() {
  command -v "$1" >/dev/null 2>&1
}

require_cmd() {
  if ! have_cmd "$1"; then
    echo "${danger}Missing command: $1${reset}" >&2
    return 1
  fi
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

valid_mtproto_secret() {
  [[ "$1" =~ ^[A-Fa-f0-9]{32}$ ]]
}

valid_headscale_user() {
  [[ "$1" =~ ^[A-Za-z0-9._-]{1,63}$ ]] && [[ "$1" != *@* ]]
}

public_ip() {
  curl -fsSL --max-time 10 https://api.ipify.org
}

random_mtproto_secret() {
  if have_cmd openssl; then
    openssl rand -hex 16
  else
    od -An -N16 -tx1 /dev/urandom | tr -d ' \n'
  fi
}

env_value() {
  local file="$1"
  local key="$2"
  awk -F= -v key="$key" '$1 == key { value=$0; sub("^[^=]*=", "", value); print value }' "$file" 2>/dev/null | tail -1
}

headscale_arch() {
  case "$(uname -m)" in
    x86_64|amd64) echo "amd64" ;;
    aarch64|arm64) echo "arm64" ;;
    *)
      echo "${danger}Unsupported Headscale architecture: $(uname -m)${reset}" >&2
      return 1
      ;;
  esac
}

headscale_latest_version() {
  require_cmd curl || return 1
  require_cmd python3 || return 1
  curl -fsSL --max-time 20 "$HEADSCALE_LATEST_API" \
    | python3 -c 'import json,sys; print(json.load(sys.stdin)["tag_name"].lstrip("v"))'
}

cloudflare_token_from_file() {
  awk -F= '/dns_cloudflare_api_token/ { value=$2; sub(/^[[:space:]]+/, "", value); sub(/[[:space:]]+$/, "", value); print value }' "$CLOUDFLARE_CREDENTIALS" 2>/dev/null | tail -1
}

headscale_cmd() {
  headscale -c "$HEADSCALE_CONFIG" "$@"
}

json_first_id() {
  python3 -c 'import json,sys; data=json.load(sys.stdin); result=data.get("result") or []; print(result[0].get("id","") if result else "")'
}

cloudflare_get() {
  local token="$1"
  local url="$2"
  shift 2
  curl -fsS \
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
  require_cmd python3 || return 1
  [[ -n "$token" ]] || { echo "${danger}Cloudflare API token is required.${reset}" >&2; return 1; }
  valid_domain "$zone" || { echo "${danger}Invalid zone: $zone${reset}" >&2; return 1; }
  valid_domain "$record" || { echo "${danger}Invalid record: $record${reset}" >&2; return 1; }
  valid_ipv4 "$ip" || { echo "${danger}Invalid IPv4: $ip${reset}" >&2; return 1; }

  local zone_id record_id payload method url
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

  curl -fsS -X "$method" \
    --config <(printf 'header = "Authorization: Bearer %s"\nheader = "Content-Type: application/json"\n' "$token") \
    --data "$payload" \
    "$url" >/dev/null
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
  for service in "${CORE_SERVICES[@]}"; do
    unit_state "$service"
  done
  unit_state "$HEADSCALE_SERVICE"
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
  header
  echo "1) Restart panel"
  echo "2) Reload nginx"
  echo "3) Validate and reload SSH"
  echo "4) Restart all enabled core services"
  echo "5) Restart Headscale"
  echo "6) Reboot server"
  echo "0) Back"
  read_menu_choice || return
  case "$choice" in
    1) need_root; run_cmd systemctl restart "$PANEL_SERVICE" || true ;;
    2)
      need_root
      if command -v nginx >/dev/null 2>&1; then
        run_cmd nginx -t && run_cmd systemctl reload nginx.service || true
      else
        echo "${danger}nginx is not installed.${reset}"
      fi
      ;;
    3)
      need_root
      if command -v sshd >/dev/null 2>&1; then
        run_cmd sshd -t && (run_cmd systemctl reload ssh.service || run_cmd systemctl reload sshd.service) || true
      else
        echo "${danger}sshd is not installed.${reset}"
      fi
      ;;
    4)
      need_root
      for service in "${CORE_SERVICES[@]}"; do
        if systemctl is-enabled --quiet "$service" 2>/dev/null; then
          run_cmd systemctl restart "$service" || true
        fi
      done
      ;;
    5)
      need_root
      if have_cmd headscale; then
        headscale_cmd configtest || true
      fi
      run_cmd systemctl restart "$HEADSCALE_SERVICE" || true
      ;;
    6)
      need_root
      read -r -p "Type REBOOT to reboot this server: " confirm
      [[ "$confirm" == "REBOOT" ]] && run_cmd systemctl reboot || true
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

toggle_danger_shell() {
  need_root
  header
  secure_env_file
  if grep -q '^INFIPROXY_ENABLE_DANGER_SHELL=' "$ENV_FILE"; then
    current="$(grep '^INFIPROXY_ENABLE_DANGER_SHELL=' "$ENV_FILE" | tail -1 | cut -d= -f2-)"
    if [[ "$current" == "true" ]]; then
      sed -i.bak 's/^INFIPROXY_ENABLE_DANGER_SHELL=.*/INFIPROXY_ENABLE_DANGER_SHELL=false/' "$ENV_FILE"
    else
      sed -i.bak 's/^INFIPROXY_ENABLE_DANGER_SHELL=.*/INFIPROXY_ENABLE_DANGER_SHELL=true/' "$ENV_FILE"
    fi
  else
    echo "INFIPROXY_ENABLE_DANGER_SHELL=true" >>"$ENV_FILE"
  fi
  secure_env_file
  run_cmd systemctl restart "$PANEL_SERVICE" || true
  grep '^INFIPROXY_ENABLE_DANGER_SHELL=' "$ENV_FILE" || true
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
  echo "1) Install/repair from current source"
  echo "2) Install/repair with nginx template"
  echo "3) Force env template rewrite"
  echo "0) Back"
  read_menu_choice || return
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
  echo "1) xray"
  echo "2) sing-box"
  echo "3) hysteria"
  echo "4) tuic"
  echo "5) Telegram MTProto"
  echo "0) Back"
  read_menu_choice || return 1
  case "$choice" in
    1) core="xray"; binary="xray"; service="infiproxy-xray.service" ;;
    2) core="sing-box"; binary="sing-box"; service="infiproxy-sing-box.service" ;;
    3) core="hysteria"; binary="hysteria"; service="infiproxy-hysteria.service" ;;
    4) core="tuic"; binary="tuic-server"; service="infiproxy-tuic.service" ;;
    5) core="mtproto"; binary="mtproto-proxy"; service="infiproxy-mtproto.service" ;;
    0) return 2 ;;
    *) invalid_choice; return 1 ;;
  esac
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
  read -r -p "Version: " version
  read -r -p "Release archive URL: " url
  read -r -p "SHA256: " sha256
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

secure_mtproto_dir() {
  install -d -m 0770 -o root -g "$APP_GROUP" "$MTPROTO_DIR"
  chown root:"$APP_GROUP" "$MTPROTO_DIR" 2>/dev/null || true
  chmod 0770 "$MTPROTO_DIR" 2>/dev/null || true
}

# MTProxy needs Telegram-maintained upstream files in addition to its binary.
# Keep them owned by root/infiproxy so the panel can display/edit metadata while
# the runtime service only reads the resulting files.
download_mtproto_upstream_config() {
  need_root
  require_cmd curl || return 1
  secure_mtproto_dir

  local secret_tmp config_tmp
  secret_tmp="$(mktemp)"
  config_tmp="$(mktemp)"

  if ! curl -fsSL --max-time 30 "$MTPROTO_SECRET_URL" -o "$secret_tmp"; then
    rm -f "$secret_tmp" "$config_tmp"
    echo "${danger}Failed to download Telegram proxy-secret.${reset}" >&2
    return 1
  fi
  if ! curl -fsSL --max-time 30 "$MTPROTO_CONFIG_URL" -o "$config_tmp"; then
    rm -f "$secret_tmp" "$config_tmp"
    echo "${danger}Failed to download Telegram proxy-multi.conf.${reset}" >&2
    return 1
  fi
  install -m 0640 -o root -g "$APP_GROUP" "$secret_tmp" "$MTPROTO_DIR/proxy-secret"
  install -m 0640 -o root -g "$APP_GROUP" "$config_tmp" "$MTPROTO_DIR/proxy-multi.conf"
  rm -f "$secret_tmp" "$config_tmp"
  echo "${green}Telegram upstream config refreshed.${reset}"
}

write_mtproto_env() {
  local port="$1"
  local stats_port="$2"
  local secret="$3"
  local workers="$4"

  valid_port "$port" || { echo "${danger}Invalid MTProto port: $port${reset}" >&2; return 1; }
  valid_port "$stats_port" || { echo "${danger}Invalid stats port: $stats_port${reset}" >&2; return 1; }
  valid_mtproto_secret "$secret" || { echo "${danger}Secret must be exactly 32 hex characters.${reset}" >&2; return 1; }
  if [[ ! "$workers" =~ ^[0-9]{1,2}$ ]] || ((10#$workers < 1 || 10#$workers > 16)); then
    echo "${danger}Workers must be between 1 and 16.${reset}" >&2
    return 1
  fi

  secure_mtproto_dir
  if [[ -f "$MTPROTO_ENV" ]]; then
    cp -a "$MTPROTO_ENV" "${MTPROTO_ENV}.bak.$(date +%Y%m%d%H%M%S)"
  fi
  cat >"$MTPROTO_ENV" <<EOF
# Telegram MTProxy runtime configuration managed by Infiproxy.
MTPROTO_PORT=${port}
MTPROTO_STATS_PORT=${stats_port}
MTPROTO_SECRET=${secret}
MTPROTO_WORKERS=${workers}
MTPROTO_AES_PWD=${MTPROTO_DIR}/proxy-secret
MTPROTO_PROXY_CONFIG=${MTPROTO_DIR}/proxy-multi.conf
EOF
  chown root:"$APP_GROUP" "$MTPROTO_ENV" 2>/dev/null || true
  chmod 0660 "$MTPROTO_ENV" 2>/dev/null || true
  echo "${green}MTProto env written: ${MTPROTO_ENV}${reset}"
}

print_mtproto_link() {
  local host="$1"
  local port="$2"
  local secret="$3"

  valid_public_host "$host" || { echo "${danger}Invalid public host: $host${reset}" >&2; return 1; }
  valid_port "$port" || { echo "${danger}Invalid MTProto port: $port${reset}" >&2; return 1; }
  valid_mtproto_secret "$secret" || { echo "${danger}Secret must be exactly 32 hex characters.${reset}" >&2; return 1; }
  echo
  echo "${green}${bold}Telegram import link:${reset}"
  echo "https://t.me/proxy?server=${host}&port=${port}&secret=${secret}"
}

# Generate the client-facing Telegram link from validated host, port and secret
# values. The service is started only when the operator has already installed a
# verified mtproto-proxy binary.
guided_mtproto_setup() {
  local host port stats_port workers secret custom_secret start_answer

  read -r -p "Public hostname or IPv4 [auto public IPv4]: " host
  if [[ -z "$host" ]]; then
    host="$(public_ip || true)"
  fi
  read -r -p "Telegram MTProto port [8443]: " port
  port="${port:-8443}"
  read -r -p "Local stats port [8888]: " stats_port
  stats_port="${stats_port:-8888}"
  read -r -p "Workers [2]: " workers
  workers="${workers:-2}"
  secret="$(random_mtproto_secret)"
  read -r -p "Custom 32-hex secret [generated]: " custom_secret
  if [[ -n "$custom_secret" ]]; then
    secret="$custom_secret"
  fi
  download_mtproto_upstream_config || return
  write_mtproto_env "$port" "$stats_port" "$secret" "$workers" || return
  run_cmd systemctl daemon-reload
  print_mtproto_link "$host" "$port" "$secret" || return
  if [[ -x "$MTPROTO_BINARY" ]]; then
    read -r -p "Enable and start infiproxy-mtproto.service now? [y/N]: " start_answer
    if [[ "$start_answer" =~ ^[Yy]$ ]]; then
      run_cmd systemctl enable --now infiproxy-mtproto.service
      run_cmd systemctl --no-pager --full status infiproxy-mtproto.service || true
    fi
  else
    echo "${muted}Binary is not installed yet: ${MTPROTO_BINARY}${reset}"
    echo "${muted}Use Runtime modules to build the latest official MTProto commit, then start the service.${reset}"
  fi
}

mtproto_setup_menu() {
  need_root
  header
  echo "1) Guided initial MTProto setup"
  echo "2) Refresh Telegram upstream config"
  echo "3) Show Telegram import link"
  echo "4) Enable and start MTProto service"
  echo "5) Restart MTProto service"
  echo "0) Back"
  read_menu_choice || return
  case "$choice" in
    1)
      guided_mtproto_setup || true
      ;;
    2)
      download_mtproto_upstream_config || return
      ;;
    3)
      local host port secret
      read -r -p "Public hostname or IPv4 [auto public IPv4]: " host
      if [[ -z "$host" ]]; then
        host="$(public_ip || true)"
      fi
      port="$(env_value "$MTPROTO_ENV" MTPROTO_PORT)"
      secret="$(env_value "$MTPROTO_ENV" MTPROTO_SECRET)"
      print_mtproto_link "$host" "$port" "$secret" || return
      ;;
    4)
      run_cmd systemctl daemon-reload
      run_cmd systemctl enable --now infiproxy-mtproto.service || true
      run_cmd systemctl --no-pager --full status infiproxy-mtproto.service || true
      ;;
    5)
      run_cmd systemctl restart infiproxy-mtproto.service || true
      run_cmd systemctl --no-pager --full status infiproxy-mtproto.service || true
      ;;
    0) return ;;
    *) invalid_choice; return ;;
  esac
  pause
}

# Install Headscale through the same versioned module pipeline used by every
# other runtime. Its configuration and service state survive the binary switch.
install_headscale_release() {
  need_root
  run_cmd "$MODULE_UPDATE_BIN" --update headscale
  usermod -aG "$APP_GROUP" headscale 2>/dev/null || true
}

secure_headscale_paths() {
  install -d -m 0770 -o root -g "$APP_GROUP" "$(dirname "$HEADSCALE_CONFIG")"
  install -d -m 0750 -o headscale -g headscale "$HEADSCALE_STATE_DIR" 2>/dev/null \
    || install -d -m 0750 "$HEADSCALE_STATE_DIR"
  if id -u headscale >/dev/null 2>&1; then
    usermod -aG "$APP_GROUP" headscale 2>/dev/null || true
  fi
}

# Headscale upstream examples default to 127.0.0.1:8080, which collides with the
# panel. Infiproxy pins Headscale to 127.0.0.1:8088 and exposes it through a
# dedicated HTTPS virtual host.
write_headscale_config() {
  local server_url="$1"
  local base_domain="$2"

  [[ "$server_url" =~ ^https://[A-Za-z0-9.-]+(:[0-9]{1,5})?$ ]] || {
    echo "${danger}Headscale server URL must look like https://hs.example.com${reset}" >&2
    return 1
  }
  valid_domain "$base_domain" || { echo "${danger}Invalid MagicDNS base domain: $base_domain${reset}" >&2; return 1; }

  secure_headscale_paths
  if [[ -f "$HEADSCALE_CONFIG" ]]; then
    cp -a "$HEADSCALE_CONFIG" "${HEADSCALE_CONFIG}.bak.$(date +%Y%m%d%H%M%S)"
  fi
  cat >"$HEADSCALE_CONFIG" <<EOF
server_url: ${server_url}
listen_addr: ${HEADSCALE_LISTEN_ADDR}
metrics_listen_addr: ${HEADSCALE_METRICS_ADDR}
grpc_listen_addr: ${HEADSCALE_GRPC_ADDR}
grpc_allow_insecure: false
trusted_proxies:
  - 127.0.0.1/32
  - ::1/128

noise:
  private_key_path: ${HEADSCALE_STATE_DIR}/noise_private.key

prefixes:
  v4: 100.64.0.0/10
  v6: fd7a:115c:a1e0::/48
allocation: sequential

derp:
  server:
    enabled: false
    region_id: 999
    region_code: "infiproxy"
    region_name: "Infiproxy Headscale"
    verify_clients: true
    stun_listen_addr: "0.0.0.0:3478"
    private_key_path: ${HEADSCALE_STATE_DIR}/derp_server_private.key
    automatically_add_embedded_derp_region: true
  urls:
    - https://controlplane.tailscale.com/derpmap/default
  paths: []
  auto_update_enabled: true
  update_frequency: 3h

disable_check_updates: false
node:
  expiry: 0
  ephemeral:
    inactivity_timeout: 30m
  routes:
    ha:
      probe_interval: 10s
      probe_timeout: 5s

database:
  type: sqlite
  sqlite:
    path: ${HEADSCALE_STATE_DIR}/db.sqlite
    write_ahead_log: true

tls_cert_path: ""
tls_key_path: ""

log:
  level: info
  format: text

policy:
  mode: file
  path: ""

dns:
  magic_dns: true
  base_domain: ${base_domain}
  override_local_dns: true
  nameservers:
    global:
      - 1.1.1.1
      - 1.0.0.1

unix_socket: /var/run/headscale/headscale.sock
unix_socket_permission: "0770"

logtail:
  enabled: false
taildrop:
  enabled: true
auto_update:
  enabled: false
EOF
  chown root:"$APP_GROUP" "$HEADSCALE_CONFIG" 2>/dev/null || true
  chmod 0660 "$HEADSCALE_CONFIG" 2>/dev/null || true

  if have_cmd headscale; then
    headscale_cmd configtest
  fi
  echo "${green}Headscale config written: ${HEADSCALE_CONFIG}${reset}"
}

# Serve Headscale through Nginx with WebSocket upgrade forwarding. Tailscale
# clients use a custom POST-based upgrade, so this site intentionally keeps the
# proxy rules explicit instead of sharing the simpler panel reverse proxy block.
write_headscale_nginx_config() {
  local domain="$1"

  need_root
  valid_domain "$domain" || { echo "${danger}Invalid Headscale domain: $domain${reset}" >&2; return 1; }
  install -d -m 0755 "$(dirname "$HEADSCALE_NGINX_SITE")"
  cat >"$HEADSCALE_NGINX_SITE" <<EOF
map \$http_upgrade \$headscale_connection_upgrade {
    default upgrade;
    '' close;
}

upstream infiproxy_headscale {
    server ${HEADSCALE_LISTEN_ADDR} max_fails=1 fail_timeout=5s;
    keepalive 2;
}

server {
    listen 80;
    listen [::]:80;
    server_name ${domain};

    location = /generate_204 {
        return 204;
    }

    location / {
        return 301 https://\$host\$request_uri;
    }
}

server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name ${domain};

    ssl_certificate /etc/letsencrypt/live/${domain}/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/${domain}/privkey.pem;

    add_header X-Frame-Options DENY always;
    add_header X-Content-Type-Options nosniff always;
    add_header Referrer-Policy no-referrer always;

    location / {
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection \$headscale_connection_upgrade;
        proxy_set_header Host \$host;
        proxy_set_header True-Client-IP \$remote_addr;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_buffering off;
        proxy_pass http://infiproxy_headscale;
    }
}
EOF
  install -d -m 0755 "$(dirname "$HEADSCALE_NGINX_ENABLED")"
  if [[ ! -e "$HEADSCALE_NGINX_ENABLED" ]]; then
    ln -s "$HEADSCALE_NGINX_SITE" "$HEADSCALE_NGINX_ENABLED"
  fi
  run_cmd nginx -t
  run_cmd systemctl reload nginx.service
}

# Full Headscale hub flow: DNS-only Cloudflare record, DNS-01 certificate,
# reverse proxy, verified binary install, config write and service start.
guided_headscale_setup() {
  local zone domain magic_domain email ip token stored_token install_answer proxied=false

  read -r -p "Headscale hostname (hs.example.com): " domain
  read -r -p "MagicDNS base domain [tailnet.${domain}]: " magic_domain
  magic_domain="${magic_domain:-tailnet.${domain}}"
  read -r -p "Cloudflare zone (example.com): " zone
  read -r -p "Let's Encrypt email: " email
  read -r -p "IPv4 [auto]: " ip
  if [[ -z "$ip" ]]; then
    ip="$(public_ip || true)"
  fi
  stored_token="$(cloudflare_token_from_file)"
  read -r -s -p "Cloudflare API token [stored if blank]: " token
  echo
  token="${token:-$stored_token}"

  echo "${muted}Headscale must not be proxied through Cloudflare; DNS-only A record will be used.${reset}"
  install_https_deps || return
  cloudflare_write_a_record "$token" "$zone" "$domain" "$ip" "$proxied" || return
  save_cloudflare_credentials "$token" || return
  issue_cloudflare_certificate "$domain" "$email" || return
  write_headscale_nginx_config "$domain" || return

  if have_cmd headscale; then
    confirm_yes "Headscale binary already exists. Reinstall/update from verified release?" "N" && install_answer=1 || install_answer=0
  else
    install_answer=1
  fi
  if [[ "$install_answer" -eq 1 ]]; then
    install_headscale_release || return
  fi

  write_headscale_config "https://${domain}" "$magic_domain" || return
  run_cmd systemctl enable --now "$HEADSCALE_SERVICE" || true
  run_cmd systemctl --no-pager --full status "$HEADSCALE_SERVICE" || true
  echo "${green}${bold}Headscale URL: https://${domain}${reset}"
  echo "Client command:"
  echo "  tailscale up --login-server https://${domain} --authkey <key>"
}

headscale_create_preauth_key() {
  local user expiration key

  require_cmd headscale || return 1
  read -r -p "Headscale user [admin]: " user
  user="${user:-admin}"
  valid_headscale_user "$user" || { echo "${danger}Invalid Headscale user: $user${reset}" >&2; return 1; }
  read -r -p "Key expiration [24h]: " expiration
  expiration="${expiration:-24h}"
  headscale_cmd users create "$user" 2>/dev/null || true
  key="$(headscale_cmd preauthkeys create --user "$user" --expiration "$expiration")"
  echo
  echo "${green}${bold}Pre-auth key:${reset}"
  echo "$key"
  echo
  echo "Client command:"
  echo "tailscale up --login-server <HEADSCALE_URL> --authkey ${key}"
}

headscale_menu() {
  need_root
  header
  echo "1) Guided Headscale hub setup"
  echo "2) Install/update Headscale release only"
  echo "3) Write Headscale config only"
  echo "4) Create user and pre-auth key"
  echo "5) List Headscale users"
  echo "6) Restart Headscale"
  echo "7) Headscale logs"
  echo "0) Back"
  read_menu_choice || return
  case "$choice" in
    1) guided_headscale_setup || true ;;
    2) install_headscale_release || true ;;
    3)
      read -r -p "Headscale URL (https://hs.example.com): " url
      read -r -p "MagicDNS base domain (tailnet.example.com): " base_domain
      write_headscale_config "$url" "$base_domain" || true
      ;;
    4) headscale_create_preauth_key || true ;;
    5) run_cmd headscale -c "$HEADSCALE_CONFIG" users list || true ;;
    6)
      headscale_cmd configtest || true
      run_cmd systemctl restart "$HEADSCALE_SERVICE" || true
      ;;
    7) run_cmd journalctl -u "$HEADSCALE_SERVICE" -n 120 --no-pager || true ;;
    0) return ;;
    *) invalid_choice; return ;;
  esac
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
  local token="$1"
  [[ -n "$token" ]] || { echo "${danger}Cloudflare API token is required.${reset}" >&2; return 1; }
  install -d -m 0700 -o root -g root "$(dirname "$CLOUDFLARE_CREDENTIALS")"
  printf 'dns_cloudflare_api_token = %s\n' "$token" >"$CLOUDFLARE_CREDENTIALS"
  chown root:root "$CLOUDFLARE_CREDENTIALS"
  chmod 0600 "$CLOUDFLARE_CREDENTIALS"
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

  need_root
  valid_domain "$domain" || { echo "${danger}Invalid domain: $domain${reset}" >&2; return 1; }
  install -d -m 0755 "$(dirname "$NGINX_SITE")"
  cat >"$NGINX_SITE" <<EOF
server {
    listen 443 ssl http2;
    server_name ${domain};

    ssl_certificate /etc/letsencrypt/live/${domain}/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/${domain}/privkey.pem;

    add_header X-Frame-Options DENY always;
    add_header X-Content-Type-Options nosniff always;
    add_header Referrer-Policy no-referrer always;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
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
  fi
  run_cmd nginx -t
  run_cmd systemctl reload nginx.service
}

guided_https_setup() {
  local zone domain email ip proxy_answer token proxied

  read -r -p "Cloudflare zone (example.com): " zone
  read -r -p "Panel hostname (panel.example.com): " domain
  read -r -p "Let's Encrypt email: " email
  read -r -p "IPv4 [auto]: " ip
  if [[ -z "$ip" ]]; then
    ip="$(public_ip || true)"
  fi
  read -r -p "Proxy through Cloudflare? [y/N]: " proxy_answer
  read -r -s -p "Cloudflare API token: " token
  echo
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
  header
  echo "1) Install HTTPS dependencies"
  echo "2) Upsert Cloudflare A record"
  echo "3) Issue certificate with Cloudflare DNS-01"
  echo "4) Write nginx HTTPS config"
  echo "5) Full guided setup"
  echo "0) Back"
  read_menu_choice || return
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
  header
  echo "${bold}Guided deployment cycle${reset}"
  echo "This path keeps everything inside one SSH TUI session:"
  echo "  1. install or repair the panel"
  echo "  2. optionally publish HTTPS through Cloudflare"
  echo "  3. optionally install current verified runtime modules"
  echo "  4. optionally configure Telegram MTProto"
  echo "  5. optionally configure Headscale mesh hub"
  echo "  6. show final service status"
  echo

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
    local module
    for module in xray sing-box hysteria tuic; do
      if confirm_yes "Install or update ${module}?" "N"; then
        "$MODULE_UPDATE_BIN" --update "$module" || {
          echo "${danger}${module} installation failed; see ${MODULE_UPDATE_LOG}.${reset}" >&2
        }
      fi
    done
  fi

  echo
  if confirm_yes "Configure Telegram MTProto module now?" "N"; then
    if [[ ! -x "$MTPROTO_BINARY" ]]; then
      echo "${muted}MTProto binary is not installed yet.${reset}"
      if confirm_yes "Build and install it from the latest official commit?" "Y"; then
        "$MODULE_UPDATE_BIN" --update mtproto || true
      fi
    fi
    guided_mtproto_setup || {
      echo "${danger}MTProto setup did not complete. You can rerun Telegram MTProto setup later.${reset}" >&2
    }
  fi

  echo
  if confirm_yes "Configure Headscale mesh hub now?" "N"; then
    guided_headscale_setup || {
      echo "${danger}Headscale setup did not complete. You can rerun Headscale hub setup later.${reset}" >&2
    }
  fi

  echo
  echo "${green}${bold}Guided deployment cycle complete.${reset}"
  echo "Open the panel:"
  echo "  HTTPS:      https://<your-domain>/admin/setup"
  echo "  SSH tunnel: http://127.0.0.1:8080/admin/setup"
  echo
  echo "${bold}Service summary${reset}"
  printf "%-34s %-12s %-12s\n" "unit" "active" "enabled"
  printf "%-34s %-12s %-12s\n" "----" "------" "-------"
  unit_state "$PANEL_SERVICE"
  for service in "${CORE_SERVICES[@]}"; do
    unit_state "$service"
  done
  unit_state "$HEADSCALE_SERVICE"
  pause
}

logs_menu() {
  while true; do
    header
    echo "1) Panel journal"
    echo "2) Module updater log"
    echo "3) Panel updater log"
    echo "4) Nginx journal"
    echo "5) Failed systemd units"
    echo "0) Back"
    read_menu_choice || return
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
  local domain
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
  echo "${bold}Local probes${reset}"
  curl -fsS --max-time 3 http://127.0.0.1:8080/health || true
  echo
  curl -fsS --max-time 3 http://127.0.0.1:8080/ready || true
  echo
  pause
}

select_module_runtime() {
  echo "1) xray"
  echo "2) sing-box"
  echo "3) hysteria"
  echo "4) tuic"
  echo "5) Telegram MTProto"
  echo "6) Headscale"
  echo "0) Back"
  read_menu_choice || return 1
  case "$choice" in
    1) module="xray" ;;
    2) module="sing-box" ;;
    3) module="hysteria" ;;
    4) module="tuic" ;;
    5) module="mtproto" ;;
    6) module="headscale" ;;
    0) return 2 ;;
    *) invalid_choice; return 1 ;;
  esac
}

module_update_menu() {
  need_root
  while true; do
    header
    echo "Runtime modules"
    echo
    echo "1) Show installed/latest status"
    echo "2) Check one module"
    echo "3) Install or update one module"
    echo "4) Restart module updater"
    echo "5) Show module updater log"
    echo "0) Back"
    read_menu_choice || return
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
      0) return ;;
      *) invalid_choice ;;
    esac
  done
}

panel_update_check() {
  local repo ref current latest
  repo="$(env_value "$UPDATE_CONFIG_FILE" REPO)"
  ref="$(env_value "$UPDATE_CONFIG_FILE" REF)"
  repo="${repo:-infinitrator/stealthhub-panel}"
  ref="${ref:-main}"
  [[ "$repo" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]] || return 1
  [[ "$ref" =~ ^[A-Za-z0-9_./-]+$ && "$ref" != *..* ]] || return 1
  current="$(git -C "$SOURCE_DIR" rev-parse HEAD 2>/dev/null || echo unknown)"
  latest="$(git ls-remote "https://github.com/${repo}.git" "$ref" | awk 'NR == 1 {print $1}')"
  echo "repository  ${repo}"
  echo "reference   ${ref}"
  echo "installed   ${current:0:12}"
  echo "latest      ${latest:0:12}"
  if [[ -n "$latest" && "$current" == "$latest" ]]; then
    echo "status      current"
  else
    echo "status      update available"
  fi
}

panel_update_menu() {
  while true; do
    header
    echo "Panel updater"
    echo
    systemctl --no-pager --full status infiproxy-panel-update.timer infiproxy-panel-update.path 2>/dev/null || true
    echo
    echo "1) Check GitHub now"
    echo "2) Update panel now"
    echo "3) Show updater log"
    echo "4) Restart update timer and path watcher"
    echo "0) Back"
    read_menu_choice || return
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
    header
    echo "1) Install or repair panel"
    echo "2) Telegram MTProto configuration"
    echo "3) Headscale hub configuration"
    echo "4) Manual verified archive import"
    echo "5) Toggle web danger shell"
    echo "0) Back"
    read_menu_choice || return
    case "$choice" in
      1) install_or_repair ;;
      2) mtproto_setup_menu ;;
      3) headscale_menu ;;
      4) core_helper ;;
      5) toggle_danger_shell ;;
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
systemctl disable --now infiproxy-module-update.timer infiproxy-module-update.path infiproxy-module-update.service || true
rm -f /etc/systemd/system/infiproxy.service
rm -f /etc/systemd/system/infiproxy-panel-update.service /etc/systemd/system/infiproxy-panel-update.timer /etc/systemd/system/infiproxy-panel-update.path
rm -f /etc/systemd/system/infiproxy-module-update.service /etc/systemd/system/infiproxy-module-update.timer /etc/systemd/system/infiproxy-module-update.path
systemctl daemon-reload
rm -f /usr/local/bin/infiproxy /usr/local/sbin/infiproxy-manager /usr/local/sbin/infiproxy-panel-update /usr/local/sbin/infiproxy-module-update /usr/local/sbin/infiproxy-core-install
rm -f /etc/profile.d/infiproxy-manager.sh
rm -f /etc/infiproxy-update.conf
rm -rf /etc/infiproxy /var/lib/infiproxy /var/lib/infiproxy-maintenance
userdel infiproxy 2>/dev/null || true
groupdel infiproxy 2>/dev/null || true
EOF
      ;;
    full)
      cat <<'EOF'
systemctl disable --now infiproxy.service infiproxy-panel-update.timer infiproxy-panel-update.path infiproxy-panel-update.service infiproxy-module-update.timer infiproxy-module-update.path infiproxy-module-update.service infiproxy-xray.service infiproxy-sing-box.service infiproxy-hysteria.service infiproxy-tuic.service infiproxy-mtproto.service headscale.service || true
rm -f /etc/systemd/system/infiproxy.service
rm -f /etc/systemd/system/infiproxy-panel-update.service /etc/systemd/system/infiproxy-panel-update.timer /etc/systemd/system/infiproxy-panel-update.path
rm -f /etc/systemd/system/infiproxy-module-update.service /etc/systemd/system/infiproxy-module-update.timer /etc/systemd/system/infiproxy-module-update.path
rm -f /etc/systemd/system/infiproxy-xray.service /etc/systemd/system/infiproxy-sing-box.service /etc/systemd/system/infiproxy-hysteria.service /etc/systemd/system/infiproxy-tuic.service /etc/systemd/system/infiproxy-mtproto.service
rm -f /etc/systemd/system/headscale.service
rm -f /etc/systemd/system/headscale.service.d/infiproxy-module.conf
rmdir /etc/systemd/system/headscale.service.d 2>/dev/null || true
systemctl daemon-reload
rm -f /usr/local/bin/infiproxy /usr/local/bin/headscale /usr/local/sbin/infiproxy-manager /usr/local/sbin/infiproxy-panel-update /usr/local/sbin/infiproxy-module-update /usr/local/sbin/infiproxy-core-install
rm -f /etc/profile.d/infiproxy-manager.sh
rm -f /etc/infiproxy-update.conf
rm -rf /etc/infiproxy /var/lib/infiproxy /var/lib/infiproxy-maintenance
rm -rf /etc/infiproxy-cores /opt/infiproxy/cores /opt/infiproxy/modules /var/log/infiproxy-cores
rm -rf /etc/headscale /var/lib/headscale
rm -rf /opt/infiproxy/source
rm -f /etc/nginx/sites-enabled/infiproxy.conf /etc/nginx/sites-available/infiproxy.conf
rm -f /etc/nginx/sites-enabled/infiproxy-headscale.conf /etc/nginx/sites-available/infiproxy-headscale.conf
nginx -t && systemctl reload nginx.service || true
userdel infiproxy 2>/dev/null || true
groupdel infiproxy 2>/dev/null || true
EOF
      ;;
    factory)
      cat <<'EOF'
systemctl disable --now infiproxy.service infiproxy-panel-update.timer infiproxy-panel-update.path infiproxy-panel-update.service infiproxy-module-update.timer infiproxy-module-update.path infiproxy-module-update.service infiproxy-xray.service infiproxy-sing-box.service infiproxy-hysteria.service infiproxy-tuic.service infiproxy-mtproto.service headscale.service || true
rm -f /etc/systemd/system/infiproxy.service
rm -f /etc/systemd/system/infiproxy-panel-update.service /etc/systemd/system/infiproxy-panel-update.timer /etc/systemd/system/infiproxy-panel-update.path
rm -f /etc/systemd/system/infiproxy-module-update.service /etc/systemd/system/infiproxy-module-update.timer /etc/systemd/system/infiproxy-module-update.path
rm -f /etc/systemd/system/infiproxy-xray.service /etc/systemd/system/infiproxy-sing-box.service /etc/systemd/system/infiproxy-hysteria.service /etc/systemd/system/infiproxy-tuic.service /etc/systemd/system/infiproxy-mtproto.service
rm -f /etc/systemd/system/headscale.service
rm -f /etc/systemd/system/headscale.service.d/infiproxy-module.conf
rmdir /etc/systemd/system/headscale.service.d 2>/dev/null || true
systemctl daemon-reload
rm -f /usr/local/bin/infiproxy /usr/local/sbin/infiproxy-manager /usr/local/sbin/infiproxy-panel-update /usr/local/sbin/infiproxy-module-update /usr/local/sbin/infiproxy-core-install
rm -f /etc/profile.d/infiproxy-manager.sh
rm -f /etc/infiproxy-update.conf
rm -rf /etc/infiproxy /var/lib/infiproxy /var/lib/infiproxy-maintenance
rm -rf /etc/infiproxy-cores /opt/infiproxy /var/log/infiproxy-cores
rm -rf /etc/headscale /var/lib/headscale
rm -f /usr/local/bin/headscale
rm -f /etc/nginx/sites-enabled/infiproxy.conf /etc/nginx/sites-available/infiproxy.conf
rm -f /etc/nginx/sites-enabled/infiproxy-headscale.conf /etc/nginx/sites-available/infiproxy-headscale.conf
nginx -t && systemctl reload nginx.service || true
userdel infiproxy 2>/dev/null || true
groupdel infiproxy 2>/dev/null || true
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
    header
    echo "1) Panel-only removal"
    echo "2) Full Infiproxy footprint removal"
    echo "3) Factory footprint cleanup"
    echo "0) Back"
    read_menu_choice || return
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
      10) advanced_menu ;;
      11) run_uninstall ;;
      0) exit 0 ;;
      *) invalid_choice ;;
    esac
  done
}

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
