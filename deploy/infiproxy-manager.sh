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
NGINX_SITE="${INFIPROXY_NGINX_SITE:-/etc/nginx/sites-available/infiproxy.conf}"
NGINX_ENABLED="${INFIPROXY_NGINX_ENABLED:-/etc/nginx/sites-enabled/infiproxy.conf}"
CLOUDFLARE_CREDENTIALS="${INFIPROXY_CF_CREDENTIALS:-/etc/letsencrypt/cloudflare.ini}"
CF_API="https://api.cloudflare.com/client/v4"
CORE_SERVICES=(
  "infiproxy-xray.service"
  "infiproxy-sing-box.service"
  "infiproxy-hysteria.service"
  "infiproxy-tuic.service"
)

green=$'\033[38;5;71m'
soft=$'\033[38;5;250m'
muted=$'\033[38;5;245m'
danger=$'\033[38;5;167m'
reset=$'\033[0m'
bold=$'\033[1m'

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

header() {
  clear 2>/dev/null || true
  echo "${green}${bold}+--------------------------------------------+${reset}"
  echo "${green}${bold}| ${APP} manager                             |${reset}"
  echo "${green}${bold}+--------------------------------------------+${reset}"
  echo "${muted}systemd / bare-metal / KISS control surface${reset}"
  echo
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

public_ip() {
  curl -fsSL --max-time 10 https://api.ipify.org
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
  [[ "$ip" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]] || { echo "${danger}Invalid IPv4: $ip${reset}" >&2; return 1; }

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
  printf "%-34s %-12s %-12s\n" "unit" "active" "enabled"
  printf "%-34s %-12s %-12s\n" "----" "------" "-------"
  unit_state "$PANEL_SERVICE"
  for service in "${CORE_SERVICES[@]}"; do
    unit_state "$service"
  done
  pause
}

restart_menu() {
  header
  echo "1) Restart panel"
  echo "2) Reload nginx"
  echo "3) Validate and reload SSH"
  echo "4) Restart all enabled core services"
  echo "5) Reboot server"
  echo "0) Back"
  read -r -p "> " choice
  case "$choice" in
    1) need_root; run_cmd systemctl restart "$PANEL_SERVICE" ;;
    2)
      need_root
      if command -v nginx >/dev/null 2>&1; then
        run_cmd nginx -t && run_cmd systemctl reload nginx.service
      else
        echo "${danger}nginx is not installed.${reset}"
      fi
      ;;
    3)
      need_root
      if command -v sshd >/dev/null 2>&1; then
        run_cmd sshd -t && (run_cmd systemctl reload ssh.service || run_cmd systemctl reload sshd.service)
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
      read -r -p "Type REBOOT to reboot this server: " confirm
      [[ "$confirm" == "REBOOT" ]] && run_cmd systemctl reboot
      ;;
    0) return ;;
  esac
  pause
}

edit_env() {
  need_root
  header
  secure_env_file
  "$(pick_editor)" "$ENV_FILE"
  secure_env_file
  run_cmd systemctl restart "$PANEL_SERVICE"
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
  run_cmd systemctl restart "$PANEL_SERVICE"
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
  read -r -p "> " choice
  case "$choice" in
    1) bash "${SOURCE_DIR}/deploy/install.sh" --build ;;
    2) bash "${SOURCE_DIR}/deploy/install.sh" --build --with-nginx ;;
    3) bash "${SOURCE_DIR}/deploy/install.sh" --build --force-env ;;
    0) return ;;
  esac
  pause
}

core_helper() {
  need_root
  header
  if [[ ! -x "${SOURCE_DIR}/deploy/cores/install-core.sh" ]]; then
    echo "${danger}Core installer not found at ${SOURCE_DIR}/deploy/cores/install-core.sh${reset}"
    pause
    return
  fi
  echo "1) xray"
  echo "2) sing-box"
  echo "3) hysteria"
  echo "4) tuic"
  echo "0) Back"
  read -r -p "> " choice
  case "$choice" in
    1) core="xray"; binary="xray"; service="infiproxy-xray.service" ;;
    2) core="sing-box"; binary="sing-box"; service="infiproxy-sing-box.service" ;;
    3) core="hysteria"; binary="hysteria"; service="infiproxy-hysteria.service" ;;
    4) core="tuic"; binary="tuic-server"; service="infiproxy-tuic.service" ;;
    0) return ;;
    *) return ;;
  esac
  read -r -p "Version: " version
  read -r -p "Release archive URL: " url
  read -r -p "SHA256: " sha256
  if [[ -z "$version" || -z "$url" || -z "$sha256" ]]; then
    echo "${danger}Version, URL and SHA256 are required.${reset}"
    pause
    return
  fi
  bash "${SOURCE_DIR}/deploy/cores/install-core.sh" \
    --core "$core" \
    --version "$version" \
    --url "$url" \
    --sha256 "$sha256" \
    --binary "$binary" \
    --restart "$service"
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

https_setup_menu() {
  need_root
  header
  echo "1) Install HTTPS dependencies"
  echo "2) Upsert Cloudflare A record"
  echo "3) Issue certificate with Cloudflare DNS-01"
  echo "4) Write nginx HTTPS config"
  echo "5) Full guided setup"
  echo "0) Back"
  read -r -p "> " choice
  case "$choice" in
    1)
      install_https_deps
      ;;
    2)
      read -r -p "Cloudflare zone (example.com): " zone
      read -r -p "Panel hostname (panel.example.com): " domain
      read -r -p "IPv4 [auto]: " ip
      if [[ -z "$ip" ]]; then
        ip="$(public_ip)"
      fi
      read -r -p "Proxy through Cloudflare? [y/N]: " proxy_answer
      read -r -s -p "Cloudflare API token: " token
      echo
      proxied=false
      [[ "$proxy_answer" =~ ^[Yy]$ ]] && proxied=true
      cloudflare_write_a_record "$token" "$zone" "$domain" "$ip" "$proxied"
      ;;
    3)
      read -r -p "Panel hostname: " domain
      read -r -p "Let's Encrypt email: " email
      read -r -s -p "Cloudflare API token (stored in ${CLOUDFLARE_CREDENTIALS}): " token
      echo
      save_cloudflare_credentials "$token"
      issue_cloudflare_certificate "$domain" "$email"
      ;;
    4)
      read -r -p "Panel hostname: " domain
      write_nginx_https_config "$domain"
      echo "${green}Secure panel URL: https://${domain}/admin/setup${reset}"
      ;;
    5)
      read -r -p "Cloudflare zone (example.com): " zone
      read -r -p "Panel hostname (panel.example.com): " domain
      read -r -p "Let's Encrypt email: " email
      read -r -p "IPv4 [auto]: " ip
      if [[ -z "$ip" ]]; then
        ip="$(public_ip)"
      fi
      read -r -p "Proxy through Cloudflare? [y/N]: " proxy_answer
      read -r -s -p "Cloudflare API token: " token
      echo
      proxied=false
      [[ "$proxy_answer" =~ ^[Yy]$ ]] && proxied=true
      install_https_deps
      cloudflare_write_a_record "$token" "$zone" "$domain" "$ip" "$proxied"
      save_cloudflare_credentials "$token"
      issue_cloudflare_certificate "$domain" "$email"
      write_nginx_https_config "$domain"
      echo
      echo "${green}${bold}Secure panel URL: https://${domain}/admin/setup${reset}"
      ;;
    0) return ;;
  esac
  pause
}

logs_menu() {
  header
  run_cmd journalctl -u "$PANEL_SERVICE" -n 120 --no-pager || true
  pause
}

uninstall_commands() {
  case "$1" in
    panel)
      cat <<'EOF'
systemctl disable --now infiproxy.service || true
rm -f /etc/systemd/system/infiproxy.service
systemctl daemon-reload
rm -f /usr/local/bin/infiproxy
rm -rf /etc/infiproxy /var/lib/infiproxy
userdel infiproxy 2>/dev/null || true
groupdel infiproxy 2>/dev/null || true
EOF
      ;;
    full)
      cat <<'EOF'
systemctl disable --now infiproxy.service infiproxy-xray.service infiproxy-sing-box.service infiproxy-hysteria.service infiproxy-tuic.service || true
rm -f /etc/systemd/system/infiproxy.service
rm -f /etc/systemd/system/infiproxy-xray.service /etc/systemd/system/infiproxy-sing-box.service /etc/systemd/system/infiproxy-hysteria.service /etc/systemd/system/infiproxy-tuic.service
systemctl daemon-reload
rm -f /usr/local/bin/infiproxy
rm -rf /etc/infiproxy /var/lib/infiproxy
rm -rf /etc/infiproxy-cores /opt/infiproxy/cores /var/log/infiproxy-cores
rm -rf /opt/infiproxy/source
rm -f /etc/nginx/sites-enabled/infiproxy.conf /etc/nginx/sites-available/infiproxy.conf
nginx -t && systemctl reload nginx.service || true
userdel infiproxy 2>/dev/null || true
groupdel infiproxy 2>/dev/null || true
EOF
      ;;
    factory)
      cat <<'EOF'
systemctl disable --now infiproxy.service infiproxy-xray.service infiproxy-sing-box.service infiproxy-hysteria.service infiproxy-tuic.service || true
rm -f /etc/systemd/system/infiproxy.service
rm -f /etc/systemd/system/infiproxy-xray.service /etc/systemd/system/infiproxy-sing-box.service /etc/systemd/system/infiproxy-hysteria.service /etc/systemd/system/infiproxy-tuic.service
systemctl daemon-reload
rm -f /usr/local/bin/infiproxy /usr/local/sbin/infiproxy-manager
rm -rf /etc/infiproxy /var/lib/infiproxy
rm -rf /etc/infiproxy-cores /opt/infiproxy /var/log/infiproxy-cores
rm -f /etc/nginx/sites-enabled/infiproxy.conf /etc/nginx/sites-available/infiproxy.conf
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
    read -r -p "> " choice
    case "$choice" in
      1) mode="panel" ;;
      2) mode="full" ;;
      3) mode="factory" ;;
      0) return ;;
      *) return ;;
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
  while true; do
    header
    echo "1) Status dashboard"
    echo "2) Restart / reload services"
    echo "3) Edit panel environment"
    echo "4) Toggle web danger shell"
    echo "5) HTTPS / Cloudflare setup"
    echo "6) Install / repair panel"
    echo "7) Core installer helper"
    echo "8) Panel logs"
    echo "${danger}9) Uninstall / cleanup${reset}"
    echo "0) Exit"
    read -r -p "> " choice
    case "$choice" in
      1) service_status ;;
      2) restart_menu ;;
      3) edit_env ;;
      4) toggle_danger_shell ;;
      5) https_setup_menu ;;
      6) install_or_repair ;;
      7) core_helper ;;
      8) logs_menu ;;
      9) run_uninstall ;;
      0) exit 0 ;;
    esac
  done
}

case "${1:-}" in
  --uninstall)
    run_uninstall "${2:-}"
    ;;
  --help|-h)
    echo "Usage: sudo infiproxy-manager [--uninstall panel|full|factory]"
    ;;
  *)
    main_menu
    ;;
esac
