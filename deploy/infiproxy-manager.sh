#!/usr/bin/env bash
set -Eeuo pipefail

APP="Infiproxy"
ENV_FILE="${INFIPROXY_ENV_FILE:-/etc/infiproxy/infiproxy.env}"
SOURCE_DIR="${INFIPROXY_SRC_DIR:-/opt/infiproxy/source}"
PANEL_SERVICE="infiproxy.service"
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

need_root() {
  if [[ "${EUID}" -ne 0 ]]; then
    echo "${danger}Run as root: sudo infiproxy-manager${reset}" >&2
    exit 1
  fi
}

pause() {
  echo
  read -r -p "${muted}Press Enter to continue...${reset}" _
}

header() {
  clear
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

service_status() {
  header
  run_cmd systemctl --no-pager --full status "$PANEL_SERVICE" || true
  for service in "${CORE_SERVICES[@]}"; do
    echo
    run_cmd systemctl --no-pager --full status "$service" || true
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
    2) need_root; run_cmd nginx -t && run_cmd systemctl reload nginx.service ;;
    3) need_root; run_cmd sshd -t && (run_cmd systemctl reload ssh.service || run_cmd systemctl reload sshd.service) ;;
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
  install -d -m 0755 "$(dirname "$ENV_FILE")"
  touch "$ENV_FILE"
  "${EDITOR:-nano}" "$ENV_FILE"
  run_cmd systemctl restart "$PANEL_SERVICE"
  pause
}

toggle_danger_shell() {
  need_root
  header
  install -d -m 0755 "$(dirname "$ENV_FILE")"
  touch "$ENV_FILE"
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
  echo "This helper opens the verified core installer. Prepare URL, version and sha256 first."
  echo "Example:"
  echo "  sudo ${SOURCE_DIR}/deploy/cores/install-core.sh --core xray --version <ver> --url <url> --sha256 <sha256> --binary xray --restart infiproxy-xray.service"
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
    echo "5) Install / repair panel"
    echo "6) Core installer helper"
    echo "7) Panel logs"
    echo "${danger}8) Uninstall / cleanup${reset}"
    echo "0) Exit"
    read -r -p "> " choice
    case "$choice" in
      1) service_status ;;
      2) restart_menu ;;
      3) edit_env ;;
      4) toggle_danger_shell ;;
      5) install_or_repair ;;
      6) core_helper ;;
      7) logs_menu ;;
      8) run_uninstall ;;
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
