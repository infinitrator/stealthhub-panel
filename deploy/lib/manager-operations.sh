#!/usr/bin/env bash
# Finite noninteractive operations for the compiled SSH TUI. This file is
# sourced by the root manager; no argument is evaluated as shell code.

manager_confirm() {
  [[ "$1" == "$2" ]] || { echo 'Exact operation confirmation required.' >&2; return 1; }
}

manager_module_service() {
  local id="$1" record
  [[ "$id" =~ ^[a-z][a-z0-9-]{0,31}$ ]] || return 1
  record="$("$MODULE_MANIFEST_HELPER" read "$MODULE_MANIFEST_DIR/$id.module" --root-owned)" || return 1
  printf '%s\n' "$record" | cut -d'|' -f11
}

manager_known_service() {
  case "$1" in
    infiproxy.service|infiproxy-reconcile.service|infiproxy-panel-update.service|infiproxy-module-update.service|nginx.service|ssh.service) return 0 ;;
  esac
  local service
  while IFS= read -r service; do [[ "$service" != "$1" ]] || return 0; done < <(registered_services)
  return 1
}

manager_operation() {
  local operation="${1:-}" service token
  [[ $# -ge 1 ]] || return 2
  shift
  need_root
  case "$operation" in
    diagnostics)
      [[ $# -eq 0 ]] || return 2
      systemctl show infiproxy.service --property=ActiveState,SubState --no-pager
      curl --noproxy '*' -fsS --max-time 3 http://127.0.0.1:8080/health
      curl --noproxy '*' -fsS --max-time 3 http://127.0.0.1:8080/ready
      ;;
    failed-units) [[ $# -eq 0 ]] || return 2; systemctl --failed --no-pager --full ;;
    disk) [[ $# -eq 0 ]] || return 2; df -h / /var/lib/infiproxy ;;
    listeners) [[ $# -eq 0 ]] || return 2; ss -lntu ;;
    logs)
      [[ $# -eq 1 ]] || return 2
      manager_known_service "$1" || return 2
      journalctl -u "$1" -n 120 --no-pager --output=short-iso
      ;;
    update-check) [[ $# -eq 0 ]] || return 2; panel_update_check ;;
    update-apply)
      [[ $# -eq 1 ]] || return 2; manager_confirm "$1" APPLY || return 2
      install -m 0640 -o root -g root /dev/null "$PANEL_UPDATE_REQUEST"
      systemctl start --no-block infiproxy-panel-update.service
      echo 'Requested. The root updater verifies and publishes the applied SHA after readiness.'
      ;;
    update-timer)
      [[ $# -eq 1 ]] || return 2; manager_confirm "$1" APPLY || return 2
      systemctl daemon-reload
      systemctl enable --now infiproxy-panel-update.timer infiproxy-panel-update.path
      ;;
    module-check) [[ $# -eq 1 ]] || return 2; manager_module_service "$1" >/dev/null || return 2; "$MODULE_UPDATE_BIN" --check "$1" ;;
    module-update)
      [[ $# -eq 2 ]] || return 2; [[ "$2" == APPLY || "$2" == INSTALL ]] || return 2
      manager_module_service "$1" >/dev/null || return 2
      "$MODULE_UPDATE_BIN" --update "$1"
      ;;
    module-start|module-stop|module-restart)
      [[ $# -eq 2 ]] || return 2
      if [[ "$operation" == module-stop ]]; then manager_confirm "$2" STOP || return 2; else manager_confirm "$2" APPLY || return 2; fi
      service="$(manager_module_service "$1")" || return 2
      systemctl "${operation#module-}" "$service"
      ;;
    module-remove)
      [[ $# -eq 2 ]] || return 2; manager_confirm "$2" REMOVE || return 2
      manager_module_service "$1" >/dev/null || return 2
      write_module_request "$1" remove
      systemctl start --no-block infiproxy-module-update.service
      echo 'Removal requested. Refresh the registry to verify completion.'
      ;;
    reconcile|panel-restart|nginx-reload|ssh-reload|modules-restart)
      [[ $# -eq 1 ]] || return 2; manager_confirm "$1" APPLY || return 2
      case "$operation" in
        reconcile) systemctl start --no-block infiproxy-reconcile.service; echo 'Reconciliation requested.' ;;
        panel-restart) systemctl restart infiproxy.service ;;
        nginx-reload) nginx -t && systemctl reload nginx.service ;;
        ssh-reload) sshd -t && systemctl reload ssh.service ;;
        modules-restart)
          while IFS= read -r service; do
            if systemctl is-enabled --quiet "$service"; then systemctl restart "$service" || return 1; fi
          done < <(registered_services)
          ;;
      esac
      ;;
    secret-store)
      [[ $# -eq 2 ]] || return 2; manager_confirm "$2" STORE || return 2
      valid_secret_reference "$1" || return 2
      store_privileged_secret "$1"
      ;;
    secret-delete)
      [[ $# -eq 2 ]] || return 2; manager_confirm "$2" DELETE || return 2
      valid_secret_reference "$1" || return 2
      delete_privileged_secret "$1"
      ;;
    secret-adopt)
      [[ $# -eq 2 ]] || return 2; manager_confirm "$2" ADOPT || return 2
      valid_secret_reference "$1" || return 2
      "$RECONCILE_HELPER" --adopt-server-secret "$1"
      systemctl start --no-block infiproxy-reconcile.service
      ;;
    https-deps) [[ $# -eq 1 ]] || return 2; manager_confirm "$1" INSTALL || return 2; install_https_deps ;;
    https-setup)
      [[ $# -eq 5 ]] || return 2; manager_confirm "$5" HTTPS || return 2
      valid_domain "$1" && valid_domain "$2" && valid_ipv4 "$4" || return 2
      [[ "$2" == "$1" || "$2" == *."$1" ]] || return 2
      [[ "$3" =~ ^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$ ]] || return 2
      IFS= read -r token || return 2
      valid_cloudflare_token "$token" || return 2
      install_https_deps || return 1
      cloudflare_write_a_record "$token" "$1" "$2" "$4" false || return 1
      save_cloudflare_credentials "$token" || return 1
      unset token
      issue_cloudflare_certificate "$2" "$3" || return 1
      write_nginx_https_config "$2" || return 1
      systemctl enable --now certbot.timer
      ;;
    https-renew) [[ $# -eq 1 ]] || return 2; manager_confirm "$1" RENEW || return 2; certbot renew --non-interactive && nginx -t && systemctl reload nginx.service ;;
    repair) [[ $# -eq 1 ]] || return 2; manager_confirm "$1" INSTALL || return 2; run_panel_install_from_source 0 0 ;;
    uninstall-preview)
      [[ $# -eq 1 ]] || return 2
      uninstall_commands "$1"
      ;;
    uninstall)
      [[ $# -eq 2 ]] || return 2; manager_confirm "$2" 'DELETE INFIPROXY' || return 2
      [[ "$1" == panel || "$1" == full || "$1" == factory ]] || return 2
      printf '%s\n' "$2" | run_uninstall "$1"
      ;;
    reboot) [[ $# -eq 1 ]] || return 2; manager_confirm "$1" REBOOT || return 2; systemctl reboot ;;
    *) echo 'Unsupported manager operation.' >&2; return 2 ;;
  esac
}
