#!/usr/bin/env bash
# Reload nginx after any Certbot renewal if it is currently active.
set -Eeuo pipefail
[[ "$(id -u)" -eq 0 ]] || { echo "Infiproxy nginx hook requires root" >&2; exit 1; }
[[ -n "${RENEWED_LINEAGE:-}" ]] || exit 0
if systemctl is-active --quiet nginx.service; then
  /usr/sbin/nginx -t
  /usr/bin/systemctl reload nginx.service
fi
