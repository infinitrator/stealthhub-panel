# shellcheck shell=sh
# Infiproxy SSH manager launcher for interactive root login shells.
# Set INFIPROXY_TUI_AUTO=0 before login to bypass it for troubleshooting.
if [ "$(id -u)" -eq 0 ] \
  && [ -n "${SSH_TTY:-}" ] \
  && [ -t 0 ] \
  && [ -t 1 ] \
  && [ "${INFIPROXY_TUI_AUTO:-1}" != "0" ] \
  && [ -z "${INFIPROXY_TUI_ACTIVE:-}" ] \
  && [ -x /usr/local/sbin/infiproxy-manager ]; then
  export INFIPROXY_TUI_ACTIVE=1
  /usr/local/sbin/infiproxy-manager
  unset INFIPROXY_TUI_ACTIVE
fi
