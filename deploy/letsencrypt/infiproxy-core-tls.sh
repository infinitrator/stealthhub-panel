#!/usr/bin/env bash
# Portable Certbot deploy hook; --sync applies the current named lineage.
set -Eeuo pipefail
umask 077
TLS_DIR="/etc/infiproxy-cores/tls"
DOMAIN_FILE="/etc/infiproxy/core-tls-domain"
RUNTIME_GROUP=infiproxy-runtime
die() { echo "Infiproxy TLS: $*" >&2; exit 1; }
valid_domain() {
  [[ "$1" =~ ^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$ &&
     "$1" == *.* && "$1" != *..* && "${#1}" -le 253 &&
     "$1" != *.-* && "$1" != *-.* ]]
}
[[ "$(id -u)" -eq 0 ]] || die "requires root"
mode="${1:---deploy}"
[[ "$mode" == --sync || "$mode" == --deploy ]] || die "usage: --sync or --deploy"
if [[ ! -e "$DOMAIN_FILE" ]]; then
  [[ "$mode" == --deploy ]] && exit 0
  die "core TLS domain has not been configured"
fi
[[ -f "$DOMAIN_FILE" && ! -L "$DOMAIN_FILE" &&
   "$(stat -c %u:%a "$DOMAIN_FILE")" == 0:600 ]] || die "unsafe domain file"
[[ "$(wc -l < "$DOMAIN_FILE")" -eq 1 ]] || die "invalid domain file"
IFS= read -r domain < "$DOMAIN_FILE" || die "empty domain file"
valid_domain "$domain" || die "invalid core TLS domain"
lineage="/etc/letsencrypt/live/$domain"
if [[ "$mode" == --deploy ]]; then
  [[ "${RENEWED_LINEAGE:-}" == "$lineage" ]] || exit 0
fi
[[ -r "$lineage/fullchain.pem" && -r "$lineage/privkey.pem" ]] ||
  die "named certificate lineage is missing"
getent group "$RUNTIME_GROUP" >/dev/null || die "runtime group is missing"
install -d -o root -g "$RUNTIME_GROUP" -m 0750 "$TLS_DIR"
exec 9>/run/lock/infiproxy-core-tls.lock
flock -x 9
stage="$(mktemp -d "$TLS_DIR/.release.XXXXXXXX")"
next=""
cleanup() {
  [[ -z "$next" ]] || rm -f -- "$next"
  [[ -z "$stage" ]] || rm -rf -- "$stage"
}
trap cleanup EXIT
chown root:"$RUNTIME_GROUP" "$stage"
chmod 0750 "$stage"
install -o root -g "$RUNTIME_GROUP" -m 0640 "$lineage/fullchain.pem" "$stage/fullchain.pem"
install -o root -g "$RUNTIME_GROUP" -m 0640 "$lineage/privkey.pem" "$stage/privkey.pem"
openssl x509 -in "$stage/fullchain.pem" -checkend 86400 -noout >/dev/null ||
  die "certificate is expired or invalid"
openssl x509 -in "$stage/fullchain.pem" -checkhost "$domain" -noout >/dev/null ||
  die "certificate does not cover $domain"
openssl x509 -in "$stage/fullchain.pem" -pubkey -noout > "$stage/cert.pub" ||
  die "invalid certificate key"
openssl pkey -pubin -in "$stage/cert.pub" -outform DER -out "$stage/cert.der" 2>/dev/null ||
  die "invalid certificate public key"
openssl pkey -in "$stage/privkey.pem" -pubout -outform DER -out "$stage/key.der" 2>/dev/null ||
  die "invalid private key"
cmp -s "$stage/cert.der" "$stage/key.der" || die "certificate/private key mismatch"
rm -f "$stage/cert.pub" "$stage/cert.der" "$stage/key.der"

cert="$TLS_DIR/fullchain.pem"
key="$TLS_DIR/privkey.pem"
if [[ -L "$cert" || -L "$key" ]]; then
  [[ -L "$cert" && -L "$key" &&
     "$(readlink "$cert")" == current/fullchain.pem &&
     "$(readlink "$key")" == current/privkey.pem ]] || die "unsafe TLS link layout"
  [[ -L "$TLS_DIR/current" ]] || die "missing current release"
elif [[ -e "$cert" || -e "$key" ]]; then
  [[ -f "$cert" && -f "$key" && ! -L "$cert" && ! -L "$key" &&
     ! -e "$TLS_DIR/current" && ! -L "$TLS_DIR/current" ]] ||
    die "incomplete legacy TLS pair"
  legacy="$(mktemp -d "$TLS_DIR/.release.legacy.XXXXXXXX")"
  chown root:"$RUNTIME_GROUP" "$legacy"
  chmod 0750 "$legacy"
  install -o root -g "$RUNTIME_GROUP" -m 0640 "$cert" "$legacy/fullchain.pem"
  install -o root -g "$RUNTIME_GROUP" -m 0640 "$key" "$legacy/privkey.pem"
  ln -s "$(basename "$legacy")" "$TLS_DIR/current"
  ln -s current/fullchain.pem "$TLS_DIR/.fullchain.new"
  ln -s current/privkey.pem "$TLS_DIR/.privkey.new"
  mv -Tf "$TLS_DIR/.fullchain.new" "$cert"
  mv -Tf "$TLS_DIR/.privkey.new" "$key"
else
  [[ ! -e "$TLS_DIR/current" && ! -L "$TLS_DIR/current" ]] ||
    die "unexpected current release"
  ln -s "$(basename "$stage")" "$TLS_DIR/current"
  ln -s current/fullchain.pem "$cert"
  ln -s current/privkey.pem "$key"
fi
old="$(readlink "$TLS_DIR/current")"
[[ "$old" == .release.* && "$old" != */* &&
   -f "$TLS_DIR/$old/fullchain.pem" && -f "$TLS_DIR/$old/privkey.pem" ]] ||
  die "unsafe current release target"
if cmp -s "$cert" "$stage/fullchain.pem" &&
   cmp -s "$key" "$stage/privkey.pem"; then
  echo "Infiproxy TLS unchanged: $domain"
  exit 0
fi
next="$TLS_DIR/.current.$$.new"
ln -s "$(basename "$stage")" "$next"
mv -Tf "$next" "$TLS_DIR/current"
next=""
stage=""
restart_active() {
  local failed=0 unit
  for unit in infiproxy-xray.service infiproxy-sing-box.service \
              infiproxy-hysteria.service infiproxy-tuic.service infiproxy-mihomo.service; do
    if systemctl is-active --quiet "$unit"; then
      systemctl restart "$unit" || failed=1
    fi
  done
  return "$failed"
}
rollback() {
  ln -s "$old" "$TLS_DIR/.current.$$.rollback"
  mv -Tf "$TLS_DIR/.current.$$.rollback" "$TLS_DIR/current"
}
if [[ -x /usr/local/libexec/infiproxy-reconcile ]] &&
   ! /usr/local/libexec/infiproxy-reconcile --publish-tls-readiness; then
  rollback
  die "TLS readiness failed: previous pair restored"
fi
if ! restart_active; then
  rollback
  restart_active || true
  if [[ -x /usr/local/libexec/infiproxy-reconcile ]]; then
    /usr/local/libexec/infiproxy-reconcile --publish-tls-readiness || true
  fi
  die "runtime restart failed: previous pair restored"
fi
echo "Infiproxy TLS updated for $domain"
