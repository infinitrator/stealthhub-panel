#!/usr/bin/env bash
# End-to-end HTTP smoke test for the unprivileged control plane.
set -euo pipefail
umask 077

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PANEL_BIN="${INFIPROXY_SMOKE_BIN:-${ROOT_DIR}/target/debug/stealthhub-panel}"
PORT="${INFIPROXY_SMOKE_PORT:-18765}"
BASE_URL="http://127.0.0.1:${PORT}"
SETUP_TOKEN="$(printf '%064x' "$$")"
OLD_PASSWORD='Correct-Horse-Battery-1!'
NEW_PASSWORD='Rotated-Horse-Battery-2!'
TMP_DIR="$(mktemp -d)"
COOKIE_JAR="${TMP_DIR}/cookies.txt"
BODY_FILE="${TMP_DIR}/body"
HEADER_FILE="${TMP_DIR}/headers"
LOG_FILE="${TMP_DIR}/panel.log"
PANEL_PID=""

fail() {
    printf 'HTTP smoke test failed: %s\n' "$*" >&2
    if [[ -f "$LOG_FILE" ]]; then
        printf '%s\n' '--- panel log ---' >&2
        tail -n 80 "$LOG_FILE" >&2 || true
    fi
    if [[ -f "$BODY_FILE" ]]; then
        printf '%s\n' '--- response body (first 2 KiB) ---' >&2
        head -c 2048 "$BODY_FILE" >&2 || true
        printf '\n' >&2
    fi
    exit 1
}

cleanup() {
    if [[ -n "$PANEL_PID" ]]; then
        kill "$PANEL_PID" 2>/dev/null || true
        wait "$PANEL_PID" 2>/dev/null || true
    fi
    rm -rf "$TMP_DIR"
}
trap cleanup EXIT

request() {
    local expected="$1"
    local path="$2"
    local actual
    shift 2

    : >"$BODY_FILE"
    : >"$HEADER_FILE"
    actual="$(curl --silent --show-error \
        --cookie "$COOKIE_JAR" --cookie-jar "$COOKIE_JAR" \
        --dump-header "$HEADER_FILE" --output "$BODY_FILE" \
        --write-out '%{http_code}' "$@" "${BASE_URL}${path}")" \
        || fail "curl failed for ${path}"
    [[ "$actual" == "$expected" ]] \
        || fail "${path}: expected HTTP ${expected}, received ${actual}"
}

body_contains() {
    grep -Fq "$1" "$BODY_FILE" || fail "response does not contain: $1"
}

body_excludes() {
    if grep -Fq "$1" "$BODY_FILE"; then
        fail "response unexpectedly contains: $1"
    fi
}

csrf_from_body() {
    local value
    value="$(grep -oE 'name="csrf_token" value="[A-Za-z0-9_-]+"' "$BODY_FILE" \
        | sed -n '1p' | cut -d'"' -f4)"
    [[ -n "$value" ]] || fail "CSRF token was not rendered"
    printf '%s' "$value"
}

subscription_token_from_body() {
    local value
    value="$(grep -oE '/sub/[A-Za-z0-9_-]+/mihomo\.yaml' "$BODY_FILE" \
        | sed -n '1p' | cut -d/ -f3)"
    [[ -n "$value" ]] || fail "subscription token was not rendered"
    printf '%s' "$value"
}

[[ -x "$PANEL_BIN" ]] || fail "panel binary is missing: ${PANEL_BIN}"
if curl --silent --fail --max-time 1 "${BASE_URL}/health" >/dev/null 2>&1; then
    fail "test port ${PORT} is already in use"
fi
touch "$COOKIE_JAR"

INFIPROXY_BIND="127.0.0.1:${PORT}" \
INFIPROXY_DB="sqlite://${TMP_DIR}/panel.sqlite?mode=rwc" \
INFIPROXY_DB_MAX_CONNECTIONS=2 \
INFIPROXY_COOKIE_SECURE=false \
INFIPROXY_SETUP_TOKEN="$SETUP_TOKEN" \
INFIPROXY_PANEL_UPDATE_STATE="${TMP_DIR}/panel-update-state.env" \
INFIPROXY_PANEL_UPDATE_REQUEST="${TMP_DIR}/panel-update-now.request" \
INFIPROXY_UPDATE_CONFIG_FILE="${TMP_DIR}/update.conf" \
INFIPROXY_MODULE_MANIFEST_DIR="${ROOT_DIR}/deploy/modules.d" \
INFIPROXY_MODULE_AVAILABLE_DIR="${ROOT_DIR}/deploy/modules.d" \
INFIPROXY_MODULE_STATE_DIR="${TMP_DIR}/module-state" \
INFIPROXY_MODULE_REQUEST_DIR="${TMP_DIR}/module-requests" \
INFIPROXY_MODULE_VERSION_DIR="${TMP_DIR}/module-versions" \
RUST_LOG=warn \
"$PANEL_BIN" >"$LOG_FILE" 2>&1 &
PANEL_PID="$!"

for _ in {1..100}; do
    if curl --silent --fail --max-time 1 "${BASE_URL}/health" >/dev/null 2>&1; then
        break
    fi
    kill -0 "$PANEL_PID" 2>/dev/null || fail "panel exited during startup"
    sleep 0.1
done

request 200 /health
[[ "$(cat "$BODY_FILE")" == "ok" ]] || fail "health body is not minimal"
request 200 /ready
[[ "$(cat "$BODY_FILE")" == "ready" ]] || fail "readiness body is not minimal"
request 200 /assets/panel.css
grep -Fqi 'content-type: text/css' "$HEADER_FILE" || fail "CSS content type is missing"
body_contains ':root'

request 200 /admin/setup
body_contains 'Initial admin setup'
request 403 /admin/setup --request POST \
    --data-urlencode setup_token=wrong \
    --data-urlencode username=owner \
    --data-urlencode password="$OLD_PASSWORD" \
    --data-urlencode password_confirm="$OLD_PASSWORD"
request 303 /admin/setup --request POST \
    --data-urlencode setup_token="$SETUP_TOKEN" \
    --data-urlencode username=owner \
    --data-urlencode password="$OLD_PASSWORD" \
    --data-urlencode password_confirm="$OLD_PASSWORD"
grep -Fqi 'location: /admin' "$HEADER_FILE" || fail "setup redirect is incorrect"
grep -Fqi 'set-cookie: infiproxy_admin_session=' "$HEADER_FILE" \
    || fail "admin session cookie is missing"
grep -Fqi 'path=/admin' "$HEADER_FILE" || fail "session cookie path is too broad"
grep -Fqi 'httponly' "$HEADER_FILE" || fail "session cookie is not HttpOnly"
grep -Fqi 'samesite=lax' "$HEADER_FILE" || fail "session cookie SameSite policy is missing"

request 200 /admin
grep -Fqi "content-security-policy: default-src 'none'; style-src 'self';" "$HEADER_FILE" \
    || fail "strict CSP is missing"
if grep -Fqi "unsafe-inline" "$HEADER_FILE"; then
    fail "CSP still permits unsafe inline styles"
fi
grep -Fqi 'cache-control: no-store' "$HEADER_FILE" || fail "admin cache policy is missing"
CSRF_TOKEN="$(csrf_from_body)"

for path in \
    /admin/account \
    /admin/users \
    /admin/settings \
    /admin/protocols \
    /admin/secrets \
    /admin/routing \
    /admin/cores \
    /admin/ip \
    /admin/system \
    /admin/configs \
    /admin/health \
    /admin/credits
do
    request 200 "$path"
done

head -c 70000 /dev/zero | tr '\0' A >"${TMP_DIR}/large-config"
request 400 /admin/configs --request POST \
    --data-urlencode csrf_token="$CSRF_TOKEN" \
    --data-urlencode target=xray-core \
    --data-urlencode content@"${TMP_DIR}/large-config"
body_excludes 'length limit'

request 403 /admin/users/create --request POST --data-urlencode username=no-csrf
request 400 /admin/settings --request POST \
    --data-urlencode csrf_token="$CSRF_TOKEN" \
    --data-urlencode panel_name=Smoke \
    --data-urlencode subscription_domain=sub.example.test \
    --data-urlencode node_domain=node.example.test \
    --data-urlencode panel_update_enabled=invalid \
    --data-urlencode panel_update_time=05:00
request 400 /admin/settings --request POST \
    --data-urlencode csrf_token="$CSRF_TOKEN" \
    --data-urlencode panel_name=Smoke \
    --data-urlencode 'subscription_domain=bad host' \
    --data-urlencode node_domain=node.example.test \
    --data-urlencode panel_update_enabled=false \
    --data-urlencode panel_update_time=05:00
request 303 /admin/settings --request POST \
    --data-urlencode csrf_token="$CSRF_TOKEN" \
    --data-urlencode 'panel_name=<script>alert(1)</script>' \
    --data-urlencode subscription_domain=sub.example.test \
    --data-urlencode node_domain=node.example.test \
    --data-urlencode panel_update_enabled=false \
    --data-urlencode panel_update_time=05:00
request 200 /admin/settings
body_contains '&lt;script&gt;alert(1)&lt;/script&gt;'
body_excludes '<script>alert(1)</script>'

request 303 /admin/users/create --request POST \
    --data-urlencode csrf_token="$CSRF_TOKEN" \
    --data-urlencode username=field-user \
    --data-urlencode traffic_limit_gb=10 \
    --data-urlencode expires_in_days=30
request 200 /admin/users
body_contains 'field-user'
SUBSCRIPTION_TOKEN="$(subscription_token_from_body)"
request 200 "/sub/${SUBSCRIPTION_TOKEN}"
request 503 "/sub/${SUBSCRIPTION_TOKEN}/mihomo.yaml"
body_contains 'subscription is not configured'

request 303 /admin/secrets --request POST \
    --data-urlencode csrf_token="$CSRF_TOKEN" \
    --data-urlencode name=tuic.password \
    --data-urlencode value=smoke-tuic-password
request 200 /admin/secrets
body_contains 'tuic.password'
body_excludes 'smoke-tuic-password'
request 303 /admin/protocols/TUIC-SPEED/update --request POST \
    --data-urlencode csrf_token="$CSRF_TOKEN" \
    --data-urlencode enabled=on \
    --data-urlencode server=node.example.test \
    --data-urlencode port=11443 \
    --data-urlencode sni=www.github.com \
    --data-urlencode password_secret=tuic.password
request 200 "/sub/${SUBSCRIPTION_TOKEN}/mihomo.yaml"
body_contains 'type: tuic'
body_contains 'smoke-tuic-password'
body_excludes 'REPLACE_WITH_'
body_excludes 'tuic.password'

request 400 /admin/routing --request POST \
    --data-urlencode csrf_token="$CSRF_TOKEN" \
    --data-urlencode slug=proxy-ai \
    --data-urlencode enabled=on \
    --data-urlencode target=AUTO-SAFE \
    --data-urlencode payload=MATCH
request 303 /admin/routing --request POST \
    --data-urlencode csrf_token="$CSRF_TOKEN" \
    --data-urlencode slug=proxy-ai \
    --data-urlencode enabled=on \
    --data-urlencode target=AUTO-SAFE \
    --data-urlencode payload=DOMAIN-SUFFIX,openai.com
request 200 /rules/proxy-ai.yaml
body_contains 'DOMAIN-SUFFIX,openai.com'
RULE_ETAG="$(sed -nE 's/^[Ee][Tt][Aa][Gg]:[[:space:]]*(.*)\r$/\1/p' "$HEADER_FILE")"
[[ -n "$RULE_ETAG" ]] || fail "routing provider ETag is missing"
request 304 /rules/proxy-ai.yaml --header "If-None-Match: ${RULE_ETAG}"
[[ ! -s "$BODY_FILE" ]] || fail "304 routing provider response contains a body"

mkdir -p "${TMP_DIR}/module-requests"
printf 'module-victim-preserved\n' >"${TMP_DIR}/module-request-victim"
ln -s "${TMP_DIR}/module-request-victim" "${TMP_DIR}/module-requests/xray.request"
request 303 /admin/modules/xray/update --request POST \
    --data-urlencode csrf_token="$CSRF_TOKEN"
[[ -f "${TMP_DIR}/module-requests/xray.request" ]] \
    || fail "module update request was not queued"
[[ ! -L "${TMP_DIR}/module-requests/xray.request" ]] \
    || fail "module request symlink was not replaced"
grep -Fq 'module-victim-preserved' "${TMP_DIR}/module-request-victim" \
    || fail "module request followed an attacker-controlled symlink"
printf 'panel-victim-preserved\n' >"${TMP_DIR}/panel-request-victim"
ln -s "${TMP_DIR}/panel-request-victim" "${TMP_DIR}/panel-update-now.request"
request 303 /admin/panel-update-now --request POST \
    --data-urlencode csrf_token="$CSRF_TOKEN"
[[ -f "${TMP_DIR}/panel-update-now.request" ]] \
    || fail "panel update request was not queued"
[[ ! -L "${TMP_DIR}/panel-update-now.request" ]] \
    || fail "panel update request symlink was not replaced"
grep -Fq 'panel-victim-preserved' "${TMP_DIR}/panel-request-victim" \
    || fail "panel update request followed an attacker-controlled symlink"
request 303 "/admin/users/1/toggle" --request POST \
    --data-urlencode csrf_token="$CSRF_TOKEN"
request 403 "/sub/${SUBSCRIPTION_TOKEN}/mihomo.yaml"
request 303 "/admin/users/1/toggle" --request POST \
    --data-urlencode csrf_token="$CSRF_TOKEN"
request 200 "/admin/users/1/reset-token"
RESET_CSRF="$(csrf_from_body)"
request 303 "/admin/users/1/reset-token" --request POST \
    --data-urlencode csrf_token="$RESET_CSRF"
request 401 "/sub/${SUBSCRIPTION_TOKEN}/mihomo.yaml"
request 200 /admin/users
NEW_SUBSCRIPTION_TOKEN="$(subscription_token_from_body)"
[[ "$NEW_SUBSCRIPTION_TOKEN" != "$SUBSCRIPTION_TOKEN" ]] \
    || fail "subscription token did not rotate"
request 200 "/sub/${NEW_SUBSCRIPTION_TOKEN}/mihomo.yaml"

request 400 /admin/secrets/delete --request POST \
    --data-urlencode csrf_token="$CSRF_TOKEN" \
    --data-urlencode name=tuic.password \
    --data-urlencode confirm=wrong-name
request 303 /admin/secrets/delete --request POST \
    --data-urlencode csrf_token="$CSRF_TOKEN" \
    --data-urlencode name=tuic.password \
    --data-urlencode confirm=tuic.password
request 503 "/sub/${NEW_SUBSCRIPTION_TOKEN}/mihomo.yaml"
body_contains 'subscription is not configured'

request 200 /admin/account
ACCOUNT_CSRF="$(csrf_from_body)"
request 403 /admin/account --request POST \
    --data-urlencode csrf_token="$ACCOUNT_CSRF" \
    --data-urlencode current_password=wrong-password \
    --data-urlencode new_password="$NEW_PASSWORD" \
    --data-urlencode new_password_confirm="$NEW_PASSWORD"
request 200 /admin/account
ACCOUNT_CSRF="$(csrf_from_body)"
request 303 /admin/account --request POST \
    --data-urlencode csrf_token="$ACCOUNT_CSRF" \
    --data-urlencode current_password="$OLD_PASSWORD" \
    --data-urlencode new_password="$NEW_PASSWORD" \
    --data-urlencode new_password_confirm="$NEW_PASSWORD"
request 303 /admin
grep -Fqi 'location: /admin/login' "$HEADER_FILE" \
    || fail "revoked session did not redirect to login"
request 401 /admin/login --request POST \
    --data-urlencode username=owner \
    --data-urlencode password="$OLD_PASSWORD"
request 303 /admin/login --request POST \
    --data-urlencode username=owner \
    --data-urlencode password="$NEW_PASSWORD"
request 200 /admin

{
    printf 'csrf_token=invalid&username='
    head -c 70000 /dev/zero | tr '\0' A
} >"${TMP_DIR}/oversized-form"
request 413 /admin/users/create --request POST \
    --header 'Content-Type: application/x-www-form-urlencoded' \
    --data-binary "@${TMP_DIR}/oversized-form"

for _ in {1..5}; do
    request 401 /admin/login --request POST \
        --data-urlencode username=rate-limit-probe \
        --data-urlencode password=wrong-password
done
request 429 /admin/login --request POST \
    --data-urlencode username=rate-limit-probe \
    --data-urlencode password=wrong-password
grep -Fqi 'retry-after:' "$HEADER_FILE" || fail "rate-limit Retry-After is missing"

printf '%s\n' 'HTTP smoke test passed.'
