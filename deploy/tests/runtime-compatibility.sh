#!/usr/bin/env bash
# Validate generated configs with the exact production runtime pins.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
WORK_DIR="$(mktemp -d)"
trap 'rm -rf "$WORK_DIR"' EXIT

for command in curl jq cargo openssl; do
  command -v "$command" >/dev/null || {
    printf 'required command is missing: %s\n' "$command" >&2
    exit 1
  }
done

case "$(uname -s)-$(uname -m)" in
  Darwin-arm64)
    MIHOMO_ASSET="mihomo-darwin-arm64-v1.19.30.gz"
    XRAY_ASSET="Xray-macos-arm64-v8a.zip"
    SING_BOX_ASSET="sing-box-1.13.20-darwin-arm64.tar.gz"
    HYSTERIA_ASSET="hysteria-darwin-arm64"
    TUIC_ASSET="tuic-server-1.0.0-aarch64-apple-darwin"
    ;;
  Linux-x86_64)
    MIHOMO_ASSET="mihomo-linux-amd64-v1.19.30.gz"
    XRAY_ASSET="Xray-linux-64.zip"
    SING_BOX_ASSET="sing-box-1.13.20-linux-amd64.tar.gz"
    HYSTERIA_ASSET="hysteria-linux-amd64"
    TUIC_ASSET="tuic-server-1.0.0-x86_64-unknown-linux-gnu"
    ;;
  *)
    printf 'unsupported compatibility host: %s-%s\n' "$(uname -s)" "$(uname -m)" >&2
    exit 1
    ;;
esac

sha256_check() {
  local expected="$1" file="$2" actual
  if command -v sha256sum >/dev/null; then
    actual="$(sha256sum "$file" | awk '{print $1}')"
  else
    actual="$(shasum -a 256 "$file" | awk '{print $1}')"
  fi
  [[ "$actual" == "$expected" ]] || {
    printf 'SHA-256 mismatch for %s\n' "$(basename "$file")" >&2
    exit 1
  }
}

release_asset() {
  local repo="$1" tag="$2" asset="$3" output="$4"
  local metadata url digest
  metadata="$(curl -fsSL --proto '=https' --tlsv1.2 \
    "https://api.github.com/repos/${repo}/releases/tags/${tag}")"
  [[ "$(jq -r '.draft' <<<"$metadata")" == "false" ]]
  [[ "$(jq -r '.prerelease' <<<"$metadata")" == "false" ]]
  url="$(jq -r --arg asset "$asset" \
    '.assets[] | select(.name == $asset) | .browser_download_url' <<<"$metadata")"
  digest="$(jq -r --arg asset "$asset" \
    '.assets[] | select(.name == $asset) | .digest // empty' <<<"$metadata")"
  [[ -n "$url" ]] || {
    printf 'official asset is absent: %s %s %s\n' "$repo" "$tag" "$asset" >&2
    exit 1
  }
  curl -fsSL --proto '=https' --tlsv1.2 -o "$output" "$url"
  if [[ -n "$digest" ]]; then
    sha256_check "${digest#sha256:}" "$output"
  else
    local checksum
    checksum="$(curl -fsSL --proto '=https' --tlsv1.2 "${url}.sha256sum")"
    sha256_check "${checksum%%[[:space:]]*}" "$output"
  fi
}

release_asset MetaCubeX/mihomo v1.19.30 "$MIHOMO_ASSET" "$WORK_DIR/mihomo.gz"
gzip -dc "$WORK_DIR/mihomo.gz" >"$WORK_DIR/mihomo"

release_asset XTLS/Xray-core v26.3.27 "$XRAY_ASSET" "$WORK_DIR/xray.zip"
unzip -q "$WORK_DIR/xray.zip" xray -d "$WORK_DIR"

release_asset SagerNet/sing-box v1.13.20 "$SING_BOX_ASSET" "$WORK_DIR/sing-box.tar.gz"
tar -xzf "$WORK_DIR/sing-box.tar.gz" -C "$WORK_DIR"
find "$WORK_DIR" -mindepth 2 -type f -name sing-box -exec cp {} "$WORK_DIR/sing-box" \;

release_asset apernet/hysteria app/v2.12.2 "$HYSTERIA_ASSET" "$WORK_DIR/hysteria"
release_asset tuic-protocol/tuic tuic-server-1.0.0 "$TUIC_ASSET" "$WORK_DIR/tuic-server"
chmod 0700 "$WORK_DIR/mihomo" "$WORK_DIR/xray" "$WORK_DIR/sing-box" \
  "$WORK_DIR/hysteria" "$WORK_DIR/tuic-server"

"$WORK_DIR/mihomo" -v 2>&1 | grep -Fq 'v1.19.30'
"$WORK_DIR/xray" version 2>&1 | grep -Fq '26.3.27'
"$WORK_DIR/sing-box" version 2>&1 | grep -Fq '1.13.20'
"$WORK_DIR/hysteria" version 2>&1 | grep -Fq 'v2.12.2'
"$WORK_DIR/tuic-server" --version 2>&1 | grep -Fq '1.0.0'

cd "$ROOT_DIR"
INFIPROXY_TEST_MIHOMO_BIN="$WORK_DIR/mihomo" \
INFIPROXY_TEST_XRAY_BIN="$WORK_DIR/xray" \
INFIPROXY_TEST_SING_BOX_BIN="$WORK_DIR/sing-box" \
INFIPROXY_TEST_HYSTERIA_BIN="$WORK_DIR/hysteria" \
INFIPROXY_TEST_TUIC_BIN="$WORK_DIR/tuic-server" \
  cargo test --locked -p stealthhub-core exact_ -- --nocapture
