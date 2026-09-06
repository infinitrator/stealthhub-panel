#!/usr/bin/env bash
# Target-owned, repository-controlled build contract for panel updates.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
JOBS="${INFIPROXY_BUILD_JOBS:-2}"
[[ "$JOBS" =~ ^[1-9][0-9]?$ ]] || {
    echo "INFIPROXY_BUILD_JOBS must be between 1 and 99" >&2
    exit 2
}

cargo build --locked --release -p stealthhub-panel -p infiproxy-manager \
    --jobs "$JOBS" --manifest-path "${ROOT_DIR}/Cargo.toml"

for artifact in stealthhub-panel infiproxy-module-manifest infiproxy-reconcile infiproxy-tui; do
    [[ -x "${ROOT_DIR}/target/release/${artifact}" ]] || {
        echo "Required control-plane artifact is missing: ${artifact}" >&2
        exit 1
    }
done
