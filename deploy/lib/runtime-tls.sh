#!/usr/bin/env bash
# Ownership normalization for fixed proxy-runtime TLS files.

normalize_runtime_tls_file() {
    local path="$1" runtime_group="$2"

    if [[ -L "$path" ]]; then
        return 0
    fi
    if [[ ! -e "$path" ]]; then
        return 0
    fi
    if [[ ! -f "$path" ]]; then
        printf 'Unsupported TLS path type: %s\n' "$path" >&2
        return 1
    fi

    # -h prevents an unexpected symlink replacement from changing its target.
    chown -h root:"$runtime_group" -- "$path"
    if [[ -L "$path" || ! -f "$path" ]]; then
        printf 'TLS path changed during ownership normalization: %s\n' "$path" >&2
        return 1
    fi
    chmod 0640 "$path"
}
