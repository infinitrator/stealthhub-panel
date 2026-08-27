#!/usr/bin/env bash
# Shared fail-closed setup-token and applied-revision helpers.

valid_commit_sha() {
    [[ "${1:-}" =~ ^[A-Fa-f0-9]{40}$ ]]
}

normalized_commit_sha() {
    printf '%s' "$1" | tr 'A-F' 'a-f'
}

random_setup_token() {
    if command -v openssl >/dev/null 2>&1; then
        openssl rand -hex 32
    else
        od -An -N32 -tx1 /dev/urandom | tr -d ' \n'
    fi
}

ensure_setup_token() {
    local env_file="$1" owner="$2" group="$3" current count token temporary
    current="$(awk -F= '$1 == "INFIPROXY_SETUP_TOKEN" { sub("^[^=]*=", ""); print; exit }' \
        "$env_file")"
    count="$(awk -F= '$1 == "INFIPROXY_SETUP_TOKEN" { count++ } END { print count + 0 }' \
        "$env_file")"
    if [[ "$count" -eq 1 && "${#current}" -ge 32 ]]; then
        return 0
    fi
    token="$(random_setup_token)"
    [[ "${#token}" -ge 32 ]] || {
        echo "Failed to generate the initial setup token" >&2
        return 1
    }
    temporary="$(mktemp "${env_file}.setup-token.XXXXXX")"
    awk -v token="$token" '
        BEGIN { found = 0 }
        /^INFIPROXY_SETUP_TOKEN=/ {
            if (!found) print "INFIPROXY_SETUP_TOKEN=" token
            found++
            next
        }
        { print }
        END {
            if (!found) print "INFIPROXY_SETUP_TOKEN=" token
        }
    ' "$env_file" >"$temporary"
    if ! chown "$owner:$group" "$temporary" \
        || ! chmod 0660 "$temporary" \
        || ! mv -f -- "$temporary" "$env_file"; then
        rm -f -- "$temporary"
        return 1
    fi
}

record_source_commit() {
    local env_file="$1" commit="$2" owner="$3" group="$4" temporary
    valid_commit_sha "$commit" || return 1
    temporary="$(mktemp "${env_file}.source-commit.XXXXXX")"
    commit="$(normalized_commit_sha "$commit")"
    awk -v commit="$commit" '
        BEGIN { found = 0 }
        /^INFIPROXY_CURRENT_COMMIT=/ {
            if (!found) print "INFIPROXY_CURRENT_COMMIT=" commit
            found++
            next
        }
        { print }
        END {
            if (!found) print "INFIPROXY_CURRENT_COMMIT=" commit
        }
    ' "$env_file" >"$temporary"
    if ! chown "$owner:$group" "$temporary" \
        || ! chmod 0660 "$temporary" \
        || ! mv -f -- "$temporary" "$env_file"; then
        rm -f -- "$temporary"
        return 1
    fi
}

read_applied_sha() {
    local marker="$1" value
    [[ -f "$marker" && ! -L "$marker" ]] || return 1
    [[ "$(wc -c <"$marker")" -eq 41 && "$(wc -l <"$marker")" -eq 1 ]] || return 1
    IFS= read -r value <"$marker" || return 1
    valid_commit_sha "$value" || return 1
    normalized_commit_sha "$value"
}

publish_applied_sha() {
    local marker="$1" commit="$2" owner="$3" group="$4" temporary
    valid_commit_sha "$commit" || {
        echo "Refusing to publish an invalid applied commit" >&2
        return 1
    }
    install -d -o "$owner" -g "$group" -m 0751 "$(dirname "$marker")"
    temporary="$(mktemp "${marker}.tmp.XXXXXX")"
    commit="$(normalized_commit_sha "$commit")"
    if ! printf '%s\n' "$commit" >"$temporary" \
        || ! chown "$owner:$group" "$temporary" \
        || ! chmod 0640 "$temporary" \
        || ! mv -f -- "$temporary" "$marker"; then
        rm -f -- "$temporary"
        return 1
    fi
    [[ "$(read_applied_sha "$marker")" == "$commit" ]]
}

verify_and_publish_applied_sha() {
    local marker="$1" commit="$2" owner="$3" group="$4" readiness_callback="$5"
    "$readiness_callback" || return 1
    publish_applied_sha "$marker" "$commit" "$owner" "$group"
}
