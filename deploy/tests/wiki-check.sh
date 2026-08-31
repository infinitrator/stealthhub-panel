#!/usr/bin/env bash
# Validate the versioned Markdown source before it is published to GitHub Wiki.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

required_pages=(
  wiki/Home.md
  wiki/_Sidebar.md
  wiki/_Footer.md
  wiki/00-WIKI-PUBLISHING.md
  wiki/01-QUICK-START.md
  wiki/02-ARCHITECTURE-AND-NETWORKING.md
  wiki/03-WEB-INTERFACE.md
  wiki/04-USERS-AND-SUBSCRIPTIONS.md
  wiki/05-PROTOCOL-PROFILES-AND-RUNTIMES.md
  wiki/06-PROXY-PROTOCOLS.md
  wiki/07-ROUTING.md
  wiki/08-MODULES-AND-UPDATES.md
  wiki/09-RECONCILIATION-AND-DESIRED-STATE.md
  wiki/10-SYSTEM-AND-TUI.md
  wiki/11-CONFIGURATION.md
  wiki/12-BACKUP-RESTORE-UNINSTALL.md
  wiki/13-SECURITY-OPERATIONS.md
  wiki/14-TROUBLESHOOTING-AND-REFERENCE.md
  wiki/15-RELEASE-AND-COMPATIBILITY.md
  wiki/16-ADAPTER-ARCHITECTURE.md
  wiki/17-RUNTIME-COMPATIBILITY.md
)

for page in "${required_pages[@]}"; do
  [[ -s "$page" ]] || {
    printf 'wiki check failed: required page is missing or empty: %s\n' "$page" >&2
    exit 1
  }
done

retired_pages=(
  wiki/05-MIHOMO-PROFILES.md
  wiki/15-RELEASE-0.1-BETA.md
  wiki/16-ADAPTERS-AND-RECONCILIATION.md
)
for page in "${retired_pages[@]}"; do
  [[ ! -e "$page" ]] || {
    printf 'wiki check failed: retired page still exists: %s\n' "$page" >&2
    exit 1
  }
done

if find wiki -type l -print -quit | grep -q .; then
  echo 'wiki check failed: symbolic links are not allowed in publishable Wiki sources' >&2
  exit 1
fi

if grep -R -n -E 'INFIPROXY_ENABLE_DEMO_USER|STEALTHHUB_ENABLE_DEMO_USER' README.md wiki deploy/infiproxy.env.example; then
  echo 'wiki check failed: removed demo-user configuration is still documented' >&2
  exit 1
fi

while IFS= read -r page; do
  fence_count="$(awk '/^[[:space:]]*```/{count++} END {print count + 0}' "$page")"
  if ((fence_count % 2 != 0)); then
    printf 'wiki check failed: unbalanced fenced code block: %s\n' "$page" >&2
    exit 1
  fi
done < <(find wiki -maxdepth 1 -type f -name '*.md' -print | sort)

if grep -Hn -E ' \+ {3,}' wiki/*.md; then
  echo 'wiki check failed: malformed command continuation found in Wiki source' >&2
  exit 1
fi

link_failure=0
while IFS=: read -r source line match; do
  target="${match#*](}"
  target="${target%)}"
  target="${target%%#*}"
  case "$target" in
    http://*|https://*|mailto:*|'') continue ;;
  esac

  if [[ "$source" == wiki/* ]]; then
    resolved="$(dirname "$source")/$target"
  else
    resolved="$target"
  fi
  if [[ ! -f "$resolved" ]]; then
    printf 'wiki check failed: %s:%s links to missing %s\n' "$source" "$line" "$resolved" >&2
    link_failure=1
  fi
done < <(grep -Hn -o -E '\[[^]]+\]\([^)]+\.md(#[^)]+)?\)' README.md wiki/*.md || true)

((link_failure == 0)) || exit 1

wiki_prefix='https://github.com/infinitrator/stealthhub-panel/wiki/'
while IFS=: read -r source line match; do
  target="${match#*](}"
  target="${target%)}"
  slug="${target#"${wiki_prefix}"}"
  slug="${slug%%#*}"
  if [[ ! -f "wiki/${slug}.md" ]]; then
    printf 'wiki check failed: %s:%s links to missing Wiki page %s\n' \
      "$source" "$line" "$slug" >&2
    link_failure=1
  fi
done < <(grep -Hn -o -E \
  '\[[^]]+\]\(https://github\.com/infinitrator/stealthhub-panel/wiki/[^)#]+(#[^)]+)?\)' \
  wiki/*.md || true)

while IFS=: read -r source line match; do
  target="${match#*](}"
  target="${target%)}"
  target="${target%%#*}"
  case "$target" in
    Home|[0-9][0-9]-*) ;;
    *) continue ;;
  esac
  if [[ ! -f "wiki/${target}.md" ]]; then
    printf 'wiki check failed: %s:%s links to missing Wiki page %s\n' \
      "$source" "$line" "$target" >&2
    link_failure=1
  fi
done < <(grep -Hn -o -E '\[[^]]+\]\((Home|[0-9][0-9]-[A-Za-z0-9._-]+)(#[^)]+)?\)' \
  wiki/*.md || true)

if grep -Hn -E '\[[^]]+\]\([A-Za-z0-9._-]+\.md(#[^)]+)?\)' wiki/*.md; then
  echo 'wiki check failed: internal Wiki links must use canonical page URLs without .md' >&2
  link_failure=1
fi

((link_failure == 0)) || exit 1

if git grep -niE '(headscale|mtproto)' -- README.md wiki docs; then
  echo 'wiki check failed: retired modules are still advertised in documentation' >&2
  exit 1
fi

if git grep -niE 'refactor/atomic-adapter-reconciler|stealthhub\.service' -- README.md wiki docs; then
  echo 'wiki check failed: stale branch or service contract remains documented' >&2
  exit 1
fi

grep -Fq "UPDATE_REF=\"\${INFIPROXY_UPDATE_REF:-main}\"" deploy/install.sh || {
  echo 'wiki check failed: installer no longer defaults the update ref to main' >&2
  exit 1
}
grep -Fq 'REF=main' README.md || {
  echo 'wiki check failed: README does not document the production update ref' >&2
  exit 1
}

module_ids="$(awk -F= '$1 == "id" {print $2}' deploy/modules.d/*.module | sort)"
expected_modules="$(printf '%s\n' hysteria mihomo sing-box tuic xray)"
if [[ "$module_ids" != "$expected_modules" ]]; then
  printf 'wiki check failed: bundled module set changed:\n%s\n' "$module_ids" >&2
  exit 1
fi
while IFS= read -r module_id; do
  grep -Fiq "$module_id" README.md || {
    printf 'wiki check failed: README omits bundled module %s\n' "$module_id" >&2
    exit 1
  }
  grep -Fiq "$module_id" wiki/08-MODULES-AND-UPDATES.md || {
    printf 'wiki check failed: module Wiki omits bundled module %s\n' "$module_id" >&2
    exit 1
  }
done <<< "$module_ids"

echo "Wiki contracts passed (${#required_pages[@]} required pages)."
