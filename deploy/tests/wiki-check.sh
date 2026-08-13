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
  wiki/05-MIHOMO-PROFILES.md
  wiki/06-PROXY-PROTOCOLS.md
  wiki/07-ROUTING.md
  wiki/08-MODULES-AND-UPDATES.md
  wiki/09-HEADSCALE.md
  wiki/10-SYSTEM-AND-TUI.md
  wiki/11-CONFIGURATION.md
  wiki/12-BACKUP-RESTORE-UNINSTALL.md
  wiki/13-SECURITY-OPERATIONS.md
  wiki/14-TROUBLESHOOTING-AND-REFERENCE.md
  wiki/15-RELEASE-0.1-BETA.md
)

for page in "${required_pages[@]}"; do
  [[ -s "$page" ]] || {
    printf 'wiki check failed: required page is missing or empty: %s\n' "$page" >&2
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
  slug="${target#${wiki_prefix}}"
  slug="${slug%%#*}"
  if [[ ! -f "wiki/${slug}.md" ]]; then
    printf 'wiki check failed: %s:%s links to missing Wiki page %s\n' \
      "$source" "$line" "$slug" >&2
    link_failure=1
  fi
done < <(grep -Hn -o -E \
  '\[[^]]+\]\(https://github\.com/infinitrator/stealthhub-panel/wiki/[^)#]+(#[^)]+)?\)' \
  wiki/*.md || true)

if grep -Hn -E '\[[^]]+\]\([A-Za-z0-9._-]+\.md(#[^)]+)?\)' wiki/*.md; then
  echo 'wiki check failed: internal Wiki links must use canonical page URLs without .md' >&2
  link_failure=1
fi

((link_failure == 0)) || exit 1

echo "Wiki contracts passed (${#required_pages[@]} required pages)."
