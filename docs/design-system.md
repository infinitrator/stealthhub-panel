# Infiproxy Theme System

Infiproxy ships two original visual themes. **Hades / Obsidian Gate** is the
default: obsidian, ivory, antique gold, crimson, and gate/flame geometry.
**ULTRAKILL** is an aggressive graphite, black, and hard-red industrial theme
reconstructed from the pre-Obsidian interface. Neither theme bundles game
artwork, lettering, fonts, logos, or other third-party assets.

## Web architecture

`crates/stealthhub-panel/src/assets/panel.css` contains shared layout and
component rules. Themes override semantic token values on `html[data-theme]`:

- surfaces: `--surface-page`, `--surface-panel`, `--surface-elevated`,
  `--surface-hover`, and `--surface-recessed`;
- text: `--text-primary`, `--text-secondary`, and `--text-muted`;
- borders: `--border-muted`, `--border-accent`, and `--border-strong`;
- identity: `--accent-primary` and `--accent-secondary`;
- state: `--state-success`, `--state-warning`, `--state-danger`, and
  `--state-info`;
- interaction: `--focus` and `--disabled`.

Components must consume these tokens. Do not duplicate the component sheet for
a new theme or put theme-specific literal colors in component declarations.
Keep visible focus, text labels for status, reduced-motion and forced-colors
rules, the skip link, and narrow one-column layouts.

The authenticated selector posts to `/admin/theme` with the existing session
and CSRF contract. Its value is stored as `admin.<id>.theme` in the existing
SQLite settings table. Storage failures do not invalidate authentication;
missing or unrecognized values fall back to Obsidian Gate. Public setup/login,
subscription, and generic error shells are deterministically Obsidian Gate.

## Identity and cache contract

Obsidian Gate uses `underworld-gate.svg`; ULTRAKILL uses the original
`ultrakill-mark.svg`. Each theme emits its own versioned SVG/PNG/Apple Touch and
manifest URLs. The unchanged `/favicon.ico` URL remains an Obsidian Gate
fallback and is served with `no-cache, no-store, must-revalidate`, so a browser
cannot legitimately retain a retired icon. Versioned metadata assets
are immutable.

When changing a mark, change its URL version and regenerate its PNG derivatives.
`GET /favicon.ico` must always remain the current default-theme fallback. Never
restore or route a deleted legacy identity asset.

## TUI

The Rust TUI maps the same two theme identities across truecolor, 256-color,
ANSI, `NO_COLOR`, and ASCII modes. Press `T` outside a form to switch themes for
the current session, or set `INFIPROXY_TUI_THEME=obsidian-gate|hades|ultrakill` before
launch. Theme selection changes palette and labels only; status meaning,
operations, dirty rendering, and idle CPU behavior are invariant.

## Adding a theme

1. Add one parsed theme identifier and a safe fallback in the web and TUI enums.
2. Override every semantic token value; do not clone component CSS.
3. Add original SVG identity artwork and versioned raster/manifest metadata.
4. Add parser, markup, favicon, palette, persistence, accessibility, and idle
   redraw tests.
5. Inspect all authenticated pages, public login/setup, error pages, mobile
   layout, and the TUI at 80x24 before release.
