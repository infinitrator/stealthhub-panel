# Obsidian Gate Design System

Infiproxy uses the original **Obsidian Gate** visual system across the web panel,
browser icons, and SSH TUI. Its geometry draws on the gates, fire, bronze, and
stone of classical Greek underworld mythology. It does not copy artwork,
lettering, UI, logos, or other assets from any game or third-party property.

## Foundations

The web source of truth is `crates/stealthhub-panel/src/assets/panel.css`. Its
semantic tokens separate intent from individual components:

- surfaces: `--page-background`, `--surface-elevated`, `--surface-panel`, and
  `--surface-hover`;
- borders: `--border-muted` and `--border-accent`;
- text: `--text-primary`, `--text-secondary`, and `--text-muted`;
- identity: `--gold-accent` and `--crimson-accent`;
- state: `--danger`, `--warning`, `--success`, `--info`, `--focus`, and
  `--disabled`.

Display headings use a local serif stack, ordinary controls use the system UI
stack, and machine values use a monospace stack. No CDN, remote font, client
script, or runtime image dependency is required.

The gate-and-flame mark lives in `underworld-gate.svg`. PNG, Apple Touch, and
ICO derivatives are generated from that source. Keep the silhouette legible at
16 px and retain the existing dark, gold, crimson, and ivory palette.

## Component rules

- Use semantic tokens instead of adding one-off colors.
- Keep health and lifecycle states labeled in text; color is supporting signal.
- Preserve visible keyboard focus, the skip link, semantic navigation, and
  reduced-motion/forced-colors behavior.
- Tables may scroll horizontally on narrow screens. Forms, cards, and health
  layouts must collapse to one column without hiding actions.
- Destructive actions use both explicit copy and the danger treatment.

The TUI mirrors the same obsidian, ivory, gold, and crimson hierarchy while
retaining truecolor, 256-color, ANSI, `NO_COLOR`, and ASCII fallbacks. Theme
changes must not change its idle redraw gate or introduce animations.

## Verification

When changing the shell or tokens, update the narrow Rust/static-asset tests,
run the HTTP smoke test, inspect the panel at desktop and narrow breakpoints,
and render the TUI tests at 80x24. Documentation and generated icon derivatives
must be updated in the same commit as their source.
