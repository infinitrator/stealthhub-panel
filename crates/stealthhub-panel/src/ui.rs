//! Server-rendered UI shell for the Infiproxy panel.
//!
//! The layout is intentionally static CSS and Maud markup: no client-side build
//! pipeline, no JavaScript dependency and fast rendering on small VPS machines.

use maud::{html, Markup, DOCTYPE};

pub(crate) const APP_NAME: &str = "Infiproxy";
pub(crate) const PANEL_CSS: &str = include_str!("assets/panel.css");
pub(crate) const UNDERWORLD_GATE_SVG: &[u8] = include_bytes!("assets/underworld-gate.svg");
pub(crate) const ULTRAKILL_MARK_SVG: &[u8] = include_bytes!("assets/ultrakill-mark.svg");
pub(crate) const FAVICON_ICO: &[u8] = include_bytes!("assets/favicon.ico");
pub(crate) const FAVICON_16: &[u8] = include_bytes!("assets/favicon-16x16.png");
pub(crate) const FAVICON_32: &[u8] = include_bytes!("assets/favicon-32x32.png");
pub(crate) const APPLE_TOUCH_ICON: &[u8] = include_bytes!("assets/apple-touch-icon.png");
pub(crate) const ULTRAKILL_FAVICON_16: &[u8] = include_bytes!("assets/ultrakill-16x16.png");
pub(crate) const ULTRAKILL_FAVICON_32: &[u8] = include_bytes!("assets/ultrakill-32x32.png");
pub(crate) const ULTRAKILL_APPLE_TOUCH_ICON: &[u8] =
    include_bytes!("assets/ultrakill-apple-touch-icon.png");
pub(crate) const SITE_MANIFEST: &str = include_str!("assets/site.webmanifest");
pub(crate) const OBSIDIAN_GATE_MANIFEST: &str =
    include_str!("assets/manifest-obsidian-gate.webmanifest");
pub(crate) const ULTRAKILL_MANIFEST: &str = include_str!("assets/manifest-ultrakill.webmanifest");

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) enum Theme {
    #[default]
    ObsidianGate,
    Ultrakill,
}

impl Theme {
    pub(crate) fn parse(value: &str) -> Option<Self> {
        match value {
            "obsidian-gate" | "hades" => Some(Self::ObsidianGate),
            "ultrakill" => Some(Self::Ultrakill),
            _ => None,
        }
    }

    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::ObsidianGate => "obsidian-gate",
            Self::Ultrakill => "ultrakill",
        }
    }

    const fn theme_color(self) -> &'static str {
        match self {
            Self::ObsidianGate => "#120e12",
            Self::Ultrakill => "#17191d",
        }
    }

    pub(crate) const fn display_name(self) -> &'static str {
        match self {
            Self::ObsidianGate => "Hades / Obsidian Gate",
            Self::Ultrakill => "ULTRAKILL",
        }
    }

    const fn mark_url(self) -> &'static str {
        match self {
            Self::ObsidianGate => "/assets/underworld-gate.svg?v=og-20260927",
            Self::Ultrakill => "/assets/ultrakill-mark.svg?v=uk-20260927",
        }
    }

    const fn favicon_16_url(self) -> &'static str {
        match self {
            Self::ObsidianGate => "/favicon-16x16.png?v=og-20260927",
            Self::Ultrakill => "/assets/ultrakill-16x16.png?v=uk-20260927",
        }
    }

    const fn favicon_32_url(self) -> &'static str {
        match self {
            Self::ObsidianGate => "/favicon-32x32.png?v=og-20260927",
            Self::Ultrakill => "/assets/ultrakill-32x32.png?v=uk-20260927",
        }
    }

    const fn apple_touch_url(self) -> &'static str {
        match self {
            Self::ObsidianGate => "/apple-touch-icon.png?v=og-20260927",
            Self::Ultrakill => "/assets/ultrakill-apple-touch-icon.png?v=uk-20260927",
        }
    }

    const fn manifest_url(self) -> &'static str {
        match self {
            Self::ObsidianGate => "/assets/manifest-obsidian-gate.webmanifest?v=og-20260927",
            Self::Ultrakill => "/assets/manifest-ultrakill.webmanifest?v=uk-20260927",
        }
    }

    const fn identity_label(self) -> &'static str {
        match self {
            Self::ObsidianGate => "OBSIDIAN GATE / NODE CONTROL",
            Self::Ultrakill => "ULTRAKILL / NODE CONTROL",
        }
    }

    const fn sigil(self) -> &'static str {
        match self {
            Self::ObsidianGate => "◆ ◇ ◆",
            Self::Ultrakill => "[ // ]",
        }
    }
}

const NAVIGATION: &[(&str, &str, &str)] = &[
    ("Node", "/admin", "Health"),
    ("Access", "/admin/users", "Users"),
    ("Access", "/admin/secrets", "Secrets"),
    ("Network", "/admin/protocols", "Protocols"),
    ("Network", "/admin/routing", "Routing"),
    ("Network", "/admin/cores", "Modules"),
    ("Network", "/admin/ip", "IP Check"),
    ("Operations", "/admin/settings", "Settings"),
    ("Operations", "/admin/system", "System"),
    ("Operations", "/admin/configs", "Configs"),
    ("Operations", "/admin/audit", "Audit"),
    ("Session", "/admin/account", "Account"),
    ("Session", "/admin/credits", "Credits"),
];

fn active_navigation(title: &str, label: &str) -> bool {
    title.eq_ignore_ascii_case(label)
        || (label == "Users"
            && [
                "Edit user",
                "Subscription access",
                "Reset subscription URL",
                "Rotate runtime identity",
                "Delete user",
            ]
            .contains(&title))
}

pub(crate) fn layout(title: &str, body: Markup) -> Markup {
    themed_layout(title, Theme::default(), body)
}

pub(crate) fn themed_layout(title: &str, theme: Theme, body: Markup) -> Markup {
    html! {
        (DOCTYPE)
        html lang="en" data-theme=(theme.as_str()) {
            head {
                meta charset="utf-8";
                meta name="viewport" content="width=device-width, initial-scale=1";
                title { (title) }
                meta name="theme-color" content=(theme.theme_color());
                link rel="icon" type="image/svg+xml" href=(theme.mark_url());
                @if theme == Theme::ObsidianGate {
                    link rel="icon" href="/favicon.ico?v=og-20260927" sizes="any";
                }
                link rel="icon" type="image/png" sizes="16x16" href=(theme.favicon_16_url());
                link rel="icon" type="image/png" sizes="32x32" href=(theme.favicon_32_url());
                link rel="apple-touch-icon" sizes="180x180" href=(theme.apple_touch_url());
                link rel="manifest" href=(theme.manifest_url());
                link rel="stylesheet" href="/assets/panel.css?v=themes-20260927";
            }
            body {
                a class="skip-link" href="#workspace" { "Skip to workspace" }
                div class="app-chrome" {
                    header class="masthead" {
                        div class="masthead-title" {
                            img class="brand-mark" src=(theme.mark_url()) alt="" width="42" height="42";
                            div class="brand-copy" {
                                a href="/admin" class="wordmark" { (APP_NAME) }
                                span class="masthead-label" { (theme.identity_label()) }
                            }
                        }
                        div class="masthead-meta" { "SINGLE NODE / " (env!("CARGO_PKG_VERSION")) }
                    }
                    div class="layout-shell" {
                        nav class="top-nav" aria-label="Main navigation" {
                            @for (index, (group, href, label)) in NAVIGATION.iter().enumerate() {
                                @if index == 0 || NAVIGATION[index - 1].0 != *group { div class="nav-section" { (group) } }
                                a href=(href) aria-current=[active_navigation(title, label).then_some("page")] {
                                    span class="nav-index" aria-hidden="true" { "◆" } (label)
                                }
                            }
                        }
                        main class="content" id="workspace" tabindex="-1" {
                            div class="window-titlebar" {
                                span { (title) }
                                span class="window-sigil" aria-hidden="true" { (theme.sigil()) }
                            }
                            (body)
                            footer class="workspace-footer" { "INFIPROXY / " (theme.display_name()) span { "Server-rendered control plane" } }
                        }
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use maud::html;

    #[test]
    fn shell_keeps_semantic_navigation_and_no_script_dependency() {
        let rendered =
            themed_layout("Health", Theme::ObsidianGate, html! { p { "test" } }).into_string();
        assert!(rendered.contains("class=\"app-chrome\""));
        assert!(rendered.contains("aria-label=\"Main navigation\""));
        assert!(rendered.contains("aria-current=\"page\""));
        assert!(rendered.contains("href=\"#workspace\""));
        assert!(!rendered.contains("<script"));
        for token in [
            "--surface-page:",
            "--surface-elevated:",
            "--surface-panel:",
            "--surface-hover:",
            "--border-muted:",
            "--border-accent:",
            "--text-primary:",
            "--text-secondary:",
            "--text-muted:",
            "--accent-primary:",
            "--accent-secondary:",
            "--state-danger:",
            "--state-warning:",
            "--state-success:",
            "--state-info:",
            "--focus:",
            "--disabled:",
        ] {
            assert!(PANEL_CSS.contains(token), "missing design token {token}");
        }
        assert!(PANEL_CSS.contains("prefers-reduced-motion"));
        assert!(rendered.contains("data-theme=\"obsidian-gate\""));
        assert!(rendered.contains("href=\"/assets/underworld-gate.svg?v=og-20260927\""));
        assert!(rendered.contains("OBSIDIAN GATE / NODE CONTROL"));
        assert_eq!(UNDERWORLD_GATE_SVG.first(), Some(&b'<'));
        assert!(!rendered.contains(">Dashboard<"));
        assert!(rendered.contains("href=\"/admin\" aria-current=\"page\">"));
    }

    #[test]
    fn themes_parse_safely_and_emit_distinct_identity_metadata() {
        assert_eq!(Theme::default(), Theme::ObsidianGate);
        assert_eq!(Theme::parse("hades"), Some(Theme::ObsidianGate));
        assert_eq!(Theme::parse("ultrakill"), Some(Theme::Ultrakill));
        assert_eq!(Theme::parse("unknown"), None);

        let hades = themed_layout("Health", Theme::ObsidianGate, html! {}).into_string();
        let ultrakill = themed_layout("Health", Theme::Ultrakill, html! {}).into_string();
        assert!(hades.contains("underworld-gate.svg?v=og-20260927"));
        assert!(!hades.contains("smile"));
        assert!(ultrakill.contains("ultrakill-mark.svg?v=uk-20260927"));
        assert!(ultrakill.contains("data-theme=\"ultrakill\""));
        assert_eq!(hades.matches("aria-label=\"Main navigation\"").count(), 1);
        assert_eq!(
            ultrakill.matches("aria-label=\"Main navigation\"").count(),
            1
        );
    }
}
