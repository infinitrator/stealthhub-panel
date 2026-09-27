//! Server-rendered UI shell for the Infiproxy panel.
//!
//! The layout is intentionally static CSS and Maud markup: no client-side build
//! pipeline, no JavaScript dependency and fast rendering on small VPS machines.

use maud::{html, Markup, DOCTYPE};

pub(crate) const APP_NAME: &str = "Infiproxy";
pub(crate) const PANEL_CSS: &str = include_str!("assets/panel.css");
pub(crate) const UNDERWORLD_GATE_SVG: &[u8] = include_bytes!("assets/underworld-gate.svg");
pub(crate) const FAVICON_ICO: &[u8] = include_bytes!("assets/favicon.ico");
pub(crate) const FAVICON_16: &[u8] = include_bytes!("assets/favicon-16x16.png");
pub(crate) const FAVICON_32: &[u8] = include_bytes!("assets/favicon-32x32.png");
pub(crate) const APPLE_TOUCH_ICON: &[u8] = include_bytes!("assets/apple-touch-icon.png");
pub(crate) const SITE_MANIFEST: &str = include_str!("assets/site.webmanifest");

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
    html! {
        (DOCTYPE)
        html lang="en" {
            head {
                meta charset="utf-8";
                meta name="viewport" content="width=device-width, initial-scale=1";
                title { (title) }
                meta name="theme-color" content="#120e12";
                link rel="icon" type="image/svg+xml" href="/assets/underworld-gate.svg";
                link rel="icon" href="/favicon.ico" sizes="any";
                link rel="icon" type="image/png" sizes="16x16" href="/favicon-16x16.png";
                link rel="icon" type="image/png" sizes="32x32" href="/favicon-32x32.png";
                link rel="apple-touch-icon" sizes="180x180" href="/apple-touch-icon.png";
                link rel="manifest" href="/site.webmanifest";
                link rel="stylesheet" href="/assets/panel.css";
            }
            body {
                a class="skip-link" href="#workspace" { "Skip to workspace" }
                div class="app-chrome" {
                    header class="masthead" {
                        div class="masthead-title" {
                            img class="brand-mark" src="/assets/underworld-gate.svg" alt="" width="42" height="42";
                            div class="brand-copy" {
                                a href="/admin" class="wordmark" { (APP_NAME) }
                                span class="masthead-label" { "OBSIDIAN GATE / NODE CONTROL" }
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
                                span class="window-sigil" aria-hidden="true" { "◆ ◇ ◆" }
                            }
                            (body)
                            footer class="workspace-footer" { "INFIPROXY / OBSIDIAN GATE" span { "Server-rendered control plane" } }
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
        let rendered = layout("Health", html! { p { "test" } }).into_string();
        assert!(rendered.contains("class=\"app-chrome\""));
        assert!(rendered.contains("aria-label=\"Main navigation\""));
        assert!(rendered.contains("aria-current=\"page\""));
        assert!(rendered.contains("href=\"#workspace\""));
        assert!(!rendered.contains("<script"));
        for token in [
            "--page-background:",
            "--surface-elevated:",
            "--surface-panel:",
            "--surface-hover:",
            "--border-muted:",
            "--border-accent:",
            "--text-primary:",
            "--text-secondary:",
            "--text-muted:",
            "--gold-accent:",
            "--crimson-accent:",
            "--danger:",
            "--warning:",
            "--success:",
            "--info:",
            "--focus:",
            "--disabled:",
        ] {
            assert!(PANEL_CSS.contains(token), "missing design token {token}");
        }
        assert!(PANEL_CSS.contains("prefers-reduced-motion"));
        assert!(rendered.contains("href=\"/assets/underworld-gate.svg\""));
        assert!(rendered.contains("OBSIDIAN GATE / NODE CONTROL"));
        assert_eq!(UNDERWORLD_GATE_SVG.first(), Some(&b'<'));
        assert!(!rendered.contains(">Dashboard<"));
        assert!(rendered.contains("href=\"/admin\" aria-current=\"page\">"));
    }
}
