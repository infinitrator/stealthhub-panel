//! Server-rendered UI shell for the Infiproxy panel.
//!
//! The layout is intentionally static CSS and Maud markup: no client-side build
//! pipeline, no JavaScript dependency and fast rendering on small VPS machines.

use maud::{html, Markup, DOCTYPE};

pub(crate) const APP_NAME: &str = "Infiproxy";
pub(crate) const PANEL_CSS: &str = include_str!("assets/panel.css");

const NAVIGATION: &[(&str, &str, &str)] = &[
    ("Node", "/admin", "Dashboard"),
    ("Node", "/admin/health", "Health"),
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
                link rel="stylesheet" href="/assets/panel.css";
            }
            body {
                a class="skip-link" href="#workspace" { "Skip to workspace" }
                div class="app-chrome" {
                    header class="masthead" {
                        div class="masthead-title" {
                            a href="/admin" class="wordmark" { (APP_NAME) }
                            span class="masthead-label" { "NODE CONTROL" }
                        }
                        div class="masthead-meta" { "SINGLE NODE / " (env!("CARGO_PKG_VERSION")) }
                    }
                    div class="layout-shell" {
                        nav class="top-nav" aria-label="Main navigation" {
                            @for (index, (group, href, label)) in NAVIGATION.iter().enumerate() {
                                @if index == 0 || NAVIGATION[index - 1].0 != *group { div class="nav-section" { (group) } }
                                a href=(href) aria-current=[active_navigation(title, label).then_some("page")] {
                                    span class="nav-index" aria-hidden="true" { ">" } (label)
                                }
                            }
                        }
                        main class="content" id="workspace" tabindex="-1" {
                            div class="window-titlebar" {
                                span { (title) }
                                span aria-hidden="true" { "[ = ]" }
                            }
                            (body)
                            footer class="workspace-footer" { "INFIPROXY / NODE CONTROL" span { "Server-rendered control plane" } }
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
        let rendered = layout("Dashboard", html! { p { "test" } }).into_string();
        assert!(rendered.contains("class=\"app-chrome\""));
        assert!(rendered.contains("aria-label=\"Main navigation\""));
        assert!(rendered.contains("aria-current=\"page\""));
        assert!(rendered.contains("href=\"#workspace\""));
        assert!(!rendered.contains("<script"));
        assert!(PANEL_CSS.contains("--accent:"));
        assert!(PANEL_CSS.contains("prefers-reduced-motion"));
    }
}
