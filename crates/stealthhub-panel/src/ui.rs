//! Server-rendered UI shell for the Infiproxy panel.
//!
//! The layout is intentionally static CSS and Maud markup: no client-side build
//! pipeline, no JavaScript dependency and fast rendering on small VPS machines.

use maud::{html, Markup, PreEscaped, DOCTYPE};

pub(crate) const APP_NAME: &str = "Infiproxy";
const PANEL_CSS: &str = include_str!("assets/panel.css");

pub(crate) fn layout(title: &str, body: Markup) -> Markup {
    html! {
        (DOCTYPE)
        html lang="ru" {
            head {
                meta charset="utf-8";
                meta name="viewport" content="width=device-width, initial-scale=1";
                title { (title) }
                style {
                    (PreEscaped(PANEL_CSS))
                }
            }
            body {
                div class="app-chrome" {
                    header class="masthead" {
                        div class="masthead-title" {
                            span { (APP_NAME) }
                        }
                        div class="masthead-meta" { "control plane" }
                    }
                    div class="layout-shell" {
                        nav class="top-nav" aria-label="Main navigation" {
                            div class="nav-section" { "Operate" }
                            a href="/" { "Home" }
                            a href="/admin" { "Dashboard" }
                            a href="/admin/users" { "Users" }
                            a href="/admin/settings" { "Settings" }
                            a href="/admin/protocols" { "Protocols" }
                            a href="/admin/routing" { "Routing" }
                            a href="/admin/cores" { "Modules" }
                            a href="/admin/ip" { "IP Check" }
                            div class="nav-section" { "Maintenance" }
                            a href="/admin/system" { "System" }
                            a href="/admin/configs" { "Configs" }
                            a href="/health" { "Health" }
                            a href="/admin/credits" { "Credits" }
                        }
                        main class="content" {
                            (body)
                        }
                    }
                }
            }
        }
    }
}
