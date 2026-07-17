//! Project credits page.

use crate::{admin_bar, ui::layout, ui::APP_NAME, AuthenticatedAdmin};
use axum::response::{Html, IntoResponse, Response};
use maud::html;

pub(crate) fn render(auth: &AuthenticatedAdmin) -> Response {
    Html(
        layout(
            "Credits",
            html! {
                (admin_bar(auth))
                h1 { "Credits" }
                section class="product-card" {
                    div {
                        span class="eyebrow" { "control plane" }
                        h2 { (APP_NAME) }
                        p { "Rust, SQLite, systemd and Mihomo-compatible subscriptions." }
                    }
                }
                section {
                    h2 { "Project" }
                    dl class="details" {
                        dt { "Repository" }
                        dd { a href="https://github.com/infinitrator/stealthhub-panel" rel="noreferrer" { "github.com/infinitrator/stealthhub-panel" } }
                        dt { "License" } dd { code { "AGPL-3.0-or-later" } }
                        dt { "Runtime" } dd { code { "Rust + Axum + SQLx + SQLite" } }
                    }
                    a class="button" href="https://github.com/infinitrator/stealthhub-panel" rel="noreferrer" { "Open GitHub" }
                }
                section {
                    h2 { "Components" }
                    div class="table-wrap" {
                        table {
                            thead { tr { th { "Area" } th { "Technology" } th { "Role" } } }
                            tbody {
                                tr { td { "Web" } td { "Axum / Maud" } td { "Server-rendered admin interface" } }
                                tr { td { "Storage" } td { "SQLite / SQLx" } td { "Single-node durable state" } }
                                tr { td { "Subscriptions" } td { "Mihomo YAML" } td { "Client import format" } }
                                tr { td { "Deployment" } td { "systemd" } td { "Bare-metal VPS runtime" } }
                            }
                        }
                    }
                }
            },
        )
        .into_string(),
    )
    .into_response()
}
