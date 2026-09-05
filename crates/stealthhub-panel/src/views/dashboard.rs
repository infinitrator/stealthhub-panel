//! Dashboard presentation.

use crate::{admin_bar, ui::layout, AuthenticatedAdmin};
use axum::response::{Html, IntoResponse, Response};
use maud::html;
use stealthhub_core::{inventory::AdapterInventory, storage::ReconcileStateRecord};

pub(crate) fn render(
    auth: &AuthenticatedAdmin,
    reconcile: &ReconcileStateRecord,
    inventory: &AdapterInventory,
) -> Response {
    Html(
            layout(
                "Dashboard",
                html! {
                    (admin_bar(auth))
                    h1 { "Dashboard" }

                    div class="status-strip" {
                        div class="metric" {
                            span { "Desired generation" }
                            strong { (reconcile.desired_generation) }
                        }
                        div class="metric" {
                            span { "Applied generation" }
                            strong { (reconcile.applied_generation) }
                        }
                        div class="metric" {
                            span { "Reconciliation" }
                            strong { (&reconcile.status) }
                        }
                        div class="metric" {
                            span { "Adapters" }
                            strong { (inventory.adapters.len()) }
                        }
                        div class="metric" {
                            span { "Runtimes" }
                            strong { (inventory.runtimes.len()) }
                        }
                        div class="metric" {
                            span { "Resources" }
                            strong { (inventory.resources.len()) }
                        }
                    }

                    @if let Some(error) = &reconcile.last_error {
                        div class="notice warning" { strong { "Last operation: " } (error) }
                    }

                    div class="grid" {
                        section {
                            h2 { "Users" }
                            p { "Effective access, expiry, quota and identity rotation." }
                            a class="button" href="/admin/users" { "Open Users" }
                        }

                        section {
                            h2 { "Settings" }
                            p { "Panel name, subscription host, node host." }
                            a class="button" href="/admin/settings" { "Open Settings" }
                        }

                        section {
                            h2 { "Protocols" }
                            p { "Enabled profiles, endpoint, SNI, transport path, secret names." }
                            a class="button" href="/admin/protocols" { "Open Protocols" }
                        }

                        section {
                            h2 { "Routing" }
                            p { "Mihomo rule providers, RULE-SET targets, classical payload." }
                            a class="button" href="/admin/routing" { "Open Routing" }
                        }

                        section {
                            h2 { "System" }
                            p { "Bind address, SQLite readiness, cookie mode, service paths." }
                            a class="button" href="/admin/system" { "Open System" }
                        }

                        section {
                            h2 { "Modules" }
                            p { "Independent versions, update policies, services and configuration paths." }
                            a class="button" href="/admin/cores" { "Open Modules" }
                        }
                    }
                },
            )
            .into_string(),
        )
        .into_response()
}
