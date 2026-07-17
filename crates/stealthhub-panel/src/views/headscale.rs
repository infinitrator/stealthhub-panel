//! Headscale management-page presentation.

use crate::{admin_bar, csrf_field, headscale::HeadscaleSnapshot, ui::layout, AuthenticatedAdmin};
use axum::response::{Html, IntoResponse, Response};
use maud::html;

pub(crate) fn render(
    auth: &AuthenticatedAdmin,
    snapshot: &HeadscaleSnapshot,
    installed: bool,
) -> Response {
    Html(
        layout(
            "Headscale",
            html! {
                (admin_bar(auth))
                h1 { "Headscale" }

                div class="status-strip" {
                    div class="metric" {
                        span { "Module" }
                        strong {
                            @if installed { span class="badge ok" { "installed" } }
                            @else { span class="badge neutral" { "not installed" } }
                        }
                    }
                    div class="metric" { span { "Control state" } strong { (&snapshot.status) } }
                    div class="metric" {
                        span { "Last snapshot" }
                        strong { @if snapshot.updated_at.is_empty() { "never" } @else { (&snapshot.updated_at) } }
                    }
                }

                div class="actions" {
                    form method="post" action="/admin/headscale/refresh" class="inline-form" {
                        (csrf_field(&auth.csrf_token))
                        button type="submit" { "Refresh users and nodes" }
                    }
                    a class="button secondary" href="/admin/configs" { "Open configuration" }
                }

                @if !snapshot.last_result.is_empty() {
                    section class="command-output" {
                        div class="section-heading" {
                            div {
                                h2 { @if snapshot.result_is_secret { "New pre-auth key" } @else { "Last operation" } }
                                @if snapshot.result_is_secret {
                                    p { "This value grants network enrollment. Copy it, then clear it from panel state." }
                                }
                            }
                            form method="post" action="/admin/headscale/clear-result" class="inline-form" {
                                (csrf_field(&auth.csrf_token))
                                button class="compact danger" type="submit" { "Clear result" }
                            }
                        }
                        pre { (&snapshot.last_result) }
                    }
                }

                section {
                    h2 { "Users and enrollment" }
                    div class="config-row" {
                        form method="post" action="/admin/headscale/users/create" class="inline-settings" {
                            (csrf_field(&auth.csrf_token))
                            label {
                                span { "New username" }
                                input name="username" maxlength="63" pattern="[A-Za-z0-9._-]+" required;
                            }
                            button type="submit" { "Create user" }
                        }
                    }
                    div class="config-row" {
                        form method="post" action="/admin/headscale/keys/create" class="inline-settings" {
                            (csrf_field(&auth.csrf_token))
                            label {
                                span { "User ID or login" }
                                input type="number" name="user_id" min="1" required;
                            }
                            label {
                                span { "Lifetime" }
                                input name="expiration" value="24h" pattern="[1-9][0-9]{0,3}[mh]" required;
                            }
                            label class="check-row" { input type="checkbox" name="reusable"; span { "Reusable" } }
                            label class="check-row" { input type="checkbox" name="ephemeral"; span { "Ephemeral node" } }
                            button type="submit" { "Create pre-auth key" }
                        }
                    }
                }

                section class="command-output" {
                    h2 { "Users" }
                    pre { @if snapshot.users.is_empty() { "No snapshot available." } @else { (&snapshot.users) } }
                }

                section class="command-output" {
                    div class="section-heading" {
                        div { h2 { "Nodes" } p { "Expire forces the selected client to authenticate again." } }
                        form method="post" action="/admin/headscale/nodes/expire" class="inline-form" {
                            (csrf_field(&auth.csrf_token))
                            input type="number" min="1" name="node_id" placeholder="Node ID" required;
                            button class="compact danger" type="submit" { "Expire node" }
                        }
                    }
                    pre { @if snapshot.nodes.is_empty() { "No snapshot available." } @else { (&snapshot.nodes) } }
                }
            },
        )
        .into_string(),
    )
    .into_response()
}
