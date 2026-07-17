//! User-management presentation.

use crate::{
    admin_bar, csrf_field, format_bytes, format_user_expiry, format_user_traffic, ui::layout,
    AuthenticatedAdmin,
};
use axum::response::{Html, IntoResponse, Response};
use maud::html;
use stealthhub_core::storage::UserRecord;

pub(crate) fn render_index(auth: &AuthenticatedAdmin, users: &[UserRecord]) -> Response {
    Html(
            layout(
                "Users",
                html! {
                    (admin_bar(auth))
                    h1 { "Users" }

                    section {
                        h2 { "Create user" }
                        form method="post" action="/admin/users/create" class="form" {
                            (csrf_field(&auth.csrf_token))
                            label {
                                span { "Username" }
                                input type="text" name="username" placeholder="fedor-phone" required;
                            }

                            label {
                                span { "Traffic limit, GB" }
                                input type="number" name="traffic_limit_gb" min="0" placeholder="empty = unlimited";
                            }

                            label {
                                span { "Expires in days" }
                                input type="number" name="expires_in_days" min="0" max="3650" placeholder="empty = never";
                            }

                            button type="submit" { "Create" }
                        }
                    }

                    section {
                        h2 { "Existing users" }

                        @if users.is_empty() {
                            p { "No users yet." }
                        } @else {
                            div class="table-wrap" {
                                table {
                                    thead {
                                        tr {
                                            th { "ID" }
                                            th { "Username" }
                                            th { "Enabled" }
                                            th { "UUID" }
                                            th { "Subscription" }
                                            th { "Traffic" }
                                            th { "Expires" }
                                            th { "Actions" }
                                        }
                                    }
                                    tbody {
                                        @for user in users {
                                            tr {
                                                td { (user.id) }
                                                td { (user.username) }
                                                td {
                                                    @if user.enabled {
                                                        span class="badge ok" { "on" }
                                                    } @else {
                                                        span class="badge off" { "off" }
                                                    }
                                                }
                                                td {
                                                    code { (user.uuid) }
                                                }
                                                td {
                                                    code { (format!("/sub/{}", user.subscription_token)) }
                                                    br;
                                                    a href=(format!("/sub/{}", user.subscription_token)) { "open" }
                                                    " "
                                                    a href=(format!("/sub/{}/mihomo.yaml", user.subscription_token)) { "download" }
                                                }
                                                td {
                                                    (format_user_traffic(user))
                                                }
                                                td {
                                                    (format_user_expiry(user))
                                                }
                                                td {
                                                    @if user.enabled {
                                                        form method="post" action=(format!("/admin/users/{}/toggle", user.id)) class="inline-form" {
                                                            (csrf_field(&auth.csrf_token))
                                                            button type="submit" { "Disable" }
                                                        }
                                                    } @else {
                                                        form method="post" action=(format!("/admin/users/{}/toggle", user.id)) class="inline-form" {
                                                            (csrf_field(&auth.csrf_token))
                                                            button type="submit" { "Enable" }
                                                        }
                                                    }

                                                    a class="button compact" href=(format!("/admin/users/{}/reset-token", user.id)) { "Reset token" }
                                                    a class="button compact danger" href=(format!("/admin/users/{}/delete", user.id)) { "Delete" }
                                                }
                                            }
                                        }
                                    }
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

pub(crate) fn render_reset(auth: &AuthenticatedAdmin, user: &UserRecord) -> Response {
    Html(
            layout(
                "Reset token",
                html! {
                    (admin_bar(auth))
                    h1 { "Reset token" }

                    section class="confirm-panel" {
                        h2 { "Confirm subscription token reset" }
                        p {
                            "Old subscription URL for "
                            strong { (user.username) }
                            " will stop working immediately. The user will need the new URL."
                        }
                        dl class="details" {
                            dt { "Current subscription" }
                            dd { code { (format!("/sub/{}/mihomo.yaml", user.subscription_token)) } }
                            dt { "Status" }
                            dd {
                                @if user.enabled {
                                    span class="badge ok" { "on" }
                                } @else {
                                    span class="badge off" { "off" }
                                }
                            }
                        }
                        div class="actions" {
                            form method="post" action=(format!("/admin/users/{}/reset-token", user.id)) class="inline-form" {
                                (csrf_field(&auth.csrf_token))
                                button type="submit" class="danger" { "Reset token" }
                            }
                            a class="button secondary" href="/admin/users" { "Cancel" }
                        }
                    }
                },
            )
            .into_string(),
        )
        .into_response()
}

pub(crate) fn render_delete(auth: &AuthenticatedAdmin, user: &UserRecord) -> Response {
    Html(
            layout(
                "Delete user",
                html! {
                    (admin_bar(auth))
                    h1 { "Delete user" }

                    section class="confirm-panel danger-zone" {
                        h2 { "Confirm user deletion" }
                        p {
                            "This removes "
                            strong { (user.username) }
                            " from the users table and invalidates the subscription token."
                        }
                        dl class="details" {
                            dt { "UUID" }
                            dd { code { (user.uuid) } }
                            dt { "Subscription" }
                            dd { code { (format!("/sub/{}/mihomo.yaml", user.subscription_token)) } }
                            dt { "Traffic" }
                            dd {
                                (format_bytes(user.traffic_used_bytes))
                                " / "
                                @match user.traffic_limit_bytes {
                                    Some(limit) => {
                                        (format_bytes(limit))
                                    },
                                    None => {
                                        "unlimited"
                                    },
                                }
                            }
                        }
                        div class="actions" {
                            form method="post" action=(format!("/admin/users/{}/delete", user.id)) class="inline-form" {
                                (csrf_field(&auth.csrf_token))
                                button type="submit" class="danger" { "Delete user" }
                            }
                            a class="button secondary" href="/admin/users" { "Cancel" }
                        }
                    }
                },
            )
            .into_string(),
        )
        .into_response()
}
