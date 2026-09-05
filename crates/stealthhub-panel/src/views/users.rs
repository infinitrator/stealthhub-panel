//! User lifecycle presentation without exposing credentials in list views.

use crate::{
    admin_bar, csrf_field, format_bytes, format_user_expiry, format_user_traffic, ui::layout,
    views::components::user_sync_badges, AuthenticatedAdmin,
};
use axum::response::{Html, IntoResponse, Response};
use chrono::{DateTime, SecondsFormat, Utc};
use maud::{html, Markup};
use stealthhub_core::storage::{UserRecord, UserSyncStatusRecord};

const GIB_BYTES: i64 = 1024 * 1024 * 1024;

pub(crate) fn render_index(
    auth: &AuthenticatedAdmin,
    users: &[UserRecord],
    user_sync: &[UserSyncStatusRecord],
    now: DateTime<Utc>,
) -> Response {
    Html(
        layout(
            "Users",
            html! {
                (admin_bar(auth))
                h1 { "Users" }

                section {
                    h2 { "Runtime authorization" }
                    p { "Count-only comparison of allowed per-user identities and active runtime configurations." }
                    (user_sync_badges(user_sync, None, None))
                    p { small { "Shared-credential protocols cannot revoke one previously imported credential. Rotate that protocol's shared secret when revocation is required." } }
                }

                section {
                    h2 { "Create user" }
                    form method="post" action="/admin/users/create" class="form" {
                        (csrf_field(&auth.csrf_token))
                        label {
                            span { "Username" }
                            input type="text" name="username" minlength="3" maxlength="64" placeholder="fedor-phone" required;
                        }

                        label {
                            span { "Traffic limit, GiB" }
                            input type="number" name="traffic_limit_gb" min="0" step="1" placeholder="empty = unlimited";
                            small { "Stored access gate only; live traffic collection is not implemented." }
                        }

                        label {
                            span { "Expires in days" }
                            input type="number" name="expires_in_days" min="0" max="3650" step="1" placeholder="empty = never";
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
                                        th { "Effective access" }
                                        th { "Stored traffic / quota" }
                                        th { "Expires" }
                                        th { "Actions" }
                                    }
                                }
                                tbody {
                                    @for user in users {
                                        tr {
                                            td { (user.id) }
                                            td { (user.username) }
                                            td { (access_badges(user, now)) }
                                            td {
                                                (format_user_traffic(user))
                                                br;
                                                small { "No live collector" }
                                            }
                                            td { (format_user_expiry(user)) }
                                            td {
                                                a class="button compact secondary" href=(format!("/admin/users/{}/subscription", user.id)) { "Subscription access" }
                                                a class="button compact" href=(format!("/admin/users/{}/edit", user.id)) { "Edit" }
                                                @if user.enabled {
                                                    form method="post" action=(format!("/admin/users/{}/toggle", user.id)) class="inline-form" {
                                                        (csrf_field(&auth.csrf_token))
                                                        button type="submit" class="secondary compact" { "Disable" }
                                                    }
                                                } @else {
                                                    form method="post" action=(format!("/admin/users/{}/toggle", user.id)) class="inline-form" {
                                                        (csrf_field(&auth.csrf_token))
                                                        button type="submit" class="compact" { "Enable" }
                                                    }
                                                }
                                                a class="button compact secondary" href=(format!("/admin/users/{}/reset-token", user.id)) { "Reset subscription URL" }
                                                a class="button compact secondary" href=(format!("/admin/users/{}/rotate-identity", user.id)) { "Rotate runtime identity" }
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

pub(crate) fn render_edit(auth: &AuthenticatedAdmin, user: &UserRecord) -> Response {
    let traffic_limit_gib = user
        .traffic_limit_bytes
        .map(|value| (value / GIB_BYTES).to_string())
        .unwrap_or_default();
    let expiry = user
        .expires_at
        .map(|value| value.to_rfc3339_opts(SecondsFormat::Nanos, true))
        .unwrap_or_default();
    Html(
        layout(
            "Edit user",
            html! {
                (admin_bar(auth))
                h1 { "Edit user" }
                section {
                    form method="post" action=(format!("/admin/users/{}/edit", user.id)) class="form" {
                        (csrf_field(&auth.csrf_token))
                        input type="hidden" name="expected_updated_at" value=(user.updated_at.to_rfc3339_opts(SecondsFormat::Nanos, true));
                        label {
                            span { "Username" }
                            input type="text" name="username" minlength="3" maxlength="64" value=(&user.username) required;
                            small { "Used as a runtime label by current per-user adapters; changing it queues reconciliation." }
                        }
                        label {
                            span { "Traffic limit, GiB" }
                            input type="number" name="traffic_limit_gb" min="0" step="1" value=(traffic_limit_gib) placeholder="empty = unlimited";
                            small { "Blank or 0 means unlimited. Stored usage is read-only and no live collector is present." }
                        }
                        label {
                            span { "Expiry, UTC" }
                            input type="text" name="expires_at_utc" value=(expiry) placeholder="2030-01-31T05:00:00Z";
                            small { "RFC 3339 in UTC. Blank means never. Access expires exactly at the stated instant." }
                        }
                        label {
                            span { "Stored traffic usage" }
                            input type="text" value=(format_bytes(user.traffic_used_bytes)) readonly;
                            small { "This value cannot be edited from the web interface." }
                        }
                        div class="actions" {
                            button type="submit" { "Save user" }
                            a class="button secondary" href="/admin/users" { "Cancel" }
                        }
                    }
                    div class="notice" {
                        "Blocking access immediately denies subscription responses and removes the user from per-user desired authorization. Shared credentials already imported by a client remain valid until their protocol secret is rotated."
                    }
                }
            },
        )
        .into_string(),
    )
    .into_response()
}

pub(crate) fn render_subscription_access(
    auth: &AuthenticatedAdmin,
    user: &UserRecord,
    account_url: &str,
    yaml_url: &str,
    import_url: &str,
) -> Response {
    Html(
        layout(
            "Subscription access",
            html! {
                (admin_bar(auth))
                h1 { "Subscription access" }
                section {
                    h2 { (user.username) }
                    div class="notice error" {
                        "These bearer URLs grant access to user configuration. Share them only through a trusted channel and do not place them in tickets, logs or screenshots."
                    }
                    div class="form" {
                        label class="full-span" {
                            span { "Account URL" }
                            input type="text" readonly value=(account_url);
                        }
                        label class="full-span" {
                            span { "Mihomo YAML URL" }
                            input type="text" readonly value=(yaml_url);
                        }
                        label class="full-span" {
                            span { "Mihomo one-click import" }
                            input type="text" readonly value=(import_url);
                        }
                    }
                    div class="actions" {
                        a class="button" href=(account_url) rel="noreferrer" { "Open account" }
                        a class="button secondary" href="/admin/users" { "Back to Users" }
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
            "Reset subscription URL",
            html! {
                (admin_bar(auth))
                h1 { "Reset subscription URL" }

                section class="confirm-panel" {
                    h2 { "Confirm subscription token reset" }
                    p {
                        "The old subscription URL for "
                        strong { (user.username) }
                        " will stop working immediately. This does not rotate the runtime UUID or shared protocol credentials."
                    }
                    div class="actions" {
                        form method="post" action=(format!("/admin/users/{}/reset-token", user.id)) class="inline-form" {
                            (csrf_field(&auth.csrf_token))
                            button type="submit" class="danger" { "Reset subscription URL" }
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

pub(crate) fn render_rotate_identity(auth: &AuthenticatedAdmin, user: &UserRecord) -> Response {
    Html(
        layout(
            "Rotate runtime identity",
            html! {
                (admin_bar(auth))
                h1 { "Rotate runtime identity" }
                section class="confirm-panel danger-zone" {
                    h2 { "Confirm UUID rotation" }
                    p {
                        "A new per-user UUID will be generated on the server for "
                        strong { (user.username) }
                        ". The subscription URL, username, quota and expiry remain unchanged."
                    }
                    div class="notice error" {
                        "Rotation reaches the data plane only after the new desired generation is Applied. Previously imported shared credentials are not revoked by UUID rotation."
                    }
                    div class="actions" {
                        form method="post" action=(format!("/admin/users/{}/rotate-identity", user.id)) class="inline-form" {
                            (csrf_field(&auth.csrf_token))
                            input type="hidden" name="expected_updated_at" value=(user.updated_at.to_rfc3339_opts(SecondsFormat::Nanos, true));
                            button type="submit" class="danger" { "Rotate runtime identity" }
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
                        " from the users table and invalidates the subscription URL."
                    }
                    dl class="details" {
                        dt { "Effective access" }
                        dd { (access_badges(user, Utc::now())) }
                        dt { "Stored traffic" }
                        dd { (format_user_traffic(user)) }
                        dt { "Expiry" }
                        dd { (format_user_expiry(user)) }
                    }
                    div class="notice error" {
                        "Per-user runtime authorization converges through the next generation. Shared protocol credentials already known by a client are not individually revoked."
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

fn access_badges(user: &UserRecord, now: DateTime<Utc>) -> Markup {
    let state = user.access_state_at(now);
    html! {
        @if state.allowed() {
            span class="badge ok" { "Active" }
        } @else {
            @if state.disabled { span class="badge off" { "Disabled" } }
            @if state.expired { span class="badge off" { "Expired" } }
            @if state.quota_exceeded { span class="badge off" { "Quota blocked" } }
        }
    }
}
