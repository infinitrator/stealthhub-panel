//! Shared presentation components and error pages.

use crate::{
    is_owner_admin,
    ops::{ServiceState, ServiceStatus},
    ui::layout,
    update, AuthenticatedAdmin,
};
use axum::{
    http::StatusCode,
    response::{Html, IntoResponse, Response},
};
use maud::{html, Markup};

pub(crate) fn csrf_field(token: &str) -> Markup {
    html! { input type="hidden" name="csrf_token" value=(token); }
}

pub(crate) fn service_state_badge(state: &ServiceState) -> Markup {
    let (class, label) = match state.status {
        ServiceStatus::Active => ("ok", "active"),
        ServiceStatus::Inactive => ("neutral", "inactive"),
        ServiceStatus::Failed => ("off", "failed"),
        ServiceStatus::Unknown => ("off", "unknown"),
    };
    html! {
        span class=(format!("badge {class}")) { (label) }
        br;
        small { (&state.unit) }
    }
}

pub(crate) fn meter_bar(percent: Option<u8>) -> Markup {
    let value = percent.unwrap_or(0);
    html! {
        div class="meter" title=(percent.map(|value| format!("{value}%")).unwrap_or_else(|| "unknown".to_string())) {
            div class="meter-fill" style=(format!("width: {value}%")) {}
        }
    }
}

pub(crate) fn admin_bar(auth: &AuthenticatedAdmin) -> Markup {
    html! {
        div class="admin-stack" {
            @if let Some(notice) = &auth.update_notice {
                div class="update-banner" role="status" {
                    div {
                        strong { "Panel update available" }
                        span {
                            " Latest commit " code { (update::short_sha(&notice.latest_sha)) }
                            " is scheduled " (notice.planned_for) "."
                        }
                    }
                    @if is_owner_admin(auth) {
                        form method="post" action="/admin/panel-update-now" class="inline-form" {
                            (csrf_field(&auth.csrf_token))
                            button type="submit" { "Update Now" }
                        }
                    }
                }
            }
            div class="admin-bar" {
                span {
                    "Signed in as " strong { (auth.admin.username) }
                    @if is_owner_admin(auth) {
                        " " span class="badge ok" { "owner" }
                    }
                }
                form method="post" action="/admin/logout" class="inline-form" {
                    (csrf_field(&auth.csrf_token))
                    button type="submit" { "Logout" }
                }
            }
        }
    }
}

pub(crate) fn error_response(
    status: StatusCode,
    title: &'static str,
    message: impl Into<String>,
    back_href: &'static str,
    back_label: &'static str,
) -> Response {
    let message = message.into();
    (
        status,
        Html(
            layout(
                title,
                html! {
                    h1 { (title) }
                    div class="notice error" { (message) }
                    a class="button" href=(back_href) { (back_label) }
                },
            )
            .into_string(),
        ),
    )
        .into_response()
}
