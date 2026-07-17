//! Public subscription account and import page.

use crate::{ui::layout, UserRecord};
use axum::{
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::{Html, IntoResponse, Response},
};
use maud::html;

pub(crate) fn render_invalid() -> Response {
    (
        StatusCode::UNAUTHORIZED,
        Html(
            layout(
                "Subscription",
                html! {
                    h1 { "Subscription" }
                    div class="notice error" { "Invalid subscription token." }
                },
            )
            .into_string(),
        ),
    )
        .into_response()
}

pub(crate) fn render(
    user: &UserRecord,
    block_reason: Option<&str>,
    traffic: &str,
    expiry: &str,
    yaml_url: &str,
    import_url: &str,
) -> Response {
    let mut headers = HeaderMap::new();
    headers.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("no-store, max-age=0"),
    );
    (
        headers,
        Html(
            layout(
                "Subscription",
                html! {
                    h1 { "Subscription" }
                    section {
                        h2 { "Account" }
                        dl class="details" {
                            dt { "User" } dd { code { (&user.username) } }
                            dt { "Status" }
                            dd {
                                @if let Some(reason) = block_reason {
                                    span class="badge off" { (reason) }
                                } @else {
                                    span class="badge ok" { "active" }
                                }
                            }
                            dt { "Traffic" } dd { (traffic) }
                            dt { "Expires" } dd { (expiry) }
                        }
                    }
                    section {
                        h2 { "Client import" }
                        @if block_reason.is_none() {
                            div class="config-list" {
                                div class="config-row" {
                                    div class="config-row-head" {
                                        h3 { "Mihomo / Clash" }
                                        div class="config-row-meta" {
                                            a class="button compact" href=(import_url) { "Import" }
                                            a class="button compact secondary" href=(yaml_url) { "Download YAML" }
                                        }
                                    }
                                    div class="config-form wide" {
                                        label class="full-span" {
                                            span { "Subscription URL" }
                                            input type="text" readonly value=(yaml_url);
                                            small { "Use this URL in Mihomo-compatible clients when one-click import is unavailable." }
                                        }
                                        label class="full-span" {
                                            span { "One-click import URL" }
                                            input type="text" readonly value=(import_url);
                                            small { "Uses the standard Clash import scheme and points back to the YAML subscription." }
                                        }
                                    }
                                }
                            }
                        } @else {
                            div class="notice error" {
                                "Subscription is not available for import until the account state is fixed."
                            }
                        }
                    }
                },
            )
            .into_string(),
        ),
    )
        .into_response()
}
