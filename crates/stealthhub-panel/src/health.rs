//! Health and readiness endpoints.
//!
//! Browser clients receive a compact HTML operations dashboard, while automation
//! keeps the stable plain-text `/health` and `/ready` contracts expected by load
//! balancers, uptime checks and shell probes.

use axum::{
    extract::State,
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use std::{sync::OnceLock, time::Instant};

use crate::{
    ops::{format_duration, host_snapshot},
    views::health::Component,
    AppState,
};

static APP_STARTED_AT: OnceLock<Instant> = OnceLock::new();

pub(crate) fn mark_started() {
    let _ = APP_STARTED_AT.set(Instant::now());
}

pub(crate) async fn health(headers: HeaderMap) -> Response {
    if !wants_html(&headers) {
        return "ok\n".into_response();
    }

    render_dashboard(
        StatusCode::OK,
        "operational",
        "Process liveness probe is passing.",
        &[
            Component {
                name: "Process",
                state: "ok",
                detail: "Runtime is accepting HTTP requests.",
            },
            Component {
                name: "Router",
                state: "ok",
                detail: "Public and admin routes are registered.",
            },
            Component {
                name: "Security headers",
                state: "ok",
                detail: "Frame, content type, referrer and CSP headers are enforced.",
            },
            Component {
                name: "Probe contract",
                state: "ok",
                detail: "Non-browser clients still receive plain text ok.",
            },
        ],
    )
}

pub(crate) async fn readiness(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let readiness = match sqlx::query_scalar::<_, i64>("SELECT 1")
        .fetch_one(&state.pool)
        .await
    {
        Ok(1) => Ok(()),
        Ok(_) => Err((
            StatusCode::SERVICE_UNAVAILABLE,
            "database readiness probe returned an unexpected value",
        )),
        Err(_) => Err((StatusCode::SERVICE_UNAVAILABLE, "database is not ready")),
    };

    if !wants_html(&headers) {
        return match readiness {
            Ok(()) => (StatusCode::OK, "ready\n").into_response(),
            Err((status, message)) => (status, format!("{message}\n")).into_response(),
        };
    }

    match readiness {
        Ok(()) => render_dashboard(
            StatusCode::OK,
            "ready",
            "SQLite readiness probe is passing.",
            &[
                Component {
                    name: "Process",
                    state: "ok",
                    detail: "Runtime is alive.",
                },
                Component {
                    name: "SQLite",
                    state: "ok",
                    detail: "Database connection returned the expected readiness value.",
                },
                Component {
                    name: "Subscriptions",
                    state: "ok",
                    detail: "Mihomo YAML generation can use persisted settings.",
                },
                Component {
                    name: "Admin panel",
                    state: "ok",
                    detail: "Authenticated control plane is available.",
                },
            ],
        ),
        Err((status, message)) => render_dashboard(
            status,
            "degraded",
            message,
            &[
                Component {
                    name: "Process",
                    state: "ok",
                    detail: "Runtime is alive.",
                },
                Component {
                    name: "SQLite",
                    state: "off",
                    detail: message,
                },
                Component {
                    name: "Subscriptions",
                    state: "off",
                    detail: "Subscription generation may fail until storage recovers.",
                },
                Component {
                    name: "Admin panel",
                    state: "warn",
                    detail:
                        "Login may work, but state-changing operations require database access.",
                },
            ],
        ),
    }
}

pub(crate) fn wants_html(headers: &HeaderMap) -> bool {
    headers
        .get(header::ACCEPT)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| {
            value
                .split(',')
                .any(|part| part.trim_start().starts_with("text/html"))
        })
}

fn render_dashboard(
    status: StatusCode,
    state_label: &'static str,
    summary: &'static str,
    components: &[Component],
) -> Response {
    let host = host_snapshot();
    crate::views::health::render(
        status,
        state_label,
        summary,
        components,
        &host,
        &app_uptime_label(),
    )
}

pub(crate) fn app_uptime_label() -> String {
    APP_STARTED_AT
        .get()
        .map(|started_at| format_duration(started_at.elapsed().as_secs()))
        .unwrap_or_else(|| "starting".to_string())
}
