//! Health and readiness endpoints.
//!
//! Browser clients receive a compact HTML operations dashboard, while automation
//! keeps the stable plain-text `/health` and `/ready` contracts expected by load
//! balancers, uptime checks and shell probes.

use axum::{
    extract::State,
    http::{header, HeaderMap, StatusCode},
    response::{Html, IntoResponse, Response},
};
use maud::{html, Markup};
use std::{sync::OnceLock, time::Instant};

use crate::{
    ops::{
        format_duration, host_snapshot, meter_bar, service_state, service_state_badge,
        SYSTEM_TARGETS,
    },
    ui::layout,
    AppState, DEPLOYMENT_MODE,
};

static APP_STARTED_AT: OnceLock<Instant> = OnceLock::new();

pub(crate) fn mark_started() {
    let _ = APP_STARTED_AT.set(Instant::now());
}

pub(crate) async fn health(headers: HeaderMap) -> Response {
    if !wants_html(&headers) {
        return "ok\n".into_response();
    }

    health_dashboard(
        StatusCode::OK,
        "operational",
        "Process liveness probe is passing.",
        html! {
            (health_component("Process", "ok", "Runtime is accepting HTTP requests."))
            (health_component("Router", "ok", "Public and admin routes are registered."))
            (health_component("Security headers", "ok", "Frame, content type, referrer and CSP headers are enforced."))
            (health_component("Probe contract", "ok", "Non-browser clients still receive plain text ok."))
        },
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
        Ok(()) => health_dashboard(
            StatusCode::OK,
            "ready",
            "SQLite readiness probe is passing.",
            html! {
                (health_component("Process", "ok", "Runtime is alive."))
                (health_component("SQLite", "ok", "Database connection returned the expected readiness value."))
                (health_component("Subscriptions", "ok", "Mihomo YAML generation can use persisted settings."))
                (health_component("Admin panel", "ok", "Authenticated control plane is available."))
            },
        ),
        Err((status, message)) => health_dashboard(
            status,
            "degraded",
            message,
            html! {
                (health_component("Process", "ok", "Runtime is alive."))
                (health_component("SQLite", "off", message))
                (health_component("Subscriptions", "off", "Subscription generation may fail until storage recovers."))
                (health_component("Admin panel", "warn", "Login may work, but state-changing operations require database access."))
            },
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

fn health_dashboard(
    status: StatusCode,
    state_label: &'static str,
    summary: &'static str,
    components: Markup,
) -> Response {
    let host = host_snapshot();

    (
        status,
        Html(
            layout(
                "Health",
                html! {
                    h1 { "Health" }

                    section class=(format!("health-hero {}", health_state_class(state_label))) {
                        div {
                            span class="eyebrow" { "Infiproxy control plane" }
                            h2 { (state_label) }
                            p { (summary) }
                        }
                        div class="health-ring" {
                            span class=(format!("health-led {}", health_state_class(state_label))) {}
                            strong { (status.as_u16()) }
                            small { (status.canonical_reason().unwrap_or("status")) }
                        }
                    }

                    section {
                        h2 { "Component status" }
                        div class="health-grid" {
                            (components)
                        }
                    }

                    section {
                        h2 { "Runtime statistics" }
                        div class="status-strip compact-status" {
                            div class="metric" {
                                span { "Version" }
                                strong { (env!("CARGO_PKG_VERSION")) }
                            }
                            div class="metric" {
                                span { "Uptime" }
                                strong { (app_uptime_label()) }
                            }
                            div class="metric" {
                                span { "Deployment" }
                                strong { (DEPLOYMENT_MODE) }
                            }
                            div class="metric" {
                                span { "Probe mode" }
                                strong { "html + plain text" }
                            }
                        }
                    }

                    section {
                        h2 { "Host sensors" }
                        div class="sys-grid" {
                            div class="sys-card" {
                                span { "OS" }
                                strong { (&host.os_name) }
                                small { "Kernel " (&host.kernel) }
                            }
                            div class="sys-card" {
                                span { "Load" }
                                strong { (&host.load_average) }
                                small { "Uptime " (&host.uptime) }
                            }
                            div class="sys-card" {
                                span { "Memory" }
                                strong { (&host.memory_label) }
                                (meter_bar(host.memory_used_percent))
                            }
                            div class="sys-card" {
                                span { "Root disk" }
                                strong { (&host.disk_label) }
                                (meter_bar(host.disk_used_percent))
                            }
                        }
                    }

                    section {
                        h2 { "Service sensors" }
                        div class="table-wrap" {
                            table {
                                thead {
                                    tr {
                                        th { "Target" }
                                        th { "State" }
                                        th { "Config" }
                                    }
                                }
                                tbody {
                                    @for target in SYSTEM_TARGETS {
                                        @let state = service_state(target.units);
                                        tr {
                                            td { strong { (target.name) } }
                                            td { (service_state_badge(&state)) }
                                            td { code { (target.config) } }
                                        }
                                    }
                                }
                            }
                        }
                    }

                    section {
                        h2 { "Probe contract" }
                        dl class="details" {
                            dt { "Browser" }
                            dd { "HTML health console with component status." }
                            dt { "Automation" }
                            dd { code { "curl -H 'Accept: */*' /health" } " returns " code { "ok" } "." }
                            dt { "Readiness" }
                            dd { code { "/ready" } " includes SQLite connectivity and preserves HTTP status semantics." }
                        }
                    }
                },
            )
            .into_string(),
        ),
    )
        .into_response()
}

fn health_component(name: &'static str, state: &'static str, detail: &'static str) -> Markup {
    html! {
        div class="health-card" {
            div class="health-card-head" {
                span class=(format!("health-led {}", health_state_class(state))) {}
                strong { (name) }
            }
            p { (detail) }
            span class=(format!("badge {}", health_badge_class(state))) { (state) }
        }
    }
}

fn health_state_class(state: &str) -> &'static str {
    match state {
        "ok" | "ready" | "operational" => "ok",
        "warn" | "degraded" => "warn",
        _ => "off",
    }
}

fn health_badge_class(state: &str) -> &'static str {
    match health_state_class(state) {
        "ok" => "ok",
        "warn" => "neutral",
        _ => "off",
    }
}

pub(crate) fn app_uptime_label() -> String {
    APP_STARTED_AT
        .get()
        .map(|started_at| format_duration(started_at.elapsed().as_secs()))
        .unwrap_or_else(|| "starting".to_string())
}
