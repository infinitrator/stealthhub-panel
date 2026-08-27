//! Health and readiness endpoints.
//!
//! Public probes remain minimal and stable for load balancers. Detailed host and
//! service diagnostics are rendered only after admin authentication.

use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use std::{sync::OnceLock, time::Instant};

use crate::{
    ops::{format_duration, host_snapshot},
    views::health::{Component, Report},
    AppState,
};

static APP_STARTED_AT: OnceLock<Instant> = OnceLock::new();

pub(crate) fn mark_started() {
    let _ = APP_STARTED_AT.set(Instant::now());
}

pub(crate) async fn health() -> &'static str {
    "ok\n"
}

pub(crate) async fn readiness(State(state): State<AppState>) -> Response {
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

    match readiness {
        Ok(()) => (StatusCode::OK, "ready\n").into_response(),
        Err((status, _)) => (status, "not ready\n").into_response(),
    }
}

pub(crate) async fn admin_health(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let auth = match crate::require_admin(&state, &headers).await {
        Ok(value) => value,
        Err(response) => return response,
    };
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

    let host = host_snapshot().await;
    let service_states = crate::ops::control_plane_service_states().await;
    let inventory =
        match crate::inventory::load(&state.pool, &state.protocol_registry, &state.core_registry)
            .await
        {
            Ok(value) => value.inventory,
            Err(error) => {
                tracing::warn!("health inventory unavailable: {error}");
                Default::default()
            }
        };
    let context = DashboardContext {
        host: &host,
        service_states: &service_states,
        inventory: &inventory,
    };
    match readiness {
        Ok(()) => render_dashboard(
            &auth,
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
                    state: "warn",
                    detail: "Storage is available; each request still validates enabled profiles and required secrets.",
                },
                Component {
                    name: "Admin panel",
                    state: "ok",
                    detail: "Authenticated control plane is available.",
                },
            ],
            context,
        ),
        Err((status, message)) => render_dashboard(
            &auth,
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
            context,
        ),
    }
}

#[derive(Clone, Copy)]
struct DashboardContext<'a> {
    host: &'a crate::ops::HostSnapshot,
    service_states: &'a [crate::ops::ServiceState],
    inventory: &'a stealthhub_core::inventory::AdapterInventory,
}

fn render_dashboard(
    auth: &crate::AuthenticatedAdmin,
    status: StatusCode,
    state_label: &'static str,
    summary: &'static str,
    components: &[Component],
    context: DashboardContext<'_>,
) -> Response {
    crate::views::health::render(
        auth,
        Report {
            status,
            state_label,
            summary,
            components,
            host: context.host,
            service_states: context.service_states,
            inventory: context.inventory,
            uptime: app_uptime_label(),
        },
    )
}

pub(crate) fn app_uptime_label() -> String {
    APP_STARTED_AT.get().map_or_else(
        || "starting".to_string(),
        |started_at| format_duration(started_at.elapsed().as_secs()),
    )
}
