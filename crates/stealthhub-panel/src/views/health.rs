//! Health dashboard presentation.

use crate::{
    ops::{service_state, HostSnapshot, SYSTEM_TARGETS},
    ui::layout,
    views::components::{meter_bar, service_state_badge},
    DEPLOYMENT_MODE,
};
use axum::{
    http::StatusCode,
    response::{Html, IntoResponse, Response},
};
use maud::{html, Markup};

pub(crate) struct Component {
    pub(crate) name: &'static str,
    pub(crate) state: &'static str,
    pub(crate) detail: &'static str,
}

pub(crate) fn render(
    status: StatusCode,
    state_label: &'static str,
    summary: &'static str,
    components: &[Component],
    host: &HostSnapshot,
    uptime: &str,
) -> Response {
    (
        status,
        Html(
            layout(
                "Health",
                html! {
                    h1 { "Health" }
                    section class=(format!("health-hero {}", state_class(state_label))) {
                        div {
                            span class="eyebrow" { "Infiproxy control plane" }
                            h2 { (state_label) }
                            p { (summary) }
                        }
                        div class="health-ring" {
                            span class=(format!("health-led {}", state_class(state_label))) {}
                            strong { (status.as_u16()) }
                            small { (status.canonical_reason().unwrap_or("status")) }
                        }
                    }
                    section {
                        h2 { "Component status" }
                        div class="health-grid" {
                            @for component in components { (component_card(component)) }
                        }
                    }
                    section {
                        h2 { "Runtime statistics" }
                        div class="status-strip compact-status" {
                            div class="metric" { span { "Version" } strong { (env!("CARGO_PKG_VERSION")) } }
                            div class="metric" { span { "Uptime" } strong { (uptime) } }
                            div class="metric" { span { "Deployment" } strong { (DEPLOYMENT_MODE) } }
                            div class="metric" { span { "Probe mode" } strong { "html + plain text" } }
                        }
                    }
                    section {
                        h2 { "Host sensors" }
                        div class="sys-grid" {
                            div class="sys-card" { span { "OS" } strong { (&host.os_name) } small { "Kernel " (&host.kernel) } }
                            div class="sys-card" { span { "Load" } strong { (&host.load_average) } small { "Uptime " (&host.uptime) } }
                            div class="sys-card" { span { "Memory" } strong { (&host.memory_label) } (meter_bar(host.memory_used_percent)) }
                            div class="sys-card" { span { "Root disk" } strong { (&host.disk_label) } (meter_bar(host.disk_used_percent)) }
                        }
                    }
                    section {
                        h2 { "Service sensors" }
                        div class="table-wrap" {
                            table {
                                thead { tr { th { "Target" } th { "State" } th { "Config" } } }
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
                            dt { "Browser" } dd { "HTML health dashboard with component status." }
                            dt { "Automation" } dd { code { "curl -H 'Accept: */*' /health" } " returns " code { "ok" } "." }
                            dt { "Readiness" } dd { code { "/ready" } " includes SQLite connectivity and preserves HTTP status semantics." }
                        }
                    }
                },
            )
            .into_string(),
        ),
    )
        .into_response()
}

fn component_card(component: &Component) -> Markup {
    html! {
        div class="health-card" {
            div class="health-card-head" {
                span class=(format!("health-led {}", state_class(component.state))) {}
                strong { (component.name) }
            }
            p { (component.detail) }
            span class=(format!("badge {}", badge_class(component.state))) { (component.state) }
        }
    }
}

fn state_class(state: &str) -> &'static str {
    match state {
        "ok" | "ready" | "operational" => "ok",
        "warn" | "degraded" => "warn",
        _ => "off",
    }
}

fn badge_class(state: &str) -> &'static str {
    match state_class(state) {
        "ok" => "ok",
        "warn" => "neutral",
        _ => "off",
    }
}
