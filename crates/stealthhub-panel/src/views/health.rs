//! Health dashboard presentation.

use crate::{
    admin_bar,
    ops::{HostSnapshot, ServiceState, CONTROL_PLANE_TARGETS},
    ui::layout,
    views::components::{
        adapter_inventory_table, meter_bar, resource_inventory_table, runtime_inventory_table,
        service_state_badge,
    },
    DEPLOYMENT_MODE,
};
use axum::{
    http::StatusCode,
    response::{Html, IntoResponse, Response},
};
use maud::{html, Markup};
use stealthhub_core::inventory::{adapter_kind, AdapterInventory};

pub(crate) struct Component {
    pub(crate) name: &'static str,
    pub(crate) state: &'static str,
    pub(crate) detail: &'static str,
}

pub(crate) struct Report<'a> {
    pub(crate) status: StatusCode,
    pub(crate) state_label: &'static str,
    pub(crate) summary: &'static str,
    pub(crate) components: &'a [Component],
    pub(crate) host: &'a HostSnapshot,
    pub(crate) service_states: &'a [ServiceState],
    pub(crate) inventory: &'a AdapterInventory,
    pub(crate) uptime: String,
}

pub(crate) fn render(auth: &crate::AuthenticatedAdmin, report: Report<'_>) -> Response {
    (
        report.status,
        Html(
            layout(
                "Health",
                html! {
                    (admin_bar(auth))
                    h1 { "Health" }
                    section class=(format!("health-hero {}", state_class(report.state_label))) {
                        div {
                            span class="eyebrow" { "Infiproxy control plane" }
                            h2 { (report.state_label) }
                            p { (report.summary) }
                        }
                        div class="health-ring" {
                            span class=(format!("health-led {}", state_class(report.state_label))) {}
                            strong { (report.status.as_u16()) }
                            small { (report.status.canonical_reason().unwrap_or("status")) }
                        }
                    }
                    section {
                        h2 { "Component status" }
                        div class="health-grid" {
                            @for component in report.components { (component_card(component)) }
                        }
                    }
                    section {
                        h2 { "Runtime statistics" }
                        div class="status-strip compact-status" {
                            div class="metric" { span { "Version" } strong { (env!("CARGO_PKG_VERSION")) } }
                            div class="metric" { span { "Uptime" } strong { (&report.uptime) } }
                            div class="metric" { span { "Deployment" } strong { (DEPLOYMENT_MODE) } }
                            div class="metric" { span { "Probe mode" } strong { "private dashboard" } }
                        }
                    }
                    section {
                        h2 { "Host sensors" }
                        div class="sys-grid" {
                            div class="sys-card" { span { "OS" } strong { (&report.host.os_name) } small { "Kernel " (&report.host.kernel) } }
                            div class="sys-card" { span { "Load" } strong { (&report.host.load_average) } small { "Uptime " (&report.host.uptime) } }
                            div class="sys-card" { span { "Memory" } strong { (&report.host.memory_label) } (meter_bar(report.host.memory_used_percent)) }
                            div class="sys-card" { span { "Root disk" } strong { (&report.host.disk_label) } (meter_bar(report.host.disk_used_percent)) }
                        }
                    }
                    section {
                        h2 { "Control plane" }
                        div class="table-wrap" {
                            table {
                                thead { tr { th { "Target" } th { "State" } th { "Config" } } }
                                tbody {
                                    @for (target, state) in CONTROL_PLANE_TARGETS.iter().zip(report.service_states) {
                                        tr {
                                            td { strong { (target.name) } }
                                            td { (service_state_badge(state)) }
                                            td { code { (target.config) } }
                                        }
                                    }
                                }
                            }
                        }
                    }
                    section {
                        h2 { "Protocol adapters" }
                        (adapter_inventory_table(report.inventory, Some(adapter_kind::PROTOCOL)))
                    }
                    section {
                        h2 { "Core and runtime adapters" }
                        (adapter_inventory_table(report.inventory, Some(adapter_kind::CORE)))
                        (adapter_inventory_table(report.inventory, Some(adapter_kind::MODULE)))
                    }
                    section {
                        h2 { "Active runtimes" }
                        (runtime_inventory_table(report.inventory))
                    }
                    section {
                        h2 { "Infrastructure resources" }
                        (adapter_inventory_table(report.inventory, Some(adapter_kind::INFRASTRUCTURE)))
                        (resource_inventory_table(report.inventory))
                    }
                    section {
                        h2 { "Probe contract" }
                        dl class="details" {
                            dt { "Browser" } dd { code { "/admin/health" } " requires an authenticated admin session." }
                            dt { "Automation" } dd { code { "curl /health" } " returns only " code { "ok" } "." }
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
