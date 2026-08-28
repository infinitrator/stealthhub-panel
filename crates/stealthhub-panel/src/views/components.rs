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
use stealthhub_core::inventory::{
    AdapterInventory, AdapterInventoryState, ResourceInventoryState, RuntimeInventoryState,
};
use stealthhub_core::storage::UserSyncStatusRecord;

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
        progress class="meter" max="100" value=(value)
            title=(percent.map_or_else(|| "unknown".to_string(), |value| format!("{value}%"))) {}
    }
}

pub(crate) fn user_sync_badges(
    records: &[UserSyncStatusRecord],
    profile_id: Option<&str>,
    runtime_id: Option<&str>,
) -> Markup {
    let matches = records
        .iter()
        .filter(|record| profile_id.is_none_or(|value| record.profile_id == value))
        .filter(|record| runtime_id.is_none_or(|value| record.runtime_id == value))
        .collect::<Vec<_>>();
    html! {
        @if matches.is_empty() {
            span class="badge neutral" { "not applicable" }
        } @else {
            @for record in matches {
                @let class = match record.status.as_str() {
                    "synced" => "ok",
                    "pending" => "neutral",
                    _ => "off",
                };
                span class=(format!("badge {class}")) { (&record.status) }
                " "
                small {
                    (record.desired_count) " desired"
                    @if let Some(observed) = record.observed_count { ", " (observed) " observed" }
                    " / " code { (&record.runtime_id) }
                }
                br;
            }
        }
    }
}

pub(crate) fn adapter_inventory_table(inventory: &AdapterInventory, kind: Option<&str>) -> Markup {
    html! {
        div class="table-wrap" {
            table {
                thead { tr { th { "Adapter" } th { "Kind" } th { "State" } th { "Present" } th { "Configured" } th { "Capabilities" } th { "Detail" } } }
                tbody {
                    @for adapter in inventory.adapters.iter().filter(|entry| kind.is_none_or(|kind| entry.kind == kind)) {
                        tr {
                            td { strong { (&adapter.display_name) } br; code { (&adapter.id) } }
                            td { code { (&adapter.kind) } }
                            td { (inventory_badge(adapter_state(adapter.state))) }
                            td { (yes_no(Some(adapter.present))) }
                            td { (yes_no(Some(adapter.configured))) }
                            td { @for capability in &adapter.capabilities { code { (capability) } " " } }
                            td { (&adapter.detail) }
                        }
                    }
                }
            }
        }
    }
}

pub(crate) fn runtime_inventory_table(inventory: &AdapterInventory) -> Markup {
    html! {
        div class="table-wrap" {
            table {
                thead { tr { th { "Runtime" } th { "State" } th { "Installed" } th { "Desired" } th { "Applied" } th { "Active" } th { "Health" } th { "Listeners" } th { "Service / version" } th { "Detail" } } }
                tbody {
                    @for runtime in &inventory.runtimes {
                        tr {
                            td { strong { (&runtime.display_name) } br; code { (&runtime.id) } }
                            td { (inventory_badge(runtime_state(runtime.state))) }
                            td { (yes_no(runtime.installed)) }
                            td { (yes_no(Some(runtime.desired))) }
                            td { (yes_no(Some(runtime.applied))) }
                            td { (yes_no(runtime.active)) }
                            td { (yes_no(runtime.healthy)) }
                            td { (yes_no(runtime.listeners_healthy)) }
                            td { code { (runtime.service.as_deref().unwrap_or("not declared")) } br; small { (runtime.version.as_deref().unwrap_or("version unknown")) } }
                            td { (&runtime.detail) }
                        }
                    }
                }
            }
        }
    }
}

pub(crate) fn resource_inventory_table(inventory: &AdapterInventory) -> Markup {
    html! {
        div class="table-wrap" {
            table {
                thead { tr { th { "Resource" } th { "Adapter" } th { "State" } th { "Enabled" } th { "Desired" } th { "Applied" } th { "Runtime" } th { "Schema" } th { "Detail" } } }
                tbody {
                    @for resource in &inventory.resources {
                        tr {
                            td { strong { (&resource.display_name) } br; code { (&resource.id) } }
                            td { code { (&resource.adapter_id) } }
                            td { (inventory_badge(resource_state(resource.state))) }
                            td { (yes_no(Some(resource.enabled))) }
                            td { (yes_no(Some(resource.desired))) }
                            td { (yes_no(Some(resource.applied))) }
                            td { code { (resource.runtime_id.as_deref().unwrap_or("unassigned")) } }
                            td { (resource.schema_version) }
                            td { (&resource.detail) }
                        }
                    }
                }
            }
        }
    }
}

fn yes_no(value: Option<bool>) -> &'static str {
    match value {
        Some(true) => "yes",
        Some(false) => "no",
        None => "unknown",
    }
}

fn inventory_badge((class, label): (&'static str, &'static str)) -> Markup {
    html! { span class=(format!("badge {class}")) { (label) } }
}

const fn adapter_state(state: AdapterInventoryState) -> (&'static str, &'static str) {
    match state {
        AdapterInventoryState::Available => ("ok", "available"),
        AdapterInventoryState::AdapterOnly => ("neutral", "adapter only"),
        AdapterInventoryState::Historical => ("warn", "historical"),
        AdapterInventoryState::UnsupportedSchema => ("off", "unsupported schema"),
    }
}

const fn runtime_state(state: RuntimeInventoryState) -> (&'static str, &'static str) {
    match state {
        RuntimeInventoryState::AvailableNotInstalled => ("neutral", "not installed"),
        RuntimeInventoryState::InstalledInactive => ("neutral", "installed inactive"),
        RuntimeInventoryState::ActiveHealthy => ("ok", "active healthy"),
        RuntimeInventoryState::ActiveDegraded => ("warn", "active degraded"),
        RuntimeInventoryState::Failed => ("off", "failed"),
        RuntimeInventoryState::MissingAdapter => ("off", "missing adapter"),
    }
}

const fn resource_state(state: ResourceInventoryState) -> (&'static str, &'static str) {
    match state {
        ResourceInventoryState::AdapterOnly => ("neutral", "adapter only"),
        ResourceInventoryState::ConfiguredPending => ("warn", "configured pending"),
        ResourceInventoryState::AppliedHealthy => ("ok", "applied healthy"),
        ResourceInventoryState::AppliedDegraded => ("warn", "applied degraded"),
        ResourceInventoryState::Unsupported => ("off", "unsupported"),
        ResourceInventoryState::CoreUnavailable => ("off", "core unavailable"),
        ResourceInventoryState::Disabled => ("neutral", "disabled"),
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
