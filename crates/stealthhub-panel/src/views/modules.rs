//! Modules-page presentation.

use crate::{
    admin_bar, csrf_field, is_owner_admin,
    modules::{self, ModuleSpec, ModuleStatus},
    ui::layout,
    views::components::{runtime_inventory_table, user_sync_badges},
    AuthenticatedAdmin,
};
use axum::response::{Html, IntoResponse, Response};
use maud::html;
use stealthhub_core::{inventory::AdapterInventory, storage::UserSyncStatusRecord};

pub(crate) fn render(
    auth: &AuthenticatedAdmin,
    inventory: &AdapterInventory,
    statuses: &[ModuleStatus],
    available: &[ModuleSpec],
    diagnostics: &[String],
    user_sync: &[UserSyncStatusRecord],
) -> Response {
    let installed_count = statuses.iter().filter(|status| status.installed).count();
    let updates_count = statuses
        .iter()
        .filter(|status| status.update_available)
        .count();
    let auto_count = statuses.iter().filter(|status| status.auto_update).count();

    Html(
            layout(
                "Runtimes",
                html! {
                    (admin_bar(auth))
                    h1 { "Runtimes" }

                    @for diagnostic in diagnostics {
                        div class="notice warning" { (diagnostic) }
                    }

                    div class="status-strip" {
                        div class="metric" {
                            span { "Installed" }
                            strong { (installed_count) "/" (statuses.len()) }
                        }
                        div class="metric" {
                            span { "Updates available" }
                            strong { (updates_count) }
                        }
                        div class="metric" {
                            span { "Automatic updates" }
                            strong { (auto_count) "/" (statuses.len()) }
                        }
                        div class="metric" {
                            span { "Upstream check" }
                            strong { "every 2 hours" }
                        }
                    }

                    section {
                        h2 { "Adapter inventory" }
                        (runtime_inventory_table(inventory))
                    }

                    section {
                        div class="section-heading" {
                            div {
                                h2 { "Runtime lifecycle" }
                                p { "Typed lifecycle operations are executed by the root-owned worker; the panel never accepts commands or package URLs." }
                            }
                            @if is_owner_admin(auth) {
                                form method="post" action="/admin/modules/check" class="inline-form" {
                                    (csrf_field(&auth.csrf_token))
                                    button type="submit" { "Check all" }
                                }
                            }
                        }
                        div class="table-wrap" {
                            table {
                                thead {
                                    tr {
                                        th { "Module" }
                                        th { "Role" }
                                        th { "Capabilities / dependents" }
                                        th { "Installed" }
                                        th { "Latest" }
                                        th { "Runtime state" }
                                        th { "User sync" }
                                        th { "Automatic" }
                                        th { "Actions" }
                                    }
                                }
                                tbody {
                                    @for status in statuses {
                                        @let runtime = inventory.runtimes.iter().find(|runtime| runtime.id == status.spec.id);
                                        @let dependent_count = inventory.resources.iter().filter(|resource| resource.enabled && resource.desired && resource.runtime_id.as_deref() == Some(status.spec.id.as_str())).count();
                                        tr {
                                            td {
                                                strong { (status.spec.name) }
                                                br;
                                                small { (status.spec.kind) " / " (status.spec.repo) }
                                            }
                                            td {
                                                (status.spec.role)
                                                br;
                                                small { (status.spec.service) }
                                                br;
                                                small { (status.spec.config_path) }
                                            }
                                            td {
                                                @if let Some(runtime) = runtime {
                                                    @if runtime.capabilities.is_empty() {
                                                        small { "none declared" }
                                                    } @else {
                                                        @for capability in &runtime.capabilities {
                                                            code { (capability) " " }
                                                        }
                                                    }
                                                }
                                                br;
                                                small { (dependent_count) " enabled resource(s)" }
                                            }
                                            td { code { (modules::short_version(&status.installed_version)) } }
                                            td { code { (modules::short_version(&status.latest_version)) } }
                                            td {
                                                span class=(format!("badge {}", modules::status_class(status))) {
                                                    (&status.status)
                                                }
                                                br;
                                                small { "checked " (&status.checked_at) }
                                                @if let Some(runtime) = runtime {
                                                    br;
                                                    small {
                                                        "service "
                                                        @match runtime.active {
                                                            Some(true) => { "active" }
                                                            Some(false) => { "inactive" }
                                                            None => { "unknown" }
                                                        }
                                                        ", health "
                                                        @match runtime.healthy {
                                                            Some(true) => { "healthy" }
                                                            Some(false) => { "degraded" }
                                                            None => { "unknown" }
                                                        }
                                                    }
                                                }
                                            }
                                            td { (user_sync_badges(user_sync, None, Some(&status.spec.id))) }
                                            td {
                                                @if is_owner_admin(auth) {
                                                    form method="post" action=(format!("/admin/modules/{}/auto", status.spec.id)) class="inline-form" {
                                                        (csrf_field(&auth.csrf_token))
                                                        select name="enabled" aria-label=(format!("Automatic updates for {}", status.spec.name)) {
                                                            option value="true" selected[status.auto_update] { "On" }
                                                            option value="false" selected[!status.auto_update] { "Off" }
                                                        }
                                                        button class="compact" type="submit" { "Save" }
                                                    }
                                                } @else if status.auto_update {
                                                    span class="badge ok" { "on" }
                                                } @else {
                                                    span class="badge neutral" { "off" }
                                                }
                                            }
                                            td class="module-actions" {
                                                @if is_owner_admin(auth) {
                                                    form method="post" action=(format!("/admin/modules/{}/check", status.spec.id)) class="inline-form" {
                                                        (csrf_field(&auth.csrf_token))
                                                        button class="compact secondary" type="submit" { "Check" }
                                                    }
                                                    @if status.latest_version != "unknown" && (!status.installed || status.update_available) {
                                                        form method="post" action=(format!("/admin/modules/{}/update", status.spec.id)) class="inline-form" {
                                                            (csrf_field(&auth.csrf_token))
                                                            button class="compact" type="submit" {
                                                                @if status.installed { "Update" } @else { "Install latest" }
                                                            }
                                                        }
                                                    }
                                                    @if status.installed {
                                                        form method="post" action=(format!("/admin/modules/{}/start", status.spec.id)) class="inline-form" {
                                                            (csrf_field(&auth.csrf_token))
                                                            button class="compact secondary" type="submit" { "Start" }
                                                        }
                                                        form method="post" action=(format!("/admin/modules/{}/stop", status.spec.id)) class="inline-form" {
                                                            (csrf_field(&auth.csrf_token))
                                                            button class="compact secondary" type="submit" { "Stop" }
                                                        }
                                                        form method="post" action=(format!("/admin/modules/{}/restart", status.spec.id)) class="inline-form" {
                                                            (csrf_field(&auth.csrf_token))
                                                            button class="compact secondary" type="submit" { "Restart" }
                                                        }
                                                    }
                                                    form method="post" action=(format!("/admin/modules/{}/remove", status.spec.id)) class="inline-form" {
                                                        (csrf_field(&auth.csrf_token))
                                                        input name="confirm" aria-label=(format!("Type {} to remove", status.spec.id)) placeholder=(&status.spec.id) required;
                                                        button class="compact danger" type="submit" disabled[dependent_count > 0] { "Remove" }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }

                    @if is_owner_admin(auth) && !available.is_empty() {
                        section {
                            h2 { "Available catalog" }
                            p { "These manifests are root-owned and can be activated without accepting executable commands or arbitrary URLs from the browser." }
                            div class="table-wrap" {
                                table {
                                    thead { tr { th { "Module" } th { "Role" } th { "Repository" } th { "Action" } } }
                                    tbody {
                                        @for spec in available {
                                            tr {
                                                td { strong { (&spec.name) } br; code { (&spec.id) } }
                                                td { (&spec.role) }
                                                td { code { (&spec.repo) } }
                                                td {
                                                    form method="post" action=(format!("/admin/modules/{}/install", spec.id)) class="inline-form" {
                                                        (csrf_field(&auth.csrf_token))
                                                        button type="submit" { "Install latest" }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }

                    section {
                        h2 { "Runtime contract" }
                        dl class="details" {
                            dt { "Proxy runtimes" }
                            dd { code { "/opt/infiproxy/cores/{core}/{version}" } }
                            dt { "Active version" }
                            dd { code { "/opt/infiproxy/cores/{core}/current" } }
                            dt { "Configs" }
                            dd { code { "/etc/infiproxy-cores/{module}" } " or the manifest-declared path" }
                            dt { "Verification" }
                            dd { "GitHub release digest or official checksum sidecar, followed by a binary smoke test." }
                            dt { "Activation" }
                            dd { "Atomic current symlink switch; active/enabled service state is restored after update." }
                        }
                    }
                },
            )
            .into_string(),
        )
        .into_response()
}
