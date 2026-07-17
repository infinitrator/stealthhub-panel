//! Modules-page presentation.

use crate::{
    admin_bar, csrf_field, is_owner_admin,
    modules::{self, ModuleSpec, ModuleStatus},
    ui::layout,
    AuthenticatedAdmin,
};
use axum::response::{Html, IntoResponse, Response};
use maud::html;

pub(crate) fn render(
    auth: &AuthenticatedAdmin,
    statuses: &[ModuleStatus],
    available: &[ModuleSpec],
) -> Response {
    let installed_count = statuses.iter().filter(|status| status.installed).count();
    let updates_count = statuses
        .iter()
        .filter(|status| status.update_available)
        .count();
    let auto_count = statuses.iter().filter(|status| status.auto_update).count();

    Html(
            layout(
                "Modules",
                html! {
                    (admin_bar(auth))
                    h1 { "Modules" }

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
                        div class="section-heading" {
                            div {
                                h2 { "Runtime registry" }
                                p { "Each runtime keeps its own binary, configuration, systemd state and update history." }
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
                                        th { "Installed" }
                                        th { "Latest" }
                                        th { "State" }
                                        th { "Automatic" }
                                        th { "Actions" }
                                    }
                                }
                                tbody {
                                    @for status in statuses {
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
                                            td { code { (modules::short_version(&status.installed_version)) } }
                                            td { code { (modules::short_version(&status.latest_version)) } }
                                            td {
                                                span class=(format!("badge {}", modules::status_class(status))) {
                                                    (&status.status)
                                                }
                                                br;
                                                small { "checked " (&status.checked_at) }
                                            }
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
                                                    form method="post" action=(format!("/admin/modules/{}/remove", status.spec.id)) class="inline-form" {
                                                        (csrf_field(&auth.csrf_token))
                                                        input name="confirm" aria-label=(format!("Type {} to remove", status.spec.id)) placeholder=(&status.spec.id) required;
                                                        button class="compact danger" type="submit" { "Remove" }
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
                        h2 { "Module contract" }
                        dl class="details" {
                            dt { "Proxy runtimes" }
                            dd { code { "/opt/infiproxy/cores/{core}/{version}" } }
                            dt { "Headscale runtime" }
                            dd { code { "/opt/infiproxy/modules/headscale/{version}" } }
                            dt { "Active version" }
                            dd { code { "/opt/infiproxy/cores/{core}/current" } }
                            dt { "Configs" }
                            dd { code { "/etc/infiproxy-cores/{core} and /etc/headscale" } }
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
