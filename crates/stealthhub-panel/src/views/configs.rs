//! Configuration-workbench presentation.

use crate::{
    admin_bar, csrf_field,
    ops::{ConfigFileSnapshot, ConfigWriteReport},
    ui::layout,
    AuthenticatedAdmin,
};
use axum::{
    http::StatusCode,
    response::{Html, IntoResponse, Response},
};
use maud::{html, Markup};

pub(crate) fn render_index(
    auth: &AuthenticatedAdmin,
    snapshots: &[ConfigFileSnapshot],
) -> Response {
    Html(
            layout(
                "Configs",
                html! {
                    (admin_bar(auth))
                    h1 { "Configs" }

                    div class="status-strip" {
                        div class="metric" {
                            span { "Allowlisted files" }
                            strong { (snapshots.len()) }
                        }
                        div class="metric" {
                            span { "Readable" }
                            strong { (snapshots.iter().filter(|item| item.status == "ready").count()) }
                        }
                        div class="metric" {
                            span { "Editable" }
                            strong { (snapshots.iter().filter(|item| item.spec.editable).count()) }
                        }
                        div class="metric" {
                            span { "Shell access" }
                            strong { "none" }
                        }
                    }

                    section {
                        h2 { "Config workbench" }
                        div class="notice" {
                            "Only allowlisted panel-managed files are editable. Root-owned SSH and Nginx files stay read-only and must be changed through "
                            code { "sudo infiproxy-manager" }
                            ". Every web save creates a sibling backup before an atomic write."
                        }
                        div class="config-list" {
                            @for snapshot in snapshots {
                                (config_editor_card(snapshot, auth))
                            }
                        }
                    }

                    section {
                        h2 { "Operational checklist" }
                        div class="table-wrap" {
                            table {
                                thead {
                                    tr {
                                        th { "Change" }
                                        th { "Validate" }
                                        th { "Apply" }
                                    }
                                }
                                tbody {
                                    @for snapshot in snapshots {
                                        @let spec = &snapshot.spec;
                                        tr {
                                            td { strong { (spec.name) } br; code { (spec.path) } }
                                            td { code { (spec.validate_hint) } }
                                            td { code { (spec.reload_hint) } }
                                        }
                                    }
                                }
                            }
                        }
                    }
                },
            )
            .into_string(),
        )
        .into_response()
}

fn config_editor_card(snapshot: &ConfigFileSnapshot, auth: &AuthenticatedAdmin) -> Markup {
    let status_class = if snapshot.status == "ready" {
        "ok"
    } else if snapshot.exists {
        "warn"
    } else {
        "neutral"
    };

    html! {
        section class="config-row" {
            div class="config-row-head" {
                h3 { (snapshot.spec.name) }
                div class="config-row-meta" {
                    span class=(format!("badge {status_class}")) { (&snapshot.status) }
                    span class="badge neutral" { (snapshot.spec.category) }
                    span class="badge neutral" { (snapshot.spec.syntax) }
                    @if snapshot.spec.editable {
                        span class="badge ok" { "editable" }
                    } @else {
                        span class="badge neutral" { "root read-only" }
                    }
                }
            }
            form method="post" action="/admin/configs" class="config-form wide" {
                (csrf_field(&auth.csrf_token))
                input type="hidden" name="target" value=(snapshot.spec.slug);
                label {
                    span { "Path" }
                    input type="text" value=(snapshot.spec.path) readonly;
                    small { (snapshot.spec.description) }
                }
                label {
                    span { "Limits" }
                    input type="text" value=(format!("{} bytes now, {} bytes max", snapshot.bytes, snapshot.spec.max_bytes)) readonly;
                    small { "Large files are intentionally not loaded into the browser editor." }
                }
                label class="full-span" {
                    span { "Content" }
                    textarea class="code-editor" name="content" rows="18" spellcheck="false" readonly[!snapshot.spec.editable] {
                        (&snapshot.content)
                    }
                    small {
                        "Validate: " code { (snapshot.spec.validate_hint) }
                        " | Apply: " code { (snapshot.spec.reload_hint) }
                    }
                }
                @if snapshot.spec.editable {
                    button type="submit" { "Save with backup" }
                } @else {
                    small { "Web saving is disabled for this root-owned target." }
                }
            }
        }
    }
}

pub(crate) fn render_save(
    auth: &AuthenticatedAdmin,
    report: &ConfigWriteReport,
    status: StatusCode,
) -> Response {
    (
        status,
        Html(
            layout(
                "Config save",
                html! {
                    (admin_bar(auth))
                    h1 { "Config save" }

                    section class="config-row" {
                        div class="config-row-head" {
                            h3 { (report.spec.name) }
                            @if report.success {
                                span class="badge ok" { "saved" }
                            } @else {
                                span class="badge off" { "failed" }
                            }
                        }
                        dl class="details" {
                            dt { "Path" }
                            dd { code { (report.spec.path) } }
                            dt { "Result" }
                            dd { (report.message) }
                            @if let Some(path) = &report.backup_path {
                                dt { "Backup" }
                                dd { code { (path) } }
                            }
                            dt { "Validate" }
                            dd { code { (report.spec.validate_hint) } }
                            dt { "Apply" }
                            dd { code { (report.spec.reload_hint) } }
                        }
                        div class="actions" {
                            a class="button" href="/admin/configs" { "Back to Configs" }
                            a class="button" href="/admin/system" { "Open System actions" }
                        }
                    }
                },
            )
            .into_string(),
        ),
    )
        .into_response()
}
