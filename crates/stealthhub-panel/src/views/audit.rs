//! Owner-only, bounded administrative audit history.

use crate::{admin_bar, ui::layout, AuthenticatedAdmin};
use axum::response::{Html, IntoResponse, Response};
use maud::html;
use stealthhub_core::{audit::AuditMetadata, storage::AuditEventRecord};

fn safe_metadata(value: &str) -> String {
    serde_json::from_str::<AuditMetadata>(value)
        .and_then(|metadata| serde_json::to_string(&metadata))
        .unwrap_or_else(|_| "[invalid metadata]".to_string())
}

pub(crate) fn render(
    auth: &AuthenticatedAdmin,
    events: &[AuditEventRecord],
    page: u32,
    has_next: bool,
) -> Response {
    let previous = page.saturating_sub(1);
    Html(layout("Audit", html! {
        (admin_bar(auth))
        h1 { "Administrative audit" }
        p class="muted" { "Append-only application history. A requested privileged action is not a completion result." }
        div class="table-wrap" { table {
            thead { tr { th { "UTC" } th { "Actor" } th { "Action" } th { "Object" } th { "Outcome" } th { "Metadata" } } }
            tbody {
                @if events.is_empty() { tr { td colspan="6" { "No audit events." } } }
                @for event in events {
                    tr class="audit-row" {
                        td { time { (event.created_at.to_rfc3339()) } }
                        td { (event.actor_username) " (" (event.actor_role) ")" }
                        td { code { (event.action) } }
                        td { (event.object_type) ":" (event.object_id) }
                        td { (event.outcome) }
                        td { code { (safe_metadata(&event.metadata_json)) } }
                    }
                }
            }
        } }
        nav class="pagination actions" aria-label="Audit pagination" {
            @if page > 0 { a class="button" href=(format!("/admin/audit?page={previous}")) { "Newer" } }
            @if has_next { a class="button" href=(format!("/admin/audit?page={}", page + 1)) { "Older" } }
        }
    }).into_string()).into_response()
}
