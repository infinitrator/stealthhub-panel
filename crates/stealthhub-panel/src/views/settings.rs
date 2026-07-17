//! Settings-page presentation.

use crate::{admin_bar, csrf_field, is_owner_admin, ui::layout, update, AuthenticatedAdmin};
use axum::response::{Html, IntoResponse, Response};
use maud::html;
use stealthhub_core::models::PanelSettings;

pub(crate) fn render(
    auth: &AuthenticatedAdmin,
    settings: &PanelSettings,
    update_status: &update::Status,
) -> Response {
    Html(
            layout(
                "Settings",
                html! {
                    (admin_bar(auth))
                    h1 { "Settings" }

                    div class="status-strip" {
                        div class="metric" {
                            span { "Panel name" }
                            strong { (&settings.panel_name) }
                        }
                        div class="metric" {
                            span { "Subscription host" }
                            strong { (&settings.subscription_domain) }
                        }
                        div class="metric" {
                            span { "Node host" }
                            strong { (&settings.node_domain) }
                        }
                        div class="metric" {
                            span { "Config source" }
                            strong { "SQLite settings" }
                        }
                        div class="metric" {
                            span { "Panel update" }
                                    strong { (update::status_label(update_status)) }
                        }
                    }

                    section {
                        h2 { "Global parameters" }
                        form method="post" action="/admin/settings" class="config-form" {
                            (csrf_field(&auth.csrf_token))
                            label {
                                span { "Panel name" }
                                input type="text" name="panel_name" value=(&settings.panel_name) minlength="2" maxlength="80" required;
                                small { "Displayed in generated metadata and admin screens." }
                            }
                            label {
                                span { "Subscription host" }
                                input type="text" name="subscription_domain" value=(&settings.subscription_domain) required;
                                small { "Public HTTPS host used by clients to fetch subscription and rule providers." }
                            }
                            label {
                                span { "Node host" }
                                input type="text" name="node_domain" value=(&settings.node_domain) required;
                                small { "Public host that Mihomo clients use to connect to proxy profiles." }
                            }
                            label {
                                span { "Panel auto-update" }
                                    select name="panel_update_enabled" disabled[!is_owner_admin(auth)] {
                                    option value="true" selected[update_status.enabled] { "Enabled" }
                                    option value="false" selected[!update_status.enabled] { "Disabled" }
                                }
                                small { "Owner-only. GitHub is checked every two hours; a pending update is applied in the maintenance window." }
                            }
                            label {
                                span { "Maintenance time (server time)" }
                                    input type="time" name="panel_update_time" value=(&update_status.schedule_time) step="60" required disabled[!is_owner_admin(auth)];
                                small { "Owner-only. Default: 05:00. Automatic execution starts in the first 15-minute scheduler window at or after this time." }
                            }
                            label {
                                span { "GitHub repository" }
                                input type="text" value=(&update_status.repo) disabled;
                                small { "Pinned by the root-owned bootstrap configuration." }
                            }
                            label {
                                span { "Git reference" }
                                input type="text" value=(&update_status.git_ref) disabled;
                                small { "Change the deployment channel by rerunning bootstrap with --ref." }
                            }
                            div class="full-span" {
                                button type="submit" { "Save Settings" }
                            }
                        }
                    }

                    section {
                        h2 { "Generated client endpoints" }
                        dl class="details" {
                            dt { "Subscription template" }
                            dd { code { (format!("https://{}/sub/{{token}}/mihomo.yaml", settings.subscription_domain)) } }
                            dt { "Rule provider template" }
                            dd { code { (format!("https://{}/rules/{{name}}", settings.subscription_domain)) } }
                            dt { "Proxy endpoint host" }
                            dd { code { (&settings.node_domain) } }
                            dt { "Update checker" }
                            dd { code { (format!("{} / checked {}", update_status.status, update_status.checked_at)) } }
                            dt { "Current commit" }
                            dd { code { (update::short_sha(&update_status.current_sha)) } }
                            dt { "Latest commit" }
                            dd { code { (update::short_sha(&update_status.latest_sha)) } }
                            dt { "Planned update" }
                            dd { code { (&update_status.planned_for) } }
                        }
                    }
                },
            )
            .into_string(),
        )
        .into_response()
}
