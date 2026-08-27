//! Protocols-page presentation and form components.

use crate::{
    admin_bar, csrf_field, ui::layout, views::components::adapter_inventory_table,
    AuthenticatedAdmin,
};
use axum::response::{Html, IntoResponse, Response};
use maud::{html, Markup};
use stealthhub_core::{
    adapter::{ConfigField, ConfigFieldKind, ProtocolRegistry},
    inventory::{adapter_kind, AdapterInventory},
    models::{PanelSettings, ProtocolProfile, ProxyRole},
};

pub(crate) fn render(
    auth: &AuthenticatedAdmin,
    settings: &PanelSettings,
    profiles: &[ProtocolProfile],
    secret_names: &[String],
    registry: &ProtocolRegistry,
    inventory: &AdapterInventory,
) -> Response {
    Html(
            layout(
                "Protocols",
                html! {
                    (admin_bar(auth))
                    h1 { "Protocols" }

                    div class="status-strip" {
                        div class="metric" {
                            span { "Profiles" }
                            strong { (profiles.len()) }
                        }
                        div class="metric" {
                            span { "Enabled" }
                            strong { (profiles.iter().filter(|profile| profile.enabled).count()) }
                        }
                        div class="metric" {
                            span { "Secrets" }
                            strong { (secret_names.len()) }
                        }
                        div class="metric" {
                            span { "Subscription host" }
                            strong { (&settings.subscription_domain) }
                        }
                    }

                    section {
                        h2 { "Mihomo subscription endpoint" }
                        dl class="details" {
                            dt { "Subscription domain" }
                            dd { code { (&settings.subscription_domain) } }
                            dt { "Node domain" }
                            dd { code { (&settings.node_domain) } }
                        }
                    }

                    section {
                        h2 { "Protocol adapter inventory" }
                        (adapter_inventory_table(inventory, Some(adapter_kind::PROTOCOL)))
                    }

                    section {
                        h2 { "Protocol profiles" }
                        @if profiles.is_empty() {
                            p { "No protocol profiles configured yet." }
                        } @else {
                            div class="table-wrap" {
                                table {
                                    thead {
                                        tr {
                                            th { "Name" }
                                            th { "Kind" }
                                            th { "Role" }
                                            th { "Enabled" }
                                            th { "Endpoint" }
                                            th { "Secrets" }
                                        }
                                    }
                                    tbody {
                                        @for profile in profiles {
                                            tr {
                                                td { code { (&profile.name) } }
                                                td { (protocol_label(profile, registry)) }
                                                td { (proxy_role_label(&profile.role)) }
                                                td {
                                                    @if profile.enabled {
                                                        span class="badge ok" { "on" }
                                                    } @else {
                                                        span class="badge off" { "off" }
                                                    }
                                                }
                                                td { code { (format!("{}:{}", profile.server, profile.port)) } }
                                                td {
                                                    @let required = required_secret_names(profile, registry);
                                                    @let missing = missing_secret_names(&required, secret_names);
                                                    @if required.is_empty() {
                                                        span class="badge ok" { "none" }
                                                    } @else if missing.is_empty() {
                                                        span class="badge ok" { "ready" }
                                                        br;
                                                        @for secret in required {
                                                            code { (secret) }
                                                            " "
                                                        }
                                                    } @else {
                                                        span class="badge off" { "missing" }
                                                        br;
                                                        @for secret in missing {
                                                            code { (secret) }
                                                            " "
                                                        }
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
                        h2 { "Profile parameters" }
                        datalist id="secret-names" {
                            @for secret in secret_names {
                                option value=(secret) {}
                            }
                        }
                        div class="config-list" {
                            @for profile in profiles {
                                (protocol_profile_editor(profile, auth, secret_names, registry))
                            }
                        }
                    }
                },
            )
            .into_string(),
        )
        .into_response()
}

fn protocol_profile_editor(
    profile: &ProtocolProfile,
    auth: &AuthenticatedAdmin,
    secret_names: &[String],
    registry: &ProtocolRegistry,
) -> Markup {
    html! {
        section class="config-row" {
            div class="config-row-head" {
                h3 { (&profile.name) }
                div class="config-row-meta" {
                    span class=(format!("badge {}", if profile.enabled { "ok" } else { "off" })) {
                        @if profile.enabled { "enabled" } @else { "disabled" }
                    }
                    span class="badge neutral" { (protocol_label(profile, registry)) }
                    span class="badge neutral" { (proxy_role_label(&profile.role)) }
                }
            }
            form method="post" action=(format!("/admin/protocols/{}/update", profile.name)) class="config-form" {
                (csrf_field(&auth.csrf_token))
                label class="switch-field" {
                    input type="checkbox" name="enabled" checked[profile.enabled];
                    span class="switch-ui" {}
                    span {
                        strong { "Enabled" }
                        small { "Include this proxy in generated Mihomo subscriptions." }
                    }
                }
                label {
                    span { "Server address" }
                    input type="text" name="server" value=(&profile.server) required;
                    small { "Hostname or IP used by the Mihomo proxy object." }
                }
                label {
                    span { "Server port" }
                    input type="number" name="port" min="1" max="65535" value=(profile.port) required;
                    small { "Remote port used by the client." }
                }
                (protocol_specific_fields(profile, secret_names, registry))
                button type="submit" { "Save profile" }
            }
        }
    }
}

fn protocol_specific_fields(
    profile: &ProtocolProfile,
    secret_names: &[String],
    registry: &ProtocolRegistry,
) -> Markup {
    let Some(adapter) = registry.get(&profile.protocol_id) else {
        return html! { p class="inline-warn" { "The required protocol adapter is not installed." } };
    };
    html! {
        @for field in adapter.fields() {
            (adapter_field(profile, field, secret_names))
        }
    }
}

fn adapter_field(
    profile: &ProtocolProfile,
    field: &ConfigField,
    secret_names: &[String],
) -> Markup {
    let value = profile
        .config
        .get(&field.name)
        .and_then(serde_json::Value::as_str)
        .unwrap_or("");
    html! {
        label {
            span { (&field.label) }
            @if field.kind == ConfigFieldKind::SecretRef {
                input type="text" name=(&field.name) value=(value) list="secret-names" required[field.required];
            } @else {
                input type="text" name=(&field.name) value=(value) required[field.required];
            }
            small {
                (&field.help)
                @if field.kind == ConfigFieldKind::SecretRef && !value.is_empty() {
                    " "
                    @if secret_names.iter().any(|secret| secret == value) {
                        span class="inline-ok" { "present" }
                    } @else {
                        span class="inline-warn" { "missing" }
                    }
                }
            }
        }
    }
}

fn required_secret_names(profile: &ProtocolProfile, registry: &ProtocolRegistry) -> Vec<String> {
    registry
        .get(&profile.protocol_id)
        .and_then(|adapter| adapter.secret_references(&profile.config).ok())
        .unwrap_or_default()
        .into_iter()
        .map(|reference| reference.as_str().to_string())
        .collect()
}

fn missing_secret_names(required: &[String], present_secret_names: &[String]) -> Vec<String> {
    required
        .iter()
        .filter(|name| !present_secret_names.iter().any(|present| present == *name))
        .cloned()
        .collect()
}

fn protocol_label(profile: &ProtocolProfile, registry: &ProtocolRegistry) -> String {
    registry
        .get(&profile.protocol_id)
        .map(|adapter| adapter.manifest().display_name.clone())
        .unwrap_or_else(|| format!("Unavailable: {}", profile.protocol_id))
}

const fn proxy_role_label(role: &ProxyRole) -> &'static str {
    match role {
        ProxyRole::AutoSafe => "AUTO-SAFE",
        ProxyRole::Speed => "SPEED",
        ProxyRole::Compatibility => "COMPAT",
        ProxyRole::RuAccess => "RU-ACCESS",
        ProxyRole::Manual => "MANUAL",
    }
}
