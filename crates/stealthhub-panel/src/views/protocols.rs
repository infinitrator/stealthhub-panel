//! Protocols-page presentation and form components.

use crate::{
    admin_bar, csrf_field,
    ui::layout,
    views::components::{adapter_inventory_table, user_sync_badges},
    AuthenticatedAdmin,
};
use axum::response::{Html, IntoResponse, Response};
use maud::{html, Markup};
use stealthhub_core::{
    adapter::{AdapterMaturity, ConfigField, ConfigFieldKind, ProtocolRegistry},
    inventory::{adapter_kind, AdapterInventory, RuntimeInventoryEntry},
    models::{PanelSettings, ProtocolProfile, ProxyRole},
    module_manifest::normalized_release_version,
    storage::{ProtocolProfileRecord, ReconcileStateRecord, UserSyncStatusRecord},
};

pub(crate) struct ProtocolPage<'a> {
    pub settings: &'a PanelSettings,
    pub profiles: &'a [ProtocolProfile],
    pub secret_names: &'a [String],
    pub registry: &'a ProtocolRegistry,
    pub inventory: &'a AdapterInventory,
    pub user_sync: &'a [UserSyncStatusRecord],
    pub reconcile: &'a ReconcileStateRecord,
}

pub(crate) fn render(auth: &AuthenticatedAdmin, page: ProtocolPage<'_>) -> Response {
    let ProtocolPage {
        settings,
        profiles,
        secret_names,
        registry,
        inventory,
        user_sync,
        reconcile,
    } = page;
    Html(
            layout(
                "Protocols",
                html! {
                    (admin_bar(auth))
                    h1 { "Protocols" }
                    div class="actions" {
                        a class="button" href="/admin/protocols/new" { "Create profile" }
                    }

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
                                            th { "Composition" }
                                            th { "Runtime contract" }
                                            th { "Compatibility" }
                                            th { "Role" }
                                            th { "Enabled" }
                                            th { "Endpoint" }
                                            th { "Secrets" }
                                            th { "User sync" }
                                            th { "Desired state" }
                                            th { "Actions" }
                                        }
                                    }
                                    tbody {
                                        @for profile in profiles {
                                            tr {
                                                td {
                                                    strong { (&profile.display_name) }
                                                    br;
                                                    code { (&profile.name) }
                                                }
                                                td { (protocol_label(profile, registry)) }
                                                td { (protocol_composition(profile, registry)) }
                                                td { (runtime_contract(profile, registry, inventory)) }
                                                td { (compatibility_status(profile, registry, inventory)) }
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
                                                td { (user_sync_badges(user_sync, Some(&profile.name), None)) }
                                                td { (reconcile_badge(reconcile)) }
                                                td class="module-actions" {
                                                    a class="button compact" href=(format!("/admin/protocols/{}", profile.name)) { "Inspect" }
                                                }
                                            }
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

fn protocol_profile_editor(
    profile: &ProtocolProfile,
    record: &ProtocolProfileRecord,
    auth: &AuthenticatedAdmin,
    secret_names: &[String],
    registry: &ProtocolRegistry,
) -> Markup {
    html! {
        section class="config-row" {
            div class="config-row-head" {
                h3 { (&profile.display_name) }
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
                input type="hidden" name="expected_updated_at" value=(record.updated_at.to_rfc3339());
                label {
                    span { "Display name" }
                    input type="text" name="display_name" maxlength="96" value=(&profile.display_name) required;
                    small { "Operator label. The stable ID and routing references do not change." }
                }
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

fn reconcile_badge(reconcile: &ReconcileStateRecord) -> Markup {
    if reconcile.status == "failed" || reconcile.status == "recovery-required" {
        html! { span class="badge off" { "failed" } }
    } else if reconcile.desired_generation > reconcile.applied_generation {
        html! { span class="badge neutral" { "pending" } }
    } else {
        html! { span class="badge ok" { "applied" } }
    }
}

pub(crate) fn render_detail(
    auth: &AuthenticatedAdmin,
    profile: &ProtocolProfile,
    record: &ProtocolProfileRecord,
    secret_names: &[String],
    registry: &ProtocolRegistry,
    reconcile: &ReconcileStateRecord,
    references: u64,
) -> Response {
    Html(layout("Profile", html! {
        (admin_bar(auth))
        h1 { (&profile.display_name) }
        div class="actions" { a class="button compact" href="/admin/protocols" { "Back to profiles" } }
        section {
            h2 { "Lifecycle" }
            dl class="details" {
                dt { "Stable ID" } dd { code { (&profile.name) } }
                dt { "Adapter" } dd { code { (&profile.protocol_id) } }
                dt { "Endpoint" } dd { code { (format!("{}:{}", profile.server, profile.port)) } }
                dt { "Preferred runtime" } dd {
                    @if let Some(runtime) = &profile.preferred_core_id {
                        code { (runtime) }
                    } @else {
                        "adapter-selected"
                    }
                }
                dt { "State" } dd { @if profile.enabled { "enabled" } @else { "disabled" } }
                dt { "Desired / applied" } dd { (reconcile.desired_generation) " / " (reconcile.applied_generation) " " (reconcile_badge(reconcile)) }
                dt { "Routing references" } dd { (references) }
                dt { "Revision" } dd { code { (record.updated_at.to_rfc3339()) } }
            }
            @if let Some(error) = &reconcile.last_error { p class="inline-warn" { (error) } }
        }
        (protocol_profile_editor(profile, record, auth, secret_names, registry))
        section class="danger-zone" {
            h2 { "Lifecycle actions" }
            div class="actions" {
                form method="post" action=(format!("/admin/protocols/{}/enabled", profile.name)) class="inline-form" {
                    (csrf_field(&auth.csrf_token))
                    input type="hidden" name="expected_updated_at" value=(record.updated_at.to_rfc3339());
                    input type="hidden" name="enabled" value=(if profile.enabled { "false" } else { "true" });
                    button type="submit" { @if profile.enabled { "Disable" } @else { "Enable" } }
                }
                a class="button compact danger" href=(format!("/admin/protocols/{}/delete", profile.name)) { "Delete" }
            }
        }
    }).into_string()).into_response()
}

pub(crate) fn render_delete(
    auth: &AuthenticatedAdmin,
    profile: &ProtocolProfile,
    record: &ProtocolProfileRecord,
    references: u64,
) -> Response {
    Html(layout("Delete profile", html! {
        (admin_bar(auth))
        h1 { "Delete profile" }
        section class="confirm-panel danger-zone" {
            h2 { (&profile.display_name) }
            p { "This removes the desired-state object. It does not rewrite routing." }
            p { "Stable ID: " code { (&profile.name) } }
            p { "Routing references: " strong { (references) } }
            @if references > 0 { p class="inline-warn" { "Deletion is blocked until these references are removed." } }
            div class="actions" {
                form method="post" action=(format!("/admin/protocols/{}/delete", profile.name)) {
                    (csrf_field(&auth.csrf_token))
                    input type="hidden" name="expected_updated_at" value=(record.updated_at.to_rfc3339());
                    button class="danger" type="submit" disabled[references > 0] { "Delete profile" }
                }
                a class="button" href=(format!("/admin/protocols/{}", profile.name)) { "Cancel" }
            }
        }
    }).into_string()).into_response()
}

pub(crate) fn render_new(
    auth: &AuthenticatedAdmin,
    registry: &ProtocolRegistry,
    selected_adapter: Option<&str>,
    secret_names: &[String],
) -> Response {
    let manifests = registry.manifests();
    let selected = selected_adapter.and_then(|id| registry.get(id));
    Html(layout("Create profile", html! {
        (admin_bar(auth))
        h1 { "Create protocol profile" }
        div class="actions" { a class="button compact" href="/admin/protocols" { "Back to profiles" } }
        section class="config-row" {
            h2 { "Adapter" }
            form method="get" action="/admin/protocols/new" class="config-form" {
                label {
                    span { "Protocol adapter" }
                    select name="adapter" required {
                        option value="" { "Select an adapter" }
                        @for manifest in &manifests {
                            option value=(&manifest.id) selected[selected_adapter == Some(manifest.id.as_str())] {
                                (&manifest.display_name) " (" (&manifest.id) ")"
                            }
                        }
                    }
                }
                button type="submit" { "Load fields" }
            }
        }
        @if let Some(adapter) = selected {
            @let manifest = adapter.manifest();
            @let empty = ProtocolProfile {
                name: String::new(),
                display_name: String::new(),
                protocol_id: manifest.id.clone(),
                schema_version: manifest.schema_version,
                role: ProxyRole::Manual,
                server: String::new(),
                port: 443,
                enabled: false,
                preferred_core_id: manifest.composition.preferred_runtime.as_ref().map(|runtime| runtime.adapter_id.clone()),
                managed_resource_id: None,
                config: serde_json::json!({}),
            };
            section class="config-row" {
                h2 { "Profile parameters" }
                datalist id="secret-names" { @for secret in secret_names { option value=(secret) {} } }
                form method="post" action="/admin/protocols/new" class="config-form" {
                    (csrf_field(&auth.csrf_token))
                    input type="hidden" name="protocol_id" value=(&manifest.id);
                    input type="hidden" name="schema_version" value=(manifest.schema_version);
                    label { span { "Stable ID" } input type="text" name="name" maxlength="64" pattern="[a-z][a-z0-9-]*" required; small { "Permanent routing and runtime identity. It cannot be renamed." } }
                    label { span { "Display name" } input type="text" name="display_name" maxlength="96" required; }
                    label { span { "Role" } select name="role" { option value="auto-safe" { "AUTO-SAFE" } option value="speed" { "SPEED" } option value="compatibility" { "COMPAT" } option value="ru-access" { "RU-ACCESS" } option value="manual" selected { "MANUAL" } } }
                    label class="switch-field" { input type="checkbox" name="enabled"; span class="switch-ui" {} span { strong { "Enabled" } small { "Publish immediately after validation. Keep off until its runtime is installed." } } }
                    label { span { "Server address" } input type="text" name="server" required; }
                    label { span { "Server port" } input type="number" name="port" min="1" max="65535" value="443" required; }
                    @for field in adapter.fields() { (adapter_field(&empty, field, secret_names)) }
                    button type="submit" { "Create profile" }
                }
            }
        }
    }).into_string()).into_response()
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

fn protocol_composition(profile: &ProtocolProfile, registry: &ProtocolRegistry) -> Markup {
    let Some(adapter) = registry.get(&profile.protocol_id) else {
        return html! { span class="badge off" { "unavailable" } };
    };
    let composition = &adapter.manifest().composition;
    let (class, maturity) = match composition.maturity {
        AdapterMaturity::Stable => ("ok", "stable"),
        AdapterMaturity::Experimental => ("neutral", "experimental"),
        AdapterMaturity::Unsupported => ("off", "unsupported"),
    };
    html! {
        code {
            (&composition.protocol) " + " (&composition.transport) " + " (&composition.security)
            @if let Some(flow) = &composition.flow { " + " (flow) }
        }
        br;
        span class=(format!("badge {class}")) { (maturity) }
    }
}

fn runtime_contract(
    profile: &ProtocolProfile,
    registry: &ProtocolRegistry,
    inventory: &AdapterInventory,
) -> Markup {
    let Some(adapter) = registry.get(&profile.protocol_id) else {
        return html! { span class="badge off" { "unavailable" } };
    };
    let composition = &adapter.manifest().composition;
    let Some(runtime) = &composition.preferred_runtime else {
        return html! { span class="badge neutral" { "adapter-defined" } };
    };
    let installed = inventory
        .runtimes
        .iter()
        .find(|candidate| candidate.id == runtime.adapter_id)
        .and_then(|candidate| candidate.version.as_deref())
        .unwrap_or("not installed");
    html! {
        strong { (&runtime.adapter_id) }
        br;
        small { "installed " code { (installed) } }
        br;
        small { "validated " code { (&runtime.version) } }
        @if let Some(fallback) = &composition.fallback_runtime {
            br;
            small { "fallback " code { (&fallback.adapter_id) " " (&fallback.version) } }
        }
    }
}

fn runtime_contract_status(
    runtime: &RuntimeInventoryEntry,
    contract_version: &str,
) -> (&'static str, &'static str) {
    if runtime.installed != Some(true) {
        return ("neutral", "pending runtime");
    }

    // Binary probing, marker validation and release-version normalization belong
    // to the core adapter. Presentation code must not re-interpret display
    // strings such as `1.19.30` and `v1.19.30` as different releases.
    //
    // We still verify that the protocol adapter's declared runtime contract and
    // the core adapter's validated contract describe the same release. This
    // prevents a future protocol/core contract drift from being shown green.
    let declared_contract_matches = runtime
        .validated_version
        .as_deref()
        .and_then(normalized_release_version)
        .zip(normalized_release_version(contract_version))
        .is_some_and(|(runtime_contract, profile_contract)| runtime_contract == profile_contract);

    match (runtime.version_compatible, declared_contract_matches) {
        (Some(true), true) => ("ok", "validated"),
        (Some(false), _) | (Some(true), false) => ("off", "outside contract"),
        (None, _) => ("neutral", "not observed"),
    }
}

fn compatibility_status(
    profile: &ProtocolProfile,
    registry: &ProtocolRegistry,
    inventory: &AdapterInventory,
) -> Markup {
    let Some(adapter) = registry.get(&profile.protocol_id) else {
        return html! { span class="badge off" { "adapter missing" } };
    };
    let composition = &adapter.manifest().composition;
    let status = composition.preferred_runtime.as_ref().and_then(|contract| {
        inventory
            .runtimes
            .iter()
            .find(|runtime| runtime.id == contract.adapter_id)
            .map(|runtime| runtime_contract_status(runtime, &contract.version))
    });
    let (class, label) = status.unwrap_or(("neutral", "not observed"));
    html! {
        span class=(format!("badge {class}")) { (label) }
        @if let Some(baseline) = &composition.client_baseline {
            br;
            small { "client " code { (baseline) } }
        }
        @if let Some(note) = &composition.compatibility_note {
            br;
            small { (note) }
        }
    }
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

#[cfg(test)]
mod protocol_runtime_contract_tests {
    use std::collections::BTreeSet;

    use stealthhub_core::inventory::{RuntimeInventoryEntry, RuntimeInventoryState};

    use super::runtime_contract_status;

    fn runtime(
        version_compatible: Option<bool>,
        validated_version: Option<&str>,
    ) -> RuntimeInventoryEntry {
        RuntimeInventoryEntry {
            id: "mihomo".to_string(),
            display_name: "Mihomo".to_string(),
            state: RuntimeInventoryState::InstalledInactive,
            adapter_present: true,
            installed: Some(true),
            desired: false,
            applied: false,
            active: Some(false),
            healthy: None,
            listeners_healthy: None,
            service: Some("infiproxy-mihomo.service".to_string()),
            // Deliberately lacks the `v` prefix. This is the real presentation
            // shape that previously produced the false "outside contract".
            version: Some("1.19.30".to_string()),
            validated_version: validated_version.map(str::to_string),
            version_compatible,
            telemetry: None,
            capabilities: BTreeSet::new(),
            detail: String::new(),
        }
    }

    #[test]
    fn canonical_probe_prevents_false_v_prefix_mismatch() {
        let observed = runtime(Some(true), Some("v1.19.30"));

        assert_eq!(observed.version.as_deref(), Some("1.19.30"));
        assert_eq!(
            runtime_contract_status(&observed, "v1.19.30"),
            ("ok", "validated")
        );
    }

    #[test]
    fn known_binary_or_marker_mismatch_remains_outside_contract() {
        let observed = runtime(Some(false), Some("v1.19.30"));

        assert_eq!(
            runtime_contract_status(&observed, "v1.19.30"),
            ("off", "outside contract")
        );
    }

    #[test]
    fn protocol_and_core_contract_drift_fails_closed() {
        let observed = runtime(Some(true), Some("v1.20.0"));

        assert_eq!(
            runtime_contract_status(&observed, "v1.19.30"),
            ("off", "outside contract")
        );
    }

    #[test]
    fn unavailable_probe_is_not_misreported_as_version_mismatch() {
        let observed = runtime(None, Some("v1.19.30"));

        assert_eq!(
            runtime_contract_status(&observed, "v1.19.30"),
            ("neutral", "not observed")
        );
    }

    #[test]
    fn missing_runtime_is_pending() {
        let mut observed = runtime(Some(false), Some("v1.19.30"));
        observed.installed = Some(false);

        assert_eq!(
            runtime_contract_status(&observed, "v1.19.30"),
            ("neutral", "pending runtime")
        );
    }
}
