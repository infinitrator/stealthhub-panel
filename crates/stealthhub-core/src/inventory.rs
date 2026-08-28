//! Unified, protocol-agnostic adapter/runtime/resource inventory.
//!
//! Inventory is observational. Callers supply registry, persistence and probe
//! facts; one malformed or unavailable runtime becomes a degraded entry rather
//! than an error for the complete inventory.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{
    adapter::{CoreAdapterManifest, CoreRuntimeProbe, ProtocolAdapterManifest},
    desired::InfrastructureResource,
    models::ProtocolProfile,
};

/// Stable persistence namespaces. Unknown strings remain valid durable data.
pub mod adapter_kind {
    pub const PROTOCOL: &str = "protocol";
    pub const CORE: &str = "core";
    pub const INFRASTRUCTURE: &str = "infrastructure";
    pub const MODULE: &str = "module";
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum AdapterInventoryState {
    Available,
    AdapterOnly,
    Historical,
    UnsupportedSchema,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum RuntimeInventoryState {
    AvailableNotInstalled,
    InstalledInactive,
    ActiveHealthy,
    ActiveDegraded,
    Failed,
    MissingAdapter,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum ResourceInventoryState {
    AdapterOnly,
    ConfiguredPending,
    AppliedHealthy,
    AppliedDegraded,
    Unsupported,
    CoreUnavailable,
    Disabled,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AdapterInventoryEntry {
    pub id: String,
    pub kind: String,
    pub display_name: String,
    pub state: AdapterInventoryState,
    pub present: bool,
    pub configured: bool,
    pub schema_version: Option<u32>,
    pub capabilities: BTreeSet<String>,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RuntimeInventoryEntry {
    pub id: String,
    pub display_name: String,
    pub state: RuntimeInventoryState,
    pub adapter_present: bool,
    pub installed: Option<bool>,
    pub desired: bool,
    pub applied: bool,
    pub active: Option<bool>,
    pub healthy: Option<bool>,
    pub listeners_healthy: Option<bool>,
    pub service: Option<String>,
    pub version: Option<String>,
    pub capabilities: BTreeSet<String>,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ResourceInventoryEntry {
    pub id: String,
    pub adapter_id: String,
    pub kind: String,
    pub display_name: String,
    pub state: ResourceInventoryState,
    pub adapter_present: bool,
    pub enabled: bool,
    pub desired: bool,
    pub applied: bool,
    pub runtime_id: Option<String>,
    pub schema_version: u32,
    pub detail: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct AdapterInventory {
    pub adapters: Vec<AdapterInventoryEntry>,
    pub runtimes: Vec<RuntimeInventoryEntry>,
    pub resources: Vec<ResourceInventoryEntry>,
    pub desired_generation: u64,
    pub applied_generation: u64,
    pub reconcile_status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PersistedAdapterState {
    pub adapter_id: String,
    pub adapter_kind: String,
    pub resource_id: String,
    pub schema_version: u32,
    pub config: Value,
    pub enabled: bool,
}

#[derive(Debug, Clone, Default)]
pub struct RuntimeInventoryFact {
    pub id: String,
    pub adapter_kind: String,
    pub display_name: String,
    pub service: Option<String>,
    pub capabilities: BTreeSet<String>,
    pub adapter_present: bool,
    pub state_schema_version: u32,
    pub probe: CoreRuntimeProbe,
}

pub struct InventoryFacts<'a> {
    pub protocol_manifests: &'a [ProtocolAdapterManifest],
    pub core_manifests: &'a [CoreAdapterManifest],
    pub runtime_facts: &'a [RuntimeInventoryFact],
    pub profiles: &'a [ProtocolProfile],
    pub infrastructure: &'a [InfrastructureResource],
    pub persisted_adapter_state: &'a [PersistedAdapterState],
    pub desired_generation: u64,
    pub applied_generation: u64,
    pub reconcile_status: &'a str,
    pub applied_runtime_ids: &'a BTreeSet<String>,
}

/// Builds the one inventory consumed by all panel surfaces.
#[must_use]
pub fn build_inventory(facts: InventoryFacts<'_>) -> AdapterInventory {
    let protocol_manifests = facts
        .protocol_manifests
        .iter()
        .map(|manifest| (manifest.id.as_str(), manifest))
        .collect::<BTreeMap<_, _>>();
    let runtime_facts = facts
        .runtime_facts
        .iter()
        .map(|runtime| (runtime.id.as_str(), runtime))
        .collect::<BTreeMap<_, _>>();

    let mut adapters = build_protocol_adapters(&facts, &protocol_manifests, &runtime_facts);
    adapters.extend(build_non_protocol_adapters(&facts));
    adapters.sort_by(|left, right| (&left.kind, &left.id).cmp(&(&right.kind, &right.id)));
    adapters.dedup_by(|left, right| left.kind == right.kind && left.id == right.id);

    let runtimes = build_runtimes(&facts, &runtime_facts);
    let resources = build_resources(&facts, &protocol_manifests, &runtime_facts, &runtimes);

    AdapterInventory {
        adapters,
        runtimes,
        resources,
        desired_generation: facts.desired_generation,
        applied_generation: facts.applied_generation,
        reconcile_status: facts.reconcile_status.to_string(),
    }
}

fn build_protocol_adapters(
    facts: &InventoryFacts<'_>,
    manifests: &BTreeMap<&str, &ProtocolAdapterManifest>,
    runtimes: &BTreeMap<&str, &RuntimeInventoryFact>,
) -> Vec<AdapterInventoryEntry> {
    let mut ids = manifests
        .keys()
        .map(|id| (*id).to_string())
        .collect::<BTreeSet<_>>();
    ids.extend(
        facts
            .profiles
            .iter()
            .map(|profile| profile.protocol_id.clone()),
    );
    ids.extend(
        facts
            .persisted_adapter_state
            .iter()
            .filter(|state| state.adapter_kind == adapter_kind::PROTOCOL)
            .map(|state| state.adapter_id.clone()),
    );
    ids.into_iter()
        .map(|id| {
            let manifest = manifests.get(id.as_str()).copied();
            let profiles = facts
                .profiles
                .iter()
                .filter(|profile| profile.protocol_id == id)
                .collect::<Vec<_>>();
            let configured = !profiles.is_empty()
                || facts.persisted_adapter_state.iter().any(|state| {
                    state.adapter_kind == adapter_kind::PROTOCOL && state.adapter_id == id
                });
            let future_schema = manifest.is_some_and(|manifest| {
                profiles
                    .iter()
                    .any(|profile| profile.schema_version > manifest.schema_version)
            });
            let compatible_installed = manifest.is_some_and(|manifest| {
                runtimes.values().any(|runtime| {
                    manifest
                        .required_core_capabilities
                        .is_subset(&runtime.capabilities)
                        && runtime.probe.installed == Some(true)
                })
            });
            let (state, detail) = if manifest.is_none() {
                (
                    AdapterInventoryState::Historical,
                    "Configuration preserved; adapter currently unavailable",
                )
            } else if future_schema {
                (
                    AdapterInventoryState::UnsupportedSchema,
                    "Persisted schema is newer than this adapter",
                )
            } else if !compatible_installed {
                (
                    AdapterInventoryState::AdapterOnly,
                    "Adapter available; compatible core not installed",
                )
            } else {
                (AdapterInventoryState::Available, "Adapter available")
            };
            AdapterInventoryEntry {
                id: id.clone(),
                kind: adapter_kind::PROTOCOL.to_string(),
                display_name: manifest.map_or_else(|| id.clone(), |item| item.display_name.clone()),
                state,
                present: manifest.is_some(),
                configured,
                schema_version: manifest.map(|item| item.schema_version),
                capabilities: manifest.map_or_else(BTreeSet::new, |item| {
                    item.required_core_capabilities.clone()
                }),
                detail: detail.to_string(),
            }
        })
        .collect()
}

fn build_non_protocol_adapters(facts: &InventoryFacts<'_>) -> Vec<AdapterInventoryEntry> {
    let available = facts.runtime_facts.iter().map(|runtime| {
        let persisted = facts.persisted_adapter_state.iter().filter(|state| {
            state.adapter_kind == runtime.adapter_kind && state.adapter_id == runtime.id
        });
        let configured = persisted.clone().next().is_some()
            || facts
                .profiles
                .iter()
                .any(|profile| profile.preferred_core_id.as_deref() == Some(&runtime.id))
            || facts
                .infrastructure
                .iter()
                .any(|resource| resource.adapter_id == runtime.id);
        let future_schema = persisted
            .clone()
            .any(|state| state.schema_version > runtime.state_schema_version);
        let state = if future_schema {
            AdapterInventoryState::UnsupportedSchema
        } else if runtime.probe.installed == Some(true) {
            AdapterInventoryState::Available
        } else {
            AdapterInventoryState::AdapterOnly
        };
        AdapterInventoryEntry {
            id: runtime.id.clone(),
            kind: runtime.adapter_kind.clone(),
            display_name: runtime.display_name.clone(),
            state,
            present: runtime.adapter_present,
            configured,
            schema_version: Some(runtime.state_schema_version),
            capabilities: runtime.capabilities.clone(),
            detail: match state {
                AdapterInventoryState::UnsupportedSchema => {
                    "Persisted schema is newer than this adapter"
                }
                AdapterInventoryState::AdapterOnly => "Adapter available; runtime is not installed",
                _ => "Runtime adapter available",
            }
            .to_string(),
        }
    });
    let known = facts
        .runtime_facts
        .iter()
        .map(|runtime| (runtime.adapter_kind.as_str(), runtime.id.as_str()))
        .chain(
            facts
                .protocol_manifests
                .iter()
                .map(|manifest| (adapter_kind::PROTOCOL, manifest.id.as_str())),
        )
        .collect::<BTreeSet<_>>();
    let historical = facts
        .persisted_adapter_state
        .iter()
        .filter(|state| !known.contains(&(state.adapter_kind.as_str(), state.adapter_id.as_str())))
        .map(|state| AdapterInventoryEntry {
            id: state.adapter_id.clone(),
            kind: state.adapter_kind.clone(),
            display_name: state.adapter_id.clone(),
            state: AdapterInventoryState::Historical,
            present: false,
            configured: true,
            schema_version: Some(state.schema_version),
            capabilities: BTreeSet::new(),
            detail: "Configuration preserved; adapter currently unavailable".to_string(),
        });
    available.chain(historical).collect()
}

fn build_runtimes(
    facts: &InventoryFacts<'_>,
    runtime_map: &BTreeMap<&str, &RuntimeInventoryFact>,
) -> Vec<RuntimeInventoryEntry> {
    let mut ids = runtime_map
        .keys()
        .map(|id| (*id).to_string())
        .collect::<BTreeSet<_>>();
    ids.extend(facts.applied_runtime_ids.iter().cloned());
    ids.extend(
        facts
            .profiles
            .iter()
            .filter_map(|profile| profile.preferred_core_id.clone()),
    );
    ids.extend(
        facts
            .infrastructure
            .iter()
            .map(|resource| resource.adapter_id.clone()),
    );
    ids.extend(
        facts
            .persisted_adapter_state
            .iter()
            .filter(|state| {
                matches!(
                    state.adapter_kind.as_str(),
                    adapter_kind::CORE | adapter_kind::MODULE | adapter_kind::INFRASTRUCTURE
                )
            })
            .map(|state| state.adapter_id.clone()),
    );
    ids.into_iter()
        .map(|id| {
            let fact = runtime_map.get(id.as_str()).copied();
            let desired = facts.profiles.iter().any(|profile| {
                profile.enabled && profile.preferred_core_id.as_deref() == Some(&id)
            }) || facts
                .infrastructure
                .iter()
                .any(|resource| resource.enabled && resource.adapter_id == id);
            let applied = facts.applied_runtime_ids.contains(&id);
            let (state, detail) = classify_runtime(fact, desired, applied, facts.reconcile_status);
            RuntimeInventoryEntry {
                id: id.clone(),
                display_name: fact.map_or_else(|| id.clone(), |item| item.display_name.clone()),
                state,
                adapter_present: fact.is_some_and(|item| item.adapter_present),
                installed: fact.and_then(|item| item.probe.installed),
                desired,
                applied,
                active: fact.and_then(|item| item.probe.active),
                healthy: fact.and_then(|item| item.probe.healthy),
                listeners_healthy: fact.and_then(|item| item.probe.listeners_healthy),
                service: fact.and_then(|item| item.service.clone()),
                version: fact.and_then(|item| item.probe.version.clone()),
                capabilities: fact.map_or_else(BTreeSet::new, |item| item.capabilities.clone()),
                detail: fact
                    .and_then(|item| item.probe.detail.clone())
                    .unwrap_or_else(|| detail.to_string()),
            }
        })
        .collect()
}

fn classify_runtime(
    fact: Option<&RuntimeInventoryFact>,
    desired: bool,
    applied: bool,
    reconcile_status: &str,
) -> (RuntimeInventoryState, &'static str) {
    let Some(fact) = fact else {
        return (
            RuntimeInventoryState::MissingAdapter,
            "Persisted runtime references a missing adapter",
        );
    };
    if fact.probe.installed != Some(true) {
        return (
            RuntimeInventoryState::AvailableNotInstalled,
            "Runtime adapter available; binary or service not installed",
        );
    }
    if !desired && !applied {
        return (
            RuntimeInventoryState::InstalledInactive,
            "Core installed but unused",
        );
    }
    if reconcile_status == "failed" {
        return (
            RuntimeInventoryState::Failed,
            "Runtime reconciliation failed",
        );
    }
    if fact.probe.active == Some(true)
        && fact.probe.healthy != Some(false)
        && fact.probe.listeners_healthy != Some(false)
    {
        (RuntimeInventoryState::ActiveHealthy, "Applied and healthy")
    } else {
        (
            RuntimeInventoryState::ActiveDegraded,
            "Applied runtime health is degraded",
        )
    }
}

fn build_resources(
    facts: &InventoryFacts<'_>,
    protocols: &BTreeMap<&str, &ProtocolAdapterManifest>,
    runtime_map: &BTreeMap<&str, &RuntimeInventoryFact>,
    runtimes: &[RuntimeInventoryEntry],
) -> Vec<ResourceInventoryEntry> {
    let mut resources = facts
        .profiles
        .iter()
        .map(|profile| {
            let manifest = protocols.get(profile.protocol_id.as_str()).copied();
            let runtime = select_runtime(profile, manifest, runtime_map);
            let runtime_entry = runtime.and_then(|id| runtimes.iter().find(|entry| entry.id == id));
            let state = if !profile.enabled {
                ResourceInventoryState::Disabled
            } else if manifest.is_none()
                || manifest.is_some_and(|item| profile.schema_version > item.schema_version)
            {
                ResourceInventoryState::Unsupported
            } else if runtime_entry.is_none_or(|entry| entry.installed != Some(true)) {
                ResourceInventoryState::CoreUnavailable
            } else if facts.desired_generation > facts.applied_generation {
                ResourceInventoryState::ConfiguredPending
            } else if runtime_entry
                .is_some_and(|entry| entry.state == RuntimeInventoryState::ActiveHealthy)
            {
                ResourceInventoryState::AppliedHealthy
            } else {
                ResourceInventoryState::AppliedDegraded
            };
            ResourceInventoryEntry {
                id: profile
                    .managed_resource_id
                    .clone()
                    .unwrap_or_else(|| profile.name.clone()),
                adapter_id: profile.protocol_id.clone(),
                kind: adapter_kind::PROTOCOL.to_string(),
                display_name: profile.name.clone(),
                state,
                adapter_present: manifest.is_some(),
                enabled: profile.enabled,
                desired: profile.enabled,
                applied: profile.enabled && facts.desired_generation == facts.applied_generation,
                runtime_id: runtime.map(str::to_string),
                schema_version: profile.schema_version,
                detail: resource_detail(state).to_string(),
            }
        })
        .collect::<Vec<_>>();
    resources.extend(facts.infrastructure.iter().map(|resource| {
        let runtime = runtimes
            .iter()
            .find(|runtime| runtime.id == resource.adapter_id);
        let state = if !resource.enabled {
            ResourceInventoryState::Disabled
        } else if runtime.is_none() {
            ResourceInventoryState::Unsupported
        } else if facts.desired_generation > facts.applied_generation {
            ResourceInventoryState::ConfiguredPending
        } else if runtime.is_some_and(|entry| entry.state == RuntimeInventoryState::ActiveHealthy) {
            ResourceInventoryState::AppliedHealthy
        } else {
            ResourceInventoryState::AppliedDegraded
        };
        ResourceInventoryEntry {
            id: resource.resource_id.clone(),
            adapter_id: resource.adapter_id.clone(),
            kind: adapter_kind::INFRASTRUCTURE.to_string(),
            display_name: resource.resource_id.clone(),
            state,
            adapter_present: runtime.is_some(),
            enabled: resource.enabled,
            desired: resource.enabled,
            applied: resource.enabled && facts.desired_generation == facts.applied_generation,
            runtime_id: Some(resource.adapter_id.clone()),
            schema_version: resource.schema_version,
            detail: resource_detail(state).to_string(),
        }
    }));
    resources
}

fn select_runtime<'a>(
    profile: &'a ProtocolProfile,
    manifest: Option<&ProtocolAdapterManifest>,
    runtimes: &'a BTreeMap<&str, &RuntimeInventoryFact>,
) -> Option<&'a str> {
    if let Some(preferred) = profile.preferred_core_id.as_deref() {
        return runtimes.contains_key(preferred).then_some(preferred);
    }
    let required = &manifest?.required_core_capabilities;
    runtimes
        .values()
        .find(|runtime| {
            required.is_subset(&runtime.capabilities) && runtime.probe.installed == Some(true)
        })
        .map(|runtime| runtime.id.as_str())
}

const fn resource_detail(state: ResourceInventoryState) -> &'static str {
    match state {
        ResourceInventoryState::AdapterOnly => "Adapter available without configured resource",
        ResourceInventoryState::ConfiguredPending => "Desired resource pending reconciliation",
        ResourceInventoryState::AppliedHealthy => "Applied and healthy",
        ResourceInventoryState::AppliedDegraded => "Applied but runtime health is degraded",
        ResourceInventoryState::Unsupported => {
            "Configuration preserved; adapter currently unavailable"
        }
        ResourceInventoryState::CoreUnavailable => {
            "Protocol adapter available; compatible core not installed"
        }
        ResourceInventoryState::Disabled => "Resource intentionally disabled",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::ProxyRole;

    fn protocol(id: &str, schema_version: u32) -> ProtocolAdapterManifest {
        ProtocolAdapterManifest {
            api_version: 1,
            id: id.to_string(),
            display_name: id.to_string(),
            schema_version,
            required_core_capabilities: BTreeSet::from(["capability-a".to_string()]),
            user_participation: crate::adapter::UserParticipation::PerUserUuid,
            listener_network: crate::adapter::ListenerNetwork::Tcp,
            composition: crate::adapter::ProtocolComposition::opaque(id),
        }
    }
    fn profile(adapter: &str, schema_version: u32, enabled: bool) -> ProtocolProfile {
        ProtocolProfile {
            name: "resource-one".to_string(),
            protocol_id: adapter.to_string(),
            schema_version,
            role: ProxyRole::Manual,
            server: "node.example.test".to_string(),
            port: 443,
            enabled,
            preferred_core_id: Some("core-a".to_string()),
            managed_resource_id: Some("resource-one".to_string()),
            config: serde_json::json!({"unknown":"preserved"}),
        }
    }
    fn runtime(installed: bool, active: bool, healthy: bool) -> RuntimeInventoryFact {
        RuntimeInventoryFact {
            id: "core-a".to_string(),
            adapter_kind: adapter_kind::CORE.to_string(),
            display_name: "Core A".to_string(),
            service: Some("core-a.service".to_string()),
            capabilities: BTreeSet::from(["capability-a".to_string()]),
            adapter_present: true,
            state_schema_version: 1,
            probe: CoreRuntimeProbe {
                installed: Some(installed),
                active: Some(active),
                healthy: Some(healthy),
                listeners_healthy: Some(healthy),
                ..CoreRuntimeProbe::default()
            },
        }
    }
    fn inventory(
        protocols: &[ProtocolAdapterManifest],
        profiles: &[ProtocolProfile],
        runtimes: &[RuntimeInventoryFact],
        persisted: &[PersistedAdapterState],
        desired: u64,
        applied: u64,
    ) -> AdapterInventory {
        let core = CoreAdapterManifest {
            api_version: 1,
            id: "core-a".to_string(),
            display_name: "Core A".to_string(),
            capabilities: BTreeSet::from(["capability-a".to_string()]),
            service: "core-a.service".to_string(),
            selection_priority: 0,
        };
        build_inventory(InventoryFacts {
            protocol_manifests: protocols,
            core_manifests: &[core],
            runtime_facts: runtimes,
            profiles,
            infrastructure: &[],
            persisted_adapter_state: persisted,
            desired_generation: desired,
            applied_generation: applied,
            reconcile_status: "applied",
            applied_runtime_ids: &BTreeSet::from(["core-a".to_string()]),
        })
    }

    #[test]
    fn dynamic_states_cover_adapter_only_pending_healthy_and_degraded() {
        let protocols = [protocol("protocol-a", 1)];
        let profiles = [profile("protocol-a", 1, true)];
        let absent = inventory(
            &protocols,
            &profiles,
            &[runtime(false, false, false)],
            &[],
            2,
            1,
        );
        assert_eq!(absent.adapters[1].state, AdapterInventoryState::AdapterOnly);
        assert_eq!(
            absent.resources[0].state,
            ResourceInventoryState::CoreUnavailable
        );
        let pending = inventory(
            &protocols,
            &profiles,
            &[runtime(true, true, true)],
            &[],
            2,
            1,
        );
        assert_eq!(
            pending.resources[0].state,
            ResourceInventoryState::ConfiguredPending
        );
        let healthy = inventory(
            &protocols,
            &profiles,
            &[runtime(true, true, true)],
            &[],
            2,
            2,
        );
        assert_eq!(
            healthy.runtimes[0].state,
            RuntimeInventoryState::ActiveHealthy
        );
        assert_eq!(
            healthy.resources[0].state,
            ResourceInventoryState::AppliedHealthy
        );
        let degraded = inventory(
            &protocols,
            &profiles,
            &[runtime(true, true, false)],
            &[],
            2,
            2,
        );
        assert_eq!(
            degraded.runtimes[0].state,
            RuntimeInventoryState::ActiveDegraded
        );
        assert_eq!(
            degraded.resources[0].state,
            ResourceInventoryState::AppliedDegraded
        );
    }

    #[test]
    fn historical_and_future_schema_are_preserved_as_explicit_states() {
        let profiles = [profile("missing-protocol", 7, true)];
        let persisted = [PersistedAdapterState {
            adapter_id: "missing-core".to_string(),
            adapter_kind: adapter_kind::CORE.to_string(),
            resource_id: "default".to_string(),
            schema_version: 9,
            config: serde_json::json!({"opaque":true}),
            enabled: true,
        }];
        let missing = inventory(&[], &profiles, &[], &persisted, 1, 0);
        assert!(missing
            .adapters
            .iter()
            .any(|entry| entry.id == "missing-protocol"
                && entry.state == AdapterInventoryState::Historical));
        assert!(missing
            .runtimes
            .iter()
            .any(|entry| entry.id == "missing-core"
                && entry.state == RuntimeInventoryState::MissingAdapter));
        let future = inventory(
            &[protocol("missing-protocol", 1)],
            &profiles,
            &[],
            &persisted,
            1,
            0,
        );
        assert!(future
            .adapters
            .iter()
            .any(|entry| entry.id == "missing-protocol"
                && entry.state == AdapterInventoryState::UnsupportedSchema));
    }
}
