//! Application service that assembles the panel's single runtime inventory.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::Result;
use sqlx::SqlitePool;
use stealthhub_core::{
    adapter::{CoreRegistry, ProtocolRegistry},
    adapters::desired_resources,
    inventory::{
        adapter_kind, build_inventory, AdapterInventory, InventoryFacts, PersistedAdapterState,
        RuntimeInventoryFact,
    },
    storage::{
        decode_adapter_state, get_reconcile_state, list_adapter_state_records, load_desired_state,
    },
};

use crate::{
    modules::{self, ModuleSpec, ModuleStatus},
    ops::{service_statuses_for_units, ServiceStatus},
};

/// Inventory plus module updater metadata needed by module-management actions.
pub(crate) struct PanelInventory {
    pub(crate) inventory: AdapterInventory,
    pub(crate) module_statuses: Vec<ModuleStatus>,
    pub(crate) available_modules: Vec<ModuleSpec>,
    pub(crate) diagnostics: Vec<String>,
}

/// Loads all durable and observational facts without mutating runtime state.
pub(crate) async fn load(
    pool: &SqlitePool,
    protocols: &ProtocolRegistry,
    cores: &CoreRegistry,
) -> Result<PanelInventory> {
    let mut desired = load_desired_state(pool).await?;
    let settings = stealthhub_core::models::PanelSettings {
        panel_name: desired
            .settings
            .get("panel_name")
            .cloned()
            .unwrap_or_else(|| stealthhub_core::models::PanelSettings::default().panel_name),
        subscription_domain: desired
            .settings
            .get("subscription_domain")
            .cloned()
            .unwrap_or_else(|| {
                stealthhub_core::models::PanelSettings::default().subscription_domain
            }),
        node_domain: desired
            .settings
            .get("node_domain")
            .cloned()
            .unwrap_or_else(|| stealthhub_core::models::PanelSettings::default().node_domain),
    };
    desired.infrastructure.extend(desired_resources(&settings));
    let reconcile = get_reconcile_state(pool).await?;
    let persisted = load_persisted_state_lossy(pool).await?;
    let mut diagnostics = Vec::new();
    let (module_statuses, available_modules) = match modules::load_page(pool).await {
        Ok(page) => page,
        Err(error) => {
            diagnostics.push(format!("module registry unavailable: {error}"));
            (Vec::new(), Vec::new())
        }
    };

    let observations = cores.observations();
    let infrastructure_ids = desired
        .infrastructure
        .iter()
        .map(|resource| resource.adapter_id.as_str())
        .collect::<BTreeSet<_>>();
    let mut runtime_facts = observations
        .iter()
        .map(|observation| RuntimeInventoryFact {
            id: observation.manifest.id.clone(),
            adapter_kind: if infrastructure_ids.contains(observation.manifest.id.as_str()) {
                adapter_kind::INFRASTRUCTURE.to_string()
            } else {
                adapter_kind::CORE.to_string()
            },
            display_name: observation.manifest.display_name.clone(),
            service: Some(observation.manifest.service.clone()),
            capabilities: observation.manifest.capabilities.clone(),
            adapter_present: true,
            state_schema_version: observation.state_schema_version,
            probe: observation.probe.clone(),
        })
        .map(|fact| (fact.id.clone(), fact))
        .collect::<BTreeMap<_, _>>();

    for status in &module_statuses {
        let fact = runtime_facts
            .entry(status.spec.id.clone())
            .or_insert_with(|| RuntimeInventoryFact {
                id: status.spec.id.clone(),
                adapter_kind: adapter_kind::MODULE.to_string(),
                display_name: status.spec.name.clone(),
                service: Some(status.spec.service.clone()),
                capabilities: BTreeSet::new(),
                adapter_present: true,
                state_schema_version: 1,
                probe: Default::default(),
            });
        fact.probe.installed = Some(status.installed);
        fact.probe.version =
            (status.installed_version != "unknown").then(|| status.installed_version.clone());
        fact.probe.detail = Some(status.status.clone());
    }

    let units = runtime_facts
        .values()
        .filter_map(|fact| fact.service.as_deref())
        .collect::<Vec<_>>();
    let service_states = service_statuses_for_units(&units).await;
    drop(units);
    for fact in runtime_facts.values_mut() {
        let status = fact
            .service
            .as_deref()
            .and_then(|unit| service_states.get(unit))
            .copied()
            .unwrap_or(ServiceStatus::Unknown);
        fact.probe.active = match status {
            ServiceStatus::Active => Some(true),
            ServiceStatus::Inactive | ServiceStatus::Failed => Some(false),
            ServiceStatus::Unknown => None,
        };
        fact.probe.healthy = match status {
            ServiceStatus::Active => Some(true),
            ServiceStatus::Failed => Some(false),
            ServiceStatus::Inactive | ServiceStatus::Unknown => None,
        };
    }

    let protocol_manifests = protocols.manifests();
    let core_manifests = observations
        .iter()
        .map(|observation| observation.manifest.clone())
        .collect::<Vec<_>>();
    let runtime_facts = runtime_facts.into_values().collect::<Vec<_>>();
    let applied_runtime_ids = if reconcile.desired_generation == reconcile.applied_generation {
        serde_json::from_str::<BTreeSet<String>>(&reconcile.active_runtime_ids_json)
            .unwrap_or_default()
    } else {
        BTreeSet::new()
    };
    let inventory = build_inventory(InventoryFacts {
        protocol_manifests: &protocol_manifests,
        core_manifests: &core_manifests,
        runtime_facts: &runtime_facts,
        profiles: &desired.profiles,
        infrastructure: &desired.infrastructure,
        persisted_adapter_state: &persisted,
        desired_generation: u64::try_from(reconcile.desired_generation).unwrap_or_default(),
        applied_generation: u64::try_from(reconcile.applied_generation).unwrap_or_default(),
        reconcile_status: &reconcile.status,
        applied_runtime_ids: &applied_runtime_ids,
    });

    Ok(PanelInventory {
        inventory,
        module_statuses,
        available_modules,
        diagnostics,
    })
}

async fn load_persisted_state_lossy(pool: &SqlitePool) -> Result<Vec<PersistedAdapterState>> {
    Ok(list_adapter_state_records(pool)
        .await?
        .into_iter()
        .map(|record| {
            decode_adapter_state(&record).unwrap_or(PersistedAdapterState {
                adapter_id: record.adapter_id,
                adapter_kind: record.adapter_kind,
                resource_id: record.resource_id,
                schema_version: u32::try_from(record.schema_version).unwrap_or(1),
                config: serde_json::Value::Null,
                enabled: record.enabled,
            })
        })
        .collect())
}
