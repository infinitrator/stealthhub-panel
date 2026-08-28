//! Versioned desired and applied state for atomic runtime reconciliation.

use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, path::PathBuf};

use crate::{
    adapter::ListenerClaim,
    models::{ProtocolProfile, SubscriptionUser},
};

/// Fixed-format unprivileged request consumed by the root worker.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ReconcileRequest {
    pub api_version: u32,
    pub generation: u64,
}

/// Durable lifecycle visible to the panel and diagnostics.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum ReconcileStatus {
    Pending,
    Applying,
    Applied,
    Failed,
    RolledBack,
    Unsupported,
    RecoveryRequired,
}

/// Complete requested state for one monotonic generation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DesiredState {
    pub generation: u64,
    pub profiles: Vec<ProtocolProfile>,
    pub users: Vec<SubscriptionUser>,
    #[serde(default)]
    pub settings: BTreeMap<String, String>,
    pub infrastructure: Vec<InfrastructureResource>,
}

/// Adapter-owned non-protocol resource participating in the same transaction.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct InfrastructureResource {
    pub resource_id: String,
    pub adapter_id: String,
    pub schema_version: u32,
    pub enabled: bool,
    #[serde(default)]
    pub kind: InfrastructureResourceKind,
    #[serde(default)]
    pub dependencies: Vec<String>,
    #[serde(default)]
    pub listeners: Vec<ListenerClaim>,
    pub config: serde_json::Value,
}

/// Stable shared-infrastructure role, independent of its concrete adapter.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum InfrastructureResourceKind {
    Domain,
    Certificate,
    TlsFrontend,
    DecoyTarget,
    Listener,
    PortAllocation,
    #[default]
    AdapterOwned,
}

/// Last generation proven healthy and atomically published.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct AppliedState {
    pub generation: u64,
    pub active_core_ids: Vec<String>,
}

/// Non-secret transaction phases persisted for crash recovery.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum JournalPhase {
    Prepared,
    Staged,
    Validated,
    Snapshotted,
    Installed,
    Activated,
    Healthy,
    Publishing,
    Published,
    RollbackStarted,
    RolledBack,
    RecoveryRequired,
}

/// Redacted journal metadata. Candidate payloads and secret values are absent.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct JournalEntry {
    pub operation_id: String,
    pub generation: u64,
    pub previous_generation: u64,
    #[serde(default)]
    pub previous_active_core_ids: Vec<String>,
    pub phase: JournalPhase,
    pub status: ReconcileStatus,
    pub core_ids: Vec<String>,
    pub current_core_id: Option<String>,
    pub resources: Vec<JournalResource>,
    pub error: Option<String>,
    pub started_at: String,
    pub completed_at: Option<String>,
}

/// Recovery information written before a live resource can be mutated.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct JournalResource {
    pub core_id: String,
    pub snapshot_path: PathBuf,
    pub service_was_enabled: bool,
    pub service_was_active: bool,
    pub mutation_started: bool,
    pub verified: bool,
}

impl JournalEntry {
    /// Starts a pending entry containing identifiers only.
    #[must_use]
    pub fn prepared(generation: u64, previous_generation: u64) -> Self {
        Self {
            operation_id: uuid::Uuid::new_v4().to_string(),
            generation,
            previous_generation,
            previous_active_core_ids: Vec::new(),
            phase: JournalPhase::Prepared,
            status: ReconcileStatus::Pending,
            core_ids: Vec::new(),
            current_core_id: None,
            resources: Vec::new(),
            error: None,
            started_at: chrono::Utc::now().to_rfc3339(),
            completed_at: None,
        }
    }
}
