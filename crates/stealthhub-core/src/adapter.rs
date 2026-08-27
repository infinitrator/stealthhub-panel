//! Extensible adapter contracts shared by subscriptions and reconciliation.
//!
//! Generic control-plane code deals only in stable IDs, capabilities, opaque
//! JSON and these interfaces. Concrete protocol and runtime behavior belongs in
//! adapter modules.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    path::{Path, PathBuf},
    sync::Arc,
};

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::models::{ProtocolProfile, SubscriptionUser};

/// Stable adapter protocol understood by this release line.
pub const ADAPTER_API_VERSION: u32 = 1;

/// Validates stable IDs used in persisted desired state and manifests.
#[must_use]
pub fn valid_adapter_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        && value.as_bytes()[0].is_ascii_lowercase()
}

/// Secret reference stored in desired state instead of plaintext material.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct SecretRef(String);

impl SecretRef {
    /// Creates a bounded reference suitable for storage and lookup.
    pub fn parse(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        if value.is_empty()
            || value.len() > 128
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
        {
            bail!("invalid secret reference");
        }
        Ok(Self(value))
    }

    /// Returns the non-secret lookup name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for SecretRef {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_tuple("SecretRef").field(&self.0).finish()
    }
}

/// Plaintext secret wrapper that cannot reveal its value through formatting.
#[derive(Clone, PartialEq, Eq)]
pub struct SecretValue(String);

impl SecretValue {
    /// Wraps one resolved value after rejecting placeholders and empties.
    pub fn new(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        let trimmed = value.trim();
        if trimmed.is_empty() || trimmed.starts_with("REPLACE_WITH_") {
            bail!("secret is not configured");
        }
        Ok(Self(trimmed.to_string()))
    }

    /// Exposes plaintext only to the adapter currently rendering a candidate.
    #[must_use]
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for SecretValue {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretValue([REDACTED])")
    }
}

impl fmt::Display for SecretValue {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("[REDACTED]")
    }
}

/// Narrow secret lookup boundary used by adapters.
pub trait SecretResolver: Send + Sync {
    /// Resolves one named secret without exposing other entries.
    fn resolve(&self, reference: &SecretRef) -> Result<SecretValue>;
}

/// In-memory resolver used for client subscriptions and tests.
pub struct MapSecretResolver<'a> {
    values: &'a BTreeMap<String, String>,
}

impl<'a> MapSecretResolver<'a> {
    /// Creates a resolver over values already authorized for this operation.
    #[must_use]
    pub const fn new(values: &'a BTreeMap<String, String>) -> Self {
        Self { values }
    }
}

impl SecretResolver for MapSecretResolver<'_> {
    fn resolve(&self, reference: &SecretRef) -> Result<SecretValue> {
        let value = self
            .values
            .get(reference.as_str())
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("required secret reference is unresolved"))?;
        SecretValue::new(value)
    }
}

/// Declarative protocol metadata consumed by generic registries and UI.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProtocolAdapterManifest {
    pub api_version: u32,
    pub id: String,
    pub display_name: String,
    pub schema_version: u32,
    pub required_core_capabilities: BTreeSet<String>,
    pub user_participation: UserParticipation,
}

/// How subscription users participate in one protocol runtime.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum UserParticipation {
    /// The protocol has no user authorization material.
    None,
    /// Every subscription user receives the same server-side credential.
    SharedCredential,
    /// Every enabled subscription user must exist in runtime state by UUID.
    PerUserUuid,
}

impl UserParticipation {
    /// Whether runtime state must contain one identity per enabled user.
    #[must_use]
    pub const fn requires_individual_users(self) -> bool {
        matches!(self, Self::PerUserUuid)
    }
}

/// Declarative runtime metadata used for capability selection.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CoreAdapterManifest {
    pub api_version: u32,
    pub id: String,
    pub display_name: String,
    pub capabilities: BTreeSet<String>,
    pub service: String,
    pub selection_priority: i32,
}

/// One adapter-owned editable configuration field.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ConfigField {
    pub name: String,
    pub label: String,
    pub help: String,
    pub kind: ConfigFieldKind,
    pub required: bool,
}

/// Presentation type for an opaque adapter field.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum ConfigFieldKind {
    Text,
    SecretRef,
}

/// Adapter-produced server fragment consumed only by a compatible core.
#[derive(Clone)]
pub struct ServerFragment {
    pub profile_id: String,
    pub capability: String,
    pub payload: Value,
    /// Expected non-secret runtime identities, or `None` for shared/no auth.
    pub expected_user_ids: Option<BTreeSet<String>>,
}

impl fmt::Debug for ServerFragment {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ServerFragment")
            .field("profile_id", &self.profile_id)
            .field("capability", &self.capability)
            .field(
                "expected_user_count",
                &self.expected_user_ids.as_ref().map(BTreeSet::len),
            )
            .field("payload", &"[REDACTED]")
            .finish()
    }
}

/// Context for rendering a client proxy object.
pub struct ClientRenderContext<'a> {
    pub profile: &'a ProtocolProfile,
    pub user: &'a SubscriptionUser,
    pub secrets: &'a dyn SecretResolver,
}

/// Context for rendering runtime authorization/configuration state.
pub struct ServerRenderContext<'a> {
    pub profile: &'a ProtocolProfile,
    pub users: &'a [SubscriptionUser],
    pub secrets: &'a dyn SecretResolver,
}

/// All concrete protocol behavior lives behind this interface.
pub trait ProtocolAdapter: Send + Sync {
    fn manifest(&self) -> &ProtocolAdapterManifest;
    fn fields(&self) -> &[ConfigField];
    fn validate_config(&self, schema_version: u32, config: &Value) -> Result<()>;
    fn migrate_config(&self, from_version: u32, config: Value) -> Result<(u32, Value)>;
    /// Current schema for optional adapter-package state outside profile rows.
    fn state_schema_version(&self) -> u32 {
        1
    }
    /// Migrates opaque package state after a previously absent adapter returns.
    fn migrate_state(&self, from_version: u32, config: Value) -> Result<(u32, Value)> {
        if from_version > self.state_schema_version() {
            bail!("adapter state schema is newer than this adapter");
        }
        Ok((self.state_schema_version(), config))
    }
    fn client_secret_references(&self, config: &Value) -> Result<Vec<SecretRef>>;
    fn server_secret_references(&self, config: &Value) -> Result<Vec<SecretRef>>;
    /// Returns the subset of server references that must only be resolved by
    /// the privileged worker and must never be stored in panel-readable state.
    fn server_only_secret_references(&self, _config: &Value) -> Result<Vec<SecretRef>> {
        Ok(Vec::new())
    }
    fn secret_references(&self, config: &Value) -> Result<Vec<SecretRef>> {
        let mut references = self.client_secret_references(config)?;
        references.extend(self.server_secret_references(config)?);
        references.sort();
        references.dedup();
        Ok(references)
    }
    fn render_client(&self, context: &ClientRenderContext<'_>) -> Result<Value>;
    fn render_server(&self, context: &ServerRenderContext<'_>) -> Result<ServerFragment>;
}

/// Candidate generated for one runtime adapter.
#[derive(Debug, Clone)]
pub struct CorePlan {
    pub generation: u64,
    pub core_id: String,
    pub fragments: Vec<ServerFragment>,
}

/// Opaque snapshot locator kept in a private transaction directory.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoreSnapshot {
    pub path: PathBuf,
    pub service_was_enabled: bool,
    pub service_was_active: bool,
}

/// Best-effort, non-mutating runtime observation used by control-plane inventory.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct CoreRuntimeProbe {
    pub installed: Option<bool>,
    pub active: Option<bool>,
    pub healthy: Option<bool>,
    pub listeners_healthy: Option<bool>,
    pub version: Option<String>,
    pub detail: Option<String>,
}

/// Result of comparing desired per-user identities with a live runtime config.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case", tag = "status")]
pub enum UserSyncObservation {
    Unsupported,
    InSync {
        user_count: usize,
    },
    Drift {
        expected_count: usize,
        observed_count: usize,
        missing_count: usize,
        unexpected_count: usize,
    },
}

impl UserSyncObservation {
    /// Builds a count-only observation without persisting user identifiers.
    #[must_use]
    pub fn compare(expected: &BTreeSet<String>, observed: &BTreeSet<String>) -> Self {
        let missing_count = expected.difference(observed).count();
        let unexpected_count = observed.difference(expected).count();
        if missing_count == 0 && unexpected_count == 0 {
            Self::InSync {
                user_count: expected.len(),
            }
        } else {
            Self::Drift {
                expected_count: expected.len(),
                observed_count: observed.len(),
                missing_count,
                unexpected_count,
            }
        }
    }
}

/// Read-only registry observation safe to pass into inventory construction.
#[derive(Debug, Clone)]
pub struct CoreAdapterObservation {
    pub manifest: CoreAdapterManifest,
    pub state_schema_version: u32,
    pub probe: CoreRuntimeProbe,
}

/// Privileged runtime behavior used by the generic transaction engine.
pub trait CoreAdapter: Send + Sync {
    fn manifest(&self) -> &CoreAdapterManifest;
    fn installed(&self) -> Result<bool>;
    /// Current schema for optional adapter-owned durable settings.
    fn state_schema_version(&self) -> u32 {
        1
    }
    /// Migrates opaque settings when this stable adapter ID becomes available.
    fn migrate_state(&self, from_version: u32, config: Value) -> Result<(u32, Value)> {
        if from_version > self.state_schema_version() {
            bail!("adapter state schema is newer than this adapter");
        }
        Ok((self.state_schema_version(), config))
    }
    /// Observes runtime state without changing files, services, or desired state.
    fn probe(&self) -> CoreRuntimeProbe {
        match self.installed() {
            Ok(installed) => CoreRuntimeProbe {
                installed: Some(installed),
                ..CoreRuntimeProbe::default()
            },
            Err(_) => CoreRuntimeProbe {
                detail: Some("runtime installation probe failed".to_string()),
                ..CoreRuntimeProbe::default()
            },
        }
    }
    fn stage(&self, plan: &CorePlan, transaction_dir: &Path) -> Result<PathBuf>;
    fn validate(&self, candidate: &Path) -> Result<()>;
    fn snapshot(&self, transaction_dir: &Path) -> Result<CoreSnapshot>;
    fn install(&self, candidate: &Path) -> Result<()>;
    fn activate(&self, plan: &CorePlan) -> Result<()>;
    fn healthcheck(&self, plan: &CorePlan) -> Result<()>;
    fn verify_listeners(&self, plan: &CorePlan) -> Result<()>;
    /// Verifies individual user authorization in the installed live config.
    fn observe_users(&self, _plan: &CorePlan) -> Result<UserSyncObservation> {
        Ok(UserSyncObservation::Unsupported)
    }
    fn rollback(&self, snapshot: &CoreSnapshot) -> Result<()>;
}

/// Registry populated by adapter packages, manifests, or tests.
#[derive(Default, Clone)]
pub struct ProtocolRegistry {
    adapters: BTreeMap<String, Arc<dyn ProtocolAdapter>>,
}

impl ProtocolRegistry {
    /// Registers one adapter after validating its stable manifest.
    pub fn register(&mut self, adapter: Arc<dyn ProtocolAdapter>) -> Result<()> {
        let manifest = adapter.manifest();
        validate_protocol_manifest(manifest)?;
        if self.adapters.contains_key(&manifest.id) {
            bail!("duplicate protocol adapter ID");
        }
        self.adapters.insert(manifest.id.clone(), adapter);
        Ok(())
    }

    /// Resolves one adapter without protocol-specific branching.
    #[must_use]
    pub fn get(&self, id: &str) -> Option<Arc<dyn ProtocolAdapter>> {
        self.adapters.get(id).cloned()
    }

    /// Returns manifests in stable ID order for UI and diagnostics.
    #[must_use]
    pub fn manifests(&self) -> Vec<ProtocolAdapterManifest> {
        self.adapters
            .values()
            .map(|adapter| adapter.manifest().clone())
            .collect()
    }
}

/// Runtime registry selected only through declared capabilities and policy.
#[derive(Default, Clone)]
pub struct CoreRegistry {
    adapters: BTreeMap<String, Arc<dyn CoreAdapter>>,
}

impl CoreRegistry {
    /// Registers one validated runtime adapter.
    pub fn register(&mut self, adapter: Arc<dyn CoreAdapter>) -> Result<()> {
        let manifest = adapter.manifest();
        validate_core_manifest(manifest)?;
        if self.adapters.contains_key(&manifest.id) {
            bail!("duplicate core adapter ID");
        }
        self.adapters.insert(manifest.id.clone(), adapter);
        Ok(())
    }

    /// Resolves a runtime by stable ID.
    #[must_use]
    pub fn get(&self, id: &str) -> Option<Arc<dyn CoreAdapter>> {
        self.adapters.get(id).cloned()
    }

    /// Selects an installed compatible runtime, honoring a desired preference.
    pub fn select(
        &self,
        required: &BTreeSet<String>,
        preferred: Option<&str>,
    ) -> Result<Option<Arc<dyn CoreAdapter>>> {
        if let Some(preferred) = preferred {
            let adapter = self
                .adapters
                .get(preferred)
                .ok_or_else(|| anyhow::anyhow!("preferred core adapter is missing"))?;
            if required.is_subset(&adapter.manifest().capabilities) && adapter.installed()? {
                return Ok(Some(adapter.clone()));
            }
            bail!("preferred core adapter is incompatible or not installed");
        }

        let mut compatible = self
            .adapters
            .values()
            .filter(|adapter| required.is_subset(&adapter.manifest().capabilities))
            .cloned()
            .collect::<Vec<_>>();
        compatible.sort_by_key(|adapter| std::cmp::Reverse(adapter.manifest().selection_priority));
        for adapter in compatible {
            if adapter.installed()? {
                return Ok(Some(adapter));
            }
        }
        Ok(None)
    }

    /// Selects a compatible runtime while excluding one removal candidate.
    pub fn select_excluding(
        &self,
        required: &BTreeSet<String>,
        excluded: &str,
    ) -> Result<Option<Arc<dyn CoreAdapter>>> {
        let mut compatible = self
            .adapters
            .iter()
            .filter(|(id, adapter)| {
                id.as_str() != excluded && required.is_subset(&adapter.manifest().capabilities)
            })
            .map(|(_, adapter)| adapter.clone())
            .collect::<Vec<_>>();
        compatible.sort_by_key(|adapter| std::cmp::Reverse(adapter.manifest().selection_priority));
        for adapter in compatible {
            if adapter.installed()? {
                return Ok(Some(adapter));
            }
        }
        Ok(None)
    }

    /// Returns runtime manifests in stable ID order for status and UI.
    #[must_use]
    pub fn manifests(&self) -> Vec<CoreAdapterManifest> {
        self.adapters
            .values()
            .map(|adapter| adapter.manifest().clone())
            .collect()
    }

    /// Probes every registered runtime independently in stable ID order.
    #[must_use]
    pub fn observations(&self) -> Vec<CoreAdapterObservation> {
        self.adapters
            .values()
            .map(|adapter| CoreAdapterObservation {
                manifest: adapter.manifest().clone(),
                state_schema_version: adapter.state_schema_version(),
                probe: adapter.probe(),
            })
            .collect()
    }
}

fn validate_protocol_manifest(manifest: &ProtocolAdapterManifest) -> Result<()> {
    if manifest.api_version != ADAPTER_API_VERSION
        || !valid_adapter_id(&manifest.id)
        || manifest.display_name.trim().is_empty()
        || manifest.schema_version == 0
        || manifest.required_core_capabilities.is_empty()
    {
        bail!("invalid protocol adapter manifest");
    }
    validate_capabilities(&manifest.required_core_capabilities)
}

fn validate_core_manifest(manifest: &CoreAdapterManifest) -> Result<()> {
    if manifest.api_version != ADAPTER_API_VERSION
        || !valid_adapter_id(&manifest.id)
        || manifest.display_name.trim().is_empty()
        || manifest.capabilities.is_empty()
        || manifest.service.trim().is_empty()
        || !(-1_000..=1_000).contains(&manifest.selection_priority)
    {
        bail!("invalid core adapter manifest");
    }
    validate_capabilities(&manifest.capabilities)
}

fn validate_capabilities(capabilities: &BTreeSet<String>) -> Result<()> {
    for capability in capabilities {
        if !valid_adapter_id(capability) {
            bail!("invalid adapter capability");
        }
    }
    Ok(())
}

/// Parses a root-owned adapter manifest after strict filesystem validation.
pub fn read_root_manifest(path: &Path) -> Result<Value> {
    let metadata = std::fs::symlink_metadata(path).context("read adapter manifest metadata")?;
    if !metadata.file_type().is_file() || metadata.len() > 64 * 1024 {
        bail!("adapter manifest must be a bounded regular file");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if metadata.uid() != 0 || metadata.permissions().mode() & 0o022 != 0 {
            bail!("adapter manifest must be root-owned and not writable by group or others");
        }
    }
    let content = std::fs::read_to_string(path).context("read adapter manifest")?;
    let value: toml::Value = toml::from_str(&content).context("parse adapter manifest")?;
    Ok(serde_json::to_value(value)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_formatting_is_always_redacted() {
        let secret = SecretValue::new("canary-secret-value").unwrap();
        assert_eq!(format!("{secret}"), "[REDACTED]");
        assert_eq!(format!("{secret:?}"), "SecretValue([REDACTED])");
        assert!(!format!("{secret:?}").contains("canary"));
    }

    #[test]
    fn server_fragments_do_not_debug_secret_payloads() {
        let fragment = ServerFragment {
            profile_id: "test".to_string(),
            capability: "fake".to_string(),
            payload: serde_json::json!({"password": "canary-secret-value"}),
            expected_user_ids: None,
        };
        let rendered = format!("{fragment:?}");
        assert!(!rendered.contains("canary"));
        assert!(rendered.contains("[REDACTED]"));
    }

    #[test]
    fn ids_and_references_are_strictly_bounded() {
        assert!(valid_adapter_id("fake-protocol-2"));
        assert!(!valid_adapter_id("Fake"));
        assert!(!valid_adapter_id("../fake"));
        assert!(SecretRef::parse("runtime.client-key_1").is_ok());
        assert!(SecretRef::parse("../../secret").is_err());
    }

    #[test]
    fn user_sync_observation_reports_counts_without_identifiers() {
        let observation = UserSyncObservation::compare(
            &BTreeSet::from(["expected-user".to_string()]),
            &BTreeSet::from(["unexpected-user".to_string()]),
        );
        assert_eq!(
            observation,
            UserSyncObservation::Drift {
                expected_count: 1,
                observed_count: 1,
                missing_count: 1,
                unexpected_count: 1,
            }
        );
        let serialized = serde_json::to_string(&observation).unwrap();
        assert!(!serialized.contains("expected-user"));
        assert!(!serialized.contains("unexpected-user"));
    }
}
