//! Generic atomic reconciler for adapter-produced runtime candidates.

use std::{
    collections::BTreeMap,
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

use anyhow::{bail, Context, Result};

use crate::{
    adapter::{
        CoreAdapter, CorePlan, CoreRegistry, CoreSnapshot, ProfileUserSyncObservation,
        ProtocolRegistry, SecretResolver, ServerRenderContext, UserSyncObservation, UserSyncStatus,
    },
    desired::{
        AppliedState, DesiredState, JournalEntry, JournalPhase, JournalResource, ReconcileStatus,
    },
};

/// Durable state boundary used by production files and deterministic fakes.
pub trait ReconcileStore: Send + Sync {
    fn load_applied(&self) -> Result<AppliedState>;
    fn compare_and_set_applied(&self, expected: u64, next: &AppliedState) -> Result<bool>;
    fn load_journal(&self) -> Result<Option<JournalEntry>>;
    fn save_journal(&self, entry: &JournalEntry) -> Result<()>;
    fn desired_generation_is_current(&self, generation: u64) -> Result<bool>;
}

/// Root-owned JSON state store using atomic rename and directory sync.
pub struct FileReconcileStore {
    directory: PathBuf,
}

impl FileReconcileStore {
    #[must_use]
    pub fn new(directory: impl Into<PathBuf>) -> Self {
        Self {
            directory: directory.into(),
        }
    }

    fn applied_path(&self) -> PathBuf {
        self.directory.join("applied.json")
    }

    fn journal_path(&self) -> PathBuf {
        self.directory.join("journal.json")
    }

    fn desired_generation_path(&self) -> PathBuf {
        self.directory.join("desired-generation")
    }

    /// Publishes the generation loaded by the privileged worker.
    pub fn publish_desired_generation(&self, generation: u64) -> Result<()> {
        write_bytes_atomic(
            &self.desired_generation_path(),
            generation.to_string().as_bytes(),
        )
    }
}

impl ReconcileStore for FileReconcileStore {
    fn load_applied(&self) -> Result<AppliedState> {
        read_json_or_default(&self.applied_path())
    }

    fn compare_and_set_applied(&self, expected: u64, next: &AppliedState) -> Result<bool> {
        let current = self.load_applied()?;
        if current.generation != expected {
            return Ok(false);
        }
        write_json_atomic(&self.applied_path(), next)?;
        Ok(true)
    }

    fn load_journal(&self) -> Result<Option<JournalEntry>> {
        let path = self.journal_path();
        let metadata = match fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        if !metadata.file_type().is_file() || metadata.len() > 1024 * 1024 {
            bail!("reconcile journal must be a bounded regular file");
        }
        let bytes = fs::read(path).context("read reconcile journal")?;
        Ok(Some(
            serde_json::from_slice(&bytes).context("parse reconcile journal")?,
        ))
    }

    fn save_journal(&self, entry: &JournalEntry) -> Result<()> {
        write_json_atomic(&self.journal_path(), entry)
    }

    fn desired_generation_is_current(&self, generation: u64) -> Result<bool> {
        let path = self.desired_generation_path();
        let metadata = match fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(true),
            Err(error) => return Err(error.into()),
        };
        if !metadata.file_type().is_file() || metadata.len() > 32 {
            bail!("desired generation marker must be a bounded regular file");
        }
        let current = fs::read_to_string(path)?.trim().parse::<u64>()?;
        Ok(current == generation)
    }
}

/// Observable result of one idempotent reconciliation pass.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReconcileOutcome {
    pub generation: u64,
    pub status: ReconcileStatus,
    pub message: Option<String>,
}

/// Serializes local mutations and applies one all-or-nothing generation.
pub struct Reconciler {
    protocols: ProtocolRegistry,
    cores: CoreRegistry,
    store: Arc<dyn ReconcileStore>,
    transaction_root: PathBuf,
    lock: Mutex<()>,
}

struct PreparedCore {
    core: Arc<dyn CoreAdapter>,
    plan: CorePlan,
    candidate: PathBuf,
    snapshot: CoreSnapshot,
}

type CorePlans = BTreeMap<String, (Arc<dyn CoreAdapter>, CorePlan)>;

impl Reconciler {
    #[must_use]
    pub fn new(
        protocols: ProtocolRegistry,
        cores: CoreRegistry,
        store: Arc<dyn ReconcileStore>,
        transaction_root: impl Into<PathBuf>,
    ) -> Self {
        Self {
            protocols,
            cores,
            store,
            transaction_root: transaction_root.into(),
            lock: Mutex::new(()),
        }
    }

    /// Applies a desired generation or returns an explicit non-mutating status.
    pub fn reconcile(
        &self,
        desired: &DesiredState,
        secrets: &dyn SecretResolver,
    ) -> Result<ReconcileOutcome> {
        let _guard = self
            .lock
            .lock()
            .map_err(|_| anyhow::anyhow!("reconciler lock is poisoned"))?;
        let applied = self.store.load_applied()?;
        if desired.generation <= applied.generation {
            return Ok(ReconcileOutcome {
                generation: applied.generation,
                status: ReconcileStatus::Applied,
                message: None,
            });
        }

        if let Some(journal) = self.store.load_journal()? {
            if journal.status == ReconcileStatus::Applying
                || journal.status == ReconcileStatus::RecoveryRequired
            {
                return Ok(ReconcileOutcome {
                    generation: desired.generation,
                    status: ReconcileStatus::RecoveryRequired,
                    message: Some("an interrupted transaction requires root recovery".to_string()),
                });
            }
        }

        let mut journal = JournalEntry::prepared(desired.generation, applied.generation);
        journal.previous_active_core_ids = applied.active_core_ids.clone();
        self.store.save_journal(&journal)?;
        if self.validate_graph(desired, &applied).is_err() {
            journal.status = ReconcileStatus::Unsupported;
            journal.error =
                Some("desired state references a missing or incompatible adapter".to_string());
            journal.completed_at = Some(chrono::Utc::now().to_rfc3339());
            self.store.save_journal(&journal)?;
            return Ok(ReconcileOutcome {
                generation: desired.generation,
                status: ReconcileStatus::Unsupported,
                message: journal.error,
            });
        }
        let plans = match self.build_plans(desired, secrets, &applied) {
            Ok(plans) => plans,
            Err(_) => return self.fail_without_mutation(journal, "desired state rendering failed"),
        };
        if validate_listener_plan(&plans).is_err() {
            return self.fail_without_mutation(journal, "desired listener plan conflicts");
        }

        journal.core_ids = plans.keys().cloned().collect();
        journal.status = ReconcileStatus::Applying;
        self.store.save_journal(&journal)?;
        let transaction_dir = self.transaction_root.join(desired.generation.to_string());
        prepare_transaction_directory(&transaction_dir)?;

        let mut prepared = Vec::new();
        for (core_id, (core, plan)) in &plans {
            journal.current_core_id = Some(core_id.clone());
            let core_dir = transaction_dir.join(core_id);
            fs::create_dir_all(&core_dir)?;
            let candidate = match core.stage_config(plan, &core_dir) {
                Ok(candidate) => candidate,
                Err(_) => return self.fail_without_mutation(journal, "candidate staging failed"),
            };
            journal.phase = JournalPhase::Staged;
            self.store.save_journal(&journal)?;
            prepared.push((core.clone(), plan.clone(), candidate));
        }
        for (core, _, candidate) in &prepared {
            journal.current_core_id = Some(core.manifest().id.clone());
            if core.validate_config(candidate).is_err() {
                return self.fail_without_mutation(journal, "candidate validation failed");
            }
        }
        journal.phase = JournalPhase::Validated;
        self.store.save_journal(&journal)?;

        let mut snapshotted = Vec::new();
        for (core, plan, candidate) in prepared {
            journal.current_core_id = Some(core.manifest().id.clone());
            let core_dir = transaction_dir.join(&plan.core_id);
            let snapshot = match core.snapshot_config(&core_dir) {
                Ok(snapshot) => snapshot,
                Err(_) => return self.fail_without_mutation(journal, "runtime snapshot failed"),
            };
            journal.resources.push(JournalResource {
                core_id: plan.core_id.clone(),
                snapshot_path: snapshot.path.clone(),
                service_was_enabled: snapshot.service_was_enabled,
                service_was_active: snapshot.service_was_active,
                mutation_started: false,
                verified: false,
            });
            self.store.save_journal(&journal)?;
            snapshotted.push(PreparedCore {
                core,
                plan,
                candidate,
                snapshot,
            });
        }
        journal.phase = JournalPhase::Snapshotted;
        self.store.save_journal(&journal)?;
        if !self
            .store
            .desired_generation_is_current(desired.generation)?
        {
            return self.fail_without_mutation(journal, "desired generation became stale");
        }

        for prepared_core in &snapshotted {
            let core_id = &prepared_core.plan.core_id;
            journal.current_core_id = Some(core_id.clone());
            let resource = journal
                .resources
                .iter_mut()
                .find(|resource| resource.core_id == *core_id)
                .context("journal resource disappeared")?;
            resource.mutation_started = true;
            self.store.save_journal(&journal)?;
            if prepared_core
                .core
                .install_config(&prepared_core.candidate)
                .is_err()
            {
                return self.rollback(
                    desired.generation,
                    snapshotted,
                    journal,
                    "candidate installation failed",
                );
            }
            journal.phase = JournalPhase::Installed;
            self.store.save_journal(&journal)?;
            let required = !prepared_core.plan.fragments.is_empty();
            if prepared_core
                .core
                .activate_config(&prepared_core.plan)
                .is_err()
            {
                return self.rollback(
                    desired.generation,
                    snapshotted,
                    journal,
                    "runtime activation failed",
                );
            }
            journal.phase = JournalPhase::Activated;
            self.store.save_journal(&journal)?;
            if required && prepared_core.core.healthcheck(&prepared_core.plan).is_err() {
                return self.rollback(
                    desired.generation,
                    snapshotted,
                    journal,
                    "runtime health check failed",
                );
            }
            if prepared_core
                .core
                .verify_listeners(&prepared_core.plan)
                .is_err()
            {
                return self.rollback(
                    desired.generation,
                    snapshotted,
                    journal,
                    "listener verification failed",
                );
            }
            let has_individual_users = prepared_core
                .plan
                .fragments
                .iter()
                .any(|fragment| fragment.expected_user_ids.is_some());
            if has_individual_users {
                match prepared_core.core.observe_users(&prepared_core.plan) {
                    Ok(crate::adapter::UserSyncObservation::InSync { .. }) => {}
                    Ok(crate::adapter::UserSyncObservation::Unsupported) => {
                        return self.rollback(
                            desired.generation,
                            snapshotted,
                            journal,
                            "runtime does not support required user observation",
                        );
                    }
                    Ok(crate::adapter::UserSyncObservation::Drift { .. }) => {
                        return self.rollback(
                            desired.generation,
                            snapshotted,
                            journal,
                            "runtime user authorization drift detected",
                        );
                    }
                    Err(_) => {
                        return self.rollback(
                            desired.generation,
                            snapshotted,
                            journal,
                            "runtime user observation failed",
                        );
                    }
                }
            }
            if let Some(resource) = journal
                .resources
                .iter_mut()
                .find(|resource| resource.core_id == *core_id)
            {
                resource.verified = true;
            }
            journal.phase = JournalPhase::Healthy;
            self.store.save_journal(&journal)?;
        }

        let next = AppliedState {
            generation: desired.generation,
            active_core_ids: plans
                .iter()
                .filter(|(_, (_, plan))| !plan.fragments.is_empty())
                .map(|(id, _)| id.clone())
                .collect(),
        };
        if !self
            .store
            .desired_generation_is_current(desired.generation)?
        {
            return self.rollback(
                desired.generation,
                snapshotted,
                journal,
                "desired generation became stale",
            );
        }
        journal.phase = JournalPhase::Publishing;
        self.store.save_journal(&journal)?;
        if !self
            .store
            .compare_and_set_applied(applied.generation, &next)?
        {
            return self.rollback(
                desired.generation,
                snapshotted,
                journal,
                "applied generation changed concurrently",
            );
        }
        journal.phase = JournalPhase::Published;
        journal.status = ReconcileStatus::Applied;
        journal.current_core_id = None;
        journal.error = None;
        journal.completed_at = Some(chrono::Utc::now().to_rfc3339());
        self.store.save_journal(&journal)?;
        self.cleanup_transaction_directory(journal.generation);
        Ok(ReconcileOutcome {
            generation: desired.generation,
            status: ReconcileStatus::Applied,
            message: None,
        })
    }

    /// Recovers an interrupted mutation to the previous known-good snapshots.
    pub fn recover(&self) -> Result<Option<ReconcileOutcome>> {
        let _guard = self
            .lock
            .lock()
            .map_err(|_| anyhow::anyhow!("reconciler lock is poisoned"))?;
        let Some(mut journal) = self.store.load_journal()? else {
            return Ok(None);
        };
        if matches!(
            journal.status,
            ReconcileStatus::Applied
                | ReconcileStatus::Failed
                | ReconcileStatus::RolledBack
                | ReconcileStatus::Unsupported
        ) {
            self.cleanup_transaction_directory(journal.generation);
            return Ok(None);
        }
        let applied = self.store.load_applied()?;
        let new_state_was_fully_verified = !journal.resources.is_empty()
            && journal
                .resources
                .iter()
                .filter(|resource| resource.mutation_started)
                .all(|resource| resource.verified);
        if applied.generation == journal.generation
            && (journal.phase == JournalPhase::Published || new_state_was_fully_verified)
        {
            journal.phase = JournalPhase::Published;
            journal.status = ReconcileStatus::Applied;
            journal.completed_at = Some(chrono::Utc::now().to_rfc3339());
            self.store.save_journal(&journal)?;
            self.cleanup_transaction_directory(journal.generation);
            return Ok(Some(ReconcileOutcome {
                generation: journal.generation,
                status: journal.status,
                message: None,
            }));
        }
        let resources = journal
            .resources
            .iter()
            .filter(|resource| resource.mutation_started)
            .cloned()
            .collect::<Vec<_>>();
        if resources.is_empty() {
            journal.status = ReconcileStatus::Failed;
            journal.error = Some("interrupted before live mutation".to_string());
            journal.completed_at = Some(chrono::Utc::now().to_rfc3339());
            self.store.save_journal(&journal)?;
            self.cleanup_transaction_directory(journal.generation);
            return Ok(Some(ReconcileOutcome {
                generation: journal.generation,
                status: journal.status,
                message: journal.error,
            }));
        }

        journal.phase = JournalPhase::RollbackStarted;
        journal.status = ReconcileStatus::Applying;
        journal.error = Some("recovering interrupted transaction".to_string());
        self.store.save_journal(&journal)?;
        let expected_root = self.transaction_root.join(journal.generation.to_string());
        let mut failed = false;
        for resource in resources.into_iter().rev() {
            let expected_core_root = expected_root.join(&resource.core_id);
            if validate_resource_id(&resource.core_id).is_err()
                || !resource.snapshot_path.starts_with(&expected_core_root)
            {
                failed = true;
                continue;
            }
            let Some(core) = self.cores.get(&resource.core_id) else {
                failed = true;
                continue;
            };
            let snapshot = CoreSnapshot {
                path: resource.snapshot_path,
                service_was_enabled: resource.service_was_enabled,
                service_was_active: resource.service_was_active,
            };
            if core.rollback_config(&snapshot).is_err() {
                failed = true;
            }
        }
        journal.current_core_id = None;
        journal.completed_at = Some(chrono::Utc::now().to_rfc3339());
        if failed {
            journal.phase = JournalPhase::RecoveryRequired;
            journal.status = ReconcileStatus::RecoveryRequired;
            journal.error = Some("automatic recovery could not verify every resource".to_string());
        } else {
            let restored = if applied.generation == journal.generation {
                self.store.compare_and_set_applied(
                    journal.generation,
                    &AppliedState {
                        generation: journal.previous_generation,
                        active_core_ids: journal.previous_active_core_ids.clone(),
                    },
                )?
            } else {
                applied.generation == journal.previous_generation
            };
            if restored {
                journal.phase = JournalPhase::RolledBack;
                journal.status = ReconcileStatus::RolledBack;
                journal.error = Some("interrupted transaction rolled back".to_string());
            } else {
                journal.phase = JournalPhase::RecoveryRequired;
                journal.status = ReconcileStatus::RecoveryRequired;
                journal.error = Some(
                    "runtime rollback succeeded but applied generation changed concurrently"
                        .to_string(),
                );
            }
        }
        self.store.save_journal(&journal)?;
        if matches!(
            journal.status,
            ReconcileStatus::Applied | ReconcileStatus::Failed | ReconcileStatus::RolledBack
        ) {
            self.cleanup_transaction_directory(journal.generation);
        }
        Ok(Some(ReconcileOutcome {
            generation: journal.generation,
            status: journal.status,
            message: journal.error,
        }))
    }

    /// Reports whether removing an installed core would leave desired state unresolved.
    pub fn core_removal_blocked(&self, desired: &DesiredState, core_id: &str) -> Result<bool> {
        for profile in desired.profiles.iter().filter(|profile| profile.enabled) {
            let protocol = self
                .protocols
                .get(&profile.protocol_id)
                .context("desired protocol adapter is missing")?;
            if profile.preferred_core_id.as_deref() == Some(core_id)
                || self
                    .cores
                    .select_excluding(&protocol.manifest().required_core_capabilities, core_id)?
                    .is_none()
            {
                return Ok(true);
            }
        }
        if desired
            .infrastructure
            .iter()
            .any(|resource| resource.enabled && resource.adapter_id == core_id)
        {
            return Ok(true);
        }
        Ok(false)
    }

    /// Compares desired and live runtime users without mutating either side.
    pub fn observe_user_sync(
        &self,
        desired: &DesiredState,
        secrets: &dyn SecretResolver,
    ) -> Result<Vec<ProfileUserSyncObservation>> {
        let applied = self.store.load_applied()?;
        let plans = self.build_plans(desired, secrets, &applied)?;
        let checked_at = chrono::Utc::now().to_rfc3339();
        let mut result = Vec::new();

        for (runtime_id, (core, plan)) in plans {
            let applicable = plan
                .fragments
                .iter()
                .filter_map(|fragment| {
                    fragment
                        .expected_user_ids
                        .as_ref()
                        .map(|users| (fragment.profile_id.clone(), users.len()))
                })
                .collect::<Vec<_>>();
            if applicable.is_empty() {
                continue;
            }

            let observation = core.observe_users(&plan);
            let probe = core.probe();
            for (profile_id, desired_count) in applicable {
                let (status, observed_count, missing_count, unexpected_count) = match &observation {
                    Ok(UserSyncObservation::InSync { user_count }) => {
                        (UserSyncStatus::Synced, Some(*user_count), Some(0), Some(0))
                    }
                    Ok(UserSyncObservation::Drift {
                        observed_count,
                        missing_count,
                        unexpected_count,
                        ..
                    }) => (
                        UserSyncStatus::Drifted,
                        Some(*observed_count),
                        Some(*missing_count),
                        Some(*unexpected_count),
                    ),
                    Ok(UserSyncObservation::Unsupported) => {
                        (UserSyncStatus::UnsupportedObservation, None, None, None)
                    }
                    Err(_) if probe.installed == Some(false) || probe.active == Some(false) => {
                        (UserSyncStatus::RuntimeUnavailable, None, None, None)
                    }
                    Err(_) => (UserSyncStatus::Failed, None, None, None),
                };
                result.push(ProfileUserSyncObservation {
                    profile_id,
                    runtime_id: runtime_id.clone(),
                    status,
                    desired_count,
                    observed_count,
                    missing_count,
                    unexpected_count,
                    checked_at: checked_at.clone(),
                });
            }
        }
        Ok(result)
    }

    fn build_plans(
        &self,
        desired: &DesiredState,
        secrets: &dyn SecretResolver,
        applied: &AppliedState,
    ) -> Result<CorePlans> {
        let mut fragments_by_core = BTreeMap::new();
        for profile in desired.profiles.iter().filter(|profile| profile.enabled) {
            let protocol = self.protocols.get(&profile.protocol_id).with_context(|| {
                format!("protocol adapter `{}` is missing", profile.protocol_id)
            })?;
            protocol.validate_config(profile.schema_version, &profile.config)?;
            let core = self
                .cores
                .select(
                    &protocol.manifest().required_core_capabilities,
                    profile.preferred_core_id.as_deref(),
                )?
                .context("no installed core satisfies protocol capabilities")?;
            let fragment = protocol.render_server(&ServerRenderContext {
                profile,
                users: &desired.users,
                secrets,
            })?;
            fragments_by_core
                .entry(core.manifest().id.clone())
                .or_insert_with(|| (core, Vec::new()))
                .1
                .push(fragment);
        }

        for resource in desired
            .infrastructure
            .iter()
            .filter(|resource| resource.enabled)
        {
            validate_resource_id(&resource.resource_id)?;
            if resource.schema_version == 0 || !resource.config.is_object() {
                bail!("invalid infrastructure resource schema");
            }
            let adapter = self.cores.get(&resource.adapter_id).with_context(|| {
                format!(
                    "infrastructure adapter `{}` is missing",
                    resource.adapter_id
                )
            })?;
            fragments_by_core
                .entry(resource.adapter_id.clone())
                .or_insert_with(|| (adapter, Vec::new()))
                .1
                .push(crate::adapter::ServerFragment {
                    profile_id: resource.resource_id.clone(),
                    capability: resource.adapter_id.clone(),
                    payload: resource.config.clone(),
                    expected_user_ids: None,
                    listeners: Vec::new(),
                });
        }

        for core_id in &applied.active_core_ids {
            if !fragments_by_core.contains_key(core_id) {
                let core = self
                    .cores
                    .get(core_id)
                    .with_context(|| format!("previously applied core `{core_id}` is missing"))?;
                fragments_by_core.insert(core_id.clone(), (core, Vec::new()));
            }
        }
        Ok(fragments_by_core
            .into_iter()
            .map(|(core_id, (core, fragments))| {
                let plan = CorePlan {
                    generation: desired.generation,
                    core_id: core_id.clone(),
                    fragments,
                };
                (core_id, (core, plan))
            })
            .collect())
    }

    fn validate_graph(&self, desired: &DesiredState, applied: &AppliedState) -> Result<()> {
        for profile in desired.profiles.iter().filter(|profile| profile.enabled) {
            let protocol = self
                .protocols
                .get(&profile.protocol_id)
                .context("desired protocol adapter is missing")?;
            self.cores
                .select(
                    &protocol.manifest().required_core_capabilities,
                    profile.preferred_core_id.as_deref(),
                )?
                .context("no installed core satisfies desired capabilities")?;
        }
        for resource in desired
            .infrastructure
            .iter()
            .filter(|resource| resource.enabled)
        {
            self.cores
                .get(&resource.adapter_id)
                .context("desired infrastructure adapter is missing")?;
        }
        for core_id in &applied.active_core_ids {
            self.cores
                .get(core_id)
                .context("previously applied core adapter is missing")?;
        }
        Ok(())
    }

    fn rollback(
        &self,
        generation: u64,
        snapshots: Vec<PreparedCore>,
        mut journal: JournalEntry,
        error: &str,
    ) -> Result<ReconcileOutcome> {
        journal.phase = JournalPhase::RollbackStarted;
        journal.status = ReconcileStatus::Failed;
        journal.error = Some(error.to_string());
        self.store.save_journal(&journal)?;
        let mut rollback_error = None;
        for prepared in snapshots.into_iter().rev() {
            if let Err(error) = prepared.core.rollback_config(&prepared.snapshot) {
                rollback_error = Some(error);
            }
        }
        if rollback_error.is_some() {
            journal.phase = JournalPhase::RecoveryRequired;
            journal.status = ReconcileStatus::RecoveryRequired;
            journal.error = Some("rollback verification failed".to_string());
        } else {
            journal.phase = JournalPhase::RolledBack;
            journal.status = ReconcileStatus::RolledBack;
        }
        journal.completed_at = Some(chrono::Utc::now().to_rfc3339());
        self.store.save_journal(&journal)?;
        if journal.status == ReconcileStatus::RolledBack {
            self.cleanup_transaction_directory(journal.generation);
        }
        Ok(ReconcileOutcome {
            generation,
            status: journal.status,
            message: journal.error,
        })
    }

    fn fail_without_mutation(
        &self,
        mut journal: JournalEntry,
        error: &str,
    ) -> Result<ReconcileOutcome> {
        journal.status = ReconcileStatus::Failed;
        journal.error = Some(error.to_string());
        journal.current_core_id = None;
        journal.completed_at = Some(chrono::Utc::now().to_rfc3339());
        self.store.save_journal(&journal)?;
        self.cleanup_transaction_directory(journal.generation);
        Ok(ReconcileOutcome {
            generation: journal.generation,
            status: journal.status,
            message: journal.error,
        })
    }

    fn cleanup_transaction_directory(&self, generation: u64) {
        let path = self.transaction_root.join(generation.to_string());
        if matches!(
            fs::symlink_metadata(&path),
            Ok(metadata) if metadata.file_type().is_dir()
        ) {
            let _ = fs::remove_dir_all(path);
        }
    }
}

fn validate_listener_plan(plans: &CorePlans) -> Result<()> {
    let mut owners = BTreeMap::new();
    for (_, plan) in plans.values() {
        for fragment in &plan.fragments {
            for listener in &fragment.listeners {
                if owners
                    .insert(*listener, fragment.profile_id.as_str())
                    .is_some()
                {
                    bail!("multiple resources claim the same listener");
                }
            }
        }
    }
    Ok(())
}

fn read_json_or_default<T>(path: &Path) -> Result<T>
where
    T: serde::de::DeserializeOwned + Default,
{
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(T::default()),
        Err(error) => return Err(error.into()),
    };
    if !metadata.file_type().is_file() || metadata.len() > 1024 * 1024 {
        bail!("reconcile state must be a bounded regular file");
    }
    Ok(serde_json::from_slice(&fs::read(path)?)?)
}

fn prepare_transaction_directory(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_dir() => fs::remove_dir_all(path)?,
        Ok(_) => bail!("reconcile transaction path must be a real directory"),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    fs::create_dir_all(path).context("create reconcile transaction directory")
}

fn write_json_atomic<T: serde::Serialize>(path: &Path, value: &T) -> Result<()> {
    let bytes = serde_json::to_vec(value)?;
    write_bytes_atomic(path, &bytes)
}

fn write_bytes_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path.parent().context("state path has no parent")?;
    fs::create_dir_all(parent)?;
    let temporary = parent.join(format!(".reconcile-{}.tmp", uuid::Uuid::new_v4()));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(&temporary)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    fs::rename(&temporary, path)?;
    OpenOptions::new().read(true).open(parent)?.sync_all()?;
    Ok(())
}

/// Rejects path traversal before any adapter creates transaction paths.
pub fn validate_resource_id(value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        bail!("invalid managed resource ID");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{
        collections::{BTreeMap, BTreeSet},
        sync::atomic::{AtomicBool, AtomicU64, Ordering},
        thread,
        time::Duration,
    };

    use serde_json::{json, Value};

    use super::*;
    use crate::{
        adapter::{
            ClientRenderContext, ConfigField, CoreAdapterManifest, MapSecretResolver,
            ProtocolAdapter, ProtocolAdapterManifest, SecretRef, ServerFragment,
            UserSyncObservation, ADAPTER_API_VERSION,
        },
        models::{ProtocolProfile, ProxyRole, SubscriptionUser},
    };

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum Failure {
        None,
        Stage,
        Validate,
        Snapshot,
        Install,
        Activate,
        Health,
        Listener,
        UserDrift,
        Rollback,
    }

    #[derive(Debug)]
    struct FakeCoreState {
        current: String,
        active: bool,
        enabled: bool,
        failure: Failure,
        installs: usize,
        rollbacks: usize,
        activations: Vec<bool>,
        delay_ms: u64,
    }

    impl Default for FakeCoreState {
        fn default() -> Self {
            Self {
                current: "known-good".to_string(),
                active: false,
                enabled: false,
                failure: Failure::None,
                installs: 0,
                rollbacks: 0,
                activations: Vec::new(),
                delay_ms: 0,
            }
        }
    }

    struct FakeCore {
        manifest: CoreAdapterManifest,
        state: Arc<Mutex<FakeCoreState>>,
    }

    impl FakeCore {
        fn new(id: &str, capabilities: &[&str]) -> Arc<Self> {
            Arc::new(Self {
                manifest: CoreAdapterManifest {
                    api_version: ADAPTER_API_VERSION,
                    id: id.to_string(),
                    display_name: id.to_string(),
                    capabilities: capabilities
                        .iter()
                        .map(|value| (*value).to_string())
                        .collect(),
                    service: format!("{id}.service"),
                    selection_priority: 0,
                },
                state: Arc::new(Mutex::new(FakeCoreState::default())),
            })
        }

        fn fail_at(&self, failure: Failure) {
            self.state.lock().unwrap().failure = failure;
        }
    }

    impl CoreAdapter for FakeCore {
        fn manifest(&self) -> &CoreAdapterManifest {
            &self.manifest
        }

        fn installed(&self) -> Result<bool> {
            Ok(true)
        }

        fn stage_config(&self, plan: &CorePlan, transaction_dir: &Path) -> Result<PathBuf> {
            let (failure, delay_ms) = {
                let state = self.state.lock().unwrap();
                (state.failure, state.delay_ms)
            };
            if failure == Failure::Stage {
                bail!("stage canary-secret-value");
            }
            if delay_ms > 0 {
                thread::sleep(Duration::from_millis(delay_ms));
            }
            let candidate = transaction_dir.join("candidate.json");
            let payloads = plan
                .fragments
                .iter()
                .map(|fragment| fragment.payload.clone())
                .collect::<Vec<_>>();
            fs::write(&candidate, serde_json::to_vec(&payloads)?)?;
            Ok(candidate)
        }

        fn validate_config(&self, _candidate: &Path) -> Result<()> {
            if self.state.lock().unwrap().failure == Failure::Validate {
                bail!("validate canary-secret-value");
            }
            Ok(())
        }

        fn snapshot_config(&self, transaction_dir: &Path) -> Result<CoreSnapshot> {
            let state = self.state.lock().unwrap();
            if state.failure == Failure::Snapshot {
                bail!("snapshot canary-secret-value");
            }
            let path = transaction_dir.join("snapshot");
            fs::write(&path, &state.current)?;
            Ok(CoreSnapshot {
                path,
                service_was_enabled: state.enabled,
                service_was_active: state.active,
            })
        }

        fn install_config(&self, candidate: &Path) -> Result<()> {
            let candidate = fs::read_to_string(candidate)?;
            let mut state = self.state.lock().unwrap();
            state.current = candidate;
            state.installs += 1;
            if state.failure == Failure::Install {
                bail!("install canary-secret-value");
            }
            Ok(())
        }

        fn activate_config(&self, plan: &CorePlan) -> Result<()> {
            let required = !plan.fragments.is_empty();
            let mut state = self.state.lock().unwrap();
            if state.failure == Failure::Activate {
                bail!("activate canary-secret-value");
            }
            state.active = required;
            state.enabled = required;
            state.activations.push(required);
            Ok(())
        }

        fn healthcheck(&self, _plan: &CorePlan) -> Result<()> {
            if self.state.lock().unwrap().failure == Failure::Health {
                bail!("health canary-secret-value");
            }
            Ok(())
        }

        fn verify_listeners(&self, plan: &CorePlan) -> Result<()> {
            let required = !plan.fragments.is_empty();
            let state = self.state.lock().unwrap();
            if state.failure == Failure::Listener || state.active != required {
                bail!("listener canary-secret-value");
            }
            Ok(())
        }

        fn observe_users(&self, plan: &CorePlan) -> Result<UserSyncObservation> {
            let expected_count = plan
                .fragments
                .iter()
                .filter_map(|fragment| fragment.expected_user_ids.as_ref())
                .flatten()
                .collect::<BTreeSet<_>>()
                .len();
            if self.state.lock().unwrap().failure == Failure::UserDrift {
                return Ok(UserSyncObservation::Drift {
                    expected_count,
                    observed_count: expected_count.saturating_sub(1),
                    missing_count: usize::from(expected_count > 0),
                    unexpected_count: 0,
                });
            }
            Ok(UserSyncObservation::InSync {
                user_count: expected_count,
            })
        }

        fn rollback_config(&self, snapshot: &CoreSnapshot) -> Result<()> {
            let mut state = self.state.lock().unwrap();
            state.rollbacks += 1;
            if state.failure == Failure::Rollback {
                bail!("rollback canary-secret-value");
            }
            state.current = fs::read_to_string(&snapshot.path)?;
            state.enabled = snapshot.service_was_enabled;
            state.active = snapshot.service_was_active;
            Ok(())
        }
    }

    struct FakeProtocol {
        manifest: ProtocolAdapterManifest,
        fields: Vec<ConfigField>,
        secret: Option<SecretRef>,
    }

    impl FakeProtocol {
        fn new(id: &str, capability: &str) -> Arc<Self> {
            Arc::new(Self {
                manifest: ProtocolAdapterManifest {
                    api_version: ADAPTER_API_VERSION,
                    id: id.to_string(),
                    display_name: id.to_string(),
                    schema_version: 1,
                    required_core_capabilities: BTreeSet::from([capability.to_string()]),
                    user_participation: crate::adapter::UserParticipation::PerUserUuid,
                    listener_network: crate::adapter::ListenerNetwork::Tcp,
                },
                fields: Vec::new(),
                secret: None,
            })
        }

        fn with_secret(id: &str, capability: &str, reference: &str) -> Arc<Self> {
            Arc::new(Self {
                manifest: ProtocolAdapterManifest {
                    api_version: ADAPTER_API_VERSION,
                    id: id.to_string(),
                    display_name: id.to_string(),
                    schema_version: 1,
                    required_core_capabilities: BTreeSet::from([capability.to_string()]),
                    user_participation: crate::adapter::UserParticipation::PerUserUuid,
                    listener_network: crate::adapter::ListenerNetwork::Tcp,
                },
                fields: Vec::new(),
                secret: Some(SecretRef::parse(reference).unwrap()),
            })
        }
    }

    impl ProtocolAdapter for FakeProtocol {
        fn manifest(&self) -> &ProtocolAdapterManifest {
            &self.manifest
        }

        fn fields(&self) -> &[ConfigField] {
            &self.fields
        }

        fn validate_config(&self, schema_version: u32, config: &Value) -> Result<()> {
            if schema_version != 1 || !config.is_object() {
                bail!("invalid fake config");
            }
            Ok(())
        }

        fn migrate_config(&self, _: u32, config: Value) -> Result<(u32, Value)> {
            Ok((1, config))
        }

        fn client_secret_references(&self, _: &Value) -> Result<Vec<SecretRef>> {
            Ok(self.secret.clone().into_iter().collect())
        }

        fn server_secret_references(&self, _: &Value) -> Result<Vec<SecretRef>> {
            Ok(self.secret.clone().into_iter().collect())
        }

        fn render_client(&self, context: &ClientRenderContext<'_>) -> Result<Value> {
            Ok(json!({"name": context.profile.name, "type": self.manifest.id}))
        }

        fn render_server(&self, context: &ServerRenderContext<'_>) -> Result<ServerFragment> {
            let secret = self
                .secret
                .as_ref()
                .map(|reference| context.secrets.resolve(reference))
                .transpose()?
                .map(|value| value.expose().to_string());
            Ok(ServerFragment {
                profile_id: context.profile.name.clone(),
                capability: self
                    .manifest
                    .required_core_capabilities
                    .iter()
                    .next()
                    .unwrap()
                    .clone(),
                payload: json!({
                    "users": context.users.iter().map(|user| &user.username).collect::<Vec<_>>(),
                    "secret": secret,
                }),
                expected_user_ids: Some(
                    context.users.iter().map(|user| user.uuid.clone()).collect(),
                ),
                listeners: vec![crate::adapter::ListenerClaim {
                    network: self.manifest.listener_network,
                    port: context.profile.port,
                }],
            })
        }
    }

    #[derive(Default)]
    struct FakeStoreState {
        applied: AppliedState,
        journal: Option<JournalEntry>,
    }

    struct FakeStore {
        state: Mutex<FakeStoreState>,
        desired_generation: AtomicU64,
        cas_conflict: AtomicBool,
    }

    impl FakeStore {
        fn new(generation: u64) -> Arc<Self> {
            Arc::new(Self {
                state: Mutex::new(FakeStoreState::default()),
                desired_generation: AtomicU64::new(generation),
                cas_conflict: AtomicBool::new(false),
            })
        }
    }

    impl ReconcileStore for FakeStore {
        fn load_applied(&self) -> Result<AppliedState> {
            Ok(self.state.lock().unwrap().applied.clone())
        }

        fn compare_and_set_applied(&self, expected: u64, next: &AppliedState) -> Result<bool> {
            if self.cas_conflict.load(Ordering::SeqCst) {
                return Ok(false);
            }
            let mut state = self.state.lock().unwrap();
            if state.applied.generation != expected {
                return Ok(false);
            }
            state.applied = next.clone();
            Ok(true)
        }

        fn load_journal(&self) -> Result<Option<JournalEntry>> {
            Ok(self.state.lock().unwrap().journal.clone())
        }

        fn save_journal(&self, entry: &JournalEntry) -> Result<()> {
            self.state.lock().unwrap().journal = Some(entry.clone());
            Ok(())
        }

        fn desired_generation_is_current(&self, generation: u64) -> Result<bool> {
            Ok(self.desired_generation.load(Ordering::SeqCst) == generation)
        }
    }

    fn temp_dir() -> PathBuf {
        let path =
            std::env::temp_dir().join(format!("infiproxy-reconcile-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&path).unwrap();
        path
    }

    fn profile(
        protocol_id: &str,
        preferred_core_id: Option<&str>,
        enabled: bool,
    ) -> ProtocolProfile {
        let port = 10_000
            + protocol_id
                .bytes()
                .map(u16::from)
                .fold(0_u16, u16::wrapping_add)
                % 50_000;
        ProtocolProfile {
            name: format!("profile-{protocol_id}"),
            protocol_id: protocol_id.to_string(),
            schema_version: 1,
            role: ProxyRole::AutoSafe,
            server: "node.example.test".to_string(),
            port,
            enabled,
            preferred_core_id: preferred_core_id.map(str::to_string),
            managed_resource_id: Some(format!("resource-{protocol_id}")),
            config: json!({}),
        }
    }

    #[test]
    fn duplicate_listener_claims_fail_before_runtime_mutation() {
        let core = FakeCore::new("core-a", &["capability-a", "capability-b"]);
        let (protocols, cores) = registries(
            vec![
                FakeProtocol::new("protocol-a", "capability-a"),
                FakeProtocol::new("protocol-b", "capability-b"),
            ],
            vec![core.clone()],
        );
        let store = FakeStore::new(1);
        let reconciler = Reconciler::new(protocols, cores, store, temp_dir());
        let mut first = profile("protocol-a", None, true);
        let mut second = profile("protocol-b", None, true);
        first.port = 443;
        second.port = 443;

        let outcome = reconciler
            .reconcile(&desired(1, vec![first, second], &["alice"]), &resolver(&[]))
            .unwrap();

        assert_eq!(outcome.status, ReconcileStatus::Failed);
        assert_eq!(core.state.lock().unwrap().installs, 0);
        assert_eq!(core.state.lock().unwrap().current, "known-good");
    }

    fn desired(generation: u64, profiles: Vec<ProtocolProfile>, users: &[&str]) -> DesiredState {
        DesiredState {
            generation,
            profiles,
            users: users
                .iter()
                .map(|username| SubscriptionUser {
                    username: (*username).to_string(),
                    uuid: format!("uuid-{username}"),
                    subscription_token: format!("token-{username}"),
                })
                .collect(),
            settings: BTreeMap::new(),
            infrastructure: Vec::new(),
        }
    }

    fn resolver(values: &[(&str, &str)]) -> MapSecretResolver<'static> {
        let values = values
            .iter()
            .map(|(name, value)| ((*name).to_string(), (*value).to_string()))
            .collect::<BTreeMap<_, _>>();
        MapSecretResolver::new(Box::leak(Box::new(values)))
    }

    fn registries(
        protocols: Vec<Arc<FakeProtocol>>,
        cores: Vec<Arc<FakeCore>>,
    ) -> (ProtocolRegistry, CoreRegistry) {
        let mut protocol_registry = ProtocolRegistry::default();
        for protocol in protocols {
            protocol_registry.register(protocol).unwrap();
        }
        let mut core_registry = CoreRegistry::default();
        for core in cores {
            core_registry.register(core).unwrap();
        }
        (protocol_registry, core_registry)
    }

    #[test]
    fn resource_ids_reject_path_traversal() {
        assert!(validate_resource_id("profile_01").is_ok());
        assert!(validate_resource_id("../../etc").is_err());
        assert!(validate_resource_id("with/slash").is_err());
    }

    #[test]
    fn journal_serialization_contains_no_candidate_payload() {
        let mut journal = JournalEntry::prepared(2, 1);
        journal.core_ids = vec!["fake-core".to_string()];
        let serialized = serde_json::to_string(&journal).unwrap();
        assert!(!serialized.contains("secret"));
        assert!(!serialized.contains("payload"));
    }

    #[test]
    fn externally_added_protocol_and_core_reconcile_without_generic_changes() {
        let protocol = FakeProtocol::new("brand-new-protocol", "brand-new-capability");
        let core = FakeCore::new("brand-new-core", &["brand-new-capability"]);
        let (protocols, cores) = registries(vec![protocol], vec![core.clone()]);
        let store = FakeStore::new(1);
        let reconciler = Reconciler::new(protocols, cores, store.clone(), temp_dir());
        let outcome = reconciler
            .reconcile(
                &desired(
                    1,
                    vec![profile("brand-new-protocol", None, true)],
                    &["alice"],
                ),
                &resolver(&[]),
            )
            .unwrap();
        assert_eq!(outcome.status, ReconcileStatus::Applied);
        let state = core.state.lock().unwrap();
        assert_eq!(state.installs, 1);
        assert!(state.current.contains("alice"));
        assert_eq!(store.state.lock().unwrap().applied.generation, 1);
    }

    #[test]
    fn capability_selection_honors_preferred_core() {
        let protocol = FakeProtocol::new("fake-protocol", "shared-capability");
        let core_a = FakeCore::new("core-a", &["shared-capability"]);
        let core_b = FakeCore::new("core-b", &["shared-capability"]);
        let (protocols, cores) = registries(vec![protocol], vec![core_a.clone(), core_b.clone()]);
        let reconciler = Reconciler::new(protocols, cores, FakeStore::new(1), temp_dir());
        reconciler
            .reconcile(
                &desired(1, vec![profile("fake-protocol", Some("core-b"), true)], &[]),
                &resolver(&[]),
            )
            .unwrap();
        assert_eq!(core_a.state.lock().unwrap().installs, 0);
        assert_eq!(core_b.state.lock().unwrap().installs, 1);
    }

    #[test]
    fn missing_protocol_is_unsupported_without_runtime_mutation() {
        let core = FakeCore::new("core-a", &["fake-capability"]);
        let (protocols, cores) = registries(Vec::new(), vec![core.clone()]);
        let reconciler = Reconciler::new(protocols, cores, FakeStore::new(1), temp_dir());
        let outcome = reconciler
            .reconcile(
                &desired(1, vec![profile("missing-protocol", None, true)], &[]),
                &resolver(&[]),
            )
            .unwrap();
        assert_eq!(outcome.status, ReconcileStatus::Unsupported);
        assert_eq!(core.state.lock().unwrap().installs, 0);
    }

    #[test]
    fn core_removal_requires_a_compatible_unpreferred_replacement() {
        let protocol = FakeProtocol::new("fake-protocol", "shared-capability");
        let core_a = FakeCore::new("core-a", &["shared-capability"]);
        let core_b = FakeCore::new("core-b", &["shared-capability"]);
        let (protocols, cores) = registries(vec![protocol], vec![core_a, core_b]);
        let reconciler = Reconciler::new(protocols, cores, FakeStore::new(1), temp_dir());
        let preferred = desired(1, vec![profile("fake-protocol", Some("core-a"), true)], &[]);
        assert!(reconciler
            .core_removal_blocked(&preferred, "core-a")
            .unwrap());
        let unbound = desired(1, vec![profile("fake-protocol", None, true)], &[]);
        assert!(!reconciler.core_removal_blocked(&unbound, "core-a").unwrap());
    }

    #[test]
    fn compatible_core_migration_deactivates_previous_core_atomically() {
        let protocol = FakeProtocol::new("fake-protocol", "shared-capability");
        let core_a = FakeCore::new("core-a", &["shared-capability"]);
        let core_b = FakeCore::new("core-b", &["shared-capability"]);
        let (protocols, cores) = registries(vec![protocol], vec![core_a.clone(), core_b.clone()]);
        let store = FakeStore::new(1);
        let reconciler = Reconciler::new(protocols, cores, store.clone(), temp_dir());
        reconciler
            .reconcile(
                &desired(1, vec![profile("fake-protocol", Some("core-a"), true)], &[]),
                &resolver(&[]),
            )
            .unwrap();
        store.desired_generation.store(2, Ordering::SeqCst);
        let outcome = reconciler
            .reconcile(
                &desired(2, vec![profile("fake-protocol", Some("core-b"), true)], &[]),
                &resolver(&[]),
            )
            .unwrap();
        assert_eq!(outcome.status, ReconcileStatus::Applied);
        assert!(!core_a.state.lock().unwrap().active);
        assert!(core_b.state.lock().unwrap().active);
    }

    #[test]
    fn same_generation_is_an_idempotent_noop() {
        let protocol = FakeProtocol::new("fake-protocol", "fake-capability");
        let core = FakeCore::new("fake-core", &["fake-capability"]);
        let (protocols, cores) = registries(vec![protocol], vec![core.clone()]);
        let reconciler = Reconciler::new(protocols, cores, FakeStore::new(1), temp_dir());
        let state = desired(1, vec![profile("fake-protocol", None, true)], &[]);
        reconciler.reconcile(&state, &resolver(&[])).unwrap();
        reconciler.reconcile(&state, &resolver(&[])).unwrap();
        assert_eq!(core.state.lock().unwrap().installs, 1);
    }

    #[test]
    fn stale_generation_aborts_before_live_mutation() {
        let protocol = FakeProtocol::new("fake-protocol", "fake-capability");
        let core = FakeCore::new("fake-core", &["fake-capability"]);
        let (protocols, cores) = registries(vec![protocol], vec![core.clone()]);
        let store = FakeStore::new(2);
        let reconciler = Reconciler::new(protocols, cores, store, temp_dir());
        let outcome = reconciler
            .reconcile(
                &desired(1, vec![profile("fake-protocol", None, true)], &[]),
                &resolver(&[]),
            )
            .unwrap();
        assert_eq!(outcome.status, ReconcileStatus::Failed);
        assert_eq!(core.state.lock().unwrap().installs, 0);
    }

    #[test]
    fn concurrent_requests_are_serialized_and_collapse_to_one_apply() {
        let protocol = FakeProtocol::new("fake-protocol", "fake-capability");
        let core = FakeCore::new("fake-core", &["fake-capability"]);
        core.state.lock().unwrap().delay_ms = 40;
        let (protocols, cores) = registries(vec![protocol], vec![core.clone()]);
        let reconciler = Arc::new(Reconciler::new(
            protocols,
            cores,
            FakeStore::new(1),
            temp_dir(),
        ));
        let desired = Arc::new(desired(1, vec![profile("fake-protocol", None, true)], &[]));
        let mut threads = Vec::new();
        for _ in 0..2 {
            let reconciler = reconciler.clone();
            let desired = desired.clone();
            threads.push(thread::spawn(move || {
                reconciler.reconcile(&desired, &resolver(&[])).unwrap()
            }));
        }
        for thread in threads {
            thread.join().unwrap();
        }
        assert_eq!(core.state.lock().unwrap().installs, 1);
    }

    fn failure_outcome(failure: Failure) -> (ReconcileOutcome, Arc<FakeCore>) {
        let protocol = FakeProtocol::new("fake-protocol", "fake-capability");
        let core = FakeCore::new("fake-core", &["fake-capability"]);
        core.fail_at(failure);
        let (protocols, cores) = registries(vec![protocol], vec![core.clone()]);
        let reconciler = Reconciler::new(protocols, cores, FakeStore::new(1), temp_dir());
        let outcome = reconciler
            .reconcile(
                &desired(1, vec![profile("fake-protocol", None, true)], &[]),
                &resolver(&[]),
            )
            .unwrap();
        (outcome, core)
    }

    #[test]
    fn pre_mutation_failures_never_change_live_state() {
        for failure in [Failure::Stage, Failure::Validate, Failure::Snapshot] {
            let (outcome, core) = failure_outcome(failure);
            assert_eq!(outcome.status, ReconcileStatus::Failed);
            let state = core.state.lock().unwrap();
            assert_eq!(state.current, "known-good");
            assert_eq!(state.installs, 0);
        }
    }

    #[test]
    fn mutation_activation_health_and_listener_failures_roll_back() {
        for failure in [
            Failure::Install,
            Failure::Activate,
            Failure::Health,
            Failure::Listener,
            Failure::UserDrift,
        ] {
            let (outcome, core) = failure_outcome(failure);
            assert_eq!(outcome.status, ReconcileStatus::RolledBack);
            let state = core.state.lock().unwrap();
            assert_eq!(state.current, "known-good");
            assert_eq!(state.rollbacks, 1);
        }
    }

    #[test]
    fn second_core_failure_rolls_back_every_affected_core() {
        let protocol_a = FakeProtocol::new("protocol-a", "capability-a");
        let protocol_b = FakeProtocol::new("protocol-b", "capability-b");
        let core_a = FakeCore::new("core-a", &["capability-a"]);
        let core_b = FakeCore::new("core-b", &["capability-b"]);
        core_b.fail_at(Failure::Install);
        let (protocols, cores) = registries(
            vec![protocol_a, protocol_b],
            vec![core_a.clone(), core_b.clone()],
        );
        let reconciler = Reconciler::new(protocols, cores, FakeStore::new(1), temp_dir());
        let outcome = reconciler
            .reconcile(
                &desired(
                    1,
                    vec![
                        profile("protocol-a", None, true),
                        profile("protocol-b", None, true),
                    ],
                    &[],
                ),
                &resolver(&[]),
            )
            .unwrap();
        assert_eq!(outcome.status, ReconcileStatus::RolledBack);
        assert_eq!(core_a.state.lock().unwrap().current, "known-good");
        assert_eq!(core_b.state.lock().unwrap().current, "known-good");
    }

    #[test]
    fn rollback_failure_is_recovery_required() {
        let protocol = FakeProtocol::new("fake-protocol", "fake-capability");
        let core = FakeCore::new("fake-core", &["fake-capability"]);
        core.fail_at(Failure::Rollback);
        let (protocols, cores) = registries(vec![protocol], vec![core]);
        let store = FakeStore::new(1);
        store.cas_conflict.store(true, Ordering::SeqCst);
        let reconciler = Reconciler::new(protocols, cores, store, temp_dir());
        let outcome = reconciler
            .reconcile(
                &desired(1, vec![profile("fake-protocol", None, true)], &[]),
                &resolver(&[]),
            )
            .unwrap();
        assert_eq!(outcome.status, ReconcileStatus::RecoveryRequired);
    }

    #[test]
    fn crash_recovery_rolls_back_a_mutated_snapshot() {
        let core = FakeCore::new("fake-core", &["fake-capability"]);
        core.state.lock().unwrap().current = "partially-applied".to_string();
        let root = temp_dir();
        let snapshot_dir = root.join("1/fake-core");
        fs::create_dir_all(&snapshot_dir).unwrap();
        let snapshot_path = snapshot_dir.join("snapshot");
        fs::write(&snapshot_path, "known-good").unwrap();
        let store = FakeStore::new(1);
        let mut journal = JournalEntry::prepared(1, 0);
        journal.status = ReconcileStatus::Applying;
        journal.phase = JournalPhase::Installed;
        journal.resources.push(JournalResource {
            core_id: "fake-core".to_string(),
            snapshot_path,
            service_was_enabled: false,
            service_was_active: false,
            mutation_started: true,
            verified: false,
        });
        store.save_journal(&journal).unwrap();
        let (protocols, cores) = registries(Vec::new(), vec![core.clone()]);
        let reconciler = Reconciler::new(protocols, cores, store, &root);
        let outcome = reconciler.recover().unwrap().unwrap();
        assert_eq!(outcome.status, ReconcileStatus::RolledBack);
        assert_eq!(core.state.lock().unwrap().current, "known-good");
    }

    #[test]
    fn crash_after_applied_cas_accepts_only_fully_verified_new_state() {
        let core = FakeCore::new("frontend-adapter", &["frontend-adapter"]);
        let snapshot_root = temp_dir();
        let snapshot = snapshot_root
            .join("2")
            .join("frontend-adapter")
            .join("snapshot");
        fs::create_dir_all(snapshot.parent().unwrap()).unwrap();
        fs::write(&snapshot, "known-good").unwrap();
        let store = FakeStore::new(2);
        let mut journal = JournalEntry::prepared(2, 1);
        journal.phase = JournalPhase::Publishing;
        journal.status = ReconcileStatus::Applying;
        journal.core_ids = vec!["frontend-adapter".to_string()];
        journal.resources.push(JournalResource {
            core_id: "frontend-adapter".to_string(),
            snapshot_path: snapshot,
            service_was_enabled: false,
            service_was_active: false,
            mutation_started: true,
            verified: true,
        });
        {
            let mut state = store.state.lock().unwrap();
            state.applied = AppliedState {
                generation: 2,
                active_core_ids: vec!["frontend-adapter".to_string()],
            };
            state.journal = Some(journal);
        }
        let mut cores = CoreRegistry::default();
        cores.register(core.clone()).unwrap();
        let reconciler = Reconciler::new(ProtocolRegistry::default(), cores, store, snapshot_root);

        let outcome = reconciler.recover().unwrap().unwrap();
        assert_eq!(outcome.status, ReconcileStatus::Applied);
        assert_eq!(core.state.lock().unwrap().rollbacks, 0);
    }

    #[test]
    fn domain_resource_remains_unapplied_until_frontend_health_succeeds() {
        let frontend = FakeCore::new("frontend-adapter", &["frontend-adapter"]);
        frontend.fail_at(Failure::Health);
        let mut cores = CoreRegistry::default();
        cores.register(frontend.clone()).unwrap();
        let store = FakeStore::new(1);
        let reconciler = Reconciler::new(
            ProtocolRegistry::default(),
            cores,
            store.clone(),
            temp_dir(),
        );
        let mut state = desired(1, Vec::new(), &[]);
        state
            .infrastructure
            .push(crate::desired::InfrastructureResource {
                resource_id: "public-domain".to_string(),
                adapter_id: "frontend-adapter".to_string(),
                schema_version: 1,
                enabled: true,
                config: json!({
                    "subscription_domain": "new.example.test",
                    "node_domain": "node.example.test"
                }),
            });

        let failed = reconciler.reconcile(&state, &resolver(&[])).unwrap();
        assert_eq!(failed.status, ReconcileStatus::RolledBack);
        assert_eq!(store.state.lock().unwrap().applied.generation, 0);

        frontend.fail_at(Failure::None);
        let applied = reconciler.reconcile(&state, &resolver(&[])).unwrap();
        assert_eq!(applied.status, ReconcileStatus::Applied);
        assert_eq!(store.state.lock().unwrap().applied.generation, 1);
    }

    #[test]
    fn user_create_disable_and_delete_are_part_of_runtime_candidates() {
        let protocol = FakeProtocol::new("fake-protocol", "fake-capability");
        let core = FakeCore::new("fake-core", &["fake-capability"]);
        let (protocols, cores) = registries(vec![protocol], vec![core.clone()]);
        let store = FakeStore::new(1);
        let reconciler = Reconciler::new(protocols, cores, store.clone(), temp_dir());
        reconciler
            .reconcile(
                &desired(1, vec![profile("fake-protocol", None, true)], &["alice"]),
                &resolver(&[]),
            )
            .unwrap();
        assert!(core.state.lock().unwrap().current.contains("alice"));
        store.desired_generation.store(2, Ordering::SeqCst);
        reconciler
            .reconcile(
                &desired(2, vec![profile("fake-protocol", None, true)], &[]),
                &resolver(&[]),
            )
            .unwrap();
        assert!(!core.state.lock().unwrap().current.contains("alice"));
    }

    #[test]
    fn user_sync_observation_is_count_only_and_reports_drift() {
        let protocol = FakeProtocol::new("fake-protocol", "fake-capability");
        let core = FakeCore::new("fake-core", &["fake-capability"]);
        let (protocols, cores) = registries(vec![protocol], vec![core.clone()]);
        let store = FakeStore::new(1);
        let reconciler = Reconciler::new(protocols, cores, store, temp_dir());
        let desired = desired(
            1,
            vec![profile("fake-protocol", None, true)],
            &["alice", "bob"],
        );

        let synced = reconciler
            .observe_user_sync(&desired, &resolver(&[]))
            .unwrap();
        assert_eq!(synced.len(), 1);
        assert_eq!(synced[0].status, UserSyncStatus::Synced);
        assert_eq!(synced[0].desired_count, 2);
        assert_eq!(synced[0].observed_count, Some(2));

        core.fail_at(Failure::UserDrift);
        let drifted = reconciler
            .observe_user_sync(&desired, &resolver(&[]))
            .unwrap();
        assert_eq!(drifted[0].status, UserSyncStatus::Drifted);
        assert_eq!(drifted[0].missing_count, Some(1));
        assert_eq!(desired.users.len(), 2);
    }

    #[test]
    fn failed_user_delete_restores_authorization_in_every_core() {
        let protocol_a = FakeProtocol::new("protocol-a", "capability-a");
        let protocol_b = FakeProtocol::new("protocol-b", "capability-b");
        let core_a = FakeCore::new("core-a", &["capability-a"]);
        let core_b = FakeCore::new("core-b", &["capability-b"]);
        let (protocols, cores) = registries(
            vec![protocol_a, protocol_b],
            vec![core_a.clone(), core_b.clone()],
        );
        let store = FakeStore::new(1);
        let reconciler = Reconciler::new(protocols, cores, store.clone(), temp_dir());
        let profiles = vec![
            profile("protocol-a", None, true),
            profile("protocol-b", None, true),
        ];
        reconciler
            .reconcile(&desired(1, profiles.clone(), &["alice"]), &resolver(&[]))
            .unwrap();
        core_b.fail_at(Failure::Health);
        store.desired_generation.store(2, Ordering::SeqCst);
        let outcome = reconciler
            .reconcile(&desired(2, profiles, &[]), &resolver(&[]))
            .unwrap();
        assert_eq!(outcome.status, ReconcileStatus::RolledBack);
        assert!(core_a.state.lock().unwrap().current.contains("alice"));
        assert!(core_b.state.lock().unwrap().current.contains("alice"));
    }

    #[test]
    fn secret_values_never_enter_journal_or_errors() {
        let protocol =
            FakeProtocol::with_secret("fake-protocol", "fake-capability", "runtime.password");
        let core = FakeCore::new("fake-core", &["fake-capability"]);
        core.fail_at(Failure::Validate);
        let (protocols, cores) = registries(vec![protocol], vec![core]);
        let store = FakeStore::new(1);
        let reconciler = Reconciler::new(protocols, cores, store.clone(), temp_dir());
        let outcome = reconciler
            .reconcile(
                &desired(1, vec![profile("fake-protocol", None, true)], &[]),
                &resolver(&[("runtime.password", "canary-secret-value")]),
            )
            .unwrap();
        assert!(!outcome.message.unwrap().contains("canary"));
        let journal = serde_json::to_string(&store.state.lock().unwrap().journal).unwrap();
        assert!(!journal.contains("canary-secret-value"));
    }

    #[test]
    fn disabling_last_profile_deactivates_core_and_removes_listener() {
        let protocol = FakeProtocol::new("fake-protocol", "fake-capability");
        let core = FakeCore::new("fake-core", &["fake-capability"]);
        let (protocols, cores) = registries(vec![protocol], vec![core.clone()]);
        let store = FakeStore::new(1);
        let reconciler = Reconciler::new(protocols, cores, store.clone(), temp_dir());
        reconciler
            .reconcile(
                &desired(1, vec![profile("fake-protocol", None, true)], &[]),
                &resolver(&[]),
            )
            .unwrap();
        store.desired_generation.store(2, Ordering::SeqCst);
        reconciler
            .reconcile(
                &desired(2, vec![profile("fake-protocol", None, false)], &[]),
                &resolver(&[]),
            )
            .unwrap();
        let state = core.state.lock().unwrap();
        assert!(!state.active);
        assert_eq!(state.activations.last(), Some(&false));
    }

    #[test]
    fn installed_but_unused_core_remains_inactive() {
        let core = FakeCore::new("fake-core", &["fake-capability"]);
        let (protocols, cores) = registries(Vec::new(), vec![core.clone()]);
        let reconciler = Reconciler::new(protocols, cores, FakeStore::new(1), temp_dir());
        let outcome = reconciler
            .reconcile(&desired(1, Vec::new(), &[]), &resolver(&[]))
            .unwrap();
        assert_eq!(outcome.status, ReconcileStatus::Applied);
        assert_eq!(core.state.lock().unwrap().installs, 0);
    }
}
