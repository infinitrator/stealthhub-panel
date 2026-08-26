//! Root-only desired-state reconciliation worker.

use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
};

use anyhow::{bail, Context, Result};
use stealthhub_core::{
    adapter::{ProtocolRegistry, SecretRef, SecretResolver, SecretValue},
    adapters::{core_registry, desired_resources, protocol_registry},
    desired::{ReconcileRequest, ReconcileStatus},
    models::PanelSettings,
    reconcile::{FileReconcileStore, ReconcileStore, Reconciler},
    storage::{
        get_secret, init_db, load_desired_state, mark_reconcile_result, open_pool,
        ReconcileResultUpdate,
    },
};

const REQUEST_API_VERSION: u32 = 1;
const DEFAULT_REQUEST_DIR: &str = "/var/lib/infiproxy/reconcile-requests";
const DEFAULT_STATE_DIR: &str = "/var/lib/infiproxy-maintenance/reconcile";
const DEFAULT_TRANSACTION_DIR: &str = "/var/lib/infiproxy-maintenance/reconcile/transactions";
const DEFAULT_SECRET_DIR: &str = "/etc/infiproxy/secrets.d";
const MAX_REQUEST_BYTES: u64 = 1024;
const MAX_SECRET_BYTES: u64 = 8192;

struct PrivilegedSecrets {
    values: BTreeMap<String, SecretValue>,
}

impl SecretResolver for PrivilegedSecrets {
    fn resolve(&self, reference: &SecretRef) -> Result<SecretValue> {
        self.values
            .get(reference.as_str())
            .cloned()
            .context("required privileged secret reference is unresolved")
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    require_root()?;
    let request_dir = env_path("INFIPROXY_RECONCILE_REQUEST_DIR", DEFAULT_REQUEST_DIR);
    validate_request_directory(&request_dir)?;
    let processing = claim_request(&request_dir)?;
    let result = process(processing.as_deref()).await;
    if let Some(processing) = processing {
        let _ = fs::remove_file(processing);
    }
    result
}

async fn process(request_path: Option<&Path>) -> Result<()> {
    let request = request_path.map(read_request).transpose()?;
    let database_url = std::env::var("INFIPROXY_DB")
        .or_else(|_| std::env::var("STEALTHHUB_DB"))
        .unwrap_or_else(|_| "sqlite:///var/lib/infiproxy/infiproxy.sqlite?mode=rwc".to_string());
    let pool = open_pool(&database_url).await?;
    init_db(&pool).await?;
    let mut desired = load_desired_state(&pool).await?;
    if request.is_some_and(|request| request.generation > desired.generation) {
        bail!("request generation is newer than durable desired state");
    }

    let settings = PanelSettings {
        panel_name: desired
            .settings
            .get("panel_name")
            .cloned()
            .unwrap_or_else(|| PanelSettings::default().panel_name),
        subscription_domain: desired
            .settings
            .get("subscription_domain")
            .cloned()
            .unwrap_or_else(|| PanelSettings::default().subscription_domain),
        node_domain: desired
            .settings
            .get("node_domain")
            .cloned()
            .unwrap_or_else(|| PanelSettings::default().node_domain),
    };
    desired.infrastructure.extend(desired_resources(&settings));
    let protocols = protocol_registry()?;
    let secret_protocols = protocols.clone();
    let state_dir = env_path("INFIPROXY_RECONCILE_STATE_DIR", DEFAULT_STATE_DIR);
    let transaction_dir = env_path(
        "INFIPROXY_RECONCILE_TRANSACTION_DIR",
        DEFAULT_TRANSACTION_DIR,
    );
    let store = std::sync::Arc::new(FileReconcileStore::new(&state_dir));
    store.publish_desired_generation(desired.generation)?;
    let reconciler = Reconciler::new(protocols, core_registry()?, store.clone(), transaction_dir);

    if let Some(recovery) = reconciler.recover()? {
        persist_status(
            &pool,
            store.as_ref(),
            recovery.status,
            recovery.message.as_deref(),
        )
        .await?;
        if recovery.status == ReconcileStatus::RecoveryRequired {
            bail!("automatic reconcile recovery requires operator attention");
        }
    }
    if desired.generation <= store.load_applied()?.generation {
        return Ok(());
    }
    let secrets = load_privileged_secrets(&pool, &secret_protocols, &desired).await?;
    let outcome = reconciler.reconcile(&desired, &secrets)?;
    persist_status(
        &pool,
        store.as_ref(),
        outcome.status,
        outcome.message.as_deref(),
    )
    .await?;
    if matches!(
        outcome.status,
        ReconcileStatus::Applied | ReconcileStatus::RolledBack
    ) {
        Ok(())
    } else {
        bail!("desired state was not applied; consult sanitized reconcile status")
    }
}

async fn persist_status(
    pool: &sqlx::SqlitePool,
    store: &FileReconcileStore,
    status: ReconcileStatus,
    error: Option<&str>,
) -> Result<()> {
    let journal = store
        .load_journal()?
        .context("reconcile journal is missing")?;
    let applied = store.load_applied()?;
    mark_reconcile_result(
        pool,
        ReconcileResultUpdate {
            desired_generation: journal.generation,
            applied_generation: applied.generation,
            status: status_name(status),
            operation_id: &journal.operation_id,
            affected_resources: &journal.core_ids,
            error,
            started_at: Some(&journal.started_at),
            completed_at: journal.completed_at.as_deref(),
        },
    )
    .await
}

async fn load_privileged_secrets(
    pool: &sqlx::SqlitePool,
    protocols: &ProtocolRegistry,
    desired: &stealthhub_core::desired::DesiredState,
) -> Result<PrivilegedSecrets> {
    let secret_dir = env_path("INFIPROXY_SECRET_DIR", DEFAULT_SECRET_DIR);
    let mut values = BTreeMap::new();
    for profile in desired.profiles.iter().filter(|profile| profile.enabled) {
        let adapter = protocols
            .get(&profile.protocol_id)
            .context("desired protocol adapter is missing")?;
        for reference in adapter.server_secret_references(&profile.config)? {
            if values.contains_key(reference.as_str()) {
                continue;
            }
            let file = secret_dir.join(reference.as_str());
            let value = if file.exists() {
                read_root_secret(&file)?
            } else if let Some(record) = get_secret(pool, reference.as_str()).await? {
                SecretValue::new(record.value)?
            } else {
                bail!("required privileged secret reference is unresolved");
            };
            values.insert(reference.as_str().to_string(), value);
        }
    }
    Ok(PrivilegedSecrets { values })
}

fn read_root_secret(path: &Path) -> Result<SecretValue> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_file() || metadata.len() > MAX_SECRET_BYTES {
        bail!("privileged secret must be a bounded regular file");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if metadata.uid() != 0 || metadata.permissions().mode() & 0o077 != 0 {
            bail!("privileged secret must be root-owned and mode 0600");
        }
    }
    SecretValue::new(fs::read_to_string(path)?)
}

fn claim_request(directory: &Path) -> Result<Option<PathBuf>> {
    let request = directory.join("reconcile.request");
    if !request.exists() {
        return Ok(None);
    }
    validate_request_file(&request, directory)?;
    let processing = directory.join(format!(".processing-{}", uuid::Uuid::new_v4()));
    match fs::rename(&request, &processing) {
        Ok(()) => {
            validate_request_file(&processing, directory)?;
            Ok(Some(processing))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}

fn read_request(path: &Path) -> Result<ReconcileRequest> {
    let request: ReconcileRequest = serde_json::from_slice(&fs::read(path)?)?;
    if request.api_version != REQUEST_API_VERSION || request.generation == 0 {
        bail!("unsupported reconcile request");
    }
    Ok(request)
}

fn validate_request_directory(directory: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(directory)?;
    if !metadata.file_type().is_dir() {
        bail!("request path must be a real directory");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if metadata.uid() == 0 || metadata.permissions().mode() & 0o022 != 0 {
            bail!("request directory must be app-owned and not group/world-writable");
        }
    }
    Ok(())
}

fn validate_request_file(path: &Path, directory: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    let directory_metadata = fs::symlink_metadata(directory)?;
    if !metadata.file_type().is_file() || metadata.len() > MAX_REQUEST_BYTES {
        bail!("request must be a bounded regular file");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if metadata.uid() != directory_metadata.uid() || metadata.permissions().mode() & 0o022 != 0
        {
            bail!("request ownership or mode is unsafe");
        }
    }
    Ok(())
}

fn require_root() -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        let status = fs::read_to_string("/proc/self/status")?;
        let effective = status
            .lines()
            .find(|line| line.starts_with("Uid:"))
            .and_then(|line| line.split_whitespace().nth(2));
        if effective != Some("0") {
            bail!("reconcile worker must run as root");
        }
    }
    Ok(())
}

fn env_path(name: &str, default: &str) -> PathBuf {
    std::env::var_os(name).map_or_else(|| PathBuf::from(default), PathBuf::from)
}

const fn status_name(status: ReconcileStatus) -> &'static str {
    match status {
        ReconcileStatus::Pending => "pending",
        ReconcileStatus::Applying => "applying",
        ReconcileStatus::Applied => "applied",
        ReconcileStatus::Failed => "failed",
        ReconcileStatus::RolledBack => "rolled-back",
        ReconcileStatus::Unsupported => "unsupported",
        ReconcileStatus::RecoveryRequired => "recovery-required",
    }
}
