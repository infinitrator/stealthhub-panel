//! Root-only desired-state reconciliation worker.

use std::{
    collections::BTreeMap,
    fs::{self, OpenOptions},
    io::Write,
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
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
        delete_secret, get_secret, init_db, load_desired_state, mark_reconcile_result,
        migrate_available_adapter_states, open_pool, replace_runtime_user_sync,
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

struct PrivilegedSecretStore {
    directory: PathBuf,
    required_uid: u32,
}

impl PrivilegedSecretStore {
    fn root(directory: PathBuf) -> Self {
        Self {
            directory,
            required_uid: 0,
        }
    }

    fn path(&self, reference: &SecretRef) -> PathBuf {
        self.directory.join(reference.as_str())
    }

    fn read(&self, reference: &SecretRef) -> Result<SecretValue> {
        let path = self.path(reference);
        let metadata = fs::symlink_metadata(&path)
            .context("required privileged secret reference is unresolved")?;
        if !metadata.file_type().is_file() || metadata.len() > MAX_SECRET_BYTES {
            bail!("privileged secret must be a bounded regular file");
        }
        if metadata.uid() != self.required_uid || metadata.permissions().mode() & 0o077 != 0 {
            bail!("privileged secret has unsafe ownership or mode");
        }
        SecretValue::new(fs::read_to_string(path)?)
    }

    fn write(&self, reference: &SecretRef, value: &SecretValue) -> Result<()> {
        let metadata = fs::symlink_metadata(&self.directory)?;
        if !metadata.file_type().is_dir()
            || metadata.uid() != self.required_uid
            || metadata.permissions().mode() & 0o077 != 0
        {
            bail!("privileged secret directory has unsafe ownership or mode");
        }
        let path = self.path(reference);
        let temporary = self
            .directory
            .join(format!(".adopt-{}", uuid::Uuid::new_v4()));
        let result = (|| {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&temporary)?;
            file.write_all(value.expose().as_bytes())?;
            file.write_all(b"\n")?;
            file.sync_all()?;
            fs::hard_link(&temporary, &path)?;
            fs::remove_file(&temporary)?;
            fs::File::open(&self.directory)?.sync_all()?;
            Ok(())
        })();
        if result.is_err() {
            let _ = fs::remove_file(temporary);
        }
        result
    }
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
    let arguments = std::env::args().skip(1).collect::<Vec<_>>();
    if arguments
        .first()
        .is_some_and(|value| value == "--adopt-server-secret")
    {
        if arguments.len() != 2 {
            bail!("usage: infiproxy-reconcile --adopt-server-secret REFERENCE");
        }
        return adopt_legacy_server_secret(&arguments[1]).await;
    }
    if !arguments.is_empty() {
        bail!("unsupported reconciler argument");
    }
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
    let cores = core_registry()?;
    migrate_available_adapter_states(&pool, &protocols, &cores).await?;
    let secret_protocols = protocols.clone();
    let state_dir = env_path("INFIPROXY_RECONCILE_STATE_DIR", DEFAULT_STATE_DIR);
    let transaction_dir = env_path(
        "INFIPROXY_RECONCILE_TRANSACTION_DIR",
        DEFAULT_TRANSACTION_DIR,
    );
    let store = std::sync::Arc::new(FileReconcileStore::new(&state_dir));
    store.publish_desired_generation(desired.generation)?;
    let reconciler = Reconciler::new(protocols, cores, store.clone(), transaction_dir);

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
    let secrets = load_privileged_secrets(&pool, &secret_protocols, &desired).await?;
    let outcome = if desired.generation > store.load_applied()?.generation {
        let outcome = reconciler.reconcile(&desired, &secrets)?;
        persist_status(
            &pool,
            store.as_ref(),
            outcome.status,
            outcome.message.as_deref(),
        )
        .await?;
        Some(outcome)
    } else {
        None
    };

    match reconciler.observe_user_sync(&desired, &secrets) {
        Ok(observations) => replace_runtime_user_sync(&pool, &observations).await?,
        Err(_) => eprintln!("runtime user synchronization observation failed"),
    }

    if outcome.as_ref().is_some_and(|outcome| {
        !matches!(
            outcome.status,
            ReconcileStatus::Applied | ReconcileStatus::RolledBack
        )
    }) {
        bail!("desired state was not applied; consult sanitized reconcile status");
    }
    Ok(())
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
            active_runtime_ids: &applied.active_core_ids,
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
    let store = PrivilegedSecretStore::root(secret_dir);
    let mut values = BTreeMap::new();
    for profile in desired.profiles.iter().filter(|profile| profile.enabled) {
        let adapter = protocols
            .get(&profile.protocol_id)
            .context("desired protocol adapter is missing")?;
        let server_only = adapter
            .server_only_secret_references(&profile.config)?
            .into_iter()
            .collect::<std::collections::BTreeSet<_>>();
        for reference in adapter.server_secret_references(&profile.config)? {
            if values.contains_key(reference.as_str()) {
                continue;
            }
            let value =
                resolve_server_secret(pool, &store, &reference, server_only.contains(&reference))
                    .await?;
            values.insert(reference.as_str().to_string(), value);
        }
    }
    Ok(PrivilegedSecrets { values })
}

async fn resolve_server_secret(
    pool: &sqlx::SqlitePool,
    store: &PrivilegedSecretStore,
    reference: &SecretRef,
    server_only: bool,
) -> Result<SecretValue> {
    if server_only {
        return store.read(reference);
    }
    if store.path(reference).exists() {
        return store.read(reference);
    }
    get_secret(pool, reference.as_str())
        .await?
        .map(|record| SecretValue::new(record.value))
        .transpose()?
        .context("required shared secret reference is unresolved")
}

async fn adopt_legacy_server_secret(reference: &str) -> Result<()> {
    let reference = SecretRef::parse(reference)?;
    let database_url = std::env::var("INFIPROXY_DB")
        .or_else(|_| std::env::var("STEALTHHUB_DB"))
        .unwrap_or_else(|_| "sqlite:///var/lib/infiproxy/infiproxy.sqlite?mode=rwc".to_string());
    let pool = open_pool(&database_url).await?;
    init_db(&pool).await?;
    let protocols = protocol_registry()?;
    let store = PrivilegedSecretStore::root(env_path("INFIPROXY_SECRET_DIR", DEFAULT_SECRET_DIR));
    adopt_server_only_secret(&pool, &protocols, &store, &reference).await?;
    println!("Privileged secret reference was adopted successfully.");
    Ok(())
}

async fn adopt_server_only_secret(
    pool: &sqlx::SqlitePool,
    protocols: &ProtocolRegistry,
    store: &PrivilegedSecretStore,
    reference: &SecretRef,
) -> Result<()> {
    let desired = load_desired_state(pool).await?;
    let mut classified = false;
    for profile in &desired.profiles {
        let Some(adapter) = protocols.get(&profile.protocol_id) else {
            continue;
        };
        classified |= adapter
            .server_only_secret_references(&profile.config)?
            .contains(reference);
    }
    if !classified {
        bail!("reference is not classified as a server-only secret");
    }

    let legacy = get_secret(pool, reference.as_str()).await?;
    if store.path(reference).exists() {
        let privileged = store.read(reference)?;
        if let Some(legacy) = &legacy {
            if privileged != SecretValue::new(legacy.value.clone())? {
                bail!("privileged and legacy secret values do not match");
            }
        }
    } else if let Some(legacy) = &legacy {
        let value = SecretValue::new(legacy.value.clone())?;
        store.write(reference, &value)?;
        if store.read(reference)? != value {
            bail!("privileged secret verification failed");
        }
    } else {
        bail!("legacy server-only secret is unavailable");
    }

    if legacy.is_some() {
        delete_secret(pool, reference.as_str()).await?;
    }
    Ok(())
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

#[cfg(test)]
mod tests {
    use super::*;
    use stealthhub_core::storage::upsert_secret;

    async fn test_context() -> Result<(sqlx::SqlitePool, PathBuf, PrivilegedSecretStore)> {
        let root = std::env::temp_dir().join(format!(
            "infiproxy-reconcile-secret-test-{}",
            uuid::Uuid::new_v4()
        ));
        let secret_dir = root.join("secrets");
        fs::create_dir_all(&secret_dir)?;
        fs::set_permissions(&secret_dir, fs::Permissions::from_mode(0o700))?;
        let database = root.join("panel.sqlite");
        let pool = open_pool(&format!("sqlite://{}?mode=rwc", database.display())).await?;
        init_db(&pool).await?;
        let required_uid = fs::metadata(&secret_dir)?.uid();
        Ok((
            pool,
            root,
            PrivilegedSecretStore {
                directory: secret_dir,
                required_uid,
            },
        ))
    }

    #[tokio::test]
    async fn server_only_sqlite_fallback_is_rejected_but_shared_sqlite_still_works() -> Result<()> {
        let (pool, root, store) = test_context().await?;
        let private = SecretRef::parse("xray.reality.private_key")?;
        let shared = SecretRef::parse("tuic.password")?;
        upsert_secret(&pool, private.as_str(), "private-plaintext-canary").await?;
        upsert_secret(&pool, shared.as_str(), "shared-secret").await?;

        let error = resolve_server_secret(&pool, &store, &private, true)
            .await
            .unwrap_err();
        assert!(!error.to_string().contains("private-plaintext-canary"));
        assert_eq!(
            resolve_server_secret(&pool, &store, &shared, false)
                .await?
                .expose(),
            "shared-secret"
        );

        let private_value = SecretValue::new("private-plaintext-canary")?;
        store.write(&private, &private_value)?;
        assert_eq!(
            resolve_server_secret(&pool, &store, &private, true).await?,
            private_value
        );
        assert!(!format!("{private_value:?}").contains("private-plaintext-canary"));

        pool.close().await;
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[tokio::test]
    async fn legacy_server_only_adoption_is_verified_and_idempotent() -> Result<()> {
        let (pool, root, store) = test_context().await?;
        let reference = SecretRef::parse("xray.reality.private_key")?;
        stealthhub_core::storage::ensure_default_protocol_profiles(&pool).await?;
        upsert_secret(&pool, reference.as_str(), "legacy-private-canary").await?;
        let protocols = protocol_registry()?;

        adopt_server_only_secret(&pool, &protocols, &store, &reference).await?;
        assert!(get_secret(&pool, reference.as_str()).await?.is_none());
        assert_eq!(store.read(&reference)?.expose(), "legacy-private-canary");

        adopt_server_only_secret(&pool, &protocols, &store, &reference).await?;
        assert!(get_secret(&pool, reference.as_str()).await?.is_none());

        pool.close().await;
        fs::remove_dir_all(root)?;
        Ok(())
    }
}
