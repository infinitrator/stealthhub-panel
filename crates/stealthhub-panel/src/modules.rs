//! Dynamic runtime-module registry and unprivileged update bridge.
//!
//! Module definitions are root-owned declarative manifests. The panel can read
//! the registry, discover upstream versions and create fixed-format requests,
//! but it never downloads binaries or executes package-management commands.

use crate::{atomic_file, ui::APP_NAME};
use chrono::Utc;
use serde::Deserialize;
use sqlx::SqlitePool;
use std::{
    collections::{BTreeSet, HashSet},
    fs,
    path::{Path, PathBuf},
    time::Duration,
};
pub(crate) use stealthhub_core::module_manifest::{ModuleSpec, UpstreamKind};
use stealthhub_core::{
    adapter::{
        RuntimeHealthState, RuntimeLifecycle, RuntimeLifecycleAction, RuntimeLifecycleStatus,
        RuntimeServiceState, RuntimeUpstreamMetadata,
    },
    module_manifest::{load_registry, valid_id, ReadOptions},
    storage::{get_setting, upsert_setting, upsert_settings},
};

const CHECK_INTERVAL: Duration = Duration::from_hours(2);
const INITIAL_DELAY: Duration = Duration::from_secs(35);
const DEFAULT_MANIFEST_DIR: &str = "/etc/infiproxy-modules.d";
const DEFAULT_AVAILABLE_DIR: &str = "/etc/infiproxy-modules.available.d";
const DEFAULT_STATE_DIR: &str = "/var/lib/infiproxy/modules";
const DEFAULT_REQUEST_DIR: &str = "/var/lib/infiproxy/module-requests";
const DEFAULT_VERSION_DIR: &str = "/var/lib/infiproxy-maintenance/module-versions";
const RETIRED_PRODUCT_MODULE_IDS: &[&str] = &["headscale", "mtproto"];
/// Persisted and locally observed module update state.
#[derive(Debug, Clone)]
pub(crate) struct ModuleStatus {
    pub(crate) spec: ModuleSpec,
    pub(crate) installed: bool,
    pub(crate) installed_version: String,
    pub(crate) latest_version: String,
    pub(crate) update_available: bool,
    pub(crate) auto_update: bool,
    pub(crate) checked_at: String,
    pub(crate) status: String,
}

/// Runtime lifecycle adapter backed by one validated root-owned manifest.
struct ManifestRuntimeLifecycle {
    spec: ModuleSpec,
    active_manifest: bool,
    upstream: RuntimeUpstreamMetadata,
}

impl ManifestRuntimeLifecycle {
    fn new(spec: ModuleSpec, active_manifest: bool) -> Self {
        let release_channel = match &spec.upstream {
            UpstreamKind::Release => "stable-release".to_string(),
            UpstreamKind::Commit { git_ref } => format!("commit:{git_ref}"),
        };
        Self {
            upstream: RuntimeUpstreamMetadata {
                repository: spec.repo.clone(),
                release_channel,
                supported_platforms: BTreeSet::from(["linux".to_string()]),
                supported_architectures: BTreeSet::from(["amd64".to_string(), "arm64".to_string()]),
            },
            spec,
            active_manifest,
        }
    }
}

impl RuntimeLifecycle for ManifestRuntimeLifecycle {
    fn runtime_id(&self) -> &str {
        &self.spec.id
    }

    fn upstream(&self) -> &RuntimeUpstreamMetadata {
        &self.upstream
    }

    fn status(&self) -> RuntimeLifecycleStatus {
        let installed = Path::new(&self.spec.binary_path).is_file();
        let version = installed_version(&self.spec);
        let installed_version = (version != "unknown").then_some(version);
        RuntimeLifecycleStatus {
            available: self.active_manifest || !installed,
            installed,
            installed_version,
            available_version: None,
            update_available: false,
            service_state: RuntimeServiceState::Unknown,
            health: if installed {
                RuntimeHealthState::Unknown
            } else {
                RuntimeHealthState::Unavailable
            },
        }
    }

    fn request(&self, action: RuntimeLifecycleAction) -> anyhow::Result<()> {
        if action == RuntimeLifecycleAction::Install && self.active_manifest {
            anyhow::bail!("runtime already exists");
        }
        if action != RuntimeLifecycleAction::Install && !self.active_manifest {
            anyhow::bail!("runtime is not active in the registry");
        }
        write_request(
            self.runtime_id(),
            action.request_suffix(),
            &format!("requested_at={}\n", Utc::now().to_rfc3339()),
        )
    }
}

#[derive(Debug, Deserialize)]
struct GithubRelease {
    tag_name: String,
}

#[derive(Debug, Deserialize)]
struct GithubCommit {
    sha: String,
}

/// Starts the low-frequency upstream checker used by the modules page.
pub(crate) fn spawn_checker(pool: SqlitePool) {
    tokio::spawn(async move {
        tokio::time::sleep(INITIAL_DELAY).await;
        loop {
            if let Err(err) = refresh_all(&pool).await {
                tracing::warn!("module update check failed: {err}");
            }
            tokio::time::sleep(CHECK_INTERVAL).await;
        }
    });
}

/// Loads every valid manifest in deterministic ID order.
pub(crate) fn registry() -> anyhow::Result<Vec<ModuleSpec>> {
    let directory = manifest_dir();
    Ok(visible_product_modules(load_registry(
        &directory,
        registry_options(&directory),
    )?))
}

/// Loads catalog entries that are not currently active.
pub(crate) fn available() -> anyhow::Result<Vec<ModuleSpec>> {
    let active = registry()?
        .into_iter()
        .map(|spec| spec.id)
        .collect::<HashSet<_>>();
    let directory = available_dir();
    Ok(load_registry(&directory, registry_options(&directory))?
        .into_iter()
        .filter(|spec| !active.contains(&spec.id) && !is_retired_product_module(&spec.id))
        .collect())
}

/// Refreshes all upstream versions with one reusable, time-bounded client.
pub(crate) async fn refresh_all(pool: &SqlitePool) -> anyhow::Result<Vec<ModuleStatus>> {
    let client = github_client()?;
    let specs = registry()?;
    let mut statuses = Vec::with_capacity(specs.len());
    for spec in specs {
        match refresh_with_client(pool, spec.clone(), &client).await {
            Ok(status) => statuses.push(status),
            Err(err) => {
                tracing::warn!(module = spec.id, "upstream check failed: {err}");
                persist_check_error(pool, &spec).await?;
                statuses.push(load_one(pool, spec).await?);
            }
        }
    }
    Ok(statuses)
}

/// Refreshes one module after an explicit owner request.
pub(crate) async fn refresh_one(
    pool: &SqlitePool,
    module_id: &str,
) -> anyhow::Result<ModuleStatus> {
    let spec = find(module_id)?.ok_or_else(|| anyhow::anyhow!("unknown module"))?;
    refresh_with_client(pool, spec, &github_client()?).await
}

/// Loads module-page state with one scan of each manifest directory.
pub(crate) async fn load_page(
    pool: &SqlitePool,
) -> anyhow::Result<(Vec<ModuleStatus>, Vec<ModuleSpec>)> {
    let specs = registry()?;
    let active = specs
        .iter()
        .map(|spec| spec.id.as_str())
        .collect::<HashSet<_>>();
    let directory = available_dir();
    let available = load_registry(&directory, registry_options(&directory))?
        .into_iter()
        .filter(|spec| !active.contains(spec.id.as_str()) && !is_retired_product_module(&spec.id))
        .collect();
    Ok((load_statuses(pool, specs).await?, available))
}

async fn load_statuses(
    pool: &SqlitePool,
    specs: Vec<ModuleSpec>,
) -> anyhow::Result<Vec<ModuleStatus>> {
    let mut statuses = Vec::with_capacity(specs.len());
    for spec in specs {
        let status = load_one(pool, spec).await?;
        if let Err(err) = write_state_file(&status) {
            tracing::warn!(
                module = status.spec.id,
                "could not mirror module state: {err}"
            );
        }
        statuses.push(status);
    }
    Ok(statuses)
}

/// Stores the owner-controlled automatic-update policy for one module.
pub(crate) async fn set_auto_update(
    pool: &SqlitePool,
    module_id: &str,
    enabled: bool,
) -> anyhow::Result<()> {
    let spec = find(module_id)?.ok_or_else(|| anyhow::anyhow!("unknown module"))?;
    upsert_setting(
        pool,
        &setting_key(&spec.id, "auto_update"),
        bool_str(enabled),
    )
    .await?;
    let status = load_one(pool, spec).await?;
    write_state_file(&status)?;
    Ok(())
}

/// Returns one manifest entry without relying on a compiled-in allowlist.
pub(crate) fn find(module_id: &str) -> anyhow::Result<Option<ModuleSpec>> {
    if !valid_id(module_id) {
        return Ok(None);
    }
    Ok(registry()?
        .into_iter()
        .find(|module| module.id == module_id))
}

/// Creates an update request consumed by the root-owned module worker.
pub(crate) fn request_update(module_id: &str) -> anyhow::Result<()> {
    request_lifecycle(module_id, RuntimeLifecycleAction::Update)
}

/// Requests safe removal of a registered runtime while preserving its config.
pub(crate) fn request_remove(module_id: &str) -> anyhow::Result<()> {
    request_lifecycle(module_id, RuntimeLifecycleAction::Remove)
}

/// Queues activation of a root-owned catalog manifest.
pub(crate) fn request_register(module_id: &str) -> anyhow::Result<()> {
    request_lifecycle(module_id, RuntimeLifecycleAction::Install)
}

/// Queues one adapter-owned operation for the root worker.
///
/// Only a stable runtime ID and a closed action enum cross the privilege
/// boundary. Runtime manifests supply every executable and service detail.
pub(crate) fn request_lifecycle(
    module_id: &str,
    action: RuntimeLifecycleAction,
) -> anyhow::Result<()> {
    if !valid_id(module_id) {
        anyhow::bail!("invalid runtime ID");
    }
    let active = find(module_id)?;
    let (spec, active_manifest) = if let Some(spec) = active {
        (spec, true)
    } else {
        let spec = available()?
            .into_iter()
            .find(|module| module.id == module_id)
            .ok_or_else(|| anyhow::anyhow!("runtime is not present in the root-owned catalog"))?;
        (spec, false)
    };
    let lifecycle = ManifestRuntimeLifecycle::new(spec, active_manifest);
    lifecycle.request(action)
}

pub(crate) fn short_version(value: &str) -> String {
    if value.len() <= 16 {
        value.to_string()
    } else {
        value.chars().take(12).collect()
    }
}

// Retired product integrations may remain on upgraded hosts solely so the
// privileged cleanup path can remove their historical footprint.
fn is_retired_product_module(module_id: &str) -> bool {
    RETIRED_PRODUCT_MODULE_IDS.contains(&module_id)
}

fn visible_product_modules(specs: Vec<ModuleSpec>) -> Vec<ModuleSpec> {
    specs
        .into_iter()
        .filter(|spec| !is_retired_product_module(&spec.id))
        .collect()
}

pub(crate) fn status_class(status: &ModuleStatus) -> &'static str {
    if !status.installed {
        "neutral"
    } else if status.update_available {
        "off"
    } else if status.status == "current" {
        "ok"
    } else {
        "neutral"
    }
}

fn write_request(module_id: &str, extension: &str, content: &str) -> anyhow::Result<()> {
    if !valid_id(module_id)
        || !matches!(
            extension,
            "request" | "register" | "remove" | "start" | "stop" | "restart"
        )
    {
        anyhow::bail!("invalid module request");
    }
    let directory = request_dir();
    fs::create_dir_all(&directory)?;
    secure_private_directory(&directory)?;
    let path = directory.join(format!("{module_id}.{extension}"));
    atomic_file::replace(&path, content.as_bytes(), 0o640)?;
    Ok(())
}

async fn refresh_with_client(
    pool: &SqlitePool,
    spec: ModuleSpec,
    client: &reqwest::Client,
) -> anyhow::Result<ModuleStatus> {
    let latest_version = match &spec.upstream {
        UpstreamKind::Release => {
            let url = format!("https://api.github.com/repos/{}/releases/latest", spec.repo);
            client
                .get(url)
                .send()
                .await?
                .error_for_status()?
                .json::<GithubRelease>()
                .await?
                .tag_name
        }
        UpstreamKind::Commit { git_ref } => {
            let url = format!(
                "https://api.github.com/repos/{}/commits/{git_ref}",
                spec.repo
            );
            client
                .get(url)
                .send()
                .await?
                .error_for_status()?
                .json::<GithubCommit>()
                .await?
                .sha
        }
    };
    let installed_version = installed_version(&spec);
    let installed = Path::new(&spec.binary_path).is_file();
    let update_available = installed
        && installed_version != "unknown"
        && versions_differ(&spec.upstream, &installed_version, &latest_version);
    let auto_update = load_auto_update(pool, &spec.id).await?;
    let status = ModuleStatus {
        spec,
        installed,
        installed_version,
        latest_version,
        update_available,
        auto_update,
        checked_at: Utc::now().to_rfc3339(),
        status: if !installed {
            "not installed"
        } else if update_available {
            "update available"
        } else {
            "current"
        }
        .to_string(),
    };
    persist_status(pool, &status).await?;
    write_state_file(&status)?;
    Ok(status)
}

async fn load_one(pool: &SqlitePool, spec: ModuleSpec) -> anyhow::Result<ModuleStatus> {
    let installed = Path::new(&spec.binary_path).is_file();
    let installed_version = installed_version(&spec);
    let latest_version = setting_or_default(pool, &spec.id, "latest_version", "unknown").await?;
    let update_available = installed
        && latest_version != "unknown"
        && installed_version != "unknown"
        && versions_differ(&spec.upstream, &installed_version, &latest_version);
    let persisted_status = setting_or_default(
        pool,
        &spec.id,
        "status",
        if installed {
            "unchecked"
        } else {
            "not installed"
        },
    )
    .await?;
    let status = if !installed {
        "not installed".to_string()
    } else if update_available {
        "update available".to_string()
    } else if latest_version != "unknown" && installed_version != "unknown" {
        "current".to_string()
    } else {
        persisted_status
    };
    Ok(ModuleStatus {
        spec: spec.clone(),
        installed,
        installed_version,
        latest_version,
        update_available,
        auto_update: load_auto_update(pool, &spec.id).await?,
        checked_at: setting_or_default(pool, &spec.id, "checked_at", "never").await?,
        status,
    })
}

async fn persist_status(pool: &SqlitePool, status: &ModuleStatus) -> anyhow::Result<()> {
    upsert_settings(
        pool,
        &[
            (
                setting_key(&status.spec.id, "latest_version"),
                status.latest_version.clone(),
            ),
            (
                setting_key(&status.spec.id, "checked_at"),
                status.checked_at.clone(),
            ),
            (
                setting_key(&status.spec.id, "status"),
                status.status.clone(),
            ),
        ],
    )
    .await
}

async fn persist_check_error(pool: &SqlitePool, spec: &ModuleSpec) -> anyhow::Result<()> {
    upsert_setting(pool, &setting_key(&spec.id, "status"), "check failed").await
}

async fn load_auto_update(pool: &SqlitePool, module_id: &str) -> anyhow::Result<bool> {
    Ok(get_setting(pool, &setting_key(module_id, "auto_update"))
        .await?
        .is_none_or(|setting| crate::update::parse_bool_setting(&setting.value)))
}

async fn setting_or_default(
    pool: &SqlitePool,
    module_id: &str,
    suffix: &str,
    default_value: &str,
) -> anyhow::Result<String> {
    Ok(get_setting(pool, &setting_key(module_id, suffix))
        .await?
        .map_or_else(|| default_value.to_string(), |setting| setting.value))
}

fn installed_version(spec: &ModuleSpec) -> String {
    let state_path = version_dir().join(format!("{}.version", spec.id));
    fs::read_to_string(state_path)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .or_else(|| version_from_symlink(&spec.binary_path))
        .unwrap_or_else(|| "unknown".to_string())
}

fn version_from_symlink(binary_path: &str) -> Option<String> {
    let current = Path::new(binary_path).parent()?;
    let target = fs::read_link(current).ok()?;
    target
        .file_name()
        .and_then(|value| value.to_str())
        .map(str::to_string)
}

fn github_client() -> anyhow::Result<reqwest::Client> {
    Ok(reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .user_agent(format!("{APP_NAME}/{}", env!("CARGO_PKG_VERSION")))
        .build()?)
}

fn write_state_file(status: &ModuleStatus) -> anyhow::Result<()> {
    let directory = state_dir();
    fs::create_dir_all(&directory)?;
    secure_private_directory(&directory)?;
    let content = format!(
        concat!(
            "AUTO_ENABLED={}\nINSTALLED={}\nUPDATE_AVAILABLE={}\n",
            "INSTALLED_VERSION={}\nLATEST_VERSION={}\nCHECKED_AT={}\n"
        ),
        bool_str(status.auto_update),
        bool_str(status.installed),
        bool_str(status.update_available),
        safe_state_value(&status.installed_version),
        safe_state_value(&status.latest_version),
        safe_state_value(&status.checked_at),
    );
    let path = directory.join(format!("{}.env", status.spec.id));
    atomic_file::replace(&path, content.as_bytes(), 0o640)?;
    Ok(())
}

fn secure_private_directory(directory: &Path) -> anyhow::Result<()> {
    let metadata = fs::symlink_metadata(directory)?;
    if !metadata.file_type().is_dir() {
        anyhow::bail!("module state path must be a real directory");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(directory, fs::Permissions::from_mode(0o750))?;
    }
    Ok(())
}

fn manifest_dir() -> PathBuf {
    if let Some(path) = std::env::var_os("INFIPROXY_MODULE_MANIFEST_DIR") {
        return PathBuf::from(path);
    }
    let installed = PathBuf::from(DEFAULT_MANIFEST_DIR);
    if installed.is_dir() {
        installed
    } else {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../deploy/modules.d")
    }
}

fn available_dir() -> PathBuf {
    if let Some(path) = std::env::var_os("INFIPROXY_MODULE_AVAILABLE_DIR") {
        return PathBuf::from(path);
    }
    let installed = PathBuf::from(DEFAULT_AVAILABLE_DIR);
    if installed.is_dir() {
        installed
    } else {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../deploy/modules.d")
    }
}

fn state_dir() -> PathBuf {
    std::env::var_os("INFIPROXY_MODULE_STATE_DIR")
        .map_or_else(|| PathBuf::from(DEFAULT_STATE_DIR), PathBuf::from)
}

fn request_dir() -> PathBuf {
    std::env::var_os("INFIPROXY_MODULE_REQUEST_DIR")
        .map_or_else(|| PathBuf::from(DEFAULT_REQUEST_DIR), PathBuf::from)
}

fn version_dir() -> PathBuf {
    std::env::var_os("INFIPROXY_MODULE_VERSION_DIR")
        .map_or_else(|| PathBuf::from(DEFAULT_VERSION_DIR), PathBuf::from)
}

fn registry_options(directory: &Path) -> ReadOptions {
    ReadOptions {
        root_owned: directory.starts_with("/etc/"),
        registration: false,
    }
}

fn setting_key(module_id: &str, suffix: &str) -> String {
    format!("module_{module_id}_{suffix}")
}

fn versions_differ(upstream: &UpstreamKind, installed: &str, latest: &str) -> bool {
    match upstream {
        UpstreamKind::Release => release_version(installed) != release_version(latest),
        UpstreamKind::Commit { .. } => installed != latest,
    }
}

fn release_version(value: &str) -> &str {
    value
        .char_indices()
        .find_map(|(index, character)| character.is_ascii_digit().then_some(&value[index..]))
        .unwrap_or(value)
}

const fn bool_str(value: bool) -> &'static str {
    if value {
        "true"
    } else {
        "false"
    }
}

fn safe_state_value(value: &str) -> String {
    value
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '/' | ':' | '+' | '-'))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bundled_registry_is_dynamic_and_valid() {
        let specs = registry().expect("bundled manifests load");
        assert!(specs.len() >= 5);
        assert!(specs.iter().any(|spec| spec.id == "xray"));
        assert!(!specs.iter().any(|spec| spec.id == "headscale"));
        assert!(!specs.iter().any(|spec| spec.id == "mtproto"));
    }

    #[test]
    fn retired_product_modules_are_not_eligible_for_panel_inventory() {
        assert!(is_retired_product_module("headscale"));
        assert!(is_retired_product_module("mtproto"));
        assert!(!is_retired_product_module("xray"));
    }

    #[test]
    fn stale_mtproto_manifests_are_filtered_from_active_and_available_catalogs() {
        let root = std::env::temp_dir().join(format!(
            "infiproxy-retired-manifest-{}-{}",
            std::process::id(),
            Utc::now().timestamp_nanos_opt().unwrap_or_default()
        ));
        fs::create_dir_all(&root).unwrap();
        fs::write(
            root.join("mtproto.module"),
            concat!(
                "id=mtproto\nname=Legacy MTProto\nkind=legacy\nrole=removal only\n",
                "repo=TelegramMessenger/MTProxy\nupstream=commit\nref=master\n",
                "driver=mtproto-source\nroot=cores\nbinary=mtproto-proxy\n",
                "service=infiproxy-mtproto.service\n",
                "config=/etc/infiproxy-cores/mtproto/mtproto.env\n",
                "asset_amd64=unused\nasset_arm64=unused\n"
            ),
        )
        .unwrap();
        let stale = load_registry(&root, ReadOptions::default()).unwrap();
        assert!(visible_product_modules(stale.clone()).is_empty());
        assert!(visible_product_modules(stale).is_empty());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn version_normalization_handles_upstream_prefixes() {
        assert_eq!(release_version("v1.2.3"), "1.2.3");
        assert_eq!(release_version("release/v2.10.0"), "2.10.0");
        assert_eq!(release_version("server-release-1.0.0"), "1.0.0");
    }

    #[test]
    fn unsafe_module_inputs_are_rejected() {
        assert!(!valid_id("../root"));
    }

    #[cfg(unix)]
    #[test]
    fn private_module_directories_reject_symlinks() {
        use std::os::unix::fs::symlink;
        use std::time::{SystemTime, UNIX_EPOCH};

        let root = std::env::temp_dir().join(format!(
            "infiproxy-module-dir-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
        let target = root.join("target");
        let link = root.join("state");
        fs::create_dir_all(&target).expect("test directory should be created");
        symlink(&target, &link).expect("test symlink should be created");

        assert!(secure_private_directory(&link).is_err());

        fs::remove_dir_all(root).expect("test directory should be removed");
    }
}
