//! Dynamic runtime-module registry and unprivileged update bridge.
//!
//! Module definitions are root-owned declarative manifests. The panel can read
//! the registry, discover upstream versions and create fixed-format requests,
//! but it never downloads binaries or executes package-management commands.

use crate::ui::APP_NAME;
use chrono::Utc;
use serde::Deserialize;
use sqlx::SqlitePool;
use std::{
    collections::HashSet,
    fs,
    path::{Path, PathBuf},
    time::Duration,
};
pub(crate) use stealthhub_core::module_manifest::{ModuleSpec, UpstreamKind};
use stealthhub_core::{
    module_manifest::{load_registry, valid_id, ReadOptions},
    storage::{get_setting, upsert_setting},
};

const CHECK_INTERVAL: Duration = Duration::from_secs(2 * 60 * 60);
const INITIAL_DELAY: Duration = Duration::from_secs(35);
const DEFAULT_MANIFEST_DIR: &str = "/etc/infiproxy-modules.d";
const DEFAULT_AVAILABLE_DIR: &str = "/etc/infiproxy-modules.available.d";
const DEFAULT_STATE_DIR: &str = "/var/lib/infiproxy/modules";
const DEFAULT_REQUEST_DIR: &str = "/var/lib/infiproxy/module-requests";
const DEFAULT_VERSION_DIR: &str = "/var/lib/infiproxy-maintenance/module-versions";
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
    load_registry(&directory, registry_options(&directory))
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
        .filter(|spec| !active.contains(&spec.id))
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
                persist_check_error(pool, &spec, &err.to_string()).await?;
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
        .filter(|spec| !active.contains(spec.id.as_str()))
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
    let spec = find(module_id)?.ok_or_else(|| anyhow::anyhow!("unknown module"))?;
    write_request(
        &spec.id,
        "request",
        &format!("requested_at={}\n", Utc::now().to_rfc3339()),
    )
}

/// Requests safe removal of a registered runtime while preserving its config.
pub(crate) fn request_remove(module_id: &str) -> anyhow::Result<()> {
    let spec = find(module_id)?.ok_or_else(|| anyhow::anyhow!("unknown module"))?;
    write_request(
        &spec.id,
        "remove",
        &format!("requested_at={}\n", Utc::now().to_rfc3339()),
    )
}

/// Queues activation of a root-owned catalog manifest.
pub(crate) fn request_register(module_id: &str) -> anyhow::Result<()> {
    if !valid_id(module_id) || find(module_id)?.is_some() {
        anyhow::bail!("module already exists");
    }
    let available = available()?
        .into_iter()
        .any(|module| module.id == module_id);
    if !available {
        anyhow::bail!("module is not present in the root-owned catalog");
    }
    write_request(
        module_id,
        "register",
        &format!("requested_at={}\n", Utc::now().to_rfc3339()),
    )
}

pub(crate) fn short_version(value: &str) -> String {
    if value.len() <= 16 {
        value.to_string()
    } else {
        value.chars().take(12).collect()
    }
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
    if !valid_id(module_id) || !matches!(extension, "request" | "register" | "remove") {
        anyhow::bail!("invalid module request");
    }
    let directory = request_dir();
    fs::create_dir_all(&directory)?;
    let path = directory.join(format!("{module_id}.{extension}"));
    fs::write(&path, content)?;
    set_private_permissions(&directory, &path);
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
        && normalize_version(&installed_version) != normalize_version(&latest_version);
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
        && normalize_version(&installed_version) != normalize_version(&latest_version);
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
    for (suffix, value) in [
        ("latest_version", status.latest_version.as_str()),
        ("checked_at", status.checked_at.as_str()),
        ("status", status.status.as_str()),
    ] {
        upsert_setting(pool, &setting_key(&status.spec.id, suffix), value).await?;
    }
    Ok(())
}

async fn persist_check_error(
    pool: &SqlitePool,
    spec: &ModuleSpec,
    error: &str,
) -> anyhow::Result<()> {
    let message = format!(
        "check failed: {}",
        error.chars().take(120).collect::<String>()
    );
    upsert_setting(pool, &setting_key(&spec.id, "status"), &message).await
}

async fn load_auto_update(pool: &SqlitePool, module_id: &str) -> anyhow::Result<bool> {
    Ok(get_setting(pool, &setting_key(module_id, "auto_update"))
        .await?
        .map(|setting| crate::update::parse_bool_setting(&setting.value))
        .unwrap_or(true))
}

async fn setting_or_default(
    pool: &SqlitePool,
    module_id: &str,
    suffix: &str,
    default_value: &str,
) -> anyhow::Result<String> {
    Ok(get_setting(pool, &setting_key(module_id, suffix))
        .await?
        .map(|setting| setting.value)
        .unwrap_or_else(|| default_value.to_string()))
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
    fs::write(&path, content)?;
    set_private_permissions(&directory, &path);
    Ok(())
}

fn set_private_permissions(directory: &Path, file: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(directory, fs::Permissions::from_mode(0o750));
        let _ = fs::set_permissions(file, fs::Permissions::from_mode(0o640));
    }
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
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_STATE_DIR))
}

fn request_dir() -> PathBuf {
    std::env::var_os("INFIPROXY_MODULE_REQUEST_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_REQUEST_DIR))
}

fn version_dir() -> PathBuf {
    std::env::var_os("INFIPROXY_MODULE_VERSION_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_VERSION_DIR))
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

fn normalize_version(value: &str) -> &str {
    value
        .strip_prefix("app/v")
        .or_else(|| value.strip_prefix("tuic-server-"))
        .or_else(|| value.strip_prefix('v'))
        .unwrap_or(value)
}

fn bool_str(value: bool) -> &'static str {
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
        assert!(specs.len() >= 6);
        assert!(specs.iter().any(|spec| spec.id == "xray"));
        assert!(specs.iter().any(|spec| spec.id == "headscale"));
    }

    #[test]
    fn version_normalization_handles_upstream_prefixes() {
        assert_eq!(normalize_version("v1.2.3"), "1.2.3");
        assert_eq!(normalize_version("app/v2.10.0"), "2.10.0");
        assert_eq!(normalize_version("tuic-server-1.0.0"), "1.0.0");
    }

    #[test]
    fn unsafe_module_inputs_are_rejected() {
        assert!(!valid_id("../root"));
    }
}
