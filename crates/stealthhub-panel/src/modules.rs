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
    collections::{HashMap, HashSet},
    fs,
    path::{Path, PathBuf},
    time::Duration,
};
use stealthhub_core::storage::{get_setting, upsert_setting};

const CHECK_INTERVAL: Duration = Duration::from_secs(2 * 60 * 60);
const INITIAL_DELAY: Duration = Duration::from_secs(35);
const DEFAULT_MANIFEST_DIR: &str = "/etc/infiproxy-modules.d";
const DEFAULT_AVAILABLE_DIR: &str = "/etc/infiproxy-modules.available.d";
const DEFAULT_STATE_DIR: &str = "/var/lib/infiproxy/modules";
const DEFAULT_REQUEST_DIR: &str = "/var/lib/infiproxy/module-requests";
const DEFAULT_VERSION_DIR: &str = "/var/lib/infiproxy-maintenance/module-versions";
const MAX_MANIFEST_BYTES: u64 = 16 * 1024;

/// Upstream version-discovery mechanism declared by a module manifest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum UpstreamKind {
    Release,
    Commit { git_ref: String },
}

/// Validated module metadata loaded from the manifest directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ModuleSpec {
    pub(crate) id: String,
    pub(crate) name: String,
    pub(crate) kind: String,
    pub(crate) role: String,
    pub(crate) repo: String,
    pub(crate) upstream: UpstreamKind,
    pub(crate) driver: String,
    pub(crate) root: String,
    pub(crate) binary: String,
    pub(crate) binary_path: String,
    pub(crate) service: String,
    pub(crate) config_path: String,
    pub(crate) asset_amd64: String,
    pub(crate) asset_arm64: String,
}

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
    load_registry(&manifest_dir())
}

/// Loads catalog entries that are not currently active.
pub(crate) fn available() -> anyhow::Result<Vec<ModuleSpec>> {
    let active = registry()?
        .into_iter()
        .map(|spec| spec.id)
        .collect::<HashSet<_>>();
    Ok(load_registry(&available_dir())?
        .into_iter()
        .filter(|spec| !active.contains(&spec.id))
        .collect())
}

fn load_registry(directory: &Path) -> anyhow::Result<Vec<ModuleSpec>> {
    let mut specs = Vec::new();
    let mut ids = HashSet::new();

    if !directory.is_dir() {
        return Ok(specs);
    }

    let mut paths = fs::read_dir(directory)?
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.extension().and_then(|value| value.to_str()) == Some("module"))
        .collect::<Vec<_>>();
    paths.sort();

    for path in paths {
        let metadata = fs::symlink_metadata(&path)?;
        if !metadata.file_type().is_file() || metadata.len() > MAX_MANIFEST_BYTES {
            tracing::warn!(path = %path.display(), "ignoring unsafe module manifest");
            continue;
        }
        let content = fs::read_to_string(&path)?;
        let spec = parse_manifest(&content, &path)?;
        if !ids.insert(spec.id.clone()) {
            anyhow::bail!("duplicate module id: {}", spec.id);
        }
        specs.push(spec);
    }
    specs.sort_by(|left, right| left.id.cmp(&right.id));
    Ok(specs)
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

/// Loads all last-known states without making network requests.
pub(crate) async fn load_all(pool: &SqlitePool) -> anyhow::Result<Vec<ModuleStatus>> {
    let specs = registry()?;
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

fn parse_manifest(content: &str, path: &Path) -> anyhow::Result<ModuleSpec> {
    let mut values = HashMap::new();
    for (index, raw_line) in content.lines().enumerate() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (key, value) = line.split_once('=').ok_or_else(|| {
            anyhow::anyhow!("{}:{}: expected key=value", path.display(), index + 1)
        })?;
        let key = key.trim();
        if !matches!(
            key,
            "id" | "name"
                | "kind"
                | "role"
                | "repo"
                | "upstream"
                | "ref"
                | "driver"
                | "root"
                | "binary"
                | "service"
                | "config"
                | "asset_amd64"
                | "asset_arm64"
        ) {
            anyhow::bail!("{}:{}: unknown key {key}", path.display(), index + 1);
        }
        if values
            .insert(key.to_string(), value.trim().to_string())
            .is_some()
        {
            anyhow::bail!("{}:{}: duplicate key {key}", path.display(), index + 1);
        }
    }

    let value = |key: &str| -> anyhow::Result<String> {
        values
            .get(key)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("{}: missing {key}", path.display()))
    };
    let upstream_name = value("upstream")?;
    let git_ref = value("ref")?;
    let upstream = match upstream_name.as_str() {
        "release" => UpstreamKind::Release,
        "commit" => UpstreamKind::Commit { git_ref },
        _ => anyhow::bail!("{}: unsupported upstream", path.display()),
    };
    let mut spec = ModuleSpec {
        id: value("id")?,
        name: value("name")?,
        kind: value("kind")?,
        role: value("role")?,
        repo: value("repo")?,
        upstream,
        driver: value("driver")?,
        root: value("root")?,
        binary: value("binary")?,
        binary_path: String::new(),
        service: value("service")?,
        config_path: value("config")?,
        asset_amd64: value("asset_amd64")?,
        asset_arm64: value("asset_arm64")?,
    };
    let expected_id = path
        .file_stem()
        .and_then(|value| value.to_str())
        .unwrap_or_default();
    if spec.id != expected_id {
        anyhow::bail!("{}: id must match the file name", path.display());
    }
    spec = validate_spec(spec)?;
    Ok(spec)
}

fn validate_spec(mut spec: ModuleSpec) -> anyhow::Result<ModuleSpec> {
    if !valid_id(&spec.id) {
        anyhow::bail!("invalid module id");
    }
    for (label, value, max) in [
        ("name", spec.name.as_str(), 80),
        ("kind", spec.kind.as_str(), 48),
        ("role", spec.role.as_str(), 160),
    ] {
        if value.is_empty() || value.len() > max || !safe_text(value) {
            anyhow::bail!("invalid module {label}");
        }
    }
    if !valid_repo(&spec.repo) {
        anyhow::bail!("invalid GitHub repository");
    }
    if let UpstreamKind::Commit { git_ref } = &spec.upstream {
        if !valid_ref(git_ref) {
            anyhow::bail!("invalid Git reference");
        }
    }
    if !matches!(
        spec.driver.as_str(),
        "release" | "headscale" | "mtproto-source"
    ) {
        anyhow::bail!("unsupported module driver");
    }
    if !matches!(spec.root.as_str(), "cores" | "modules") {
        anyhow::bail!("invalid runtime root");
    }
    if !safe_filename(&spec.binary) {
        anyhow::bail!("invalid binary name");
    }
    if !safe_service(&spec.service) {
        anyhow::bail!("invalid service name");
    }
    if !spec.config_path.starts_with("/etc/")
        || spec.config_path.contains("..")
        || !spec.config_path.chars().all(safe_path_char)
    {
        anyhow::bail!("invalid config path");
    }
    if matches!(spec.upstream, UpstreamKind::Release)
        && (!safe_asset(&spec.asset_amd64) || !safe_asset(&spec.asset_arm64))
    {
        anyhow::bail!("invalid release asset template");
    }
    match spec.driver.as_str() {
        "release" => {
            if spec.root != "cores"
                || spec.service != format!("infiproxy-{}.service", spec.id)
                || !spec
                    .config_path
                    .starts_with(&format!("/etc/infiproxy-cores/{}/", spec.id))
            {
                anyhow::bail!("generic modules must use their own core service and config tree");
            }
        }
        "headscale" => {
            if spec.id != "headscale"
                || spec.root != "modules"
                || spec.service != "headscale.service"
                || spec.config_path != "/etc/headscale/config.yaml"
            {
                anyhow::bail!("invalid Headscale module contract");
            }
        }
        "mtproto-source" => {
            if spec.id != "mtproto"
                || spec.root != "cores"
                || spec.service != "infiproxy-mtproto.service"
                || !spec
                    .config_path
                    .starts_with("/etc/infiproxy-cores/mtproto/")
            {
                anyhow::bail!("invalid MTProto module contract");
            }
        }
        _ => unreachable!("driver was validated above"),
    }
    spec.binary_path = format!(
        "/opt/infiproxy/{}/{}/current/{}",
        spec.root, spec.id, spec.binary
    );
    Ok(spec)
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

fn valid_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 32
        && value.as_bytes()[0].is_ascii_lowercase()
        && value
            .chars()
            .all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '-')
}

fn valid_repo(value: &str) -> bool {
    let mut parts = value.split('/');
    matches!((parts.next(), parts.next(), parts.next()), (Some(owner), Some(repo), None) if safe_repo_part(owner) && safe_repo_part(repo))
}

fn safe_repo_part(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 100
        && value
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '-'))
}

fn valid_ref(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 120
        && !value.starts_with('/')
        && !value.contains("..")
        && value
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '/' | '-'))
}

fn safe_text(value: &str) -> bool {
    value
        .chars()
        .all(|ch| ch.is_ascii() && !ch.is_ascii_control() && !matches!(ch, '=' | '|'))
}

fn safe_filename(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 80
        && value
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '+' | '-'))
}

fn safe_service(value: &str) -> bool {
    value.ends_with(".service")
        && value.len() <= 128
        && value
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '@' | '-'))
}

fn safe_asset(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 180
        && value
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '+' | '-' | '{' | '}'))
}

fn safe_path_char(ch: char) -> bool {
    ch.is_ascii_alphanumeric() || matches!(ch, '/' | '.' | '_' | '+' | '-')
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
    fn manifest_rejects_filename_mismatch_and_unknown_keys() {
        let valid = "id=demo\nname=Demo\nkind=core\nrole=Test\nrepo=owner/repo\nupstream=release\nref=\ndriver=release\nroot=cores\nbinary=demo\nservice=infiproxy-demo.service\nconfig=/etc/infiproxy-cores/demo/config.json\nasset_amd64=demo-{version}-amd64\nasset_arm64=demo-{version}-arm64\n";
        assert!(parse_manifest(valid, Path::new("demo.module")).is_ok());
        assert!(parse_manifest(valid, Path::new("other.module")).is_err());
        assert!(parse_manifest(
            &format!("{valid}command=rm -rf /\n"),
            Path::new("demo.module")
        )
        .is_err());
        assert!(parse_manifest(
            &valid.replace("infiproxy-demo.service", "ssh.service"),
            Path::new("demo.module")
        )
        .is_err());
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
        assert!(!valid_repo("owner/repo/extra"));
        assert!(!safe_asset("../../payload"));
        assert!(!safe_service("demo;reboot.service"));
    }
}
