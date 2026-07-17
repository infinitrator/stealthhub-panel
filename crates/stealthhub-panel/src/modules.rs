//! Independently updateable runtime-module registry.
//!
//! The panel only discovers upstream versions and creates fixed-name request
//! files. A root-owned systemd worker performs downloads, checksum validation,
//! atomic activation and service restarts, so HTTP handlers never execute
//! privileged package-management commands.

use crate::ui::APP_NAME;
use chrono::Utc;
use serde::Deserialize;
use sqlx::SqlitePool;
use std::{
    fs,
    path::{Path, PathBuf},
    time::Duration,
};
use stealthhub_core::storage::{get_setting, upsert_setting};

const CHECK_INTERVAL: Duration = Duration::from_secs(2 * 60 * 60);
const INITIAL_DELAY: Duration = Duration::from_secs(35);
const DEFAULT_STATE_DIR: &str = "/var/lib/infiproxy/modules";
const DEFAULT_REQUEST_DIR: &str = "/var/lib/infiproxy/module-requests";
const DEFAULT_VERSION_DIR: &str = "/var/lib/infiproxy-maintenance/module-versions";

/// Supported upstream version-discovery mechanism.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum UpstreamKind {
    Release,
    Commit { git_ref: &'static str },
}

/// Immutable module metadata shared by status rendering and request validation.
#[derive(Debug, Clone, Copy)]
pub(crate) struct ModuleSpec {
    pub(crate) id: &'static str,
    pub(crate) name: &'static str,
    pub(crate) kind: &'static str,
    pub(crate) role: &'static str,
    pub(crate) repo: &'static str,
    pub(crate) upstream: UpstreamKind,
    pub(crate) binary_path: &'static str,
    pub(crate) service: &'static str,
    pub(crate) config_path: &'static str,
}

/// Complete module registry. IDs are also the only values accepted by the
/// privileged request bridge and `deploy/module-update.sh`.
pub(crate) const MODULES: &[ModuleSpec] = &[
    ModuleSpec {
        id: "xray",
        name: "Xray",
        kind: "proxy core",
        role: "VLESS REALITY and XHTTP/TCP",
        repo: "XTLS/Xray-core",
        upstream: UpstreamKind::Release,
        binary_path: "/opt/infiproxy/cores/xray/current/xray",
        service: "infiproxy-xray.service",
        config_path: "/etc/infiproxy-cores/xray/config.json",
    },
    ModuleSpec {
        id: "sing-box",
        name: "sing-box",
        kind: "proxy core",
        role: "SS2022, ShadowTLS, AnyTLS and compatibility",
        repo: "SagerNet/sing-box",
        upstream: UpstreamKind::Release,
        binary_path: "/opt/infiproxy/cores/sing-box/current/sing-box",
        service: "infiproxy-sing-box.service",
        config_path: "/etc/infiproxy-cores/sing-box/config.json",
    },
    ModuleSpec {
        id: "hysteria",
        name: "Hysteria",
        kind: "proxy core",
        role: "Hysteria2 high-loss network fallback",
        repo: "apernet/hysteria",
        upstream: UpstreamKind::Release,
        binary_path: "/opt/infiproxy/cores/hysteria/current/hysteria",
        service: "infiproxy-hysteria.service",
        config_path: "/etc/infiproxy-cores/hysteria/config.yaml",
    },
    ModuleSpec {
        id: "tuic",
        name: "TUIC",
        kind: "proxy core",
        role: "QUIC low-latency fallback",
        repo: "tuic-protocol/tuic",
        upstream: UpstreamKind::Release,
        binary_path: "/opt/infiproxy/cores/tuic/current/tuic-server",
        service: "infiproxy-tuic.service",
        config_path: "/etc/infiproxy-cores/tuic/config.json",
    },
    ModuleSpec {
        id: "mtproto",
        name: "Telegram MTProto",
        kind: "proxy service",
        role: "Native Telegram proxy",
        repo: "TelegramMessenger/MTProxy",
        upstream: UpstreamKind::Commit { git_ref: "master" },
        binary_path: "/opt/infiproxy/cores/mtproto/current/mtproto-proxy",
        service: "infiproxy-mtproto.service",
        config_path: "/etc/infiproxy-cores/mtproto/mtproto.env",
    },
    ModuleSpec {
        id: "headscale",
        name: "Headscale",
        kind: "mesh service",
        role: "Tailscale-compatible coordination hub",
        repo: "juanfont/headscale",
        upstream: UpstreamKind::Release,
        binary_path: "/opt/infiproxy/modules/headscale/current/headscale",
        service: "headscale.service",
        config_path: "/etc/headscale/config.yaml",
    },
];

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

/// Refreshes all upstream versions with one reusable, time-bounded client.
pub(crate) async fn refresh_all(pool: &SqlitePool) -> anyhow::Result<Vec<ModuleStatus>> {
    let client = github_client()?;
    let mut statuses = Vec::with_capacity(MODULES.len());
    for spec in MODULES {
        match refresh_with_client(pool, *spec, &client).await {
            Ok(status) => statuses.push(status),
            Err(err) => {
                tracing::warn!(module = spec.id, "upstream check failed: {err}");
                persist_check_error(pool, *spec, &err.to_string()).await?;
                statuses.push(load_one(pool, *spec).await?);
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
    let spec = find(module_id).ok_or_else(|| anyhow::anyhow!("unknown module"))?;
    refresh_with_client(pool, spec, &github_client()?).await
}

/// Loads all last-known states without making network requests.
pub(crate) async fn load_all(pool: &SqlitePool) -> anyhow::Result<Vec<ModuleStatus>> {
    let mut statuses = Vec::with_capacity(MODULES.len());
    for spec in MODULES {
        statuses.push(load_one(pool, *spec).await?);
    }
    Ok(statuses)
}

/// Stores the owner-controlled automatic-update policy for one module.
pub(crate) async fn set_auto_update(
    pool: &SqlitePool,
    module_id: &str,
    enabled: bool,
) -> anyhow::Result<()> {
    let spec = find(module_id).ok_or_else(|| anyhow::anyhow!("unknown module"))?;
    upsert_setting(
        pool,
        &setting_key(spec.id, "auto_update"),
        bool_str(enabled),
    )
    .await?;
    let status = load_one(pool, spec).await?;
    write_state_file(&status)?;
    Ok(())
}

/// Creates a fixed-name request consumed by the root-owned module updater.
pub(crate) fn request_update(module_id: &str) -> anyhow::Result<()> {
    let spec = find(module_id).ok_or_else(|| anyhow::anyhow!("unknown module"))?;
    let request_dir = request_dir();
    fs::create_dir_all(&request_dir)?;
    let path = request_dir.join(format!("{}.request", spec.id));
    fs::write(&path, format!("requested_at={}\n", Utc::now().to_rfc3339()))?;
    set_private_permissions(&request_dir, &path);
    Ok(())
}

pub(crate) fn find(module_id: &str) -> Option<ModuleSpec> {
    MODULES
        .iter()
        .copied()
        .find(|module| module.id == module_id)
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

async fn refresh_with_client(
    pool: &SqlitePool,
    spec: ModuleSpec,
    client: &reqwest::Client,
) -> anyhow::Result<ModuleStatus> {
    let latest_version = match spec.upstream {
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
    let installed_version = installed_version(spec);
    let installed = Path::new(spec.binary_path).is_file();
    let update_available = installed
        && installed_version != "unknown"
        && normalize_version(&installed_version) != normalize_version(&latest_version);
    let auto_update = load_auto_update(pool, spec.id).await?;
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
    let installed = Path::new(spec.binary_path).is_file();
    let installed_version = installed_version(spec);
    let latest_version = setting_or_default(pool, spec.id, "latest_version", "unknown").await?;
    let update_available = installed
        && latest_version != "unknown"
        && installed_version != "unknown"
        && normalize_version(&installed_version) != normalize_version(&latest_version);
    let persisted_status = setting_or_default(
        pool,
        spec.id,
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
        spec,
        installed,
        installed_version,
        latest_version,
        update_available,
        auto_update: load_auto_update(pool, spec.id).await?,
        checked_at: setting_or_default(pool, spec.id, "checked_at", "never").await?,
        status,
    })
}

async fn persist_status(pool: &SqlitePool, status: &ModuleStatus) -> anyhow::Result<()> {
    for (suffix, value) in [
        ("latest_version", status.latest_version.as_str()),
        ("checked_at", status.checked_at.as_str()),
        ("status", status.status.as_str()),
    ] {
        upsert_setting(pool, &setting_key(status.spec.id, suffix), value).await?;
    }
    Ok(())
}

async fn persist_check_error(
    pool: &SqlitePool,
    spec: ModuleSpec,
    error: &str,
) -> anyhow::Result<()> {
    let message = format!(
        "check failed: {}",
        error.chars().take(120).collect::<String>()
    );
    upsert_setting(pool, &setting_key(spec.id, "status"), &message).await
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

fn installed_version(spec: ModuleSpec) -> String {
    let state_path = version_dir().join(format!("{}.version", spec.id));
    fs::read_to_string(state_path)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .or_else(|| version_from_symlink(spec.binary_path))
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
    let state_dir = state_dir();
    fs::create_dir_all(&state_dir)?;
    let content = format!(
        concat!(
            "AUTO_ENABLED={}\n",
            "INSTALLED={}\n",
            "UPDATE_AVAILABLE={}\n",
            "INSTALLED_VERSION={}\n",
            "LATEST_VERSION={}\n",
            "CHECKED_AT={}\n"
        ),
        bool_str(status.auto_update),
        bool_str(status.installed),
        bool_str(status.update_available),
        safe_state_value(&status.installed_version),
        safe_state_value(&status.latest_version),
        safe_state_value(&status.checked_at),
    );
    fs::write(state_dir.join(format!("{}.env", status.spec.id)), content)?;
    let state_path = state_dir.join(format!("{}.env", status.spec.id));
    set_private_permissions(&state_dir, &state_path);
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
    fn module_ids_are_unique_and_shell_safe() {
        let mut ids = std::collections::HashSet::new();
        for module in MODULES {
            assert!(ids.insert(module.id));
            assert!(module
                .id
                .chars()
                .all(|ch| ch.is_ascii_lowercase() || ch == '-'));
        }
    }

    #[test]
    fn version_normalization_handles_upstream_prefixes() {
        assert_eq!(normalize_version("v1.2.3"), "1.2.3");
        assert_eq!(normalize_version("app/v2.10.0"), "2.10.0");
        assert_eq!(normalize_version("tuic-server-1.0.0"), "1.0.0");
    }

    #[test]
    fn unknown_module_cannot_create_a_request() {
        assert!(find("../root").is_none());
    }
}
