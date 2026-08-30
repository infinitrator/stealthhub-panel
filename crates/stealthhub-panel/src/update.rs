//! Panel self-update state and scheduler integration.
//!
//! The web process never runs privileged update commands or reads GitHub
//! credentials. A root-owned checker mirrors a bounded, sanitized status file;
//! the panel writes only update policy and immediate-update requests.

use crate::atomic_file;
use chrono::{Local, Timelike, Utc};
use sqlx::SqlitePool;
use std::{fs, path::PathBuf, process::Command, time::Duration as StdDuration};
use stealthhub_core::storage::{get_setting, upsert_settings};

const CHECK_INTERVAL: StdDuration = StdDuration::from_hours(2);
const INITIAL_DELAY: StdDuration = StdDuration::from_secs(20);
const DEFAULT_STATE_PATH: &str = "/var/lib/infiproxy/panel-update-state.env";
const DEFAULT_ROOT_STATUS_PATH: &str = "/var/lib/infiproxy-maintenance/panel-update-status.env";
const DEFAULT_APPLIED_SHA_PATH: &str = "/var/lib/infiproxy-maintenance/panel-last-applied.sha";
const DEFAULT_REQUEST_PATH: &str = "/var/lib/infiproxy/panel-update-now.request";
const DEFAULT_CONFIG_PATH: &str = "/etc/infiproxy-update.conf";

/// Short update payload shown in the admin bar.
#[derive(Debug, Clone)]
pub(crate) struct Notice {
    pub(crate) latest_sha: String,
    pub(crate) planned_for: String,
}

#[derive(Debug, Clone)]
struct Config {
    enabled: bool,
    schedule_time: String,
    repo: String,
    git_ref: String,
}

/// Persisted panel update state displayed on the settings screen.
#[derive(Debug, Clone)]
pub(crate) struct Status {
    pub(crate) enabled: bool,
    pub(crate) schedule_time: String,
    pub(crate) repo: String,
    pub(crate) git_ref: String,
    pub(crate) current_sha: String,
    pub(crate) latest_sha: String,
    pub(crate) available: bool,
    pub(crate) checked_at: String,
    pub(crate) planned_for: String,
    pub(crate) status: String,
}

#[derive(Debug, Default)]
struct RootStatus {
    repo: String,
    git_ref: String,
    current_sha: String,
    latest_sha: String,
    checked_at: String,
    status: String,
}

/// Starts the lightweight two-hour root-status mirror in the panel process.
pub(crate) fn spawn_checker(pool: SqlitePool) {
    tokio::spawn(async move {
        tokio::time::sleep(INITIAL_DELAY).await;

        loop {
            if let Err(err) = refresh_state(&pool).await {
                tracing::warn!("panel update check failed: {err}");
            }

            tokio::time::sleep(CHECK_INTERVAL).await;
        }
    });
}

/// Refreshes SQLite from the root-owned checker and publishes update policy.
pub(crate) async fn refresh_state(pool: &SqlitePool) -> anyhow::Result<Status> {
    let config = load_config(pool).await?;
    let current_sha = current_source_commit();
    write_policy_file(&config);

    if !config.enabled {
        let status = Status {
            enabled: false,
            schedule_time: config.schedule_time,
            repo: config.repo,
            git_ref: config.git_ref,
            current_sha,
            latest_sha: "disabled".to_string(),
            available: false,
            checked_at: Utc::now().to_rfc3339(),
            planned_for: "disabled".to_string(),
            status: "disabled".to_string(),
        };
        persist_status(pool, &status).await?;
        return Ok(status);
    }

    let root = load_root_status()?
        .filter(|root| root.repo == config.repo && root.git_ref == config.git_ref);
    let latest_sha = root
        .as_ref()
        .map_or_else(|| "unknown".to_string(), |root| root.latest_sha.clone());
    let available = valid_commit_sha(&current_sha)
        && valid_commit_sha(&latest_sha)
        && latest_sha != current_sha;
    let root_status = root
        .as_ref()
        .map_or("waiting-for-root-check", |root| root.status.as_str());
    let status_label = if available {
        "available"
    } else if valid_commit_sha(&latest_sha) && latest_sha == current_sha {
        "current"
    } else {
        root_status
    };
    let status = Status {
        enabled: config.enabled,
        schedule_time: config.schedule_time.clone(),
        repo: config.repo,
        git_ref: config.git_ref,
        current_sha,
        latest_sha,
        available,
        checked_at: root
            .as_ref()
            .map_or_else(|| "never".to_string(), |root| root.checked_at.clone()),
        planned_for: if available {
            next_window_label(&config.schedule_time)
        } else {
            "not scheduled".to_string()
        },
        status: status_label.to_string(),
    };

    persist_status(pool, &status).await?;
    Ok(status)
}

/// Loads the last known update state for rendering.
pub(crate) async fn load_status(pool: &SqlitePool) -> anyhow::Result<Status> {
    refresh_state(pool).await
}

/// Loads the small admin-bar notice when a newer commit is known.
pub(crate) async fn load_notice(pool: &SqlitePool) -> anyhow::Result<Option<Notice>> {
    let available =
        parse_bool_setting(&setting_or_default(pool, "panel_update_available", "false").await?);
    if !available {
        return Ok(None);
    }

    Ok(Some(Notice {
        latest_sha: setting_or_default(pool, "panel_update_latest_sha", "unknown").await?,
        planned_for: setting_or_default(pool, "panel_update_planned_for", "not scheduled").await?,
    }))
}

/// Creates the systemd path trigger consumed by `infiproxy-panel-update.path`.
pub(crate) fn request_now() -> anyhow::Result<()> {
    let path = configured_path("INFIPROXY_PANEL_UPDATE_REQUEST", DEFAULT_REQUEST_PATH);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    atomic_file::replace(
        &path,
        format!("requested_at={}\n", Utc::now().to_rfc3339()).as_bytes(),
        0o640,
    )?;
    Ok(())
}

pub(crate) fn status_label(status: &Status) -> String {
    if !status.enabled {
        return "disabled".to_string();
    }
    if status.available {
        return format!("available, {}", status.planned_for);
    }
    status.status.clone()
}

pub(crate) fn short_sha(value: &str) -> String {
    if value == "unknown" || value == "disabled" {
        return value.to_string();
    }
    value.chars().take(12).collect()
}

pub(crate) fn parse_bool_setting(value: &str) -> bool {
    matches!(
        value.trim().to_ascii_lowercase().as_str(),
        "1" | "true" | "yes" | "on"
    )
}

pub(crate) fn parse_hour(value: &str) -> Option<u32> {
    value.trim().parse::<u32>().ok().filter(|hour| *hour <= 23)
}

pub(crate) fn parse_schedule_time(value: &str) -> Option<(u32, u32)> {
    let (hour_text, minute_text) = value.trim().split_once(':')?;
    if hour_text.len() != 2 || minute_text.len() != 2 {
        return None;
    }
    let hour = hour_text.parse::<u32>().ok()?;
    let minute = minute_text.parse::<u32>().ok()?;
    (hour <= 23 && minute <= 59).then_some((hour, minute))
}

pub(crate) fn non_empty_or_default<'a>(value: &'a str, default_value: &'a str) -> &'a str {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        default_value
    } else {
        trimmed
    }
}

pub(crate) fn validate_repo(repo: &str) -> Result<(), &'static str> {
    let mut parts = repo.split('/');
    let owner = parts.next().unwrap_or_default();
    let name = parts.next().unwrap_or_default();
    if owner.is_empty() || name.is_empty() || parts.next().is_some() {
        return Err("GitHub repository must use owner/repo format.");
    }
    if !owner.chars().all(is_safe_git_segment) || !name.chars().all(is_safe_git_segment) {
        return Err("GitHub repository contains unsupported characters.");
    }
    Ok(())
}

pub(crate) fn validate_ref(git_ref: &str) -> Result<(), &'static str> {
    if git_ref.is_empty()
        || git_ref.starts_with('/')
        || git_ref.starts_with('-')
        || git_ref.contains("..")
        || !git_ref.chars().all(is_safe_git_ref_char)
    {
        return Err("Git reference contains unsupported characters.");
    }
    Ok(())
}

async fn load_config(pool: &SqlitePool) -> anyhow::Result<Config> {
    load_config_with_source(pool, load_pinned_source()?).await
}

async fn load_config_with_source(
    pool: &SqlitePool,
    pinned_source: Option<(String, String)>,
) -> anyhow::Result<Config> {
    let enabled =
        parse_bool_setting(&setting_or_default(pool, "panel_update_enabled", "true").await?);
    let legacy_hour =
        parse_hour(&setting_or_default(pool, "panel_update_hour", "5").await?).unwrap_or(5);
    let legacy_time = format!("{legacy_hour:02}:00");
    let schedule_time = setting_or_default(pool, "panel_update_time", &legacy_time).await?;
    let schedule_time = if parse_schedule_time(&schedule_time).is_some() {
        schedule_time
    } else {
        "05:00".to_string()
    };
    let (repo, git_ref) = if let Some(source) = pinned_source {
        source
    } else {
        (
            setting_or_default(pool, "panel_update_repo", "infinitrator/stealthhub-panel").await?,
            setting_or_default(pool, "panel_update_ref", "main").await?,
        )
    };

    Ok(Config {
        enabled,
        schedule_time,
        repo,
        git_ref,
    })
}

fn load_pinned_source() -> anyhow::Result<Option<(String, String)>> {
    let path = configured_path("INFIPROXY_UPDATE_CONFIG_FILE", DEFAULT_CONFIG_PATH);
    load_pinned_source_from(&path)
}

fn load_pinned_source_from(path: &std::path::Path) -> anyhow::Result<Option<(String, String)>> {
    let content = match fs::read_to_string(path) {
        Ok(value) => value,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(err) => return Err(err.into()),
    };
    let mut repo = None;
    let mut git_ref = None;
    for line in content.lines() {
        if let Some(value) = line.strip_prefix("REPO=") {
            repo = Some(value.trim().to_string());
        } else if let Some(value) = line.strip_prefix("REF=") {
            git_ref = Some(value.trim().to_string());
        }
    }
    let repo = repo.ok_or_else(|| anyhow::anyhow!("update config is missing REPO"))?;
    let git_ref = git_ref.ok_or_else(|| anyhow::anyhow!("update config is missing REF"))?;
    validate_repo(&repo).map_err(anyhow::Error::msg)?;
    validate_ref(&git_ref).map_err(anyhow::Error::msg)?;
    Ok(Some((repo, git_ref)))
}

async fn setting_or_default(
    pool: &SqlitePool,
    key: &str,
    default_value: &str,
) -> anyhow::Result<String> {
    Ok(get_setting(pool, key)
        .await?
        .map_or_else(|| default_value.to_string(), |setting| setting.value))
}

async fn persist_status(pool: &SqlitePool, status: &Status) -> anyhow::Result<()> {
    upsert_settings(
        pool,
        &[
            (
                "panel_update_current_sha".to_string(),
                status.current_sha.clone(),
            ),
            (
                "panel_update_latest_sha".to_string(),
                status.latest_sha.clone(),
            ),
            (
                "panel_update_available".to_string(),
                status.available.to_string(),
            ),
            (
                "panel_update_checked_at".to_string(),
                status.checked_at.clone(),
            ),
            (
                "panel_update_planned_for".to_string(),
                status.planned_for.clone(),
            ),
            ("panel_update_status".to_string(), status.status.clone()),
        ],
    )
    .await
}

fn current_source_commit() -> String {
    let marker = configured_path("INFIPROXY_PANEL_APPLIED_SHA", DEFAULT_APPLIED_SHA_PATH);
    authoritative_commit(
        read_commit_marker(&marker),
        git_rev_parse("/opt/infiproxy/source"),
        git_rev_parse("."),
        std::env::var("INFIPROXY_CURRENT_COMMIT").ok(),
    )
}

fn authoritative_commit(
    marker: Option<String>,
    installed_source: Option<String>,
    development_source: Option<String>,
    stale_environment: Option<String>,
) -> String {
    [
        marker,
        installed_source,
        development_source,
        stale_environment,
    ]
    .into_iter()
    .flatten()
    .map(|value| value.trim().to_ascii_lowercase())
    .find(|value| valid_commit_sha(value))
    .unwrap_or_else(|| "unknown".to_string())
}

fn read_commit_marker(path: &std::path::Path) -> Option<String> {
    let metadata = fs::symlink_metadata(path).ok()?;
    if !metadata.file_type().is_file() || metadata.len() > 128 {
        return None;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if metadata.uid() != 0 || metadata.permissions().mode() & 0o022 != 0 {
            return None;
        }
    }
    fs::read_to_string(path)
        .ok()
        .map(|value| value.trim().to_ascii_lowercase())
        .filter(|value| valid_commit_sha(value))
}

fn git_rev_parse(path: &str) -> Option<String> {
    let output = Command::new("git")
        .args(["-C", path, "rev-parse", "HEAD"])
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }

    String::from_utf8(output.stdout)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

const fn is_safe_git_segment(ch: char) -> bool {
    ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.')
}

const fn is_safe_git_ref_char(ch: char) -> bool {
    is_safe_git_segment(ch) || ch == '/'
}

fn next_window_label(schedule_time: &str) -> String {
    let now = Local::now();
    let (hour, minute) = parse_schedule_time(schedule_time).unwrap_or((5, 0));
    let now_minutes = now.hour() * 60 + now.minute();
    let schedule_minutes = hour * 60 + minute;
    let suffix = if now_minutes < schedule_minutes {
        "today"
    } else {
        "tomorrow"
    };
    format!("{suffix} at {schedule_time} server time")
}

fn write_policy_file(config: &Config) {
    let path = configured_path("INFIPROXY_PANEL_UPDATE_STATE", DEFAULT_STATE_PATH);
    let Some(parent) = path.parent() else {
        return;
    };
    if fs::create_dir_all(parent).is_err() {
        return;
    }

    let content = format!(
        concat!(
            "AUTO_ENABLED={}\n",
            "SCHEDULE_HOUR={}\n",
            "SCHEDULE_TIME={}\n",
            "REPO={}\n",
            "REF={}\n"
        ),
        env_bool(config.enabled),
        config.schedule_time.split(':').next().unwrap_or("5"),
        shell_env_value(&config.schedule_time),
        shell_env_value(&config.repo),
        shell_env_value(&config.git_ref),
    );

    if let Err(error) = atomic_file::replace(&path, content.as_bytes(), 0o640) {
        tracing::warn!("could not mirror panel update state: {error}");
    }
}

fn load_root_status() -> anyhow::Result<Option<RootStatus>> {
    let path = configured_path("INFIPROXY_PANEL_UPDATE_STATUS", DEFAULT_ROOT_STATUS_PATH);
    let metadata = match fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    if !metadata.file_type().is_file() || metadata.len() > 4096 {
        anyhow::bail!("root update status is not a bounded regular file");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if metadata.uid() != 0 || metadata.permissions().mode() & 0o022 != 0 {
            anyhow::bail!("root update status ownership or mode is unsafe");
        }
    }
    let mut status = RootStatus::default();
    for line in fs::read_to_string(path)?.lines() {
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let value = value.trim();
        match key {
            "REPO" => status.repo = value.to_string(),
            "REF" => status.git_ref = value.to_string(),
            "CURRENT_SHA" => status.current_sha = value.to_string(),
            "LATEST_SHA" => status.latest_sha = value.to_string(),
            "CHECKED_AT" => status.checked_at = value.to_string(),
            "STATUS" => status.status = value.to_string(),
            _ => {}
        }
    }
    validate_repo(&status.repo).map_err(anyhow::Error::msg)?;
    validate_ref(&status.git_ref).map_err(anyhow::Error::msg)?;
    if !valid_commit_sha(&status.current_sha) || !valid_commit_sha(&status.latest_sha) {
        anyhow::bail!("root update status contains an invalid commit");
    }
    if !matches!(status.status.as_str(), "current" | "available" | "failed") {
        anyhow::bail!("root update status contains an invalid state");
    }
    Ok(Some(status))
}

fn valid_commit_sha(value: &str) -> bool {
    value.len() == 40 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn configured_path(variable: &str, default_path: &str) -> PathBuf {
    std::env::var_os(variable).map_or_else(|| PathBuf::from(default_path), PathBuf::from)
}

const fn env_bool(value: bool) -> &'static str {
    if value {
        "true"
    } else {
        "false"
    }
}

fn shell_env_value(value: &str) -> String {
    let cleaned: String = value
        .chars()
        .filter(|ch| ch.is_ascii_graphic() || *ch == ' ')
        .collect();
    format!("'{}'", cleaned.replace('\'', "'\"'\"'"))
}

#[cfg(test)]
mod tests {
    use super::{authoritative_commit, load_config_with_source, load_pinned_source_from};
    use stealthhub_core::storage::{init_db, upsert_setting};

    #[test]
    fn applied_marker_wins_over_stale_environment_commit() {
        let applied = "53b423c4f4d33708595dbcdbb247d06d2d4e5dab";
        let stale = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        assert_eq!(
            authoritative_commit(
                Some(applied.to_string()),
                None,
                None,
                Some(stale.to_string()),
            ),
            applied
        );
    }

    #[tokio::test]
    async fn pinned_source_wins_over_sqlite_update_settings() {
        let config_path = std::env::temp_dir().join(format!(
            "infiproxy-update-source-{}.conf",
            uuid::Uuid::new_v4()
        ));
        std::fs::write(
            &config_path,
            "REPO=infinitrator/stealthhub-panel\nREF=main\n",
        )
        .unwrap();
        let pool = sqlx::sqlite::SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();
        init_db(&pool).await.unwrap();
        upsert_setting(&pool, "panel_update_repo", "untrusted/example")
            .await
            .unwrap();
        upsert_setting(&pool, "panel_update_ref", "feature/unreviewed")
            .await
            .unwrap();

        let pinned_source = load_pinned_source_from(&config_path).unwrap();
        let config = load_config_with_source(&pool, pinned_source).await.unwrap();

        assert_eq!(config.repo, "infinitrator/stealthhub-panel");
        assert_eq!(config.git_ref, "main");
        pool.close().await;
        std::fs::remove_file(config_path).unwrap();
    }
}
