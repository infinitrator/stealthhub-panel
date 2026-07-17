//! Panel self-update state and scheduler integration.
//!
//! The web process never runs privileged update commands directly. It checks
//! GitHub, stores update state in SQLite and writes a request file for the
//! root-owned systemd updater when the owner asks to apply an update now.

use crate::ui::APP_NAME;
use chrono::{Local, Timelike, Utc};
use serde::Deserialize;
use sqlx::SqlitePool;
use std::{fs, path::PathBuf, process::Command, time::Duration as StdDuration};
use stealthhub_core::storage::{get_setting, upsert_setting};

const CHECK_INTERVAL: StdDuration = StdDuration::from_secs(2 * 60 * 60);
const INITIAL_DELAY: StdDuration = StdDuration::from_secs(20);
const DEFAULT_STATE_PATH: &str = "/var/lib/infiproxy/panel-update-state.env";
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

#[derive(Debug, Deserialize)]
struct GithubCommitRef {
    sha: String,
}

/// Starts the lightweight two-hour GitHub checker in the panel process.
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

/// Refreshes GitHub state and mirrors it into SQLite plus the root updater file.
pub(crate) async fn refresh_state(pool: &SqlitePool) -> anyhow::Result<Status> {
    let config = load_config(pool).await?;
    let current_sha = current_source_commit();

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
        write_state_file(&status);
        return Ok(status);
    }

    let latest_sha = github_latest_commit(&config.repo, &config.git_ref).await?;
    let available = current_sha != "unknown" && latest_sha != current_sha;
    let status = Status {
        enabled: config.enabled,
        schedule_time: config.schedule_time.clone(),
        repo: config.repo,
        git_ref: config.git_ref,
        current_sha,
        latest_sha,
        available,
        checked_at: Utc::now().to_rfc3339(),
        planned_for: if available {
            next_window_label(&config.schedule_time)
        } else {
            "not scheduled".to_string()
        },
        status: if available { "available" } else { "current" }.to_string(),
    };

    persist_status(pool, &status).await?;
    write_state_file(&status);
    Ok(status)
}

/// Loads the last known update state for rendering.
pub(crate) async fn load_status(pool: &SqlitePool) -> anyhow::Result<Status> {
    let config = load_config(pool).await?;
    Ok(Status {
        enabled: config.enabled,
        schedule_time: config.schedule_time,
        repo: config.repo,
        git_ref: config.git_ref,
        current_sha: setting_or_default(pool, "panel_update_current_sha", "unknown").await?,
        latest_sha: setting_or_default(pool, "panel_update_latest_sha", "unknown").await?,
        available: parse_bool_setting(
            &setting_or_default(pool, "panel_update_available", "false").await?,
        ),
        checked_at: setting_or_default(pool, "panel_update_checked_at", "never").await?,
        planned_for: setting_or_default(pool, "panel_update_planned_for", "not scheduled").await?,
        status: setting_or_default(pool, "panel_update_status", "idle").await?,
    })
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
    fs::write(&path, format!("requested_at={}\n", Utc::now().to_rfc3339()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o640))?;
    }
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
        || git_ref.contains("..")
        || !git_ref.chars().all(is_safe_git_ref_char)
    {
        return Err("Git reference contains unsupported characters.");
    }
    Ok(())
}

async fn load_config(pool: &SqlitePool) -> anyhow::Result<Config> {
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
    let (repo, git_ref) = if let Some(source) = load_pinned_source()? {
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
        .map(|setting| setting.value)
        .unwrap_or_else(|| default_value.to_string()))
}

async fn persist_status(pool: &SqlitePool, status: &Status) -> anyhow::Result<()> {
    for (key, value) in [
        ("panel_update_current_sha", status.current_sha.as_str()),
        ("panel_update_latest_sha", status.latest_sha.as_str()),
        (
            "panel_update_available",
            if status.available { "true" } else { "false" },
        ),
        ("panel_update_checked_at", status.checked_at.as_str()),
        ("panel_update_planned_for", status.planned_for.as_str()),
        ("panel_update_status", status.status.as_str()),
    ] {
        upsert_setting(pool, key, value).await?;
    }

    Ok(())
}

async fn github_latest_commit(repo: &str, git_ref: &str) -> anyhow::Result<String> {
    validate_repo(repo).map_err(|message| anyhow::anyhow!(message))?;
    validate_ref(git_ref).map_err(|message| anyhow::anyhow!(message))?;

    let client = reqwest::Client::builder()
        .timeout(StdDuration::from_secs(12))
        .build()?;
    let url = format!("https://api.github.com/repos/{repo}/commits/{git_ref}");
    let commit = client
        .get(url)
        .header(
            reqwest::header::USER_AGENT,
            format!("{APP_NAME}/{}", env!("CARGO_PKG_VERSION")),
        )
        .send()
        .await?
        .error_for_status()?
        .json::<GithubCommitRef>()
        .await?;

    Ok(commit.sha)
}

fn current_source_commit() -> String {
    std::env::var("INFIPROXY_CURRENT_COMMIT")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .or_else(|| git_rev_parse("/opt/infiproxy/source"))
        .or_else(|| git_rev_parse("."))
        .unwrap_or_else(|| "unknown".to_string())
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

fn is_safe_git_segment(ch: char) -> bool {
    ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.')
}

fn is_safe_git_ref_char(ch: char) -> bool {
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

fn write_state_file(status: &Status) {
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
            "UPDATE_AVAILABLE={}\n",
            "REPO={}\n",
            "REF={}\n",
            "CURRENT_SHA={}\n",
            "LATEST_SHA={}\n",
            "CHECKED_AT={}\n",
            "PLANNED_FOR={}\n"
        ),
        env_bool(status.enabled),
        status.schedule_time.split(':').next().unwrap_or("5"),
        shell_env_value(&status.schedule_time),
        env_bool(status.available),
        shell_env_value(&status.repo),
        shell_env_value(&status.git_ref),
        shell_env_value(&status.current_sha),
        shell_env_value(&status.latest_sha),
        shell_env_value(&status.checked_at),
        shell_env_value(&status.planned_for),
    );

    if fs::write(&path, content).is_ok() {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&path, fs::Permissions::from_mode(0o640));
        }
    }
}

fn configured_path(variable: &str, default_path: &str) -> PathBuf {
    std::env::var_os(variable)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(default_path))
}

fn env_bool(value: bool) -> &'static str {
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
