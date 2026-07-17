//! Root-side Headscale CLI bridge with a fixed, typed operation set.

use chrono::Utc;
use std::{
    env, fs,
    path::{Path, PathBuf},
    process::ExitCode,
    time::Duration,
};
use stealthhub_core::headscale_control::{
    valid_expiration, valid_username, HeadscaleRequest, HeadscaleSnapshot,
};
use tokio::process::Command;

const DEFAULT_REQUEST_DIR: &str = "/var/lib/infiproxy/headscale-requests";
const DEFAULT_PROCESSING_DIR: &str = "/var/lib/infiproxy-maintenance/headscale-processing";
const DEFAULT_STATE_FILE: &str = "/var/lib/infiproxy/headscale-state.json";
const DEFAULT_HEADSCALE_BIN: &str = "/usr/local/bin/headscale";
const DEFAULT_HEADSCALE_CONFIG: &str = "/etc/headscale/config.yaml";
const MAX_REQUEST_BYTES: u64 = 8 * 1024;
const MAX_OUTPUT_BYTES: usize = 64 * 1024;

#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    let args = env::args().skip(1).collect::<Vec<_>>();
    if args.as_slice() != ["--process"] {
        eprintln!("usage: infiproxy-headscale-control --process");
        return ExitCode::from(2);
    }
    match process().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("headscale control error: {error:#}");
            ExitCode::FAILURE
        }
    }
}

async fn process() -> anyhow::Result<()> {
    let request_dir = env_path("INFIPROXY_HEADSCALE_REQUEST_DIR", DEFAULT_REQUEST_DIR);
    let processing_dir = env_path("INFIPROXY_HEADSCALE_PROCESSING_DIR", DEFAULT_PROCESSING_DIR);
    let state_file = env_path("INFIPROXY_HEADSCALE_STATE_FILE", DEFAULT_STATE_FILE);
    fs::create_dir_all(&processing_dir)?;
    set_mode(&processing_dir, 0o700)?;

    let mut snapshot = read_snapshot(&state_file);
    for request_path in request_paths(&request_dir)? {
        if let Err(error) = process_one(&request_path, &processing_dir, &mut snapshot).await {
            snapshot.status = format!("operation failed: {error:#}");
            snapshot.last_result = snapshot.status.clone();
            snapshot.result_is_secret = false;
        }
    }
    refresh_snapshot(&mut snapshot).await;
    snapshot.updated_at = Utc::now().to_rfc3339();
    write_snapshot(&state_file, &snapshot)?;
    Ok(())
}

async fn process_one(
    source: &Path,
    processing_dir: &Path,
    snapshot: &mut HeadscaleSnapshot,
) -> anyhow::Result<()> {
    let file_name = source
        .file_name()
        .ok_or_else(|| anyhow::anyhow!("request has no file name"))?;
    let processing = processing_dir.join(file_name);
    fs::rename(source, &processing)?;
    let result = process_claimed(&processing, snapshot).await;
    let _ = fs::remove_file(&processing);
    result
}

async fn process_claimed(path: &Path, snapshot: &mut HeadscaleSnapshot) -> anyhow::Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_file() || metadata.len() > MAX_REQUEST_BYTES {
        anyhow::bail!("request must be a regular file no larger than 8 KiB");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o022 != 0 {
            anyhow::bail!("request must not be group/world-writable");
        }
    }
    let request: HeadscaleRequest = serde_json::from_slice(&fs::read(path)?)?;
    match request {
        HeadscaleRequest::Refresh => {
            snapshot.status = "refresh requested".to_string();
        }
        HeadscaleRequest::CreateUser { username } => {
            if !valid_username(&username) {
                anyhow::bail!("invalid Headscale username");
            }
            snapshot.last_result = run_headscale(&["users", "create", &username]).await?;
            snapshot.result_is_secret = false;
            snapshot.status = format!("user {username} created");
        }
        HeadscaleRequest::CreatePreAuthKey {
            user_id,
            expiration,
            reusable,
            ephemeral,
        } => {
            if user_id == 0 || !valid_expiration(&expiration) {
                anyhow::bail!("invalid pre-auth key parameters");
            }
            let user_id = user_id.to_string();
            let mut args = vec![
                "preauthkeys",
                "create",
                "--user",
                user_id.as_str(),
                "--expiration",
                expiration.as_str(),
            ];
            if reusable {
                args.push("--reusable");
            }
            if ephemeral {
                args.push("--ephemeral");
            }
            snapshot.last_result = run_headscale(&args).await?;
            snapshot.result_is_secret = true;
            snapshot.status = "pre-auth key created; copy it before clearing".to_string();
        }
        HeadscaleRequest::ExpireNode { node_id } => {
            if node_id == 0 {
                anyhow::bail!("invalid node id");
            }
            let node_id = node_id.to_string();
            snapshot.last_result =
                run_headscale(&["nodes", "expire", "--identifier", &node_id]).await?;
            snapshot.result_is_secret = false;
            snapshot.status = format!("node {node_id} expired");
        }
        HeadscaleRequest::ClearResult => {
            snapshot.last_result.clear();
            snapshot.result_is_secret = false;
            snapshot.status = "protected result cleared".to_string();
        }
    }
    Ok(())
}

async fn refresh_snapshot(snapshot: &mut HeadscaleSnapshot) {
    if !headscale_bin().is_file() {
        snapshot.status = "Headscale module is not installed".to_string();
        snapshot.users.clear();
        snapshot.nodes.clear();
        return;
    }
    match run_headscale(&["users", "list"]).await {
        Ok(output) => snapshot.users = output,
        Err(error) => snapshot.status = format!("user refresh failed: {error:#}"),
    }
    match run_headscale(&["nodes", "list"]).await {
        Ok(output) => {
            snapshot.nodes = output;
            if snapshot.status.is_empty() || snapshot.status == "refresh requested" {
                snapshot.status = "current".to_string();
            }
        }
        Err(error) => snapshot.status = format!("node refresh failed: {error:#}"),
    }
}

async fn run_headscale(args: &[&str]) -> anyhow::Result<String> {
    let mut command = Command::new(headscale_bin());
    command
        .arg("-c")
        .arg(env_path(
            "INFIPROXY_HEADSCALE_CONFIG",
            DEFAULT_HEADSCALE_CONFIG,
        ))
        .args(args)
        .kill_on_drop(true);
    let output = tokio::time::timeout(Duration::from_secs(20), command.output())
        .await
        .map_err(|_| anyhow::anyhow!("Headscale CLI timed out"))??;
    let stdout = bounded_text(&output.stdout);
    let stderr = bounded_text(&output.stderr);
    if !output.status.success() {
        anyhow::bail!(
            "Headscale CLI exited with {}: {}",
            output.status,
            if stderr.is_empty() { &stdout } else { &stderr }
        );
    }
    Ok(if stdout.is_empty() { stderr } else { stdout })
}

fn request_paths(directory: &Path) -> anyhow::Result<Vec<PathBuf>> {
    if !directory.is_dir() {
        return Ok(Vec::new());
    }
    let mut paths = fs::read_dir(directory)?
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.extension().and_then(|value| value.to_str()) == Some("request"))
        .collect::<Vec<_>>();
    paths.sort();
    Ok(paths)
}

fn read_snapshot(path: &Path) -> HeadscaleSnapshot {
    fs::read(path)
        .ok()
        .and_then(|body| serde_json::from_slice(&body).ok())
        .unwrap_or_default()
}

fn write_snapshot(path: &Path, snapshot: &HeadscaleSnapshot) -> anyhow::Result<()> {
    fs::write(path, serde_json::to_vec(snapshot)?)?;
    set_mode(path, 0o640)?;
    #[cfg(unix)]
    if let Some(parent) = path.parent() {
        use std::os::unix::fs::{chown, MetadataExt};
        chown(path, None, Some(fs::metadata(parent)?.gid()))?;
    }
    Ok(())
}

fn bounded_text(value: &[u8]) -> String {
    let end = value.len().min(MAX_OUTPUT_BYTES);
    String::from_utf8_lossy(&value[..end]).trim().to_string()
}

fn headscale_bin() -> PathBuf {
    env_path("INFIPROXY_HEADSCALE_BIN", DEFAULT_HEADSCALE_BIN)
}

fn env_path(name: &str, default: &str) -> PathBuf {
    env::var_os(name)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(default))
}

fn set_mode(path: &Path, mode: u32) -> anyhow::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
    }
    let _ = mode;
    Ok(())
}
