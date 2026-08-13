//! Unprivileged side of the typed Headscale maintenance bridge.

use crate::atomic_file;
use std::{fmt::Write as _, fs, path::PathBuf};
pub(crate) use stealthhub_core::headscale_control::{HeadscaleRequest, HeadscaleSnapshot};

const DEFAULT_STATE_FILE: &str = "/var/lib/infiproxy-maintenance/headscale/state.json";
const DEFAULT_REQUEST_DIR: &str = "/var/lib/infiproxy/headscale-requests";
const MAX_STATE_BYTES: u64 = 256 * 1024;

/// Reads the latest root-generated state without touching Headscale storage.
pub(crate) fn snapshot() -> anyhow::Result<HeadscaleSnapshot> {
    let path = state_file();
    if !path.exists() {
        return Ok(HeadscaleSnapshot {
            status: "waiting for first maintenance refresh".to_string(),
            ..HeadscaleSnapshot::default()
        });
    }
    let metadata = fs::symlink_metadata(&path)?;
    if !metadata.file_type().is_file() || metadata.len() > MAX_STATE_BYTES {
        anyhow::bail!("Headscale state file is not a safe regular file");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if metadata.uid() != 0 || metadata.permissions().mode() & 0o022 != 0 {
            anyhow::bail!("Headscale state file is not protected by root ownership");
        }
    }
    Ok(serde_json::from_slice(&fs::read(path)?)?)
}

/// Queues one validated operation for the root module worker.
pub(crate) fn request(request: &HeadscaleRequest) -> anyhow::Result<()> {
    let directory = request_dir();
    fs::create_dir_all(&directory)?;
    secure_private_directory(&directory)?;
    let mut nonce = [0_u8; 12];
    getrandom::fill(&mut nonce)?;
    let mut name = String::with_capacity(nonce.len() * 2);
    for byte in nonce {
        write!(&mut name, "{byte:02x}")?;
    }
    let path = directory.join(format!("{name}.request"));
    atomic_file::replace(&path, &serde_json::to_vec(request)?, 0o640)?;
    Ok(())
}

fn state_file() -> PathBuf {
    std::env::var_os("INFIPROXY_HEADSCALE_STATE_FILE")
        .map_or_else(|| PathBuf::from(DEFAULT_STATE_FILE), PathBuf::from)
}

fn request_dir() -> PathBuf {
    std::env::var_os("INFIPROXY_HEADSCALE_REQUEST_DIR")
        .map_or_else(|| PathBuf::from(DEFAULT_REQUEST_DIR), PathBuf::from)
}

fn secure_private_directory(directory: &std::path::Path) -> anyhow::Result<()> {
    let metadata = fs::symlink_metadata(directory)?;
    if !metadata.file_type().is_dir() {
        anyhow::bail!("Headscale request path must be a real directory");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(directory, fs::Permissions::from_mode(0o750))?;
    }
    Ok(())
}
