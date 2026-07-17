//! Unprivileged side of the typed Headscale maintenance bridge.

use rand_core::{OsRng, RngCore};
use std::{fs, io::Write, path::PathBuf};
pub(crate) use stealthhub_core::headscale_control::{HeadscaleRequest, HeadscaleSnapshot};

const DEFAULT_STATE_FILE: &str = "/var/lib/infiproxy/headscale-state.json";
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
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o022 != 0 {
            anyhow::bail!("Headscale state file is writable by an unsafe principal");
        }
    }
    Ok(serde_json::from_slice(&fs::read(path)?)?)
}

/// Queues one validated operation for the root module worker.
pub(crate) fn request(request: &HeadscaleRequest) -> anyhow::Result<()> {
    let directory = request_dir();
    fs::create_dir_all(&directory)?;
    let mut nonce = [0_u8; 12];
    OsRng.fill_bytes(&mut nonce);
    let name = nonce
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let path = directory.join(format!("{name}.request"));
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(&path)?;
    file.write_all(&serde_json::to_vec(request)?)?;
    file.sync_all()?;
    set_private_permissions(&directory, &path);
    Ok(())
}

fn state_file() -> PathBuf {
    std::env::var_os("INFIPROXY_HEADSCALE_STATE_FILE")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_STATE_FILE))
}

fn request_dir() -> PathBuf {
    std::env::var_os("INFIPROXY_HEADSCALE_REQUEST_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_REQUEST_DIR))
}

fn set_private_permissions(directory: &std::path::Path, file: &std::path::Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(directory, fs::Permissions::from_mode(0o750));
        let _ = fs::set_permissions(file, fs::Permissions::from_mode(0o640));
    }
}
