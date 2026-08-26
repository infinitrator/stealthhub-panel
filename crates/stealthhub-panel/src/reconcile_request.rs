//! Constrained unprivileged bridge to the root reconciliation worker.

use std::{fs, path::PathBuf};

use stealthhub_core::desired::ReconcileRequest;

use crate::atomic_file;

const DEFAULT_REQUEST_DIR: &str = "/var/lib/infiproxy/reconcile-requests";

/// Atomically publishes only a generation number, never desired payloads.
pub(crate) fn publish(generation: u64) -> anyhow::Result<()> {
    let directory = std::env::var_os("INFIPROXY_RECONCILE_REQUEST_DIR")
        .map_or_else(|| PathBuf::from(DEFAULT_REQUEST_DIR), PathBuf::from);
    let metadata = fs::symlink_metadata(&directory)?;
    if !metadata.file_type().is_dir() {
        anyhow::bail!("reconcile request path must be a real directory");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o022 != 0 {
            anyhow::bail!("reconcile request path must not be group/world-writable");
        }
    }
    let request = ReconcileRequest {
        api_version: 1,
        generation,
    };
    atomic_file::replace(
        &directory.join("reconcile.request"),
        &serde_json::to_vec(&request)?,
        0o640,
    )?;
    Ok(())
}
