//! Small atomic-file primitive for unprivileged state and request bridges.
//!
//! Writers create a private sibling file, flush its contents, rename it over
//! the destination and, on Linux, flush the parent directory. This prevents a
//! systemd path watcher or root worker from observing a partially written file.

use std::{
    ffi::OsString,
    fmt::Write as _,
    fs::{self, OpenOptions},
    io::{self, Write},
    path::Path,
};

/// Atomically replaces `path` with private contents using the requested mode.
pub(crate) fn replace(path: &Path, content: &[u8], mode: u32) -> io::Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "path has no parent"))?;
    let file_name = path
        .file_name()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "path has no file name"))?;

    let mut nonce = [0_u8; 12];
    getrandom::fill(&mut nonce).map_err(io::Error::other)?;
    let mut suffix = String::with_capacity(nonce.len() * 2);
    for byte in nonce {
        write!(&mut suffix, "{byte:02x}").map_err(io::Error::other)?;
    }
    let mut temporary_name = OsString::from(".");
    temporary_name.push(file_name);
    temporary_name.push(format!(".{suffix}.tmp"));
    let temporary = parent.join(temporary_name);

    let result = (|| {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(mode);
        }
        let mut file = options.open(&temporary)?;
        file.write_all(content)?;
        file.sync_all()?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&temporary, fs::Permissions::from_mode(mode))?;
        }
        fs::rename(&temporary, path)?;
        #[cfg(target_os = "linux")]
        fs::File::open(parent)?.sync_all()?;
        Ok(())
    })();

    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replaces_a_symlink_instead_of_following_it() -> io::Result<()> {
        let directory = std::env::temp_dir().join(format!(
            "infiproxy-atomic-file-{}-{}",
            std::process::id(),
            std::thread::current().name().unwrap_or("test")
        ));
        let _ = fs::remove_dir_all(&directory);
        fs::create_dir_all(&directory)?;
        let destination = directory.join("state.env");
        let protected = directory.join("protected");
        fs::write(&protected, b"unchanged")?;
        #[cfg(unix)]
        std::os::unix::fs::symlink(&protected, &destination)?;

        #[cfg(unix)]
        replace(&destination, b"current", 0o640)?;

        #[cfg(unix)]
        {
            assert_eq!(fs::read(&destination)?, b"current");
            assert_eq!(fs::read(&protected)?, b"unchanged");
            assert!(!fs::symlink_metadata(&destination)?.file_type().is_symlink());
        }
        fs::remove_dir_all(directory)?;
        Ok(())
    }
}
