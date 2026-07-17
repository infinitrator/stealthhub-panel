//! Parser and validator for declarative runtime-module manifests.
//!
//! Manifests are data, never shell input. This module is shared by the web
//! panel and the root-owned updater helper so both sides enforce one contract.

use anyhow::Context;
use std::{
    collections::{HashMap, HashSet},
    fs,
    path::Path,
};

/// Maximum accepted manifest size.
pub const MAX_MANIFEST_BYTES: u64 = 16 * 1024;

/// Stable field order used by the shell updater's pipe-delimited protocol.
pub const FIELDS: [&str; 14] = [
    "id",
    "name",
    "kind",
    "role",
    "repo",
    "upstream",
    "ref",
    "driver",
    "root",
    "binary",
    "service",
    "config",
    "asset_amd64",
    "asset_arm64",
];

/// Upstream version-discovery mechanism declared by a module manifest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UpstreamKind {
    /// Follow the latest stable GitHub release.
    Release,
    /// Follow the latest commit on a validated Git reference.
    Commit { git_ref: String },
}

/// Fully validated module metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModuleSpec {
    pub id: String,
    pub name: String,
    pub kind: String,
    pub role: String,
    pub repo: String,
    pub upstream: UpstreamKind,
    pub driver: String,
    pub root: String,
    pub binary: String,
    pub binary_path: String,
    pub service: String,
    pub config_path: String,
    pub asset_amd64: String,
    pub asset_arm64: String,
}

/// Additional trust checks for a manifest read.
#[derive(Debug, Clone, Copy, Default)]
pub struct ReadOptions {
    /// Require an installed file owned by root and not writable by group/other.
    pub root_owned: bool,
    /// Restrict imports to generic release modules.
    pub registration: bool,
}

/// Loads and validates all `*.module` files in deterministic ID order.
pub fn load_registry(directory: &Path, options: ReadOptions) -> anyhow::Result<Vec<ModuleSpec>> {
    if !directory.is_dir() {
        return Ok(Vec::new());
    }

    let mut paths = fs::read_dir(directory)?
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.extension().and_then(|value| value.to_str()) == Some("module"))
        .collect::<Vec<_>>();
    paths.sort();

    let mut ids = HashSet::new();
    let mut specs = Vec::with_capacity(paths.len());
    for path in paths {
        let spec = read_manifest(&path, options)?;
        if !ids.insert(spec.id.clone()) {
            anyhow::bail!("duplicate module id: {}", spec.id);
        }
        specs.push(spec);
    }
    specs.sort_by(|left, right| left.id.cmp(&right.id));
    Ok(specs)
}

/// Reads one manifest without following a symlink or evaluating its contents.
pub fn read_manifest(path: &Path, options: ReadOptions) -> anyhow::Result<ModuleSpec> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("could not inspect {}", path.display()))?;
    if !metadata.file_type().is_file() || metadata.len() > MAX_MANIFEST_BYTES {
        anyhow::bail!("manifest must be a regular file no larger than 16 KiB");
    }
    if options.root_owned {
        validate_installed_metadata(&metadata)?;
    }
    let content = fs::read_to_string(path)
        .with_context(|| format!("could not read {} as UTF-8", path.display()))?;
    parse_manifest(&content, path, options.registration)
}

/// Serializes one validated manifest for the legacy-safe shell protocol.
pub fn pipe_record(spec: &ModuleSpec) -> String {
    let (upstream, git_ref) = match &spec.upstream {
        UpstreamKind::Release => ("release", ""),
        UpstreamKind::Commit { git_ref } => ("commit", git_ref.as_str()),
    };
    [
        spec.id.as_str(),
        spec.name.as_str(),
        spec.kind.as_str(),
        spec.role.as_str(),
        spec.repo.as_str(),
        upstream,
        git_ref,
        spec.driver.as_str(),
        spec.root.as_str(),
        spec.binary.as_str(),
        spec.service.as_str(),
        spec.config_path.as_str(),
        spec.asset_amd64.as_str(),
        spec.asset_arm64.as_str(),
    ]
    .join("|")
}

/// Parses manifest text after the caller has established file trust.
pub fn parse_manifest(
    content: &str,
    path: &Path,
    registration: bool,
) -> anyhow::Result<ModuleSpec> {
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
        if !FIELDS.contains(&key) {
            anyhow::bail!("{}:{}: unknown key {key}", path.display(), index + 1);
        }
        let value = value.trim();
        if !safe_text(value) {
            anyhow::bail!("{}:{}: unsafe value", path.display(), index + 1);
        }
        if values.insert(key.to_string(), value.to_string()).is_some() {
            anyhow::bail!("{}:{}: duplicate key {key}", path.display(), index + 1);
        }
    }

    let value = |key: &str| -> anyhow::Result<String> {
        values
            .get(key)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("{}: missing {key}", path.display()))
    };
    let upstream = match value("upstream")?.as_str() {
        "release" => UpstreamKind::Release,
        "commit" => UpstreamKind::Commit {
            git_ref: value("ref")?,
        },
        _ => anyhow::bail!("{}: unsupported upstream", path.display()),
    };
    let spec = ModuleSpec {
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
    validate_spec(spec, registration)
}

fn validate_spec(mut spec: ModuleSpec, registration: bool) -> anyhow::Result<ModuleSpec> {
    if !valid_id(&spec.id) {
        anyhow::bail!("invalid module id");
    }
    for (label, value, max) in [
        ("name", spec.name.as_str(), 80),
        ("kind", spec.kind.as_str(), 48),
        ("role", spec.role.as_str(), 160),
    ] {
        if value.is_empty() || value.len() > max {
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
    if registration
        && (!matches!(spec.upstream, UpstreamKind::Release)
            || spec.driver != "release"
            || spec.root != "cores")
    {
        anyhow::bail!("registration only supports generic release modules under cores");
    }
    spec.binary_path = format!(
        "/opt/infiproxy/{}/{}/current/{}",
        spec.root, spec.id, spec.binary
    );
    Ok(spec)
}

fn validate_installed_metadata(metadata: &fs::Metadata) -> anyhow::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if metadata.uid() != 0 || metadata.permissions().mode() & 0o022 != 0 {
            anyhow::bail!("installed manifest must be root-owned and not group/world-writable");
        }
        Ok(())
    }
    #[cfg(not(unix))]
    {
        let _ = metadata;
        anyhow::bail!("root ownership checks require Unix");
    }
}

/// Returns whether a value is a safe module identifier.
pub fn valid_id(value: &str) -> bool {
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

#[cfg(test)]
mod tests {
    use super::*;

    const VALID: &str = "id=demo\nname=Demo\nkind=core\nrole=Test\nrepo=owner/repo\nupstream=release\nref=\ndriver=release\nroot=cores\nbinary=demo\nservice=infiproxy-demo.service\nconfig=/etc/infiproxy-cores/demo/config.json\nasset_amd64=demo-{version}-amd64\nasset_arm64=demo-{version}-arm64\n";

    #[test]
    fn rejects_filename_mismatch_unknown_keys_and_service_escape() {
        assert!(parse_manifest(VALID, Path::new("demo.module"), false).is_ok());
        assert!(parse_manifest(VALID, Path::new("other.module"), false).is_err());
        assert!(parse_manifest(
            &format!("{VALID}command=rm -rf /\n"),
            Path::new("demo.module"),
            false
        )
        .is_err());
        assert!(parse_manifest(
            &VALID.replace("infiproxy-demo.service", "ssh.service"),
            Path::new("demo.module"),
            false
        )
        .is_err());
    }

    #[test]
    fn pipe_protocol_has_stable_field_count() {
        let spec = parse_manifest(VALID, Path::new("demo.module"), true).unwrap();
        assert_eq!(pipe_record(&spec).split('|').count(), FIELDS.len());
    }
}
