//! Non-mutating readiness checks for proxy-runtime TLS material.

use std::{
    fs,
    os::unix::{
        fs::{MetadataExt, PermissionsExt},
        process::CommandExt,
    },
    path::Path,
    process::{Command, Stdio},
};

use serde::{Deserialize, Serialize};

pub(super) const TLS_DIRECTORY_PATH: &str = "/etc/infiproxy-cores/tls";
pub(super) const CERTIFICATE_PATH: &str = "/etc/infiproxy-cores/tls/fullchain.pem";
pub(super) const PRIVATE_KEY_PATH: &str = "/etc/infiproxy-cores/tls/privkey.pem";
const RUNTIME_USER: &str = "infiproxy-runtime";
const RUNTIME_GROUP: &str = "infiproxy-runtime";
const ROOT_UID: u32 = 0;

#[derive(Clone, Copy)]
struct RuntimeIdentity {
    uid: u32,
    gid: u32,
}

#[derive(Clone, Copy)]
enum RuntimeAccess {
    Read,
    Traverse,
}

/// Safe, content-free description of one TLS path.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TlsPathReadiness {
    pub present: bool,
    pub kind: String,
    pub target_is_regular: bool,
    pub safe_permissions: bool,
}

/// Read-only readiness result for the fixed proxy-runtime TLS pair.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TlsMaterialReadiness {
    pub ready: bool,
    pub certificate: TlsPathReadiness,
    pub private_key: TlsPathReadiness,
    pub certificate_not_expired: bool,
    pub certificate_expiry: Option<String>,
    pub hostname_covered: Option<bool>,
    pub detail: String,
}

fn getent_id(database: &str, name: &str, field: usize) -> Option<u32> {
    let output = Command::new("/usr/bin/getent")
        .args([database, name])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let record = String::from_utf8(output.stdout).ok()?;
    parse_getent_id(&record, name, field)
}

fn parse_getent_id(record: &str, expected_name: &str, field: usize) -> Option<u32> {
    let mut lines = record.lines();
    let line = lines.next()?;
    if lines.next().is_some() {
        return None;
    }
    let fields = line.split(':').collect::<Vec<_>>();
    if fields.first().copied() != Some(expected_name) {
        return None;
    }
    fields.get(field)?.parse().ok()
}

fn runtime_identity() -> Option<RuntimeIdentity> {
    Some(RuntimeIdentity {
        uid: getent_id("passwd", RUNTIME_USER, 2)?,
        gid: getent_id("group", RUNTIME_GROUP, 2)?,
    })
}

fn directory_allows_runtime(uid: u32, gid: u32, mode: u32, expected_gid: u32) -> bool {
    uid == ROOT_UID
        && gid == expected_gid
        && mode & 0o022 == 0
        && mode & 0o050 == 0o050
        && mode & 0o007 == 0
}

fn metadata_allows(
    metadata: &fs::Metadata,
    identity: RuntimeIdentity,
    owner_permission: u32,
    group_permission: u32,
    other_permission: u32,
) -> bool {
    let mode = metadata.permissions().mode();
    if metadata.uid() == identity.uid {
        mode & owner_permission != 0
    } else if metadata.gid() == identity.gid {
        mode & group_permission != 0
    } else {
        mode & other_permission != 0
    }
}

fn ancestors_allow_traversal(path: &Path, identity: RuntimeIdentity) -> bool {
    path.is_absolute()
        && path.ancestors().all(|ancestor| {
            fs::metadata(ancestor).is_ok_and(|metadata| {
                metadata.is_dir() && metadata_allows(&metadata, identity, 0o100, 0o010, 0o001)
            })
        })
}

fn path_modes_allow_runtime(path: &Path, identity: RuntimeIdentity, access: RuntimeAccess) -> bool {
    let Some(link_parent) = path.parent() else {
        return false;
    };
    if !ancestors_allow_traversal(link_parent, identity) {
        return false;
    }
    let Ok(resolved) = fs::canonicalize(path) else {
        return false;
    };
    let Some(target_parent) = resolved.parent() else {
        return false;
    };
    if !ancestors_allow_traversal(target_parent, identity) {
        return false;
    }
    fs::metadata(resolved).is_ok_and(|metadata| match access {
        RuntimeAccess::Read => metadata_allows(&metadata, identity, 0o400, 0o040, 0o004),
        RuntimeAccess::Traverse => metadata_allows(&metadata, identity, 0o100, 0o010, 0o001),
    })
}

fn runtime_access_is_effective(
    path: &Path,
    identity: RuntimeIdentity,
    access: RuntimeAccess,
) -> bool {
    let predicate = match access {
        RuntimeAccess::Read => "-r",
        RuntimeAccess::Traverse => "-x",
    };
    // CommandExt::uid clears supplementary groups; test(1) never reads file contents.
    Command::new("/usr/bin/test")
        .arg(predicate)
        .arg(path)
        .uid(identity.uid)
        .gid(identity.gid)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
}

fn runtime_can_access(path: &Path, identity: RuntimeIdentity, access: RuntimeAccess) -> bool {
    path_modes_allow_runtime(path, identity, access)
        && runtime_access_is_effective(path, identity, access)
}

fn runtime_tls_directory_ready(path: &Path, identity: RuntimeIdentity) -> bool {
    fs::symlink_metadata(path).is_ok_and(|metadata| {
        metadata.file_type().is_dir()
            && directory_allows_runtime(
                metadata.uid(),
                metadata.gid(),
                metadata.permissions().mode(),
                identity.gid,
            )
            && runtime_can_access(path, identity, RuntimeAccess::Traverse)
    })
}

fn file_allows_runtime(
    uid: u32,
    gid: u32,
    mode: u32,
    expected_gid: u32,
    expected_uid: u32,
    private_key: bool,
) -> bool {
    let group_can_read = mode & 0o040 != 0;
    let no_unsafe_writes = mode & 0o022 == 0;
    let no_other_key_access = !private_key || mode & 0o007 == 0;
    uid == expected_uid
        && gid == expected_gid
        && group_can_read
        && no_unsafe_writes
        && no_other_key_access
}

fn inspect_path_with_access(
    path: &Path,
    private_key: bool,
    identity: Option<RuntimeIdentity>,
    expected_uid: u32,
    mut effective_access: impl FnMut(&Path, RuntimeIdentity) -> bool,
) -> TlsPathReadiness {
    let Ok(link_metadata) = fs::symlink_metadata(path) else {
        return TlsPathReadiness {
            present: false,
            kind: "missing".to_string(),
            target_is_regular: false,
            safe_permissions: false,
        };
    };
    let kind = if link_metadata.file_type().is_symlink() {
        "symlink"
    } else if link_metadata.file_type().is_file() {
        "regular"
    } else {
        "unsupported"
    };
    let metadata = fs::metadata(path).ok();
    let target_is_regular = metadata.as_ref().is_some_and(fs::Metadata::is_file);
    let safe_permissions = metadata.as_ref().is_some_and(|metadata| {
        identity.is_some_and(|identity| {
            file_allows_runtime(
                metadata.uid(),
                metadata.gid(),
                metadata.permissions().mode(),
                identity.gid,
                expected_uid,
                private_key,
            ) && effective_access(path, identity)
        })
    });
    TlsPathReadiness {
        present: true,
        kind: kind.to_string(),
        target_is_regular,
        safe_permissions,
    }
}

fn inspect_path(
    path: &Path,
    private_key: bool,
    identity: Option<RuntimeIdentity>,
) -> TlsPathReadiness {
    inspect_path_with_access(path, private_key, identity, ROOT_UID, |path, identity| {
        runtime_can_access(path, identity, RuntimeAccess::Read)
    })
}

fn valid_hostname(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 253
        && value.as_bytes()[0].is_ascii_alphanumeric()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-'))
}

fn openssl_x509(certificate: &Path, arguments: &[&str]) -> Option<std::process::Output> {
    Command::new("/usr/bin/openssl")
        .arg("x509")
        .args(arguments)
        .arg("-in")
        .arg(certificate)
        .output()
        .ok()
}

struct CertificateValidation {
    not_expired: bool,
    expiry: Option<String>,
    hostname_covered: Option<bool>,
}

fn validate_certificate(
    hostname: Option<&str>,
    paths_ready: bool,
    mut x509: impl FnMut(&[&str]) -> Option<std::process::Output>,
) -> CertificateValidation {
    let not_expired = paths_ready
        && x509(&["-checkend", "0", "-noout"]).is_some_and(|output| output.status.success());
    let expiry = paths_ready
        .then(|| x509(&["-enddate", "-noout"]))
        .flatten()
        .filter(|output| output.status.success())
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .and_then(|line| line.trim().strip_prefix("notAfter=").map(str::to_string));
    let hostname_covered = hostname.map(|hostname| {
        valid_hostname(hostname)
            && paths_ready
            && x509(&["-checkhost", hostname, "-noout"])
                .is_some_and(|output| output.status.success())
    });
    CertificateValidation {
        not_expired,
        expiry,
        hostname_covered,
    }
}

/// Checks the fixed TLS pair without reading private-key contents or changing files.
#[must_use]
pub fn tls_material_readiness(hostname: Option<&str>) -> TlsMaterialReadiness {
    let identity = runtime_identity()
        .filter(|identity| runtime_tls_directory_ready(Path::new(TLS_DIRECTORY_PATH), *identity));
    let certificate = inspect_path(Path::new(CERTIFICATE_PATH), false, identity);
    let private_key = inspect_path(Path::new(PRIVATE_KEY_PATH), true, identity);
    let paths_ready = certificate.target_is_regular
        && certificate.safe_permissions
        && private_key.target_is_regular
        && private_key.safe_permissions;
    let validation = validate_certificate(hostname, paths_ready, |arguments| {
        openssl_x509(Path::new(CERTIFICATE_PATH), arguments)
    });
    let certificate_not_expired = validation.not_expired;
    let certificate_expiry = validation.expiry;
    let hostname_covered = validation.hostname_covered;
    let ready = paths_ready && certificate_not_expired && hostname_covered != Some(false);
    let detail = if !certificate.present || !private_key.present {
        "proxy TLS material is missing"
    } else if !certificate.target_is_regular || !private_key.target_is_regular {
        "proxy TLS paths must be regular files or symlinks to regular files"
    } else if !certificate.safe_permissions || !private_key.safe_permissions {
        "proxy TLS material has unsafe ownership or permissions"
    } else if !certificate_not_expired {
        "proxy TLS certificate is expired or unreadable"
    } else if hostname_covered == Some(false) {
        "proxy TLS certificate does not cover the configured hostname"
    } else {
        "proxy TLS material is ready"
    };
    TlsMaterialReadiness {
        ready,
        certificate,
        private_key,
        certificate_not_expired,
        certificate_expiry,
        hostname_covered,
        detail: detail.to_string(),
    }
}

/// Returns whether any requested capability needs the fixed certificate pair.
pub(super) fn capabilities_require_tls<'a>(
    capabilities: impl IntoIterator<Item = &'a String>,
) -> bool {
    capabilities.into_iter().any(|capability| {
        matches!(
            capability.as_str(),
            "hysteria2" | "tuic" | "any-tls" | "anytls-tls" | "trojan-tls" | "trusttunnel-h2"
        )
    })
}

/// Returns the SNI field used by certificate-backed built-in profiles.
#[must_use]
pub fn profile_requires_tls(protocol_id: &str) -> bool {
    matches!(
        protocol_id,
        "hysteria2" | "tuic" | "any-tls" | "anytls-tls" | "trojan-tls" | "trusttunnel-h2"
    )
}

/// Returns the SNI field used by certificate-backed built-in profiles.
pub fn profile_tls_hostname(protocol_id: &str, config: &serde_json::Value) -> Option<String> {
    profile_requires_tls(protocol_id)
        .then(|| config.get("sni")?.as_str().map(str::to_string))
        .flatten()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        os::unix::{fs::symlink, process::ExitStatusExt},
        process::{ExitStatus, Output},
    };

    fn command_output(success: bool, stdout: &str) -> Output {
        Output {
            status: ExitStatus::from_raw(if success { 0 } else { 1 << 8 }),
            stdout: stdout.as_bytes().to_vec(),
            stderr: Vec::new(),
        }
    }

    #[test]
    fn hostname_validation_rejects_option_and_path_injection() {
        assert!(valid_hostname("node.example.com"));
        assert!(!valid_hostname("-help"));
        assert!(!valid_hostname("../../etc/passwd"));
        assert!(!valid_hostname("node.example.com\nother"));
    }

    #[test]
    fn standard_tls_capability_classification_is_explicit() {
        let required = ["trusttunnel-h2".to_string()];
        assert!(capabilities_require_tls(required.iter()));
        let wrapped = ["vless-jls".to_string()];
        assert!(!capabilities_require_tls(wrapped.iter()));
    }

    #[test]
    fn runtime_identity_records_are_resolved_independently() {
        assert_eq!(
            parse_getent_id(
                "infiproxy-runtime:x:987:987::/nonexistent:/usr/sbin/nologin\n",
                RUNTIME_USER,
                2,
            ),
            Some(987)
        );
        assert_eq!(
            parse_getent_id("infiproxy-runtime:x:988:\n", RUNTIME_GROUP, 2),
            Some(988)
        );
        assert_eq!(
            parse_getent_id("wrong-group:x:988:\n", RUNTIME_GROUP, 2),
            None
        );
        assert_eq!(
            parse_getent_id("infiproxy-runtime:x:not-a-gid:\n", RUNTIME_GROUP, 2),
            None
        );
        assert_eq!(
            parse_getent_id(
                "infiproxy-runtime:x:988:\ninfiproxy-runtime:x:989:\n",
                RUNTIME_GROUP,
                2,
            ),
            None
        );
    }

    #[test]
    fn readiness_debug_output_cannot_contain_private_key_contents() {
        let report = tls_material_readiness(Some("node.example.com"));
        let serialized = serde_json::to_string(&report).unwrap();
        assert!(!serialized.contains("BEGIN PRIVATE KEY"));
        assert!(!serialized.contains("privkey.pem"));
    }

    #[test]
    fn runtime_file_permission_contract_requires_exact_group_readability() {
        let expected_gid = 988;
        assert!(file_allows_runtime(
            0,
            expected_gid,
            0o640,
            expected_gid,
            ROOT_UID,
            false
        ));
        assert!(file_allows_runtime(
            0,
            expected_gid,
            0o640,
            expected_gid,
            ROOT_UID,
            true
        ));
        assert!(!file_allows_runtime(
            0,
            990,
            0o640,
            expected_gid,
            ROOT_UID,
            false
        ));
        assert!(!file_allows_runtime(
            995,
            expected_gid,
            0o640,
            expected_gid,
            ROOT_UID,
            false
        ));
        assert!(!file_allows_runtime(
            0,
            expected_gid,
            0o600,
            expected_gid,
            ROOT_UID,
            false
        ));
    }

    #[test]
    fn runtime_file_permission_contract_rejects_unsafe_write_and_key_access() {
        let expected_gid = 988;
        for mode in [0o660, 0o646, 0o666] {
            assert!(!file_allows_runtime(
                0,
                expected_gid,
                mode,
                expected_gid,
                ROOT_UID,
                false
            ));
        }
        for mode in [0o644, 0o641] {
            assert!(!file_allows_runtime(
                0,
                expected_gid,
                mode,
                expected_gid,
                ROOT_UID,
                true
            ));
        }
    }

    #[test]
    fn runtime_tls_directory_requires_safe_group_traversal() {
        let expected_gid = 988;
        assert!(directory_allows_runtime(
            0,
            expected_gid,
            0o750,
            expected_gid
        ));
        assert!(!directory_allows_runtime(
            1,
            expected_gid,
            0o750,
            expected_gid
        ));
        assert!(!directory_allows_runtime(0, 990, 0o750, expected_gid));
        assert!(!directory_allows_runtime(
            0,
            expected_gid,
            0o740,
            expected_gid
        ));
        assert!(!directory_allows_runtime(
            0,
            expected_gid,
            0o770,
            expected_gid
        ));
        assert!(!directory_allows_runtime(
            0,
            expected_gid,
            0o755,
            expected_gid
        ));
    }

    #[test]
    fn matching_but_wrong_tls_group_is_rejected() {
        let actual_runtime_gid = 988;
        let wrong_matching_gid = 990;
        assert!(!directory_allows_runtime(
            ROOT_UID,
            wrong_matching_gid,
            0o750,
            actual_runtime_gid
        ));
        assert!(!file_allows_runtime(
            ROOT_UID,
            wrong_matching_gid,
            0o640,
            actual_runtime_gid,
            ROOT_UID,
            false
        ));
        assert!(!file_allows_runtime(
            ROOT_UID,
            wrong_matching_gid,
            0o640,
            actual_runtime_gid,
            ROOT_UID,
            true
        ));
    }

    #[test]
    fn symlink_to_regular_file_is_resolved_without_trusting_link_metadata() {
        let directory =
            std::env::temp_dir().join(format!("infiproxy-tls-symlink-{}", uuid::Uuid::new_v4()));
        fs::create_dir(&directory).unwrap();
        let target = directory.join("certificate.pem");
        let link = directory.join("fullchain.pem");
        fs::write(&target, b"certificate fixture").unwrap();
        fs::set_permissions(&target, fs::Permissions::from_mode(0o640)).unwrap();
        symlink(&target, &link).unwrap();

        let metadata = fs::metadata(&target).unwrap();
        let identity = RuntimeIdentity {
            uid: metadata.uid(),
            gid: metadata.gid(),
        };
        let readiness = inspect_path_with_access(
            &link,
            false,
            Some(identity),
            metadata.uid(),
            |path, identity| path_modes_allow_runtime(path, identity, RuntimeAccess::Read),
        );
        assert_eq!(readiness.kind, "symlink");
        assert!(readiness.target_is_regular);
        assert!(readiness.safe_permissions);

        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn symlink_target_with_untraversable_ancestor_is_not_ready() {
        let directory = Path::new("/tmp").join(format!(
            "infiproxy-tls-untraversable-{}",
            uuid::Uuid::new_v4()
        ));
        let tls_directory = directory.join("tls");
        let blocked_directory = directory.join("blocked");
        fs::create_dir(&directory).unwrap();
        fs::create_dir(&tls_directory).unwrap();
        fs::create_dir(&blocked_directory).unwrap();
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o750)).unwrap();
        fs::set_permissions(&tls_directory, fs::Permissions::from_mode(0o750)).unwrap();
        fs::set_permissions(&blocked_directory, fs::Permissions::from_mode(0o750)).unwrap();

        let target = blocked_directory.join("certificate.pem");
        let link = tls_directory.join("fullchain.pem");
        fs::write(&target, b"certificate fixture").unwrap();
        fs::set_permissions(&target, fs::Permissions::from_mode(0o640)).unwrap();
        symlink(&target, &link).unwrap();

        let metadata = fs::metadata(&target).unwrap();
        let identity = RuntimeIdentity {
            uid: metadata.uid().wrapping_add(1),
            gid: metadata.gid(),
        };
        let inspect = || {
            inspect_path_with_access(
                &link,
                false,
                Some(identity),
                metadata.uid(),
                |path, identity| path_modes_allow_runtime(path, identity, RuntimeAccess::Read),
            )
        };
        assert!(inspect().safe_permissions);

        fs::set_permissions(&blocked_directory, fs::Permissions::from_mode(0o700)).unwrap();
        let readiness = inspect();
        assert_eq!(readiness.kind, "symlink");
        assert!(readiness.target_is_regular);
        assert!(!readiness.safe_permissions);

        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn certificate_expiry_and_hostname_status_remain_fail_closed() {
        let valid = validate_certificate(Some("node.example.com"), true, |arguments| {
            if arguments.first() == Some(&"-enddate") {
                Some(command_output(true, "notAfter=Dec 31 23:59:59 2030 GMT\n"))
            } else {
                Some(command_output(true, ""))
            }
        });
        assert!(valid.not_expired);
        assert_eq!(valid.expiry.as_deref(), Some("Dec 31 23:59:59 2030 GMT"));
        assert_eq!(valid.hostname_covered, Some(true));

        let expired = validate_certificate(Some("node.example.com"), true, |arguments| {
            Some(command_output(arguments.first() != Some(&"-checkend"), ""))
        });
        assert!(!expired.not_expired);

        let wrong_hostname = validate_certificate(Some("other.example.com"), true, |arguments| {
            Some(command_output(arguments.first() != Some(&"-checkhost"), ""))
        });
        assert_eq!(wrong_hostname.hostname_covered, Some(false));

        let unreadable = validate_certificate(Some("node.example.com"), false, |_| {
            panic!("OpenSSL must not run for unreadable TLS paths")
        });
        assert!(!unreadable.not_expired);
        assert_eq!(unreadable.hostname_covered, Some(false));
    }
}
