//! Non-mutating readiness checks for proxy-runtime TLS material.

use std::{
    fs,
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::Path,
    process::Command,
};

use serde::{Deserialize, Serialize};

pub(super) const CERTIFICATE_PATH: &str = "/etc/infiproxy-cores/tls/fullchain.pem";
pub(super) const PRIVATE_KEY_PATH: &str = "/etc/infiproxy-cores/tls/privkey.pem";

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

fn inspect_path(path: &Path, private_key: bool) -> TlsPathReadiness {
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
        let mode = metadata.permissions().mode();
        let no_unsafe_writes = mode & 0o022 == 0;
        let no_other_key_access = !private_key || mode & 0o007 == 0;
        metadata.uid() == 0 && no_unsafe_writes && no_other_key_access
    });
    TlsPathReadiness {
        present: true,
        kind: kind.to_string(),
        target_is_regular,
        safe_permissions,
    }
}

fn valid_hostname(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 253
        && value.as_bytes()[0].is_ascii_alphanumeric()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-'))
}

fn openssl_x509(arguments: &[&str]) -> Option<std::process::Output> {
    Command::new("/usr/bin/openssl")
        .arg("x509")
        .args(arguments)
        .arg("-in")
        .arg(CERTIFICATE_PATH)
        .output()
        .ok()
}

/// Checks the fixed TLS pair without reading private-key contents or changing files.
#[must_use]
pub fn tls_material_readiness(hostname: Option<&str>) -> TlsMaterialReadiness {
    let certificate = inspect_path(Path::new(CERTIFICATE_PATH), false);
    let private_key = inspect_path(Path::new(PRIVATE_KEY_PATH), true);
    let paths_ready = certificate.target_is_regular
        && certificate.safe_permissions
        && private_key.target_is_regular
        && private_key.safe_permissions;
    let certificate_not_expired = paths_ready
        && openssl_x509(&["-checkend", "0", "-noout"])
            .is_some_and(|output| output.status.success());
    let certificate_expiry = paths_ready
        .then(|| openssl_x509(&["-enddate", "-noout"]))
        .flatten()
        .filter(|output| output.status.success())
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .and_then(|line| line.trim().strip_prefix("notAfter=").map(str::to_string));
    let hostname_covered = hostname.map(|hostname| {
        valid_hostname(hostname)
            && paths_ready
            && openssl_x509(&["-checkhost", hostname, "-noout"])
                .is_some_and(|output| output.status.success())
    });
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
    fn readiness_debug_output_cannot_contain_private_key_contents() {
        let report = tls_material_readiness(Some("node.example.com"));
        let serialized = serde_json::to_string(&report).unwrap();
        assert!(!serialized.contains("BEGIN PRIVATE KEY"));
        assert!(!serialized.contains("privkey.pem"));
    }
}
