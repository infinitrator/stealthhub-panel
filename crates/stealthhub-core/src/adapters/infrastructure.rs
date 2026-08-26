//! Public Nginx/TLS infrastructure adapter.

use std::{
    collections::BTreeSet,
    fs::{self, OpenOptions},
    io::Write,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    process::Command,
};

use anyhow::{bail, Context, Result};
use serde_json::{json, Value};

use crate::{
    adapter::{CoreAdapter, CoreAdapterManifest, CorePlan, CoreSnapshot, ADAPTER_API_VERSION},
    desired::InfrastructureResource,
    models::PanelSettings,
};

const ADAPTER_ID: &str = "public-frontend";
const SITE_PATH: &str = "/etc/nginx/sites-available/infiproxy.conf";
const ENABLED_PATH: &str = "/etc/nginx/sites-enabled/infiproxy.conf";

pub(super) struct PublicFrontendAdapter {
    manifest: CoreAdapterManifest,
}

impl PublicFrontendAdapter {
    pub(super) fn new() -> Self {
        Self {
            manifest: CoreAdapterManifest {
                api_version: ADAPTER_API_VERSION,
                id: ADAPTER_ID.to_string(),
                display_name: "Public HTTPS frontend".to_string(),
                capabilities: BTreeSet::from([ADAPTER_ID.to_string()]),
                service: "nginx.service".to_string(),
                selection_priority: 0,
            },
        }
    }

    fn domains<'a>(&self, plan: &'a CorePlan) -> Result<(&'a str, &'a str)> {
        let fragment = plan
            .fragments
            .first()
            .context("frontend resource is missing")?;
        if plan.fragments.len() != 1 {
            bail!("frontend adapter supports one desired resource");
        }
        let subscription = fragment
            .payload
            .get("subscription_domain")
            .and_then(Value::as_str)
            .context("subscription domain is missing")?;
        let node = fragment
            .payload
            .get("node_domain")
            .and_then(Value::as_str)
            .context("node domain is missing")?;
        validate_domain(subscription)?;
        validate_domain(node)?;
        Ok((subscription, node))
    }

    fn certificate_paths(domain: &str) -> (PathBuf, PathBuf) {
        let root = Path::new("/etc/letsencrypt/live").join(domain);
        (root.join("fullchain.pem"), root.join("privkey.pem"))
    }

    fn render_site(&self, plan: &CorePlan) -> Result<String> {
        let (subscription, _) = self.domains(plan)?;
        let (certificate, key) = Self::certificate_paths(subscription);
        Ok(format!(
            "server {{\n    listen 80;\n    listen [::]:80;\n    server_name {subscription};\n    return 301 https://$host$request_uri;\n}}\n\nserver {{\n    listen 443 ssl http2;\n    listen [::]:443 ssl http2;\n    server_name {subscription};\n\n    ssl_certificate {};\n    ssl_certificate_key {};\n    ssl_protocols TLSv1.2 TLSv1.3;\n    ssl_session_tickets off;\n    server_tokens off;\n\n    client_max_body_size 1m;\n    client_header_timeout 15s;\n    client_body_timeout 15s;\n    keepalive_timeout 30s;\n    send_timeout 60s;\n    proxy_connect_timeout 5s;\n    proxy_send_timeout 30s;\n    proxy_read_timeout 60s;\n\n    add_header X-Frame-Options DENY always;\n    add_header X-Content-Type-Options nosniff always;\n    add_header Referrer-Policy no-referrer always;\n    add_header Strict-Transport-Security \"max-age=31536000\" always;\n\n    location ^~ /sub/ {{\n        access_log off;\n        proxy_pass http://127.0.0.1:8080;\n        proxy_http_version 1.1;\n        proxy_set_header Host $host;\n        proxy_set_header X-Real-IP $remote_addr;\n        proxy_set_header X-Forwarded-For $remote_addr;\n        proxy_set_header X-Forwarded-Proto https;\n    }}\n\n    location / {{\n        proxy_pass http://127.0.0.1:8080;\n        proxy_http_version 1.1;\n        proxy_set_header Host $host;\n        proxy_set_header X-Real-IP $remote_addr;\n        proxy_set_header X-Forwarded-For $remote_addr;\n        proxy_set_header X-Forwarded-Proto https;\n    }}\n}}\n",
            certificate.display(),
            key.display()
        ))
    }

    fn validate_certificate(&self, plan: &CorePlan) -> Result<()> {
        let (subscription, _) = self.domains(plan)?;
        let (certificate, key) = Self::certificate_paths(subscription);
        for path in [&certificate, &key] {
            validate_letsencrypt_material(path, subscription)?;
        }
        let status = Command::new("/usr/bin/openssl")
            .args(["x509", "-in"])
            .arg(&certificate)
            .args(["-noout", "-checkend", "3600", "-checkhost", subscription])
            .status()?;
        if !status.success() {
            bail!("certificate is expired or does not cover the subscription domain");
        }
        Ok(())
    }

    fn nginx_test(candidate: &Path) -> Result<()> {
        let test_root = candidate.parent().context("candidate has no parent")?;
        let test_config = test_root.join("nginx-test.conf");
        fs::write(
            &test_config,
            format!(
                "pid {};\nevents {{}}\nhttp {{ include /etc/nginx/mime.types; include {}; }}\n",
                test_root.join("nginx.pid").display(),
                candidate.display()
            ),
        )?;
        let status = Command::new("/usr/sbin/nginx")
            .args(["-t", "-c"])
            .arg(test_config)
            .status()?;
        if !status.success() {
            bail!("nginx rejected staged frontend configuration");
        }
        Ok(())
    }

    fn atomic_site_install(source: &Path) -> Result<()> {
        let site = Path::new(SITE_PATH);
        let parent = site.parent().context("site path has no parent")?;
        fs::create_dir_all(parent)?;
        let temporary = parent.join(format!(".infiproxy-{}.tmp", uuid::Uuid::new_v4()));
        let result = (|| {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o644)
                .open(&temporary)?;
            file.write_all(&fs::read(source)?)?;
            file.sync_all()?;
            fs::set_permissions(&temporary, fs::Permissions::from_mode(0o644))?;
            fs::rename(&temporary, site)?;
            fs::File::open(parent)?.sync_all()?;
            Ok(())
        })();
        if result.is_err() {
            let _ = fs::remove_file(temporary);
        }
        result
    }

    fn reload() -> Result<()> {
        let status = Command::new("/usr/bin/systemctl")
            .args(["reload", "nginx.service"])
            .status()?;
        if !status.success() {
            bail!("nginx reload failed");
        }
        Ok(())
    }

    fn systemctl(arguments: &[&str]) -> Result<()> {
        let status = Command::new("/usr/bin/systemctl")
            .args(arguments)
            .arg("nginx.service")
            .status()?;
        if !status.success() {
            bail!("nginx service operation failed");
        }
        Ok(())
    }

    fn install_enabled_link() -> Result<()> {
        let enabled = Path::new(ENABLED_PATH);
        if let Ok(metadata) = fs::symlink_metadata(enabled) {
            if metadata.file_type().is_dir() {
                bail!("nginx enabled site path is a directory");
            }
            fs::remove_file(enabled)?;
        }
        std::os::unix::fs::symlink(SITE_PATH, enabled)?;
        Ok(())
    }
}

impl CoreAdapter for PublicFrontendAdapter {
    fn manifest(&self) -> &CoreAdapterManifest {
        &self.manifest
    }

    fn installed(&self) -> Result<bool> {
        Ok(Path::new("/usr/sbin/nginx").is_file())
    }

    fn stage(&self, plan: &CorePlan, transaction_dir: &Path) -> Result<PathBuf> {
        let candidate = transaction_dir.join("frontend.conf");
        fs::write(&candidate, self.render_site(plan)?)?;
        Ok(candidate)
    }

    fn validate(&self, candidate: &Path) -> Result<()> {
        Self::nginx_test(candidate)
    }

    fn snapshot(&self, transaction_dir: &Path) -> Result<CoreSnapshot> {
        let snapshot = transaction_dir.join("snapshot");
        fs::create_dir_all(&snapshot)?;
        match fs::symlink_metadata(SITE_PATH) {
            Ok(metadata) if metadata.file_type().is_file() => {
                fs::copy(SITE_PATH, snapshot.join("site"))?;
            }
            Ok(_) => bail!("frontend site must be a regular file"),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                fs::write(snapshot.join("site.absent"), [])?;
            }
            Err(error) => return Err(error.into()),
        }
        match fs::symlink_metadata(ENABLED_PATH) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                fs::write(
                    snapshot.join("enabled.link"),
                    fs::read_link(ENABLED_PATH)?.as_os_str().as_encoded_bytes(),
                )?;
            }
            Ok(metadata) if metadata.file_type().is_file() => {
                fs::copy(ENABLED_PATH, snapshot.join("enabled.file"))?;
            }
            Ok(_) => bail!("frontend enabled path has an unsupported file type"),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                fs::write(snapshot.join("enabled.absent"), [])?;
            }
            Err(error) => return Err(error.into()),
        }
        Ok(CoreSnapshot {
            path: snapshot,
            service_was_enabled: systemctl_is("is-enabled", "nginx.service"),
            service_was_active: systemctl_is("is-active", "nginx.service"),
        })
    }

    fn install(&self, candidate: &Path) -> Result<()> {
        Self::atomic_site_install(candidate)?;
        fs::create_dir_all("/etc/nginx/sites-enabled")?;
        Self::install_enabled_link()?;
        Ok(())
    }

    fn activate(&self, _plan: &CorePlan) -> Result<()> {
        Self::systemctl(&["enable"])?;
        if systemctl_is("is-active", "nginx.service") {
            Self::reload()
        } else {
            Self::systemctl(&["start"])
        }
    }

    fn healthcheck(&self, plan: &CorePlan) -> Result<()> {
        self.validate_certificate(plan)?;
        if !systemctl_is("is-active", "nginx.service") {
            bail!("nginx service is not active");
        }
        let (subscription, node) = self.domains(plan)?;
        let resolution = Command::new("/usr/bin/getent")
            .args(["ahosts", node])
            .output()?;
        if !resolution.status.success() || resolution.stdout.is_empty() {
            bail!("node domain does not resolve");
        }
        let status = Command::new("/usr/bin/curl")
            .args([
                "--fail",
                "--silent",
                "--show-error",
                "--max-time",
                "10",
                "--noproxy",
                "*",
                "--resolve",
            ])
            .arg(format!("{subscription}:443:127.0.0.1"))
            .arg(format!("https://{subscription}/ready"))
            .status()?;
        if !status.success() {
            bail!("public HTTPS readiness check failed");
        }
        Ok(())
    }

    fn verify_listeners(&self, _plan: &CorePlan) -> Result<()> {
        let output = Command::new("/usr/bin/ss").args(["-H", "-ltn"]).output()?;
        let listeners = String::from_utf8(output.stdout)?;
        if ![80_u16, 443].into_iter().all(|port| {
            let marker = format!(":{port}");
            listeners.lines().any(|line| {
                line.split_whitespace()
                    .any(|field| field.ends_with(&marker))
            })
        }) {
            bail!("public frontend listeners are incomplete");
        }
        Ok(())
    }

    fn rollback(&self, snapshot: &CoreSnapshot) -> Result<()> {
        if snapshot.path.join("site").is_file() {
            Self::atomic_site_install(&snapshot.path.join("site"))?;
        } else if snapshot.path.join("site.absent").is_file() {
            let _ = fs::remove_file(SITE_PATH);
        } else {
            bail!("frontend snapshot is incomplete");
        }
        let _ = fs::remove_file(ENABLED_PATH);
        if snapshot.path.join("enabled.link").is_file() {
            let target = fs::read_to_string(snapshot.path.join("enabled.link"))?;
            if target.is_empty() || target.contains('\0') {
                bail!("frontend symlink snapshot is invalid");
            }
            std::os::unix::fs::symlink(target, ENABLED_PATH)?;
        } else if snapshot.path.join("enabled.file").is_file() {
            fs::copy(snapshot.path.join("enabled.file"), ENABLED_PATH)?;
        } else if snapshot.path.join("enabled.absent").is_file() {
        } else {
            bail!("frontend enabled-site snapshot is incomplete");
        }
        let nginx_test = Command::new("/usr/sbin/nginx").arg("-t").status()?;
        if !nginx_test.success() {
            bail!("restored frontend configuration is invalid");
        }
        if snapshot.service_was_enabled {
            Self::systemctl(&["enable"])?;
        } else {
            Self::systemctl(&["disable"])?;
        }
        if snapshot.service_was_active {
            Self::systemctl(&["restart"])?;
        } else {
            Self::systemctl(&["stop"])?;
        }
        if snapshot.service_was_active && !systemctl_is("is-active", "nginx.service") {
            bail!("restored frontend is not active");
        }
        Ok(())
    }
}

fn validate_letsencrypt_material(path: &Path, domain: &str) -> Result<()> {
    let resolved = fs::canonicalize(path)
        .with_context(|| format!("TLS material is not provisioned for {domain}"))?;
    let expected_root = Path::new("/etc/letsencrypt/archive").join(domain);
    if !resolved.starts_with(&expected_root) {
        bail!("TLS material resolves outside the expected certificate archive");
    }
    let metadata = fs::metadata(&resolved)?;
    if !metadata.file_type().is_file() || metadata.len() == 0 {
        bail!("TLS material is not a non-empty regular file");
    }
    Ok(())
}

fn systemctl_is(property: &str, service: &str) -> bool {
    Command::new("/usr/bin/systemctl")
        .args([property, "--quiet", service])
        .status()
        .is_ok_and(|status| status.success())
}

fn validate_domain(value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 253
        || value.contains("..")
        || value.split('.').any(|label| {
            label.is_empty()
                || label.len() > 63
                || !label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
                || label.starts_with('-')
                || label.ends_with('-')
        })
    {
        bail!("invalid public domain");
    }
    Ok(())
}

/// Converts generic panel settings into an adapter-owned desired resource.
#[must_use]
pub fn desired_resources(settings: &PanelSettings) -> Vec<InfrastructureResource> {
    if settings.subscription_domain.ends_with(".local") || settings.node_domain.ends_with(".local")
    {
        return Vec::new();
    }
    vec![InfrastructureResource {
        resource_id: "public-frontend".to_string(),
        adapter_id: ADAPTER_ID.to_string(),
        schema_version: 1,
        enabled: true,
        config: json!({
            "subscription_domain": settings.subscription_domain,
            "node_domain": settings.node_domain,
        }),
    }]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn domains_are_strictly_validated() {
        assert!(validate_domain("sub.example.com").is_ok());
        assert!(validate_domain("bad name.example").is_err());
        assert!(validate_domain("-bad.example").is_err());
        assert!(validate_domain("../../etc/passwd").is_err());
    }

    #[test]
    fn generated_frontend_preserves_security_controls() {
        let adapter = PublicFrontendAdapter::new();
        let plan = CorePlan {
            generation: 1,
            core_id: ADAPTER_ID.to_string(),
            fragments: vec![crate::adapter::ServerFragment {
                profile_id: ADAPTER_ID.to_string(),
                capability: ADAPTER_ID.to_string(),
                payload: json!({
                    "subscription_domain": "sub.example.com",
                    "node_domain": "node.example.com"
                }),
            }],
        };
        let site = adapter.render_site(&plan).unwrap();
        assert!(site.contains("location ^~ /sub/"));
        assert!(site.contains("access_log off;"));
        assert!(site.contains("proxy_set_header X-Forwarded-For $remote_addr;"));
        assert!(site.contains("client_max_body_size 1m;"));
        assert!(site.contains("Strict-Transport-Security"));
        assert!(!site.contains("$proxy_add_x_forwarded_for"));
        assert!(!site.contains("server_name sub.example.com node.example.com"));
    }
}
