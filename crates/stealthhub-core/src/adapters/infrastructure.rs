//! Independently owned public infrastructure adapters.
//!
//! The installer owns the administrative Nginx virtual host. This module only
//! owns the dedicated subscription virtual host and a mutation-free node DNS
//! readiness resource. Certificate issuance remains an explicit operator task;
//! reconciliation validates existing Let's Encrypt material before mutation.

use std::{
    collections::BTreeSet,
    fs::{self, OpenOptions},
    io::Write,
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Component, Path, PathBuf},
    process::Command,
    thread,
    time::{Duration, Instant},
};

use anyhow::{bail, Context, Result};
use serde_json::{json, Value};

use crate::{
    adapter::{
        CoreAdapter, CoreAdapterManifest, CorePlan, CoreSnapshot, ListenerClaim, ListenerNetwork,
        ADAPTER_API_VERSION,
    },
    desired::{InfrastructureResource, InfrastructureResourceKind},
    models::PanelSettings,
};

const SUBSCRIPTION_ADAPTER_ID: &str = "subscription-frontend";
const NODE_ADAPTER_ID: &str = "node-readiness";
const MAX_NGINX_SITE_BYTES: u64 = 1024 * 1024;
const SUBSCRIPTION_READY_TIMEOUT: Duration = Duration::from_secs(5);
const SUBSCRIPTION_READY_POLL_INTERVAL: Duration = Duration::from_millis(100);

const NGINX_TEST_TEMP_DIRECTORIES: [(&str, &str); 5] = [
    ("client_body_temp_path", "client-body"),
    ("proxy_temp_path", "proxy"),
    ("fastcgi_temp_path", "fastcgi"),
    ("uwsgi_temp_path", "uwsgi"),
    ("scgi_temp_path", "scgi"),
];

struct NginxTestPaths<'a> {
    candidate: &'a Path,
    transaction: &'a Path,
}

impl<'a> NginxTestPaths<'a> {
    fn new(candidate: &'a Path) -> Result<Self> {
        let transaction = candidate.parent().context("candidate has no parent")?;
        if candidate.file_name().and_then(|name| name.to_str()) != Some("subscription.conf") {
            bail!("unexpected Nginx candidate name");
        }
        // The reconciler creates this path; reject characters that could alter
        // Nginx directive syntax rather than interpolating an untrusted path.
        for path in [transaction, candidate] {
            let value = path.to_str().context("Nginx test path is not UTF-8")?;
            if !path.is_absolute()
                || path
                    .components()
                    .any(|component| matches!(component, Component::ParentDir | Component::CurDir))
                || !value
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || b"/._-".contains(&byte))
            {
                bail!("Nginx test path has unsupported characters");
            }
        }
        Ok(Self {
            candidate,
            transaction,
        })
    }

    fn config(&self) -> PathBuf {
        self.transaction.join("nginx-test.conf")
    }

    fn runtime(&self) -> PathBuf {
        self.transaction.join("nginx-test-runtime")
    }

    fn prepare(&self) -> Result<()> {
        let runtime = self.runtime();
        fs::create_dir_all(&runtime)?;
        fs::set_permissions(&runtime, fs::Permissions::from_mode(0o700))?;
        for (_, directory) in NGINX_TEST_TEMP_DIRECTORIES {
            let path = runtime.join(directory);
            fs::create_dir_all(&path)?;
            fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
        }
        Ok(())
    }

    fn render_config(&self) -> String {
        let mut config = format!(
            "pid {};\nerror_log stderr;\nevents {{}}\nhttp {{\n    access_log off;\n    include /etc/nginx/mime.types;\n",
            self.transaction.join("nginx.pid").display()
        );
        for (directive, directory) in NGINX_TEST_TEMP_DIRECTORIES {
            config.push_str(&format!(
                "    {directive} {};\n",
                self.runtime().join(directory).display()
            ));
        }
        config.push_str(&format!("    include {};\n}}\n", self.candidate.display()));
        config
    }
}

fn run_nginx_candidate_test(executable: &Path, paths: &NginxTestPaths<'_>) -> Result<()> {
    let status = Command::new(executable)
        .args(["-t", "-p"])
        .arg(paths.transaction)
        .arg("-c")
        .arg(paths.config())
        .status()
        .context("run Nginx candidate validation")?;
    if !status.success() {
        bail!("nginx rejected staged subscription configuration");
    }
    Ok(())
}

fn validate_nginx_candidate_with(executable: &Path, candidate: &Path) -> Result<()> {
    let paths = NginxTestPaths::new(candidate)?;
    paths.prepare()?;
    fs::write(paths.config(), paths.render_config())?;
    run_nginx_candidate_test(executable, &paths)
}

fn validate_restored_nginx_site_with(
    executable: &Path,
    site: &Path,
    validation_root: &Path,
) -> Result<()> {
    if !site.is_file() {
        return Ok(());
    }
    fs::create_dir_all(validation_root)?;
    fs::set_permissions(validation_root, fs::Permissions::from_mode(0o700))?;
    let candidate = validation_root.join("subscription.conf");
    fs::copy(site, &candidate)?;
    validate_nginx_candidate_with(executable, &candidate)
}

fn subscription_readiness_command(domain: &str, max_time: Duration) -> Command {
    let max_time = max_time.max(Duration::from_millis(1));
    let mut command = Command::new("/usr/bin/curl");
    command.args([
        "--fail",
        "--silent",
        "--show-error",
        "--max-time",
        &format!("{:.3}", max_time.as_secs_f64()),
        "--noproxy",
        "*",
        "--resolve",
        &format!("{domain}:443:127.0.0.1"),
        &format!("https://{domain}/ready"),
    ]);
    command
}

fn wait_for_subscription_readiness(
    timeout: Duration,
    poll_interval: Duration,
    mut probe: impl FnMut(Duration) -> bool,
    mut elapsed: impl FnMut() -> Duration,
    mut wait: impl FnMut(Duration),
) -> Result<()> {
    loop {
        let before_probe = elapsed();
        if before_probe >= timeout {
            bail!("subscription HTTPS readiness check failed");
        }
        if probe(timeout - before_probe) {
            return Ok(());
        }
        let after_probe = elapsed();
        if after_probe >= timeout {
            bail!("subscription HTTPS readiness check failed");
        }
        wait(poll_interval.min(timeout - after_probe));
    }
}

#[derive(Clone)]
struct SubscriptionPaths {
    site: PathBuf,
    enabled: PathBuf,
    enabled_directory: PathBuf,
    letsencrypt_live: PathBuf,
    letsencrypt_archive: PathBuf,
}

impl SubscriptionPaths {
    fn production() -> Self {
        Self {
            site: "/etc/nginx/sites-available/infiproxy-subscription.conf".into(),
            enabled: "/etc/nginx/sites-enabled/infiproxy-subscription.conf".into(),
            enabled_directory: "/etc/nginx/sites-enabled".into(),
            letsencrypt_live: "/etc/letsencrypt/live".into(),
            letsencrypt_archive: "/etc/letsencrypt/archive".into(),
        }
    }
}

pub(super) struct SubscriptionFrontendAdapter {
    manifest: CoreAdapterManifest,
    paths: SubscriptionPaths,
}

impl SubscriptionFrontendAdapter {
    pub(super) fn new() -> Self {
        Self {
            manifest: CoreAdapterManifest {
                api_version: ADAPTER_API_VERSION,
                id: SUBSCRIPTION_ADAPTER_ID.to_string(),
                display_name: "Subscription HTTPS frontend".to_string(),
                capabilities: BTreeSet::from([SUBSCRIPTION_ADAPTER_ID.to_string()]),
                service: "nginx.service".to_string(),
                selection_priority: 0,
            },
            paths: SubscriptionPaths::production(),
        }
    }

    fn domain<'a>(&self, plan: &'a CorePlan) -> Result<Option<&'a str>> {
        if plan.fragments.is_empty() {
            return Ok(None);
        }
        let mut domains = plan.fragments.iter().filter_map(|fragment| {
            fragment
                .payload
                .get("subscription_domain")
                .and_then(Value::as_str)
        });
        let domain = domains.next().context("subscription domain is missing")?;
        if domains.next().is_some() {
            bail!("subscription frontend has multiple domain owners");
        }
        validate_domain(domain)?;
        Ok(Some(domain))
    }

    fn certificate_paths(&self, domain: &str) -> (PathBuf, PathBuf) {
        let root = self.paths.letsencrypt_live.join(domain);
        (root.join("fullchain.pem"), root.join("privkey.pem"))
    }

    fn render_site(&self, plan: &CorePlan) -> Result<String> {
        let Some(domain) = self.domain(plan)? else {
            return Ok(String::new());
        };
        let (certificate, key) = self.certificate_paths(domain);
        Ok(format!(
            "server {{\n    listen 80;\n    listen [::]:80;\n    server_name {domain};\n    return 301 https://$host$request_uri;\n}}\n\nserver {{\n    listen 443 ssl http2;\n    listen [::]:443 ssl http2;\n    server_name {domain};\n\n    ssl_certificate {};\n    ssl_certificate_key {};\n    ssl_protocols TLSv1.2 TLSv1.3;\n    ssl_session_tickets off;\n    server_tokens off;\n\n    client_max_body_size 1m;\n    client_header_timeout 15s;\n    client_body_timeout 15s;\n    keepalive_timeout 30s;\n    send_timeout 60s;\n    proxy_connect_timeout 5s;\n    proxy_send_timeout 30s;\n    proxy_read_timeout 60s;\n\n    add_header X-Frame-Options DENY always;\n    add_header X-Content-Type-Options nosniff always;\n    add_header Referrer-Policy no-referrer always;\n    add_header Strict-Transport-Security \"max-age=31536000\" always;\n\n    location ^~ /sub/ {{\n        access_log off;\n        proxy_pass http://127.0.0.1:8080;\n        proxy_http_version 1.1;\n        proxy_set_header Host $host;\n        proxy_set_header X-Real-IP $remote_addr;\n        proxy_set_header X-Forwarded-For $remote_addr;\n        proxy_set_header X-Forwarded-Proto https;\n    }}\n\n    location ^~ /rules/ {{\n        proxy_pass http://127.0.0.1:8080;\n        proxy_http_version 1.1;\n        proxy_set_header Host $host;\n        proxy_set_header X-Real-IP $remote_addr;\n        proxy_set_header X-Forwarded-For $remote_addr;\n        proxy_set_header X-Forwarded-Proto https;\n    }}\n\n    location = /ready {{\n        proxy_pass http://127.0.0.1:8080/ready;\n        access_log off;\n    }}\n\n    location / {{\n        return 404;\n    }}\n}}\n",
            certificate.display(),
            key.display()
        ))
    }

    fn validate_certificate(&self, domain: &str) -> Result<()> {
        let (certificate, key) = self.certificate_paths(domain);
        for path in [&certificate, &key] {
            validate_letsencrypt_material(path, domain, &self.paths.letsencrypt_archive)?;
        }
        let status = Command::new("/usr/bin/openssl")
            .args(["x509", "-in"])
            .arg(&certificate)
            .args(["-noout", "-checkend", "3600", "-checkhost", domain])
            .status()
            .context("run OpenSSL certificate preflight")?;
        if !status.success() {
            bail!("certificate is expired or does not cover the subscription domain");
        }
        Ok(())
    }

    fn reject_duplicate_server_name(&self, domain: &str) -> Result<()> {
        let entries = match fs::read_dir(&self.paths.enabled_directory) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(error).context("read enabled Nginx sites"),
        };
        for entry in entries {
            let path = entry?.path();
            if path == self.paths.enabled {
                continue;
            }
            let metadata = fs::metadata(&path)
                .with_context(|| format!("inspect enabled Nginx site {}", path.display()))?;
            if !metadata.is_file() || metadata.len() > MAX_NGINX_SITE_BYTES {
                bail!("enabled Nginx site must be a bounded regular file");
            }
            let content = fs::read_to_string(&path)
                .with_context(|| format!("read enabled Nginx site {}", path.display()))?;
            if nginx_server_names(&content).contains(domain) {
                bail!("subscription domain conflicts with another enabled Nginx site");
            }
        }
        Ok(())
    }

    fn nginx_test(candidate: &Path) -> Result<()> {
        validate_nginx_candidate_with(Path::new("/usr/sbin/nginx"), candidate)
    }

    fn atomic_site_install(&self, source: &Path) -> Result<()> {
        atomic_copy(source, &self.paths.site, 0o644)
    }

    fn install_enabled_link(&self) -> Result<()> {
        if let Ok(metadata) = fs::symlink_metadata(&self.paths.enabled) {
            if metadata.file_type().is_dir() {
                bail!("subscription enabled-site path is a directory");
            }
            fs::remove_file(&self.paths.enabled)?;
        }
        std::os::unix::fs::symlink(&self.paths.site, &self.paths.enabled)?;
        Ok(())
    }

    fn snapshot_owned_files(&self, transaction_dir: &Path) -> Result<PathBuf> {
        let snapshot = transaction_dir.join("snapshot");
        fs::create_dir_all(&snapshot)?;
        snapshot_file(&self.paths.site, &snapshot, "site")?;
        snapshot_enabled(&self.paths.enabled, &snapshot)?;
        Ok(snapshot)
    }

    fn restore_owned_files(&self, snapshot: &Path) -> Result<()> {
        restore_file(&self.paths.site, snapshot, "site")?;
        remove_non_directory(&self.paths.enabled)?;
        if snapshot.join("enabled.link").is_file() {
            let target = fs::read_to_string(snapshot.join("enabled.link"))?;
            if target.is_empty() || target.contains('\0') {
                bail!("subscription symlink snapshot is invalid");
            }
            std::os::unix::fs::symlink(target, &self.paths.enabled)?;
        } else if snapshot.join("enabled.file").is_file() {
            atomic_copy(&snapshot.join("enabled.file"), &self.paths.enabled, 0o644)?;
        } else if !snapshot.join("enabled.absent").is_file() {
            bail!("subscription enabled-site snapshot is incomplete");
        }
        Ok(())
    }
}

impl CoreAdapter for SubscriptionFrontendAdapter {
    fn manifest(&self) -> &CoreAdapterManifest {
        &self.manifest
    }

    fn installed(&self) -> Result<bool> {
        Ok(Path::new("/usr/sbin/nginx").is_file())
    }

    fn stage_config(&self, plan: &CorePlan, transaction_dir: &Path) -> Result<PathBuf> {
        let candidate = transaction_dir.join("subscription.conf");
        if let Some(domain) = self.domain(plan)? {
            self.validate_certificate(domain)?;
            self.reject_duplicate_server_name(domain)?;
        }
        fs::write(&candidate, self.render_site(plan)?)?;
        Ok(candidate)
    }

    fn validate_config(&self, candidate: &Path) -> Result<()> {
        if fs::metadata(candidate)?.len() == 0 {
            return Ok(());
        }
        Self::nginx_test(candidate)
    }

    fn snapshot_config(&self, transaction_dir: &Path) -> Result<CoreSnapshot> {
        Ok(CoreSnapshot {
            path: self.snapshot_owned_files(transaction_dir)?,
            service_was_enabled: systemctl_is("is-enabled", "nginx.service"),
            service_was_active: systemctl_is("is-active", "nginx.service"),
        })
    }

    fn install_config(&self, candidate: &Path) -> Result<()> {
        if fs::metadata(candidate)?.len() == 0 {
            remove_non_directory(&self.paths.enabled)?;
            remove_non_directory(&self.paths.site)?;
            return Ok(());
        }
        self.atomic_site_install(candidate)?;
        fs::create_dir_all(&self.paths.enabled_directory)?;
        self.install_enabled_link()
    }

    fn activate_config(&self, _plan: &CorePlan) -> Result<()> {
        systemctl(&["enable"], "nginx.service")?;
        if systemctl_is("is-active", "nginx.service") {
            reload_nginx()
        } else {
            systemctl(&["start"], "nginx.service")
        }
    }

    fn healthcheck(&self, plan: &CorePlan) -> Result<()> {
        let domain = self
            .domain(plan)?
            .context("subscription resource is absent")?;
        self.validate_certificate(domain)?;
        if !systemctl_is("is-active", "nginx.service") {
            bail!("nginx service is not active");
        }
        let started = Instant::now();
        wait_for_subscription_readiness(
            SUBSCRIPTION_READY_TIMEOUT,
            SUBSCRIPTION_READY_POLL_INTERVAL,
            |remaining| {
                subscription_readiness_command(domain, remaining)
                    .status()
                    .is_ok_and(|status| status.success())
            },
            || started.elapsed(),
            thread::sleep,
        )
    }

    fn verify_listeners(&self, plan: &CorePlan) -> Result<()> {
        if plan.fragments.is_empty() {
            Ok(())
        } else {
            verify_tcp_listeners(&[80, 443])
        }
    }

    fn rollback_config(&self, snapshot: &CoreSnapshot) -> Result<()> {
        self.restore_owned_files(&snapshot.path)?;
        validate_restored_nginx_site_with(
            Path::new("/usr/sbin/nginx"),
            &self.paths.site,
            &snapshot.path.join("nginx-rollback-validation"),
        )?;
        restore_service_state(snapshot, "nginx.service")
    }
}

pub(super) struct NodeReadinessAdapter {
    manifest: CoreAdapterManifest,
}

impl NodeReadinessAdapter {
    pub(super) fn new() -> Self {
        Self {
            manifest: CoreAdapterManifest {
                api_version: ADAPTER_API_VERSION,
                id: NODE_ADAPTER_ID.to_string(),
                display_name: "Proxy node DNS readiness".to_string(),
                capabilities: BTreeSet::from([NODE_ADAPTER_ID.to_string()]),
                service: "network-online.target".to_string(),
                selection_priority: 0,
            },
        }
    }

    fn domain<'a>(&self, plan: &'a CorePlan) -> Result<Option<&'a str>> {
        if plan.fragments.is_empty() {
            return Ok(None);
        }
        if plan.fragments.len() != 1 {
            bail!("node readiness adapter supports one desired resource");
        }
        let domain = plan.fragments[0]
            .payload
            .get("node_domain")
            .and_then(Value::as_str)
            .context("node domain is missing")?;
        validate_domain(domain)?;
        Ok(Some(domain))
    }
}

impl CoreAdapter for NodeReadinessAdapter {
    fn manifest(&self) -> &CoreAdapterManifest {
        &self.manifest
    }

    fn installed(&self) -> Result<bool> {
        Ok(Path::new("/usr/bin/getent").is_file())
    }

    fn stage_config(&self, plan: &CorePlan, transaction_dir: &Path) -> Result<PathBuf> {
        let candidate = transaction_dir.join("node-domain");
        fs::write(&candidate, self.domain(plan)?.unwrap_or_default())?;
        Ok(candidate)
    }

    fn validate_config(&self, candidate: &Path) -> Result<()> {
        let value = fs::read_to_string(candidate)?;
        if !value.is_empty() {
            validate_domain(&value)?;
        }
        Ok(())
    }

    fn snapshot_config(&self, transaction_dir: &Path) -> Result<CoreSnapshot> {
        let snapshot = transaction_dir.join("snapshot");
        fs::create_dir_all(&snapshot)?;
        Ok(CoreSnapshot {
            path: snapshot,
            service_was_enabled: false,
            service_was_active: false,
        })
    }

    fn install_config(&self, _candidate: &Path) -> Result<()> {
        Ok(())
    }
    fn activate_config(&self, _plan: &CorePlan) -> Result<()> {
        Ok(())
    }

    fn healthcheck(&self, plan: &CorePlan) -> Result<()> {
        let domain = self.domain(plan)?.context("node resource is absent")?;
        let resolution = Command::new("/usr/bin/getent")
            .args(["ahosts", domain])
            .output()?;
        if !resolution.status.success() || resolution.stdout.is_empty() {
            bail!("node domain does not resolve");
        }
        Ok(())
    }

    fn verify_listeners(&self, _plan: &CorePlan) -> Result<()> {
        Ok(())
    }
    fn rollback_config(&self, _snapshot: &CoreSnapshot) -> Result<()> {
        Ok(())
    }
}

fn nginx_server_names(content: &str) -> BTreeSet<String> {
    let uncommented = content
        .lines()
        .map(|line| line.split('#').next().unwrap_or_default())
        .collect::<Vec<_>>()
        .join(" ");
    let mut names = BTreeSet::new();
    for statement in uncommented.split(';') {
        let fields = statement.split_whitespace().collect::<Vec<_>>();
        if let Some(index) = fields.iter().position(|field| *field == "server_name") {
            names.extend(fields[index + 1..].iter().map(|name| (*name).to_string()));
        }
    }
    names
}

fn validate_letsencrypt_material(path: &Path, domain: &str, archive_root: &Path) -> Result<()> {
    let resolved = fs::canonicalize(path)
        .with_context(|| format!("TLS material is not provisioned for {domain}"))?;
    let expected_root = fs::canonicalize(archive_root.join(domain))
        .with_context(|| format!("TLS archive is not provisioned for {domain}"))?;
    if !resolved.starts_with(expected_root) {
        bail!("TLS material resolves outside the expected certificate archive");
    }
    let metadata = fs::metadata(&resolved)?;
    if !metadata.file_type().is_file() || metadata.len() == 0 {
        bail!("TLS material is not a non-empty regular file");
    }
    if metadata.uid() != 0 || metadata.permissions().mode() & 0o022 != 0 {
        bail!("TLS material has unsafe ownership or write permissions");
    }
    Ok(())
}

fn atomic_copy(source: &Path, destination: &Path, mode: u32) -> Result<()> {
    let parent = destination.parent().context("destination has no parent")?;
    fs::create_dir_all(parent)?;
    let temporary = parent.join(format!(".infiproxy-{}.tmp", uuid::Uuid::new_v4()));
    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(mode)
            .open(&temporary)?;
        file.write_all(&fs::read(source)?)?;
        file.sync_all()?;
        fs::set_permissions(&temporary, fs::Permissions::from_mode(mode))?;
        fs::rename(&temporary, destination)?;
        fs::File::open(parent)?.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(temporary);
    }
    result
}

fn snapshot_file(path: &Path, snapshot: &Path, name: &str) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata)
            if metadata.file_type().is_file() && metadata.len() <= MAX_NGINX_SITE_BYTES =>
        {
            fs::copy(path, snapshot.join(name))?;
        }
        Ok(_) => bail!("owned Nginx site must be a regular file"),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            fs::write(snapshot.join(format!("{name}.absent")), [])?;
        }
        Err(error) => return Err(error.into()),
    }
    Ok(())
}

fn snapshot_enabled(path: &Path, snapshot: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            let target = fs::read_link(path)?;
            let target = target
                .to_str()
                .context("owned enabled-site symlink is not valid UTF-8")?;
            fs::write(snapshot.join("enabled.link"), target.as_bytes())?;
        }
        Ok(metadata)
            if metadata.file_type().is_file() && metadata.len() <= MAX_NGINX_SITE_BYTES =>
        {
            fs::copy(path, snapshot.join("enabled.file"))?;
        }
        Ok(_) => bail!("owned enabled-site path has an unsupported file type"),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            fs::write(snapshot.join("enabled.absent"), [])?;
        }
        Err(error) => return Err(error.into()),
    }
    Ok(())
}

fn restore_file(path: &Path, snapshot: &Path, name: &str) -> Result<()> {
    if snapshot.join(name).is_file() {
        atomic_copy(&snapshot.join(name), path, 0o644)
    } else if snapshot.join(format!("{name}.absent")).is_file() {
        remove_non_directory(path)
    } else {
        bail!("owned Nginx snapshot is incomplete")
    }
}

fn remove_non_directory(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if !metadata.file_type().is_dir() => fs::remove_file(path)?,
        Ok(_) => bail!("refusing to remove a directory through an owned file path"),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    Ok(())
}

fn systemctl(arguments: &[&str], service: &str) -> Result<()> {
    let status = Command::new("/usr/bin/systemctl")
        .args(arguments)
        .arg(service)
        .status()?;
    if !status.success() {
        bail!("service operation failed");
    }
    Ok(())
}

fn systemctl_is(property: &str, service: &str) -> bool {
    Command::new("/usr/bin/systemctl")
        .args([property, "--quiet", service])
        .status()
        .is_ok_and(|status| status.success())
}

fn reload_nginx() -> Result<()> {
    systemctl(&["reload"], "nginx.service")
}

fn restore_service_state(snapshot: &CoreSnapshot, service: &str) -> Result<()> {
    systemctl(
        &[if snapshot.service_was_enabled {
            "enable"
        } else {
            "disable"
        }],
        service,
    )?;
    if snapshot.service_was_active {
        systemctl(&["restart"], service)?;
        if !systemctl_is("is-active", service) {
            bail!("restored service is not active");
        }
    } else {
        systemctl(&["stop"], service)?;
    }
    Ok(())
}

fn verify_tcp_listeners(ports: &[u16]) -> Result<()> {
    let output = Command::new("/usr/bin/ss").args(["-H", "-ltn"]).output()?;
    let listeners = String::from_utf8(output.stdout)?;
    if !ports.iter().all(|port| {
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

/// Converts panel settings into independently owned desired resources.
#[must_use]
pub fn desired_resources(settings: &PanelSettings) -> Vec<InfrastructureResource> {
    let mut resources = Vec::new();
    if !settings.subscription_domain.ends_with(".local") {
        let resource = |resource_id: &str,
                        kind: InfrastructureResourceKind,
                        dependencies: &[&str],
                        listeners: Vec<ListenerClaim>,
                        config: Value| InfrastructureResource {
            resource_id: resource_id.to_string(),
            adapter_id: SUBSCRIPTION_ADAPTER_ID.to_string(),
            schema_version: 1,
            enabled: true,
            kind,
            dependencies: dependencies.iter().map(ToString::to_string).collect(),
            listeners,
            config,
        };
        resources.extend([
            resource(
                "subscription-domain",
                InfrastructureResourceKind::Domain,
                &[],
                Vec::new(),
                json!({"subscription_domain": settings.subscription_domain}),
            ),
            resource(
                "subscription-certificate",
                InfrastructureResourceKind::Certificate,
                &["subscription-domain"],
                Vec::new(),
                json!({"issuer":"letsencrypt","domain_ref":"subscription-domain"}),
            ),
            resource(
                "subscription-decoy",
                InfrastructureResourceKind::DecoyTarget,
                &[],
                Vec::new(),
                json!({"mode":"not-found"}),
            ),
            resource(
                "subscription-port",
                InfrastructureResourceKind::PortAllocation,
                &[],
                Vec::new(),
                json!({"network":"tcp","port":443}),
            ),
            resource(
                "subscription-listener",
                InfrastructureResourceKind::Listener,
                &["subscription-port"],
                vec![ListenerClaim {
                    network: ListenerNetwork::Tcp,
                    port: 443,
                }],
                json!({"address":"0.0.0.0","network":"tcp","port":443}),
            ),
            resource(
                "subscription-frontend",
                InfrastructureResourceKind::TlsFrontend,
                &[
                    "subscription-domain",
                    "subscription-certificate",
                    "subscription-decoy",
                    "subscription-listener",
                ],
                Vec::new(),
                json!({"owner":"subscription-frontend"}),
            ),
        ]);
    }
    if !settings.node_domain.ends_with(".local") {
        resources.push(InfrastructureResource {
            resource_id: "node-readiness".to_string(),
            adapter_id: NODE_ADAPTER_ID.to_string(),
            schema_version: 1,
            enabled: true,
            kind: InfrastructureResourceKind::Domain,
            dependencies: Vec::new(),
            listeners: Vec::new(),
            config: json!({"node_domain": settings.node_domain}),
        });
    }
    resources
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_adapter(root: &Path) -> SubscriptionFrontendAdapter {
        SubscriptionFrontendAdapter {
            manifest: SubscriptionFrontendAdapter::new().manifest,
            paths: SubscriptionPaths {
                site: root.join("sites-available/infiproxy-subscription.conf"),
                enabled: root.join("sites-enabled/infiproxy-subscription.conf"),
                enabled_directory: root.join("sites-enabled"),
                letsencrypt_live: root.join("letsencrypt/live"),
                letsencrypt_archive: root.join("letsencrypt/archive"),
            },
        }
    }

    fn plan(domain: &str) -> CorePlan {
        CorePlan {
            generation: 1,
            core_id: SUBSCRIPTION_ADAPTER_ID.to_string(),
            fragments: vec![crate::adapter::ServerFragment {
                profile_id: SUBSCRIPTION_ADAPTER_ID.to_string(),
                capability: SUBSCRIPTION_ADAPTER_ID.to_string(),
                payload: json!({"subscription_domain": domain}),
                expected_user_ids: None,
                listeners: Vec::new(),
            }],
        }
    }

    #[test]
    fn generated_frontend_has_explicit_public_routes() {
        let site = SubscriptionFrontendAdapter::new()
            .render_site(&plan("siberia.example.test"))
            .unwrap();
        assert!(site.contains("location ^~ /sub/"));
        assert!(site.contains("location ^~ /rules/"));
        assert!(site.contains("location = /ready"));
        assert!(site.contains("location / {\n        return 404;"));
        assert!(site.find("location = /ready").unwrap() < site.find("location / {").unwrap());
        assert!(!site.contains("nexus.example.test"));
        assert!(!site.contains("node.example.test"));
    }

    #[test]
    fn subscription_readiness_succeeds_immediately() {
        let probes = std::cell::Cell::new(0);
        let waits = std::cell::Cell::new(0);
        wait_for_subscription_readiness(
            Duration::from_millis(500),
            Duration::from_millis(100),
            |_| {
                probes.set(probes.get() + 1);
                true
            },
            || Duration::ZERO,
            |_| waits.set(waits.get() + 1),
        )
        .unwrap();
        assert_eq!(probes.get(), 1);
        assert_eq!(waits.get(), 0);
    }

    #[test]
    fn subscription_readiness_retries_http_failures_until_success() {
        let elapsed = std::cell::Cell::new(Duration::ZERO);
        let probes = std::cell::Cell::new(0);
        wait_for_subscription_readiness(
            Duration::from_millis(500),
            Duration::from_millis(100),
            |_| {
                let observation = probes.get() + 1;
                probes.set(observation);
                observation == 3
            },
            || elapsed.get(),
            |duration| elapsed.set(elapsed.get() + duration),
        )
        .unwrap();
        assert_eq!(probes.get(), 3);
        assert_eq!(elapsed.get(), Duration::from_millis(200));
    }

    #[test]
    fn subscription_readiness_fails_after_bounded_exhaustion() {
        let elapsed = std::cell::Cell::new(Duration::ZERO);
        let probes = std::cell::Cell::new(0);
        let result = wait_for_subscription_readiness(
            Duration::from_millis(250),
            Duration::from_millis(100),
            |_| {
                probes.set(probes.get() + 1);
                false
            },
            || elapsed.get(),
            |duration| elapsed.set(elapsed.get() + duration),
        );
        assert!(result.is_err());
        assert_eq!(probes.get(), 3);
        assert_eq!(elapsed.get(), Duration::from_millis(250));
    }

    #[test]
    fn subscription_probe_preserves_loopback_tls_hostname_verification() {
        let command =
            subscription_readiness_command("siberia.example.test", Duration::from_secs(5));
        let arguments = command
            .get_args()
            .map(|argument| argument.to_string_lossy().into_owned())
            .collect::<Vec<_>>();

        assert_eq!(command.get_program(), Path::new("/usr/bin/curl"));
        assert!(arguments
            .windows(2)
            .any(|pair| { pair == ["--resolve", "siberia.example.test:443:127.0.0.1"] }));
        assert!(arguments.contains(&"https://siberia.example.test/ready".to_string()));
        assert!(arguments.contains(&"--fail".to_string()));
        assert!(!arguments.iter().any(|argument| {
            argument == "--insecure" || argument == "-k" || argument == "--http0.9"
        }));
    }

    #[test]
    fn staged_nginx_validation_uses_only_transaction_local_writable_paths() -> Result<()> {
        let root = std::env::temp_dir().join(format!("infiproxy-nginx-{}", uuid::Uuid::new_v4()));
        let candidate = root.join("subscription.conf");
        fs::create_dir(&root)?;
        fs::write(&candidate, "server { listen 443; }")?;
        let paths = NginxTestPaths::new(&candidate)?;
        paths.prepare()?;
        let config = paths.render_config();

        assert!(config.contains(&format!("pid {};", root.join("nginx.pid").display())));
        assert!(config.contains("error_log stderr;"));
        assert!(config.contains("access_log off;"));
        assert!(config.contains(&format!("include {};", candidate.display())));
        assert!(config.contains("include /etc/nginx/mime.types;"));
        for (directive, directory) in NGINX_TEST_TEMP_DIRECTORIES {
            let temp = paths.runtime().join(directory);
            assert!(config.contains(&format!("{directive} {};", temp.display())));
            assert!(temp.is_dir());
            assert_eq!(fs::metadata(temp)?.permissions().mode() & 0o777, 0o700);
        }
        assert!(!config.contains("/var/lib/nginx"));
        assert!(!config.contains("/var/log/nginx"));
        assert_eq!(
            fs::metadata(paths.runtime())?.permissions().mode() & 0o777,
            0o700
        );

        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn staged_nginx_validation_rejects_path_injection_and_native_test_failure() -> Result<()> {
        let root = std::env::temp_dir().join(format!("infiproxy-nginx-{}", uuid::Uuid::new_v4()));
        fs::create_dir(&root)?;
        assert!(NginxTestPaths::new(&root.join("bad;name/subscription.conf")).is_err());
        assert!(NginxTestPaths::new(&root.join("../escape/subscription.conf")).is_err());
        assert!(NginxTestPaths::new(&root.join("other.conf")).is_err());
        let candidate = root.join("subscription.conf");
        fs::write(&candidate, "server { listen 443; }")?;
        let paths = NginxTestPaths::new(&candidate)?;
        paths.prepare()?;
        fs::write(paths.config(), paths.render_config())?;
        assert!(run_nginx_candidate_test(Path::new("/usr/bin/false"), &paths).is_err());
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn rollback_nginx_validation_uses_the_restored_site_and_local_runtime() -> Result<()> {
        let root = std::env::temp_dir().join(format!("infiproxy-nginx-{}", uuid::Uuid::new_v4()));
        let site = root.join("sites-available/infiproxy-subscription.conf");
        let validation = root.join("transaction/snapshot/nginx-rollback-validation");
        fs::create_dir_all(site.parent().unwrap())?;
        fs::write(&site, "server { listen 443 ssl; }")?;

        validate_restored_nginx_site_with(Path::new("/usr/bin/true"), &site, &validation)?;

        let candidate = validation.join("subscription.conf");
        assert_eq!(fs::read(&candidate)?, fs::read(&site)?);
        let config = fs::read_to_string(validation.join("nginx-test.conf"))?;
        assert!(config.contains(&format!("include {};", candidate.display())));
        assert!(!config.contains("/var/log/nginx"));
        assert!(!config.contains("/var/lib/nginx"));
        assert_eq!(
            fs::metadata(&validation)?.permissions().mode() & 0o777,
            0o700
        );

        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn rollback_nginx_validation_fails_closed_on_native_test_failure() -> Result<()> {
        let root = std::env::temp_dir().join(format!("infiproxy-nginx-{}", uuid::Uuid::new_v4()));
        let site = root.join("sites-available/infiproxy-subscription.conf");
        let validation = root.join("transaction/snapshot/nginx-rollback-validation");
        fs::create_dir_all(site.parent().unwrap())?;
        fs::write(&site, "invalid restored configuration")?;

        assert!(
            validate_restored_nginx_site_with(Path::new("/usr/bin/false"), &site, &validation,)
                .is_err()
        );

        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn duplicate_server_name_is_rejected_before_owned_files_change() -> Result<()> {
        let root = std::env::temp_dir().join(format!("infiproxy-nginx-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(root.join("sites-enabled"))?;
        let adapter = test_adapter(&root);
        let admin = root.join("sites-enabled/admin.conf");
        fs::write(
            &admin,
            "server { server_name nexus.example.test siberia.example.test; }",
        )?;
        fs::create_dir_all(adapter.paths.site.parent().unwrap())?;
        fs::write(&adapter.paths.site, "old-subscription-bytes")?;
        assert!(adapter
            .reject_duplicate_server_name("siberia.example.test")
            .is_err());
        assert_eq!(
            fs::read(&admin)?,
            b"server { server_name nexus.example.test siberia.example.test; }"
        );
        assert_eq!(fs::read(&adapter.paths.site)?, b"old-subscription-bytes");
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn install_and_restore_touch_only_subscription_owned_files() -> Result<()> {
        let root = std::env::temp_dir().join(format!("infiproxy-nginx-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(root.join("sites-available"))?;
        fs::create_dir_all(root.join("sites-enabled"))?;
        let adapter = test_adapter(&root);
        let admin = root.join("sites-available/infiproxy.conf");
        let unrelated = root.join("sites-enabled/unrelated.conf");
        fs::write(&admin, "admin-byte-for-byte")?;
        fs::write(&unrelated, "unrelated-byte-for-byte")?;
        fs::write(&adapter.paths.site, "subscription-before")?;
        std::os::unix::fs::symlink(&adapter.paths.site, &adapter.paths.enabled)?;
        let snapshot = adapter.snapshot_owned_files(&root.join("transaction"))?;
        let candidate = root.join("candidate.conf");
        fs::write(&candidate, "subscription-after")?;
        adapter.atomic_site_install(&candidate)?;
        adapter.install_enabled_link()?;
        assert_eq!(fs::read(&admin)?, b"admin-byte-for-byte");
        assert_eq!(fs::read(&unrelated)?, b"unrelated-byte-for-byte");
        adapter.restore_owned_files(&snapshot)?;
        assert_eq!(fs::read(&adapter.paths.site)?, b"subscription-before");
        assert_eq!(fs::read(&admin)?, b"admin-byte-for-byte");
        assert_eq!(fs::read(&unrelated)?, b"unrelated-byte-for-byte");
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn missing_certificate_fails_before_live_mutation() -> Result<()> {
        let root = std::env::temp_dir().join(format!("infiproxy-nginx-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(root.join("sites-available"))?;
        fs::create_dir_all(root.join("sites-enabled"))?;
        let adapter = test_adapter(&root);
        fs::write(&adapter.paths.site, "known-good-live-config")?;
        let transaction = root.join("transaction");
        fs::create_dir_all(&transaction)?;
        assert!(adapter
            .stage_config(&plan("siberia.example.test"), &transaction)
            .is_err());
        assert_eq!(fs::read(&adapter.paths.site)?, b"known-good-live-config");
        assert!(!transaction.join("subscription.conf").exists());
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn desired_frontends_have_independent_resource_identity() {
        let settings = PanelSettings {
            subscription_domain: "siberia.example.test".to_string(),
            node_domain: "node.example.test".to_string(),
            ..PanelSettings::default()
        };
        let resources = desired_resources(&settings);
        assert_eq!(resources.len(), 7);
        assert!(resources[..6]
            .iter()
            .all(|resource| resource.adapter_id == SUBSCRIPTION_ADAPTER_ID));
        assert_eq!(resources[6].adapter_id, NODE_ADAPTER_ID);
    }

    #[test]
    fn domains_are_strictly_validated() {
        assert!(validate_domain("siberia.example.test").is_ok());
        assert!(validate_domain("bad name.example").is_err());
        assert!(validate_domain("-bad.example").is_err());
        assert!(validate_domain("../../etc/passwd").is_err());
    }
}
