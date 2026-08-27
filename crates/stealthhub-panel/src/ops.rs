//! Host operations used by the web panel.
//!
//! This module centralizes service metadata, config-file allowlists, bounded
//! command execution, uninstall runbooks and host metrics. Keeping these helpers
//! outside route handlers makes dangerous behavior easier to audit.

use std::{
    collections::HashMap,
    fs::{self, OpenOptions},
    io::{self, Write},
    path::Path,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

const CONFIG_BACKUP_RETENTION_COUNT: usize = 20;

pub(crate) const SYSTEM_TARGETS: &[SystemTarget] = &[
    SystemTarget {
        name: "Panel service",
        kind: "systemd",
        unit: "infiproxy.service",
        units: &["infiproxy.service"],
        config: "/etc/infiproxy/infiproxy.env",
        check: "systemctl status infiproxy.service",
        reload: "systemctl restart infiproxy.service",
    },
    SystemTarget {
        name: "SSH daemon",
        kind: "host",
        unit: "ssh.service / sshd.service",
        units: &["ssh.service", "sshd.service"],
        config: "/etc/ssh/sshd_config",
        check: "sshd -t && systemctl status ssh || systemctl status sshd",
        reload: "sshd -t && systemctl reload ssh || systemctl reload sshd",
    },
    SystemTarget {
        name: "Nginx reverse proxy",
        kind: "host",
        unit: "nginx.service",
        units: &["nginx.service"],
        config: "/etc/nginx/sites-available/infiproxy.conf",
        check: "nginx -t && systemctl status nginx.service",
        reload: "nginx -t && systemctl reload nginx.service",
    },
    SystemTarget {
        name: "Firewall",
        kind: "host",
        unit: "ufw / nftables",
        units: &["ufw.service", "nftables.service"],
        config: "/etc/ufw / /etc/nftables.conf",
        check: "ufw status verbose || nft list ruleset",
        reload: "ufw reload || systemctl reload nftables.service",
    },
];
#[derive(Debug, Clone, Copy)]
pub(crate) struct SystemTarget {
    pub(crate) name: &'static str,
    pub(crate) kind: &'static str,
    pub(crate) unit: &'static str,
    pub(crate) units: &'static [&'static str],
    pub(crate) config: &'static str,
    pub(crate) check: &'static str,
    pub(crate) reload: &'static str,
}

pub(crate) const CONFIG_FILES: &[StaticConfigFileSpec] = &[
    StaticConfigFileSpec {
        slug: "panel-env",
        name: "Panel environment",
        category: "panel",
        path: "/etc/infiproxy/infiproxy.env",
        syntax: "dotenv",
        description: "Bind address, database URL, cookie security and runtime flags.",
        validate_hint: "Restart panel after saving; invalid env values can stop startup.",
        reload_hint: "systemctl restart infiproxy.service",
        max_bytes: 16 * 1024,
        editable: false,
    },
    StaticConfigFileSpec {
        slug: "nginx-site",
        name: "Nginx reverse proxy",
        category: "edge",
        path: "/etc/nginx/sites-available/infiproxy.conf",
        syntax: "nginx",
        description: "HTTPS edge, localhost proxying and public exposure rules.",
        validate_hint: "nginx -t",
        reload_hint: "systemctl reload nginx.service",
        max_bytes: 64 * 1024,
        editable: false,
    },
    StaticConfigFileSpec {
        slug: "ssh-daemon",
        name: "SSH daemon",
        category: "host",
        path: "/etc/ssh/sshd_config",
        syntax: "sshd_config",
        description: "Administrative SSH access. Validate before reload to avoid lockout.",
        validate_hint: "sshd -t",
        reload_hint: "systemctl reload ssh.service",
        max_bytes: 64 * 1024,
        editable: false,
    },
];

#[derive(Debug, Clone, Copy)]
pub(crate) struct StaticConfigFileSpec {
    pub(crate) slug: &'static str,
    pub(crate) name: &'static str,
    pub(crate) category: &'static str,
    pub(crate) path: &'static str,
    pub(crate) syntax: &'static str,
    pub(crate) description: &'static str,
    pub(crate) validate_hint: &'static str,
    pub(crate) reload_hint: &'static str,
    pub(crate) max_bytes: usize,
    pub(crate) editable: bool,
}

#[derive(Debug, Clone)]
pub(crate) struct ConfigFileSpec {
    pub(crate) slug: String,
    pub(crate) name: String,
    pub(crate) category: String,
    pub(crate) path: String,
    pub(crate) syntax: String,
    pub(crate) description: String,
    pub(crate) validate_hint: String,
    pub(crate) reload_hint: String,
    pub(crate) max_bytes: usize,
    pub(crate) editable: bool,
}

impl From<StaticConfigFileSpec> for ConfigFileSpec {
    fn from(spec: StaticConfigFileSpec) -> Self {
        Self {
            slug: spec.slug.to_string(),
            name: spec.name.to_string(),
            category: spec.category.to_string(),
            path: spec.path.to_string(),
            syntax: spec.syntax.to_string(),
            description: spec.description.to_string(),
            validate_hint: spec.validate_hint.to_string(),
            reload_hint: spec.reload_hint.to_string(),
            max_bytes: spec.max_bytes,
            editable: spec.editable,
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct ConfigFileSnapshot {
    pub(crate) spec: ConfigFileSpec,
    pub(crate) exists: bool,
    pub(crate) bytes: u64,
    pub(crate) content: String,
    pub(crate) status: String,
}

#[derive(Debug, Clone)]
pub(crate) struct ConfigWriteReport {
    pub(crate) spec: ConfigFileSpec,
    pub(crate) success: bool,
    pub(crate) message: String,
    pub(crate) backup_path: Option<String>,
}

pub(crate) fn config_files() -> Vec<ConfigFileSpec> {
    let mut specs = CONFIG_FILES
        .iter()
        .copied()
        .map(ConfigFileSpec::from)
        .collect::<Vec<_>>();
    let existing_paths = specs
        .iter()
        .map(|spec| spec.path.clone())
        .collect::<std::collections::HashSet<_>>();
    if let Ok(modules) = crate::modules::registry() {
        specs.extend(
            modules
                .into_iter()
                .filter(|module| !existing_paths.contains(&module.config_path))
                .map(|module| ConfigFileSpec {
                    slug: format!("module-{}", module.id),
                    name: module.name,
                    category: module.kind,
                    syntax: config_syntax(&module.config_path).to_string(),
                    description: format!("{} module runtime configuration.", module.role),
                    validate_hint: "Run the module-specific validation before restart.".to_string(),
                    reload_hint: format!("systemctl restart {}", module.service),
                    editable: false,
                    path: module.config_path,
                    max_bytes: 256 * 1024,
                }),
        );
    }
    specs
}

pub(crate) fn config_file_by_slug(slug: &str) -> Option<ConfigFileSpec> {
    config_files().into_iter().find(|spec| spec.slug == slug)
}

fn config_syntax(path: &str) -> &'static str {
    match Path::new(path).extension().and_then(|value| value.to_str()) {
        Some("json") => "json",
        Some("yaml" | "yml") => "yaml",
        Some("toml") => "toml",
        Some("env") => "dotenv",
        _ => "text",
    }
}

pub(crate) fn read_config_spec(spec: ConfigFileSpec) -> ConfigFileSnapshot {
    let path = Path::new(&spec.path);
    if path_has_symlink_component(path) {
        return ConfigFileSnapshot {
            spec,
            exists: true,
            bytes: 0,
            content: String::new(),
            status: "symlinked config paths are not allowed".to_string(),
        };
    }
    let Ok(metadata) = fs::symlink_metadata(path) else {
        return ConfigFileSnapshot {
            spec,
            exists: false,
            bytes: 0,
            content: String::new(),
            status: "file does not exist yet".to_string(),
        };
    };

    if !metadata.is_file() {
        return ConfigFileSnapshot {
            spec,
            exists: true,
            bytes: metadata.len(),
            content: String::new(),
            status: "path is not a regular file".to_string(),
        };
    }

    if metadata.len() > spec.max_bytes as u64 {
        let status = format!(
            "file is larger than the {} byte editor limit",
            spec.max_bytes
        );
        return ConfigFileSnapshot {
            spec,
            exists: true,
            bytes: metadata.len(),
            content: String::new(),
            status,
        };
    }

    match fs::read_to_string(path) {
        Ok(content) => ConfigFileSnapshot {
            spec,
            exists: true,
            bytes: metadata.len(),
            content,
            status: "ready".to_string(),
        },
        Err(err) => ConfigFileSnapshot {
            spec,
            exists: true,
            bytes: metadata.len(),
            content: String::new(),
            status: format!("read failed: {err}"),
        },
    }
}

pub(crate) fn write_config_file(slug: &str, content: &str) -> ConfigWriteReport {
    let Some(spec) = config_file_by_slug(slug) else {
        return ConfigWriteReport {
            spec: CONFIG_FILES[0].into(),
            success: false,
            message: "unknown config target".to_string(),
            backup_path: None,
        };
    };

    if !spec.editable {
        return ConfigWriteReport {
            spec,
            success: false,
            message:
                "this root-owned config is read-only in the web panel; use sudo infiproxy-manager"
                    .to_string(),
            backup_path: None,
        };
    }

    if content.len() > spec.max_bytes {
        let message = format!(
            "content is larger than the {} byte editor limit",
            spec.max_bytes
        );
        return ConfigWriteReport {
            spec,
            success: false,
            message,
            backup_path: None,
        };
    }

    if content.contains('\0') {
        return ConfigWriteReport {
            spec,
            success: false,
            message: "content contains NUL bytes".to_string(),
            backup_path: None,
        };
    }

    if let Err(err) = validate_config_content(&spec.syntax, content) {
        return ConfigWriteReport {
            spec,
            success: false,
            message: format!("syntax validation failed: {err}"),
            backup_path: None,
        };
    }

    let path = Path::new(&spec.path);
    if path_has_symlink_component(path) {
        return ConfigWriteReport {
            spec,
            success: false,
            message: "symlinked config paths are not allowed".to_string(),
            backup_path: None,
        };
    }
    let backup_path = if path.exists() {
        match backup_config_file(path) {
            Ok(value) => Some(value),
            Err(err) => {
                return ConfigWriteReport {
                    spec,
                    success: false,
                    message: format!("backup failed: {err}"),
                    backup_path: None,
                };
            }
        }
    } else {
        None
    };

    match atomic_write(path, content.as_bytes()) {
        Ok(()) => ConfigWriteReport {
            spec,
            success: true,
            message: "saved".to_string(),
            backup_path,
        },
        Err(err) => ConfigWriteReport {
            spec,
            success: false,
            message: format!("write failed: {err}"),
            backup_path,
        },
    }
}

fn validate_config_content(syntax: &str, content: &str) -> Result<(), String> {
    match syntax {
        "json" => serde_json::from_str::<serde_json::Value>(content)
            .map(|_| ())
            .map_err(|error| error.to_string()),
        "yaml" => serde_norway::from_str::<serde_norway::Value>(content)
            .map(|_| ())
            .map_err(|error| error.to_string()),
        "dotenv" => {
            for (index, line) in content.lines().enumerate() {
                let line = line.trim();
                if line.is_empty() || line.starts_with('#') {
                    continue;
                }
                let Some((key, _)) = line.split_once('=') else {
                    return Err(format!("line {} has no '=' separator", index + 1));
                };
                if key.is_empty()
                    || !key
                        .chars()
                        .all(|ch| ch.is_ascii_alphanumeric() || ch == '_')
                {
                    return Err(format!("line {} has an invalid variable name", index + 1));
                }
            }
            Ok(())
        }
        "toml" => toml::from_str::<toml::Value>(content)
            .map(|_| ())
            .map_err(|error| error.to_string()),
        _ => Ok(()),
    }
}

fn atomic_write(path: &Path, content: &[u8]) -> io::Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "config has no parent"))?;
    let file_name = path
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invalid config file name"))?;
    let suffix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |value| value.as_nanos());
    let temporary = parent.join(format!(".{file_name}.infiproxy-{suffix}.tmp"));
    let original_permissions = fs::metadata(path)
        .ok()
        .map(|metadata| metadata.permissions());

    let result = (|| {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&temporary)?;
        file.write_all(content)?;
        file.sync_all()?;
        if let Some(permissions) = original_permissions {
            fs::set_permissions(&temporary, permissions)?;
        }
        fs::rename(&temporary, path)?;
        fs::File::open(parent)?.sync_all()?;
        Ok(())
    })();

    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

fn path_has_symlink_component(path: &Path) -> bool {
    path.ancestors()
        .take_while(|component| !component.as_os_str().is_empty())
        .any(|component| {
            fs::symlink_metadata(component).is_ok_and(|metadata| metadata.file_type().is_symlink())
        })
}

fn backup_config_file(path: &Path) -> std::io::Result<String> {
    let suffix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |value| value.as_millis());
    let backup = path.with_extension(format!(
        "{}.infiproxy-bak-{suffix}",
        path.extension()
            .and_then(|value| value.to_str())
            .unwrap_or("bak")
    ));

    fs::copy(path, &backup)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&backup, fs::Permissions::from_mode(0o600))?;
    }
    prune_config_backups(path, CONFIG_BACKUP_RETENTION_COUNT)?;
    Ok(backup.display().to_string())
}

fn prune_config_backups(path: &Path, retain: usize) -> io::Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "config has no parent"))?;
    let file_name = path
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invalid config file name"))?;
    let prefix = format!("{file_name}.infiproxy-bak-");
    let mut backups = fs::read_dir(parent)?
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|candidate| {
            candidate
                .file_name()
                .and_then(|value| value.to_str())
                .is_some_and(|name| name.starts_with(&prefix))
                && candidate.is_file()
        })
        .collect::<Vec<_>>();
    backups.sort();
    let remove_count = backups.len().saturating_sub(retain);
    for backup in backups.into_iter().take(remove_count) {
        fs::remove_file(backup)?;
    }
    Ok(())
}

pub(crate) const IP_REPUTATION_SOURCES: &[IpReputationSource] = &[
    IpReputationSource {
        name: "Spamhaus",
        scope: "DNSBL / mail reputation",
        url_template: "https://check.spamhaus.org/results/?query={ip}",
    },
    IpReputationSource {
        name: "AbuseIPDB",
        scope: "abuse reports",
        url_template: "https://www.abuseipdb.com/check/{ip}",
    },
    IpReputationSource {
        name: "VirusTotal",
        scope: "multi-engine IP reputation",
        url_template: "https://www.virustotal.com/gui/ip-address/{ip}",
    },
    IpReputationSource {
        name: "Cisco Talos",
        scope: "sender/web reputation",
        url_template: "https://talosintelligence.com/reputation_center/lookup?search={ip}",
    },
    IpReputationSource {
        name: "GreyNoise",
        scope: "internet scan/noise context",
        url_template: "https://viz.greynoise.io/ip/{ip}",
    },
    IpReputationSource {
        name: "Shodan",
        scope: "exposed services",
        url_template: "https://www.shodan.io/host/{ip}",
    },
    IpReputationSource {
        name: "Censys",
        scope: "internet exposure inventory",
        url_template: "https://search.censys.io/hosts/{ip}",
    },
    IpReputationSource {
        name: "RIPEstat",
        scope: "routing / ASN context",
        url_template: "https://stat.ripe.net/{ip}",
    },
    IpReputationSource {
        name: "BGP.Tools",
        scope: "BGP / prefix owner",
        url_template: "https://bgp.tools/ip/{ip}",
    },
    IpReputationSource {
        name: "IPinfo",
        scope: "ASN / geolocation context",
        url_template: "https://ipinfo.io/{ip}",
    },
    IpReputationSource {
        name: "Scamalytics",
        scope: "fraud score",
        url_template: "https://scamalytics.com/ip/{ip}",
    },
    IpReputationSource {
        name: "Project Honey Pot",
        scope: "comment/email abuse",
        url_template: "https://www.projecthoneypot.org/ip_{ip}",
    },
    IpReputationSource {
        name: "StopForumSpam",
        scope: "forum spam history",
        url_template: "https://www.stopforumspam.com/ipcheck/{ip}",
    },
    IpReputationSource {
        name: "BarracudaCentral",
        scope: "mail blocklist lookup",
        url_template: "https://www.barracudacentral.org/lookups/lookup-reputation?ip_address={ip}",
    },
];

#[derive(Debug, Clone, Copy)]
pub(crate) struct IpReputationSource {
    pub(crate) name: &'static str,
    pub(crate) scope: &'static str,
    pub(crate) url_template: &'static str,
}

#[derive(Debug, Clone)]
pub(crate) struct HostSnapshot {
    pub(crate) os_name: String,
    pub(crate) kernel: String,
    pub(crate) uptime: String,
    pub(crate) load_average: String,
    pub(crate) memory_label: String,
    pub(crate) memory_used_percent: Option<u8>,
    pub(crate) disk_label: String,
    pub(crate) disk_used_percent: Option<u8>,
}

#[derive(Debug, Clone)]
pub(crate) struct ServiceState {
    pub(crate) unit: String,
    pub(crate) status: ServiceStatus,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ServiceStatus {
    Active,
    Inactive,
    Failed,
    Unknown,
}

#[derive(Debug, Clone)]
pub(crate) struct CommandStep {
    pub(crate) command: String,
    pub(crate) success: bool,
    pub(crate) stdout: String,
    pub(crate) stderr: String,
}

#[derive(Debug, Clone)]
pub(crate) struct UninstallPlan {
    pub(crate) title: &'static str,
    pub(crate) warning: &'static str,
    pub(crate) commands: Vec<&'static str>,
}

pub(crate) fn uninstall_plan(mode: &str) -> Option<UninstallPlan> {
    match mode {
        "panel" => Some(UninstallPlan {
            title: "Panel-only removal",
            warning: "Removes the HTTP panel, its database, updater and Nginx site. The module updater, proxy runtimes, Headscale, their configs and the shared service account are preserved.",
            commands: vec![
                "# Review paths before running as root.",
                "systemctl disable --now infiproxy.service infiproxy-panel-update.timer infiproxy-panel-update.path infiproxy-reconcile.timer infiproxy-reconcile.path || true",
                "rm -f /etc/systemd/system/infiproxy.service /etc/systemd/system/infiproxy-panel-update.service /etc/systemd/system/infiproxy-panel-update.timer /etc/systemd/system/infiproxy-panel-update.path /etc/systemd/system/infiproxy-reconcile.service /etc/systemd/system/infiproxy-reconcile.timer /etc/systemd/system/infiproxy-reconcile.path",
                "systemctl daemon-reload",
                "rm -f /usr/local/bin/infiproxy /usr/local/sbin/infiproxy-panel-update /usr/local/libexec/infiproxy-reconcile /usr/local/libexec/infiproxy-install-state /etc/infiproxy-update.conf",
                "rm -rf /etc/infiproxy /opt/infiproxy/source",
                "rm -f /var/lib/infiproxy/infiproxy.sqlite /var/lib/infiproxy/infiproxy.sqlite-wal /var/lib/infiproxy/infiproxy.sqlite-shm /var/lib/infiproxy/panel-update-state.env /var/lib/infiproxy/panel-update-now.request",
                "rm -rf /var/lib/infiproxy-maintenance/update-backups",
                "rm -rf /var/lib/infiproxy-maintenance/reconcile /var/lib/infiproxy/reconcile-requests",
                "rm -f /var/lib/infiproxy-maintenance/panel-update-run.log /var/lib/infiproxy-maintenance/panel-last-applied.sha /var/lib/infiproxy-maintenance/panel-update-status.env",
                "rm -f /etc/nginx/sites-enabled/infiproxy.conf /etc/nginx/sites-available/infiproxy.conf /etc/nginx/sites-enabled/infiproxy-subscription.conf /etc/nginx/sites-available/infiproxy-subscription.conf",
                "if nginx -t; then systemctl reload nginx.service || true; fi",
            ],
        }),
        "full" => Some(UninstallPlan {
            title: "Full footprint removal",
            warning: "Removes panel-managed services, panel state, core binaries/configs/logs and the source checkout. It does not remove system packages such as nginx, git or Rust.",
            commands: vec![
                "# Review paths before running as root.",
                "for manifest in /etc/infiproxy-modules.d/*.module; do [ -f \"$manifest\" ] || continue; service=$(/usr/local/libexec/infiproxy-module-manifest read \"$manifest\" --root-owned | cut -d'|' -f11); systemctl disable --now \"$service\" || true; rm -f \"/etc/systemd/system/$service\"; done",
                "systemctl disable --now infiproxy.service infiproxy-panel-update.timer infiproxy-panel-update.path infiproxy-module-update.timer infiproxy-module-update.path infiproxy-reconcile.timer infiproxy-reconcile.path || true",
                "rm -f /etc/systemd/system/infiproxy.service /etc/systemd/system/infiproxy-panel-update.service /etc/systemd/system/infiproxy-panel-update.timer /etc/systemd/system/infiproxy-panel-update.path /etc/systemd/system/infiproxy-module-update.service /etc/systemd/system/infiproxy-module-update.timer /etc/systemd/system/infiproxy-module-update.path /etc/systemd/system/infiproxy-reconcile.service /etc/systemd/system/infiproxy-reconcile.timer /etc/systemd/system/infiproxy-reconcile.path",
                "systemctl daemon-reload",
                "rm -f /usr/local/bin/infiproxy /usr/local/bin/headscale /usr/local/sbin/infiproxy-manager /usr/local/sbin/infiproxy-panel-update /usr/local/sbin/infiproxy-module-update /usr/local/sbin/infiproxy-core-install /usr/local/libexec/infiproxy-module-manifest /usr/local/libexec/infiproxy-headscale-control /usr/local/libexec/infiproxy-reconcile /usr/local/libexec/infiproxy-install-state /etc/profile.d/infiproxy-manager.sh /etc/infiproxy-update.conf",
                "rm -rf /etc/infiproxy /etc/infiproxy-modules.d /etc/infiproxy-modules.available.d /var/lib/infiproxy /var/lib/infiproxy-maintenance",
                "rm -rf /etc/infiproxy-cores /opt/infiproxy/cores /opt/infiproxy/modules /var/log/infiproxy-cores",
                "rm -rf /opt/infiproxy/source",
                "rm -f /etc/nginx/sites-enabled/infiproxy.conf /etc/nginx/sites-available/infiproxy.conf /etc/nginx/sites-enabled/infiproxy-subscription.conf /etc/nginx/sites-available/infiproxy-subscription.conf",
                "if nginx -t; then systemctl reload nginx.service || true; fi",
                "userdel infiproxy 2>/dev/null || true",
                "groupdel infiproxy 2>/dev/null || true",
            ],
        }),
        "factory" => Some(UninstallPlan {
            title: "Factory footprint cleanup",
            warning: "Attempts to return the host to a pre-Infiproxy footprint by removing panel services, panel state, proxy cores, core configs/logs, nginx site files, source checkout, manager TUI and the service user. It does not purge OS packages because the installer cannot know which packages existed before Infiproxy.",
            commands: vec![
                "# Review paths before running as root.",
                "for manifest in /etc/infiproxy-modules.d/*.module; do [ -f \"$manifest\" ] || continue; service=$(/usr/local/libexec/infiproxy-module-manifest read \"$manifest\" --root-owned | cut -d'|' -f11); systemctl disable --now \"$service\" || true; rm -f \"/etc/systemd/system/$service\"; done",
                "systemctl disable --now infiproxy.service infiproxy-panel-update.timer infiproxy-panel-update.path infiproxy-module-update.timer infiproxy-module-update.path infiproxy-reconcile.timer infiproxy-reconcile.path || true",
                "rm -f /etc/systemd/system/infiproxy.service /etc/systemd/system/infiproxy-panel-update.service /etc/systemd/system/infiproxy-panel-update.timer /etc/systemd/system/infiproxy-panel-update.path /etc/systemd/system/infiproxy-module-update.service /etc/systemd/system/infiproxy-module-update.timer /etc/systemd/system/infiproxy-module-update.path /etc/systemd/system/infiproxy-reconcile.service /etc/systemd/system/infiproxy-reconcile.timer /etc/systemd/system/infiproxy-reconcile.path",
                "systemctl daemon-reload",
                "rm -f /usr/local/bin/infiproxy /usr/local/sbin/infiproxy-manager /usr/local/sbin/infiproxy-panel-update /usr/local/sbin/infiproxy-module-update /usr/local/sbin/infiproxy-core-install /usr/local/libexec/infiproxy-module-manifest /usr/local/libexec/infiproxy-headscale-control /usr/local/libexec/infiproxy-reconcile /usr/local/libexec/infiproxy-install-state /etc/profile.d/infiproxy-manager.sh /etc/infiproxy-update.conf",
                "rm -rf /etc/infiproxy /etc/infiproxy-modules.d /etc/infiproxy-modules.available.d /var/lib/infiproxy /var/lib/infiproxy-maintenance",
                "rm -rf /etc/infiproxy-cores /opt/infiproxy /var/log/infiproxy-cores",
                "rm -f /etc/nginx/sites-enabled/infiproxy.conf /etc/nginx/sites-available/infiproxy.conf /etc/nginx/sites-enabled/infiproxy-subscription.conf /etc/nginx/sites-available/infiproxy-subscription.conf",
                "if nginx -t; then systemctl reload nginx.service || true; fi",
                "userdel infiproxy 2>/dev/null || true",
                "groupdel infiproxy 2>/dev/null || true",
            ],
        }),
        _ => None,
    }
}

pub(crate) async fn host_snapshot() -> HostSnapshot {
    let disk_values = disk_values_kb().await;

    HostSnapshot {
        os_name: os_pretty_name().unwrap_or_else(|| "unknown Linux".to_string()),
        kernel: read_trimmed("/proc/sys/kernel/osrelease").unwrap_or_else(|| "unknown".to_string()),
        uptime: uptime_label().unwrap_or_else(|| "unknown".to_string()),
        load_average: load_average_label().unwrap_or_else(|| "unknown".to_string()),
        memory_label: memory_label().unwrap_or_else(|| "unknown".to_string()),
        memory_used_percent: memory_used_percent(),
        disk_label: disk_values.map_or_else(
            || "unknown".to_string(),
            |(used, total)| format!("{} / {}", format_kibibytes(used), format_kibibytes(total)),
        ),
        disk_used_percent: disk_values.and_then(|(used, total)| percent(used, total)),
    }
}

fn os_pretty_name() -> Option<String> {
    let content = fs::read_to_string("/etc/os-release").ok()?;
    content.lines().find_map(|line| {
        let value = line.strip_prefix("PRETTY_NAME=")?;
        Some(value.trim_matches('"').to_string())
    })
}

fn read_trimmed(path: &str) -> Option<String> {
    fs::read_to_string(path)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn uptime_label() -> Option<String> {
    let content = fs::read_to_string("/proc/uptime").ok()?;
    let seconds = content.split_whitespace().next()?.parse::<u64>().ok()?;
    Some(format_duration(seconds))
}

fn load_average_label() -> Option<String> {
    let content = fs::read_to_string("/proc/loadavg").ok()?;
    let mut parts = content.split_whitespace();
    Some(format!(
        "{} {} {}",
        parts.next()?,
        parts.next()?,
        parts.next()?
    ))
}

fn memory_values_kb() -> Option<(u64, u64)> {
    let content = fs::read_to_string("/proc/meminfo").ok()?;
    let mut total = None;
    let mut available = None;

    for line in content.lines() {
        if let Some(value) = meminfo_kb(line, "MemTotal:") {
            total = Some(value);
        } else if let Some(value) = meminfo_kb(line, "MemAvailable:") {
            available = Some(value);
        }
    }

    Some((total?, available?))
}

fn meminfo_kb(line: &str, key: &str) -> Option<u64> {
    line.strip_prefix(key)?
        .split_whitespace()
        .next()?
        .parse()
        .ok()
}

fn memory_label() -> Option<String> {
    let (total, available) = memory_values_kb()?;
    let used = total.saturating_sub(available);
    Some(format!(
        "{} / {}",
        format_kibibytes(used),
        format_kibibytes(total)
    ))
}

fn memory_used_percent() -> Option<u8> {
    let (total, available) = memory_values_kb()?;
    percent(total.saturating_sub(available), total)
}

async fn disk_values_kb() -> Option<(u64, u64)> {
    let mut command = tokio::process::Command::new("df");
    command.args(["-k", "/"]).kill_on_drop(true);
    let output = tokio::time::timeout(Duration::from_secs(3), command.output())
        .await
        .ok()?
        .ok()?;
    if !output.status.success() {
        return None;
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let fields: Vec<&str> = stdout.lines().nth(1)?.split_whitespace().collect();
    let used = fields.get(2)?.parse::<u64>().ok()?;
    let total = fields.get(1)?.parse::<u64>().ok()?;
    Some((used, total))
}

pub(crate) fn percent(value: u64, total: u64) -> Option<u8> {
    if total == 0 {
        return None;
    }

    Some(((value.saturating_mul(100)) / total).min(100) as u8)
}

pub(crate) fn format_duration(seconds: u64) -> String {
    let days = seconds / 86_400;
    let hours = (seconds % 86_400) / 3_600;
    let minutes = (seconds % 3_600) / 60;

    if days > 0 {
        format!("{days}d {hours}h {minutes}m")
    } else if hours > 0 {
        format!("{hours}h {minutes}m")
    } else {
        format!("{minutes}m")
    }
}

pub(crate) fn format_kibibytes(value: u64) -> String {
    const GIB: f64 = 1024.0 * 1024.0;
    const MIB: f64 = 1024.0;

    if value as f64 >= GIB {
        format!("{:.1} GiB", value as f64 / GIB)
    } else {
        format!("{:.0} MiB", value as f64 / MIB)
    }
}

pub(crate) async fn service_states_for_targets() -> Vec<ServiceState> {
    let mut units = Vec::new();
    for target in SYSTEM_TARGETS {
        for unit in target.units {
            if !units.contains(unit) {
                units.push(*unit);
            }
        }
    }

    let mut command = tokio::process::Command::new("systemctl");
    command
        .arg("show")
        .args(["--no-pager", "--property=Id,LoadState,ActiveState"])
        .args(&units)
        .kill_on_drop(true);
    let observed = match tokio::time::timeout(Duration::from_secs(3), command.output()).await {
        Ok(Ok(output)) => parse_systemctl_show(&String::from_utf8_lossy(&output.stdout)),
        _ => HashMap::new(),
    };

    SYSTEM_TARGETS
        .iter()
        .map(|target| {
            target
                .units
                .iter()
                .find_map(|unit| {
                    observed.get(*unit).and_then(|status| {
                        (*status != ServiceStatus::Unknown).then(|| ServiceState {
                            unit: (*unit).to_string(),
                            status: *status,
                        })
                    })
                })
                .unwrap_or_else(|| ServiceState {
                    unit: target
                        .units
                        .first()
                        .copied()
                        .unwrap_or("unknown")
                        .to_string(),
                    status: ServiceStatus::Unknown,
                })
        })
        .collect()
}

fn parse_systemctl_show(output: &str) -> HashMap<String, ServiceStatus> {
    output
        .split("\n\n")
        .filter_map(|block| {
            let mut id = None;
            let mut load_state = None;
            let mut active_state = None;
            for line in block.lines() {
                if let Some(value) = line.strip_prefix("Id=") {
                    id = Some(value);
                } else if let Some(value) = line.strip_prefix("LoadState=") {
                    load_state = Some(value);
                } else if let Some(value) = line.strip_prefix("ActiveState=") {
                    active_state = Some(value);
                }
            }
            let id = id?.trim();
            if id.is_empty() {
                return None;
            }
            let status = if load_state != Some("loaded") {
                ServiceStatus::Unknown
            } else {
                match active_state {
                    Some("active" | "reloading") => ServiceStatus::Active,
                    Some("failed") => ServiceStatus::Failed,
                    Some("inactive" | "deactivating") => ServiceStatus::Inactive,
                    _ => ServiceStatus::Unknown,
                }
            };
            Some((id.to_string(), status))
        })
        .collect()
}

pub(crate) async fn run_first_success_owned(commands: &[(&str, Vec<String>)]) -> CommandStep {
    let mut combined = Vec::new();

    for (program, args) in commands {
        let step = run_command_owned(program, args).await;
        let success = step.success;
        combined.push(step);

        if success {
            break;
        }
    }

    merge_command_steps(combined)
}

fn merge_command_steps(steps: Vec<CommandStep>) -> CommandStep {
    let success = steps.iter().any(|step| step.success);
    let command = steps
        .iter()
        .map(|step| step.command.as_str())
        .collect::<Vec<_>>()
        .join(" || ");
    let stdout = steps
        .iter()
        .filter(|step| !step.stdout.is_empty())
        .map(|step| format!("$ {}\n{}", step.command, step.stdout))
        .collect::<Vec<_>>()
        .join("\n");
    let stderr = steps
        .iter()
        .filter(|step| !step.stderr.is_empty())
        .map(|step| format!("$ {}\n{}", step.command, step.stderr))
        .collect::<Vec<_>>()
        .join("\n");

    CommandStep {
        command,
        success,
        stdout,
        stderr,
    }
}

pub(crate) async fn run_command_owned(program: &str, args: &[String]) -> CommandStep {
    let command = format_command_owned(program, args);
    let mut child = tokio::process::Command::new(program);
    child.args(args).kill_on_drop(true);

    match tokio::time::timeout(Duration::from_secs(5), child.output()).await {
        Ok(Ok(output)) => CommandStep {
            command,
            success: output.status.success(),
            stdout: trim_command_output(&String::from_utf8_lossy(&output.stdout)),
            stderr: trim_command_output(&String::from_utf8_lossy(&output.stderr)),
        },
        Ok(Err(err)) => CommandStep {
            command,
            success: false,
            stdout: String::new(),
            stderr: err.to_string(),
        },
        Err(_) => CommandStep {
            command,
            success: false,
            stdout: String::new(),
            stderr: "command timed out after 5 seconds".to_string(),
        },
    }
}

fn format_command_owned(program: &str, args: &[String]) -> String {
    std::iter::once(program.to_string())
        .chain(args.iter().cloned())
        .collect::<Vec<_>>()
        .join(" ")
}

pub(crate) fn trim_command_output(value: &str) -> String {
    const MAX_OUTPUT_CHARS: usize = 4096;
    let value = value.trim();

    if value.chars().count() <= MAX_OUTPUT_CHARS {
        return value.to_string();
    }

    format!(
        "{}... <truncated>",
        value.chars().take(MAX_OUTPUT_CHARS).collect::<String>()
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_backup_retention_keeps_only_the_newest_files() -> io::Result<()> {
        let directory = std::env::temp_dir().join(format!(
            "infiproxy-config-backups-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
        fs::create_dir_all(&directory)?;
        let config = directory.join("config.json");
        fs::write(&config, b"{}")?;
        for index in 0..25 {
            fs::write(
                directory.join(format!("config.json.infiproxy-bak-{index:03}")),
                b"{}",
            )?;
        }

        prune_config_backups(&config, 20)?;
        let remaining = fs::read_dir(&directory)?
            .filter_map(Result::ok)
            .filter(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with("config.json.infiproxy-bak-")
            })
            .count();
        assert_eq!(remaining, 20);
        assert!(!directory.join("config.json.infiproxy-bak-000").exists());
        assert!(directory.join("config.json.infiproxy-bak-024").exists());

        fs::remove_dir_all(directory)?;
        Ok(())
    }

    #[test]
    fn systemctl_show_parser_distinguishes_missing_and_failed_units() {
        let states = parse_systemctl_show(
            "Id=infiproxy.service\nLoadState=loaded\nActiveState=active\n\n\
             Id=nginx.service\nLoadState=loaded\nActiveState=failed\n\n\
             Id=ssh.service\nLoadState=not-found\nActiveState=inactive\n",
        );

        assert_eq!(states["infiproxy.service"], ServiceStatus::Active);
        assert_eq!(states["nginx.service"], ServiceStatus::Failed);
        assert_eq!(states["ssh.service"], ServiceStatus::Unknown);
    }
}
