//! Host operations used by the web panel.
//!
//! This module centralizes service metadata, config-file allowlists, bounded
//! command execution, uninstall runbooks and host metrics. Keeping these helpers
//! outside route handlers makes dangerous behavior easier to audit.

use std::{
    fs,
    path::Path,
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};

pub(crate) const SYSTEM_TARGETS: &[SystemTarget] = &[
    SystemTarget {
        slug: "panel",
        name: "Panel service",
        kind: "systemd",
        unit: "infiproxy.service",
        units: &["infiproxy.service"],
        config: "/etc/infiproxy/infiproxy.env",
        check: "systemctl status infiproxy.service",
        reload: "systemctl restart infiproxy.service",
        action_label: "Restart",
        action: SystemActionKind::RestartPanel,
    },
    SystemTarget {
        slug: "ssh",
        name: "SSH daemon",
        kind: "host",
        unit: "ssh.service / sshd.service",
        units: &["ssh.service", "sshd.service"],
        config: "/etc/ssh/sshd_config",
        check: "sshd -t && systemctl status ssh || systemctl status sshd",
        reload: "sshd -t && systemctl reload ssh || systemctl reload sshd",
        action_label: "Validate + reload",
        action: SystemActionKind::ReloadSsh,
    },
    SystemTarget {
        slug: "nginx",
        name: "Nginx reverse proxy",
        kind: "host",
        unit: "nginx.service",
        units: &["nginx.service"],
        config: "/etc/nginx/sites-available/infiproxy.conf",
        check: "nginx -t && systemctl status nginx.service",
        reload: "nginx -t && systemctl reload nginx.service",
        action_label: "Validate + reload",
        action: SystemActionKind::ReloadNginx,
    },
    SystemTarget {
        slug: "firewall",
        name: "Firewall",
        kind: "host",
        unit: "ufw / nftables",
        units: &["ufw.service", "nftables.service"],
        config: "/etc/ufw / /etc/nftables.conf",
        check: "ufw status verbose || nft list ruleset",
        reload: "ufw reload || systemctl reload nftables.service",
        action_label: "Reload",
        action: SystemActionKind::ReloadFirewall,
    },
    SystemTarget {
        slug: "xray",
        name: "Xray core",
        kind: "proxy-core",
        unit: "infiproxy-xray.service",
        units: &["infiproxy-xray.service"],
        config: "/etc/infiproxy-cores/xray/config.json",
        check: "systemctl status infiproxy-xray.service",
        reload: "systemctl restart infiproxy-xray.service",
        action_label: "Restart",
        action: SystemActionKind::RestartUnit("infiproxy-xray.service"),
    },
    SystemTarget {
        slug: "sing-box",
        name: "sing-box core",
        kind: "proxy-core",
        unit: "infiproxy-sing-box.service",
        units: &["infiproxy-sing-box.service"],
        config: "/etc/infiproxy-cores/sing-box/config.json",
        check: "systemctl status infiproxy-sing-box.service",
        reload: "systemctl restart infiproxy-sing-box.service",
        action_label: "Restart",
        action: SystemActionKind::RestartUnit("infiproxy-sing-box.service"),
    },
    SystemTarget {
        slug: "hysteria",
        name: "Hysteria core",
        kind: "proxy-core",
        unit: "infiproxy-hysteria.service",
        units: &["infiproxy-hysteria.service"],
        config: "/etc/infiproxy-cores/hysteria/config.yaml",
        check: "systemctl status infiproxy-hysteria.service",
        reload: "systemctl restart infiproxy-hysteria.service",
        action_label: "Restart",
        action: SystemActionKind::RestartUnit("infiproxy-hysteria.service"),
    },
    SystemTarget {
        slug: "tuic",
        name: "TUIC core",
        kind: "proxy-core",
        unit: "infiproxy-tuic.service",
        units: &["infiproxy-tuic.service"],
        config: "/etc/infiproxy-cores/tuic/config.json",
        check: "systemctl status infiproxy-tuic.service",
        reload: "systemctl restart infiproxy-tuic.service",
        action_label: "Restart",
        action: SystemActionKind::RestartUnit("infiproxy-tuic.service"),
    },
    SystemTarget {
        slug: "mtproto",
        name: "Telegram MTProto",
        kind: "proxy-core",
        unit: "infiproxy-mtproto.service",
        units: &["infiproxy-mtproto.service"],
        config: "/etc/infiproxy-cores/mtproto/mtproto.env",
        check: "systemctl status infiproxy-mtproto.service",
        reload: "systemctl restart infiproxy-mtproto.service",
        action_label: "Restart",
        action: SystemActionKind::RestartUnit("infiproxy-mtproto.service"),
    },
    SystemTarget {
        slug: "headscale",
        name: "Headscale hub",
        kind: "mesh-control",
        unit: "headscale.service",
        units: &["headscale.service"],
        config: "/etc/headscale/config.yaml",
        check: "headscale configtest && systemctl status headscale.service",
        reload: "headscale configtest && systemctl restart headscale.service",
        action_label: "Validate + restart",
        action: SystemActionKind::RestartUnit("headscale.service"),
    },
];
#[derive(Debug, Clone, Copy)]
pub(crate) struct SystemTarget {
    pub(crate) slug: &'static str,
    pub(crate) name: &'static str,
    pub(crate) kind: &'static str,
    pub(crate) unit: &'static str,
    pub(crate) units: &'static [&'static str],
    pub(crate) config: &'static str,
    pub(crate) check: &'static str,
    pub(crate) reload: &'static str,
    pub(crate) action_label: &'static str,
    pub(crate) action: SystemActionKind,
}

#[derive(Debug, Clone, Copy)]
pub(crate) enum SystemActionKind {
    RestartPanel,
    RestartUnit(&'static str),
    ReloadSsh,
    ReloadNginx,
    ReloadFirewall,
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
    },
    StaticConfigFileSpec {
        slug: "xray-core",
        name: "Xray core",
        category: "proxy-core",
        path: "/etc/infiproxy-cores/xray/config.json",
        syntax: "json",
        description: "Xray inbound/outbound runtime configuration.",
        validate_hint: "xray -test -config <file>",
        reload_hint: "systemctl restart infiproxy-xray.service",
        max_bytes: 256 * 1024,
    },
    StaticConfigFileSpec {
        slug: "sing-box-core",
        name: "sing-box core",
        category: "proxy-core",
        path: "/etc/infiproxy-cores/sing-box/config.json",
        syntax: "json",
        description: "sing-box runtime configuration for compatibility transports.",
        validate_hint: "sing-box check -c <file>",
        reload_hint: "systemctl restart infiproxy-sing-box.service",
        max_bytes: 256 * 1024,
    },
    StaticConfigFileSpec {
        slug: "hysteria-core",
        name: "Hysteria core",
        category: "proxy-core",
        path: "/etc/infiproxy-cores/hysteria/config.yaml",
        syntax: "yaml",
        description: "Hysteria2 server runtime configuration.",
        validate_hint: "hysteria server -c <file> --check",
        reload_hint: "systemctl restart infiproxy-hysteria.service",
        max_bytes: 128 * 1024,
    },
    StaticConfigFileSpec {
        slug: "tuic-core",
        name: "TUIC core",
        category: "proxy-core",
        path: "/etc/infiproxy-cores/tuic/config.json",
        syntax: "json",
        description: "TUIC server runtime configuration.",
        validate_hint: "tuic-server -c <file> check",
        reload_hint: "systemctl restart infiproxy-tuic.service",
        max_bytes: 128 * 1024,
    },
    StaticConfigFileSpec {
        slug: "mtproto-core",
        name: "Telegram MTProto",
        category: "proxy-core",
        path: "/etc/infiproxy-cores/mtproto/mtproto.env",
        syntax: "dotenv",
        description: "Telegram MTProxy bind, port, secret and upstream config paths.",
        validate_hint: "secret must be 32 hex chars; refresh Telegram config daily",
        reload_hint: "systemctl restart infiproxy-mtproto.service",
        max_bytes: 16 * 1024,
    },
    StaticConfigFileSpec {
        slug: "headscale-config",
        name: "Headscale hub",
        category: "mesh-control",
        path: "/etc/headscale/config.yaml",
        syntax: "yaml",
        description: "Tailscale coordination server URL, local listeners, DNS and SQLite state.",
        validate_hint: "HEADSCALE_CONFIG=/etc/headscale/config.yaml headscale configtest",
        reload_hint: "systemctl restart headscale.service",
        max_bytes: 128 * 1024,
    },
    StaticConfigFileSpec {
        slug: "headscale-nginx",
        name: "Headscale HTTPS site",
        category: "edge",
        path: "/etc/nginx/sites-available/infiproxy-headscale.conf",
        syntax: "nginx",
        description:
            "Dedicated HTTPS reverse proxy with Tailscale control WebSocket upgrade support.",
        validate_hint: "nginx -t",
        reload_hint: "systemctl reload nginx.service",
        max_bytes: 64 * 1024,
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

    match fs::write(path, content) {
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

fn path_has_symlink_component(path: &Path) -> bool {
    path.ancestors()
        .take_while(|component| !component.as_os_str().is_empty())
        .any(|component| {
            fs::symlink_metadata(component)
                .map(|metadata| metadata.file_type().is_symlink())
                .unwrap_or(false)
        })
}

fn backup_config_file(path: &Path) -> std::io::Result<String> {
    let suffix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_secs())
        .unwrap_or(0);
    let backup = path.with_extension(format!(
        "{}.infiproxy-bak-{suffix}",
        path.extension()
            .and_then(|value| value.to_str())
            .unwrap_or("bak")
    ));

    fs::copy(path, &backup)?;
    Ok(backup.display().to_string())
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
pub(crate) struct SystemActionReport {
    pub(crate) steps: Vec<CommandStep>,
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
            warning: "Removes only the Infiproxy panel service, binary and panel state. Proxy cores and third-party services are left intact.",
            commands: vec![
                "# Review paths before running as root.",
                "systemctl disable --now infiproxy.service infiproxy-panel-update.timer infiproxy-panel-update.path infiproxy-module-update.timer infiproxy-module-update.path || true",
                "rm -f /etc/systemd/system/infiproxy.service /etc/systemd/system/infiproxy-panel-update.service /etc/systemd/system/infiproxy-panel-update.timer /etc/systemd/system/infiproxy-panel-update.path /etc/systemd/system/infiproxy-module-update.service /etc/systemd/system/infiproxy-module-update.timer /etc/systemd/system/infiproxy-module-update.path",
                "systemctl daemon-reload",
                "rm -f /usr/local/bin/infiproxy /usr/local/sbin/infiproxy-manager /usr/local/sbin/infiproxy-panel-update /usr/local/sbin/infiproxy-module-update /usr/local/sbin/infiproxy-core-install /usr/local/libexec/infiproxy-module-manifest /usr/local/libexec/infiproxy-headscale-control /etc/profile.d/infiproxy-manager.sh /etc/infiproxy-update.conf",
                "rm -rf /etc/infiproxy /etc/infiproxy-modules.d /etc/infiproxy-modules.available.d",
                "rm -rf /var/lib/infiproxy /var/lib/infiproxy-maintenance",
                "userdel infiproxy 2>/dev/null || true",
                "groupdel infiproxy 2>/dev/null || true",
            ],
        }),
        "full" => Some(UninstallPlan {
            title: "Full footprint removal",
            warning: "Removes panel-managed services, panel state, core binaries/configs/logs and the source checkout. It does not remove system packages such as nginx, git or Rust.",
            commands: vec![
                "# Review paths before running as root.",
                "for manifest in /etc/infiproxy-modules.d/*.module; do [ -f \"$manifest\" ] || continue; service=$(/usr/local/libexec/infiproxy-module-manifest read \"$manifest\" --root-owned | cut -d'|' -f11); systemctl disable --now \"$service\" || true; rm -f \"/etc/systemd/system/$service\"; done",
                "systemctl disable --now infiproxy.service infiproxy-panel-update.timer infiproxy-panel-update.path infiproxy-module-update.timer infiproxy-module-update.path infiproxy-xray.service infiproxy-sing-box.service infiproxy-hysteria.service infiproxy-tuic.service infiproxy-mtproto.service headscale.service || true",
                "rm -f /etc/systemd/system/infiproxy.service /etc/systemd/system/infiproxy-panel-update.service /etc/systemd/system/infiproxy-panel-update.timer /etc/systemd/system/infiproxy-panel-update.path /etc/systemd/system/infiproxy-module-update.service /etc/systemd/system/infiproxy-module-update.timer /etc/systemd/system/infiproxy-module-update.path",
                "rm -f /etc/systemd/system/infiproxy-xray.service /etc/systemd/system/infiproxy-sing-box.service /etc/systemd/system/infiproxy-hysteria.service /etc/systemd/system/infiproxy-tuic.service /etc/systemd/system/infiproxy-mtproto.service",
                "rm -f /etc/systemd/system/headscale.service",
                "systemctl daemon-reload",
                "rm -f /usr/local/bin/infiproxy /usr/local/bin/headscale /usr/local/sbin/infiproxy-manager /usr/local/sbin/infiproxy-panel-update /usr/local/sbin/infiproxy-module-update /usr/local/sbin/infiproxy-core-install /usr/local/libexec/infiproxy-module-manifest /usr/local/libexec/infiproxy-headscale-control /etc/profile.d/infiproxy-manager.sh /etc/infiproxy-update.conf",
                "rm -rf /etc/infiproxy /etc/infiproxy-modules.d /etc/infiproxy-modules.available.d /var/lib/infiproxy /var/lib/infiproxy-maintenance",
                "rm -rf /etc/infiproxy-cores /opt/infiproxy/cores /opt/infiproxy/modules /var/log/infiproxy-cores",
                "rm -rf /etc/headscale /var/lib/headscale",
                "rm -rf /opt/infiproxy/source",
                "rm -f /etc/nginx/sites-enabled/infiproxy.conf /etc/nginx/sites-available/infiproxy.conf",
                "rm -f /etc/nginx/sites-enabled/infiproxy-headscale.conf /etc/nginx/sites-available/infiproxy-headscale.conf",
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
                "systemctl disable --now infiproxy.service infiproxy-panel-update.timer infiproxy-panel-update.path infiproxy-module-update.timer infiproxy-module-update.path infiproxy-xray.service infiproxy-sing-box.service infiproxy-hysteria.service infiproxy-tuic.service infiproxy-mtproto.service headscale.service || true",
                "rm -f /etc/systemd/system/infiproxy.service /etc/systemd/system/infiproxy-panel-update.service /etc/systemd/system/infiproxy-panel-update.timer /etc/systemd/system/infiproxy-panel-update.path /etc/systemd/system/infiproxy-module-update.service /etc/systemd/system/infiproxy-module-update.timer /etc/systemd/system/infiproxy-module-update.path",
                "rm -f /etc/systemd/system/infiproxy-xray.service /etc/systemd/system/infiproxy-sing-box.service /etc/systemd/system/infiproxy-hysteria.service /etc/systemd/system/infiproxy-tuic.service /etc/systemd/system/infiproxy-mtproto.service",
                "rm -f /etc/systemd/system/headscale.service",
                "systemctl daemon-reload",
                "rm -f /usr/local/bin/infiproxy /usr/local/sbin/infiproxy-manager /usr/local/sbin/infiproxy-panel-update /usr/local/sbin/infiproxy-module-update /usr/local/sbin/infiproxy-core-install /usr/local/libexec/infiproxy-module-manifest /usr/local/libexec/infiproxy-headscale-control /etc/profile.d/infiproxy-manager.sh /etc/infiproxy-update.conf",
                "rm -rf /etc/infiproxy /etc/infiproxy-modules.d /etc/infiproxy-modules.available.d /var/lib/infiproxy /var/lib/infiproxy-maintenance",
                "rm -rf /etc/infiproxy-cores /opt/infiproxy /var/log/infiproxy-cores",
                "rm -rf /etc/headscale /var/lib/headscale",
                "rm -f /usr/local/bin/headscale",
                "rm -f /etc/nginx/sites-enabled/infiproxy.conf /etc/nginx/sites-available/infiproxy.conf",
                "rm -f /etc/nginx/sites-enabled/infiproxy-headscale.conf /etc/nginx/sites-available/infiproxy-headscale.conf",
                "if nginx -t; then systemctl reload nginx.service || true; fi",
                "userdel infiproxy 2>/dev/null || true",
                "groupdel infiproxy 2>/dev/null || true",
            ],
        }),
        _ => None,
    }
}

pub(crate) fn host_snapshot() -> HostSnapshot {
    let disk_values = disk_values_kb();

    HostSnapshot {
        os_name: os_pretty_name().unwrap_or_else(|| "unknown Linux".to_string()),
        kernel: read_trimmed("/proc/sys/kernel/osrelease").unwrap_or_else(|| "unknown".to_string()),
        uptime: uptime_label().unwrap_or_else(|| "unknown".to_string()),
        load_average: load_average_label().unwrap_or_else(|| "unknown".to_string()),
        memory_label: memory_label().unwrap_or_else(|| "unknown".to_string()),
        memory_used_percent: memory_used_percent(),
        disk_label: disk_values
            .map(|(used, total)| {
                format!("{} / {}", format_kibibytes(used), format_kibibytes(total))
            })
            .unwrap_or_else(|| "unknown".to_string()),
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

fn disk_values_kb() -> Option<(u64, u64)> {
    let output = Command::new("df").args(["-k", "/"]).output().ok()?;
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

pub(crate) fn service_state(units: &[&str]) -> ServiceState {
    for unit in units {
        let Ok(output) = Command::new("systemctl")
            .args(["is-active", "--quiet", unit])
            .output()
        else {
            return ServiceState {
                unit: (*unit).to_string(),
                status: ServiceStatus::Unknown,
            };
        };

        if output.status.success() {
            return ServiceState {
                unit: (*unit).to_string(),
                status: ServiceStatus::Active,
            };
        }

        let status = systemctl_state(unit);
        if status != ServiceStatus::Unknown {
            return ServiceState {
                unit: (*unit).to_string(),
                status,
            };
        }
    }

    ServiceState {
        unit: units.first().copied().unwrap_or("unknown").to_string(),
        status: ServiceStatus::Unknown,
    }
}

fn systemctl_state(unit: &str) -> ServiceStatus {
    let Ok(output) = Command::new("systemctl").args(["is-failed", unit]).output() else {
        return ServiceStatus::Unknown;
    };

    if output.status.success() {
        ServiceStatus::Failed
    } else {
        ServiceStatus::Inactive
    }
}

pub(crate) fn run_system_action(target: SystemTarget) -> SystemActionReport {
    let steps = match target.action {
        SystemActionKind::RestartPanel => {
            vec![run_command("systemctl", &["restart", "infiproxy.service"])]
        }
        SystemActionKind::RestartUnit(unit) => vec![run_command("systemctl", &["restart", unit])],
        SystemActionKind::ReloadSsh => {
            let mut steps = vec![run_command("sshd", &["-t"])];
            if steps.last().is_some_and(|step| step.success) {
                steps.push(run_first_success(&[
                    ("systemctl", &["reload", "ssh.service"][..]),
                    ("systemctl", &["reload", "sshd.service"][..]),
                ]));
            }
            steps
        }
        SystemActionKind::ReloadNginx => {
            let mut steps = vec![run_command("nginx", &["-t"])];
            if steps.last().is_some_and(|step| step.success) {
                steps.push(run_command("systemctl", &["reload", "nginx.service"]));
            }
            steps
        }
        SystemActionKind::ReloadFirewall => vec![run_first_success(&[
            ("ufw", &["reload"][..]),
            ("systemctl", &["reload", "nftables.service"][..]),
        ])],
    };

    SystemActionReport { steps }
}

pub(crate) fn run_first_success(commands: &[(&str, &[&str])]) -> CommandStep {
    let mut combined = Vec::new();

    for (program, args) in commands {
        let step = run_command(program, args);
        let success = step.success;
        combined.push(step);

        if success {
            break;
        }
    }

    merge_command_steps(combined)
}

pub(crate) fn run_first_success_owned(commands: &[(&str, Vec<String>)]) -> CommandStep {
    let mut combined = Vec::new();

    for (program, args) in commands {
        let step = run_command_owned(program, args);
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

pub(crate) fn run_command(program: &str, args: &[&str]) -> CommandStep {
    let command = format_command(program, args);

    match Command::new(program).args(args).output() {
        Ok(output) => CommandStep {
            command,
            success: output.status.success(),
            stdout: trim_command_output(&String::from_utf8_lossy(&output.stdout)),
            stderr: trim_command_output(&String::from_utf8_lossy(&output.stderr)),
        },
        Err(err) => CommandStep {
            command,
            success: false,
            stdout: String::new(),
            stderr: err.to_string(),
        },
    }
}

pub(crate) fn run_command_owned(program: &str, args: &[String]) -> CommandStep {
    let command = format_command_owned(program, args);

    match Command::new(program).args(args).output() {
        Ok(output) => CommandStep {
            command,
            success: output.status.success(),
            stdout: trim_command_output(&String::from_utf8_lossy(&output.stdout)),
            stderr: trim_command_output(&String::from_utf8_lossy(&output.stderr)),
        },
        Err(err) => CommandStep {
            command,
            success: false,
            stdout: String::new(),
            stderr: err.to_string(),
        },
    }
}

fn format_command(program: &str, args: &[&str]) -> String {
    std::iter::once(program)
        .chain(args.iter().copied())
        .collect::<Vec<_>>()
        .join(" ")
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
