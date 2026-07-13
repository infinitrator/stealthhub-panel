use maud::{html, Markup};
use std::{fs, process::Command};

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
];
pub(crate) const CORE_RUNTIMES: &[CoreRuntime] = &[
    CoreRuntime {
        name: "Xray",
        role: "VLESS REALITY XHTTP/TCP",
        service: "infiproxy-xray.service",
        binary_path: "/opt/infiproxy/cores/xray/current/xray",
        local_binary_path: ".runtime/cores/xray/current/xray",
        config_path: "/etc/infiproxy-cores/xray/config.json",
        update_channel:
            "XTLS/Xray-core latest stable v26.3.27; upstream has newer prerelease stream",
        priority: "primary",
    },
    CoreRuntime {
        name: "sing-box",
        role: "SS2022 ShadowTLS, AnyTLS, compatibility",
        service: "infiproxy-sing-box.service",
        binary_path: "/opt/infiproxy/cores/sing-box/current/sing-box",
        local_binary_path: ".runtime/cores/sing-box/current/sing-box",
        config_path: "/etc/infiproxy-cores/sing-box/config.json",
        update_channel: "SagerNet/sing-box latest stable v1.13.14",
        priority: "compat",
    },
    CoreRuntime {
        name: "Hysteria",
        role: "Hysteria2 speed fallback",
        service: "infiproxy-hysteria.service",
        binary_path: "/opt/infiproxy/cores/hysteria/current/hysteria",
        local_binary_path: ".runtime/cores/hysteria/current/hysteria",
        config_path: "/etc/infiproxy-cores/hysteria/config.yaml",
        update_channel: "apernet/hysteria latest stable app/v2.10.0",
        priority: "speed",
    },
    CoreRuntime {
        name: "TUIC",
        role: "TUIC QUIC speed fallback",
        service: "infiproxy-tuic.service",
        binary_path: "/opt/infiproxy/cores/tuic/current/tuic-server",
        local_binary_path: ".runtime/cores/tuic/current/tuic-server",
        config_path: "/etc/infiproxy-cores/tuic/config.json",
        update_channel: "tuic-protocol/tuic latest stable tuic-server-1.0.0",
        priority: "optional",
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
    ReloadSsh,
    ReloadNginx,
    ReloadFirewall,
}

pub(crate) const CONSOLE_COMMANDS: &[ConsoleCommand] = &[
    ConsoleCommand {
        slug: "panel-status",
        name: "Panel service status",
        description: "Read systemd state for the Infiproxy panel service.",
        program: "systemctl",
        args: &["--no-pager", "--full", "status", "infiproxy.service"],
    },
    ConsoleCommand {
        slug: "panel-logs",
        name: "Panel logs",
        description: "Read the last 80 journal lines for the panel service.",
        program: "journalctl",
        args: &["-u", "infiproxy.service", "-n", "80", "--no-pager"],
    },
    ConsoleCommand {
        slug: "disk-usage",
        name: "Disk usage",
        description: "Show filesystem capacity for the root volume.",
        program: "df",
        args: &["-h", "/"],
    },
    ConsoleCommand {
        slug: "memory",
        name: "Memory snapshot",
        description: "Show kernel memory accounting from /proc/meminfo.",
        program: "head",
        args: &["-n", "12", "/proc/meminfo"],
    },
    ConsoleCommand {
        slug: "nginx-test",
        name: "Nginx config test",
        description: "Validate Nginx configuration without reloading it.",
        program: "nginx",
        args: &["-t"],
    },
    ConsoleCommand {
        slug: "ssh-test",
        name: "SSH config test",
        description: "Validate sshd configuration without reloading it.",
        program: "sshd",
        args: &["-t"],
    },
    ConsoleCommand {
        slug: "routes",
        name: "Route table",
        description: "Show kernel routing table for network debugging.",
        program: "ip",
        args: &["route"],
    },
    ConsoleCommand {
        slug: "listeners",
        name: "Listening sockets",
        description: "Show listening TCP/UDP sockets for service exposure checks.",
        program: "ss",
        args: &["-tulpn"],
    },
];

#[derive(Debug, Clone, Copy)]
pub(crate) struct ConsoleCommand {
    pub(crate) slug: &'static str,
    pub(crate) name: &'static str,
    pub(crate) description: &'static str,
    pub(crate) program: &'static str,
    pub(crate) args: &'static [&'static str],
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

#[derive(Debug, Clone, Copy)]
pub(crate) struct CoreRuntime {
    pub(crate) name: &'static str,
    pub(crate) role: &'static str,
    pub(crate) service: &'static str,
    pub(crate) binary_path: &'static str,
    pub(crate) local_binary_path: &'static str,
    pub(crate) config_path: &'static str,
    pub(crate) update_channel: &'static str,
    pub(crate) priority: &'static str,
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
                "systemctl disable --now infiproxy.service || true",
                "rm -f /etc/systemd/system/infiproxy.service",
                "systemctl daemon-reload",
                "rm -f /usr/local/bin/infiproxy",
                "rm -rf /etc/infiproxy",
                "rm -rf /var/lib/infiproxy",
                "userdel infiproxy 2>/dev/null || true",
                "groupdel infiproxy 2>/dev/null || true",
            ],
        }),
        "full" => Some(UninstallPlan {
            title: "Full footprint removal",
            warning: "Removes panel-managed services, panel state, core binaries/configs/logs and the source checkout. It does not remove system packages such as nginx, git or Rust.",
            commands: vec![
                "# Review paths before running as root.",
                "systemctl disable --now infiproxy.service infiproxy-xray.service infiproxy-sing-box.service infiproxy-hysteria.service infiproxy-tuic.service || true",
                "rm -f /etc/systemd/system/infiproxy.service",
                "rm -f /etc/systemd/system/infiproxy-xray.service /etc/systemd/system/infiproxy-sing-box.service /etc/systemd/system/infiproxy-hysteria.service /etc/systemd/system/infiproxy-tuic.service",
                "systemctl daemon-reload",
                "rm -f /usr/local/bin/infiproxy",
                "rm -rf /etc/infiproxy /var/lib/infiproxy",
                "rm -rf /etc/infiproxy-cores /opt/infiproxy/cores /var/log/infiproxy-cores",
                "rm -rf /opt/infiproxy/source",
                "rm -f /etc/nginx/sites-enabled/infiproxy.conf /etc/nginx/sites-available/infiproxy.conf",
                "nginx -t && systemctl reload nginx.service || true",
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

pub(crate) fn service_state_badge(state: &ServiceState) -> Markup {
    let (class, label) = match state.status {
        ServiceStatus::Active => ("ok", "active"),
        ServiceStatus::Inactive => ("neutral", "inactive"),
        ServiceStatus::Failed => ("off", "failed"),
        ServiceStatus::Unknown => ("off", "unknown"),
    };

    html! {
        span class=(format!("badge {class}")) { (label) }
        br;
        small { (&state.unit) }
    }
}

pub(crate) fn meter_bar(percent: Option<u8>) -> Markup {
    let value = percent.unwrap_or(0);

    html! {
        div class="meter" title=(percent.map(|value| format!("{value}%")).unwrap_or_else(|| "unknown".to_string())) {
            div class="meter-fill" style=(format!("width: {value}%")) {}
        }
    }
}

pub(crate) fn run_system_action(target: SystemTarget) -> SystemActionReport {
    let steps = match target.action {
        SystemActionKind::RestartPanel => {
            vec![run_command("systemctl", &["restart", "infiproxy.service"])]
        }
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
