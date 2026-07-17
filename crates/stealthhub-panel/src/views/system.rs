//! System-page presentation.

use crate::{
    admin_bar, csrf_field,
    ops::*,
    ui::layout,
    views::components::{meter_bar, service_state_badge},
    AuthenticatedAdmin, DEPLOYMENT_MODE,
};
use axum::response::{Html, IntoResponse, Response};
use maud::html;

pub(crate) fn render(
    auth: &AuthenticatedAdmin,
    db_ready: bool,
    cookie_secure: bool,
    host: &HostSnapshot,
) -> Response {
    Html(
            layout(
                "System",
                html! {
                    (admin_bar(auth))
                    h1 { "System" }

                    div class="status-strip" {
                        div class="metric" {
                            span { "Deploy mode" }
                            strong { (DEPLOYMENT_MODE) }
                        }
                        div class="metric" {
                            span { "Version" }
                            strong { (env!("CARGO_PKG_VERSION")) }
                        }
                        div class="metric" {
                            span { "Database" }
                            strong {
                                @if db_ready {
                                    "ready"
                                } @else {
                                    "not ready"
                                }
                            }
                        }
                        div class="metric" {
                            span { "Cookie Secure" }
                            strong {
                                @if cookie_secure {
                                    "enabled"
                                } @else {
                                    "disabled"
                                }
                            }
                        }
                    }

                    section {
                        h2 { "Host overview" }
                        div class="sys-grid" {
                            div class="sys-card" {
                                span { "OS" }
                                strong { (&host.os_name) }
                                small { "Kernel " (&host.kernel) }
                            }
                            div class="sys-card" {
                                span { "Uptime" }
                                strong { (&host.uptime) }
                                small { "Load " (&host.load_average) }
                            }
                            div class="sys-card" {
                                span { "Memory" }
                                strong { (&host.memory_label) }
                                (meter_bar(host.memory_used_percent))
                            }
                            div class="sys-card" {
                                span { "Root disk" }
                                strong { (&host.disk_label) }
                                (meter_bar(host.disk_used_percent))
                            }
                        }
                    }

                    section {
                        h2 { "Runtime contract" }
                        dl class="details" {
                            dt { "Binary" }
                            dd { code { "/usr/local/bin/infiproxy" } }
                            dt { "Environment" }
                            dd { code { "/etc/infiproxy/infiproxy.env" } }
                            dt { "Database" }
                            dd { code { "/var/lib/infiproxy/infiproxy.sqlite" } }
                            dt { "Service" }
                            dd { code { "infiproxy.service" } }
                        }
                    }

                    section {
                        h2 { "VPS install path" }
                        dl class="details" {
                            dt { "Build" }
                            dd { code { "cargo build --release -p stealthhub-panel" } }
                            dt { "Install" }
                            dd { code { "sudo bash deploy/install.sh" } }
                            dt { "Reverse proxy" }
                            dd { code { "deploy/nginx-infiproxy.conf.example" } }
                            dt { "Core updates" }
                            dd { code { "sudo deploy/cores/install-core.sh --core <name> --version <version> --url <url> --sha256 <sha256> --binary <binary>" } }
                        }
                    }

                    section {
                        h2 { "Service control" }
                        div class="notice" {
                            "Only built-in allowlisted commands are available here. Actions require OS-level permission for the panel service user."
                        }
                        div class="table-wrap" {
                            table {
                                thead {
                                    tr {
                                        th { "Target" }
                                        th { "State" }
                                        th { "Kind" }
                                        th { "Unit" }
                                        th { "Config" }
                                        th { "Check" }
                                        th { "Action" }
                                    }
                                }
                                tbody {
                                    @for target in SYSTEM_TARGETS {
                                        @let state = service_state(target.units);
                                        tr {
                                            td { strong { (target.name) } }
                                            td { (service_state_badge(&state)) }
                                            td { span class="badge neutral" { (target.kind) } }
                                            td { code { (target.unit) } }
                                            td { code { (target.config) } }
                                            td { code { (target.check) } }
                                            td {
                                                form method="post" action="/admin/system/action" class="inline-form" {
                                                    (csrf_field(&auth.csrf_token))
                                                    input type="hidden" name="target" value=(target.slug);
                                                    button class=(if target.slug == "panel" { "danger" } else { "" }) type="submit" { (target.action_label) }
                                                }
                                                br;
                                                code { (target.reload) }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }

                    section {
                        h2 { "Configuration workspace" }
                        div class="notice" {
                            "Full editor moved to the Configs tab. This table stays as a quick operational map."
                        }
                        div class="table-wrap" {
                            table {
                                thead {
                                    tr {
                                        th { "Config" }
                                        th { "Path" }
                                        th { "Validation" }
                                        th { "Reload" }
                                    }
                                }
                                tbody {
                                    tr {
                                        td { "Panel environment" }
                                        td { code { "/etc/infiproxy/infiproxy.env" } }
                                        td { code { "systemctl show infiproxy.service" } }
                                        td { code { "systemctl restart infiproxy.service" } }
                                    }
                                    tr {
                                        td { "Nginx reverse proxy" }
                                        td { code { "/etc/nginx/sites-available/infiproxy.conf" } }
                                        td { code { "nginx -t" } }
                                        td { code { "systemctl reload nginx.service" } }
                                    }
                                    tr {
                                        td { "SSH daemon" }
                                        td { code { "/etc/ssh/sshd_config" } }
                                        td { code { "sshd -t" } }
                                        td { code { "systemctl reload ssh.service" } }
                                    }
                                    tr {
                                        td { "Proxy cores" }
                                        td { code { "/etc/infiproxy-cores/{xray,sing-box,hysteria,tuic}" } }
                                        td { code { "<core> check / --version" } }
                                        td { code { "systemctl restart infiproxy-<core>.service" } }
                                    }
                                }
                            }
                        }
                    }

                    section {
                        h2 { "Bare server bootstrap" }
                        div class="runbook" {
                            ol {
                                li { "Install panel with " code { "deploy/bootstrap.sh" } " and bind it to localhost behind HTTPS." }
                                li { "Create admin, set subscription domain, node domain and cookie secure mode." }
                                li { "Install verified proxy cores into " code { "/opt/infiproxy/cores/{core}/{version}" } "." }
                                li { "Activate " code { "current" } " symlinks and enable only the core services you use." }
                                li { "Edit core configs under " code { "/etc/infiproxy-cores" } " and validate before reload." }
                            }
                        }
                    }

                    section class="danger-zone" {
                        h2 { "Uninstall planner" }
                        div class="notice error" {
                            "Owner-only destructive area. Panel-only removes only the control plane. Full footprint also removes panel-managed cores, configs, logs and nginx site files."
                        }
                        div class="actions" {
                            form method="post" action="/admin/system/uninstall-preview" class="inline-form" {
                                (csrf_field(&auth.csrf_token))
                                input type="hidden" name="mode" value="panel";
                                button type="submit" class="danger" { "Preview panel-only removal" }
                            }
                            form method="post" action="/admin/system/uninstall-preview" class="inline-form" {
                                (csrf_field(&auth.csrf_token))
                                input type="hidden" name="mode" value="full";
                                button type="submit" class="danger" { "Preview full footprint removal" }
                            }
                            form method="post" action="/admin/system/uninstall-preview" class="inline-form" {
                                (csrf_field(&auth.csrf_token))
                                input type="hidden" name="mode" value="factory";
                                button type="submit" class="danger" { "Preview factory footprint cleanup" }
                            }
                        }
                        div class="notice" {
                            "Execution is intentionally available only in the root SSH manager: "
                            code { "sudo infiproxy-manager" }
                            ". The web panel never exposes a raw shell."
                        }
                    }

                    section {
                        h2 { "Health checks" }
                        ul {
                            li { code { "/health" } " returns process liveness." }
                            li { code { "/ready" } " checks SQLite connectivity." }
                        }
                    }

                },
            )
            .into_string(),
        )
        .into_response()
}

pub(crate) fn render_action(
    auth: &AuthenticatedAdmin,
    target: &SystemTarget,
    report: &SystemActionReport,
) -> Response {
    let ok = report.steps.iter().all(|step| step.success);
    Html(
        layout(
            "System action",
            html! {
                (admin_bar(auth))
                h1 { "System action" }
                section {
                    h2 { (target.name) }
                    div class=(if ok { "notice" } else { "notice error" }) {
                        @if ok { "Action completed." } @else { "Action failed. Review command output below." }
                    }
                    div class="config-list" {
                        @for step in &report.steps { (command_result(step)) }
                    }
                    a class="button" href="/admin/system" { "Back to System" }
                }
            },
        )
        .into_string(),
    )
    .into_response()
}

pub(crate) fn render_uninstall(auth: &AuthenticatedAdmin, plan: &UninstallPlan) -> Response {
    Html(
        layout(
            "Uninstall preview",
            html! {
                (admin_bar(auth))
                h1 { "Uninstall preview" }
                section class="danger-zone" {
                    h2 { (plan.title) }
                    div class="notice error" { (plan.warning) }
                    div class="command-output" {
                        strong { "review-only command runbook" }
                        pre { (plan.commands.join("\n")) }
                    }
                    a class="button" href="/admin/system" { "Back to System" }
                }
            },
        )
        .into_string(),
    )
    .into_response()
}

fn command_result(step: &CommandStep) -> maud::Markup {
    html! {
        div class="config-row" {
            div class="config-row-head" {
                h3 { code { (&step.command) } }
                @if step.success { span class="badge ok" { "ok" } }
                @else { span class="badge off" { "failed" } }
            }
            div class="command-output" {
                @if !step.stdout.is_empty() { strong { "stdout" } pre { (&step.stdout) } }
                @if !step.stderr.is_empty() { strong { "stderr" } pre { (&step.stderr) } }
                @if step.stdout.is_empty() && step.stderr.is_empty() { small { "No output." } }
            }
        }
    }
}
