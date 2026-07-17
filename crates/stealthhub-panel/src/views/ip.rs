//! IP diagnostics presentation.

use crate::{
    admin_bar,
    ip::{ip_risk_note, ip_scope, ip_version, Diagnostics},
    ops::{CommandStep, IP_REPUTATION_SOURCES},
    percent_encode,
    ui::layout,
    AuthenticatedAdmin,
};
use axum::response::{Html, IntoResponse, Response};
use maud::{html, Markup};
use std::net::IpAddr;

pub(crate) fn render(
    auth: &AuthenticatedAdmin,
    raw_ip: &str,
    result: Option<Result<Diagnostics, ()>>,
) -> Response {
    Html(
        layout(
            "IP Check",
            html! {
                (admin_bar(auth))
                h1 { "IP Check" }
                section {
                    h2 { "Address lookup" }
                    form method="get" action="/admin/ip" class="form" {
                        label {
                            span { "IP address" }
                            input type="text" name="ip" value=(raw_ip) placeholder="203.0.113.10 or 2001:db8::1" required;
                        }
                        button type="submit" { "Analyze IP" }
                    }
                }
                @match result {
                    Some(Ok(diagnostics)) => {
                        (summary_panel(&diagnostics))
                        (reputation_panel(diagnostics.ip))
                        (speed_panel(diagnostics.ip))
                    },
                    Some(Err(())) => section {
                        h2 { "Result" }
                        div class="notice error" { "Invalid IP address. Enter a valid IPv4 or IPv6 literal." }
                    },
                    None => section {
                        h2 { "Workflow" }
                        div class="notice" {
                            "Enter a server IP to get local classification, PTR lookup, routing context links, reputation database links and speed-test runbooks."
                        }
                    },
                }
            },
        )
        .into_string(),
    )
    .into_response()
}

fn summary_panel(diagnostics: &Diagnostics) -> Markup {
    let ip = diagnostics.ip;
    html! {
        section {
            h2 { "Local diagnostics" }
            div class="status-strip compact-status" {
                div class="metric" { span { "Address" } strong { (ip) } }
                div class="metric" { span { "Version" } strong { (ip_version(ip)) } }
                div class="metric" { span { "Scope" } strong { (ip_scope(ip)) } }
                div class="metric" { span { "Risk note" } strong { (ip_risk_note(ip)) } }
            }
            div class="config-list" {
                (command_step("Reverse DNS", &diagnostics.ptr))
                (command_step("Route selection", &diagnostics.route))
            }
        }
    }
}

fn reputation_panel(ip: IpAddr) -> Markup {
    let encoded = percent_encode(&ip.to_string());
    html! {
        section {
            h2 { "Reputation databases" }
            div class="notice" {
                "These links open third-party databases in your browser. Automated checks require provider API keys and should be cached server-side to avoid rate limits."
            }
            div class="table-wrap" {
                table {
                    thead { tr { th { "Source" } th { "Scope" } th { "Lookup" } } }
                    tbody {
                        @for source in IP_REPUTATION_SOURCES {
                            tr {
                                td { strong { (source.name) } }
                                td { (source.scope) }
                                td {
                                    a class="button compact" href=(source.url_template.replace("{ip}", &encoded)) rel="noreferrer" { "Open" }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

fn speed_panel(ip: IpAddr) -> Markup {
    html! {
        section {
            h2 { "Speed diagnostics" }
            div class="notice" { "Speed tests are operator-run to avoid background traffic spikes." }
            div class="table-wrap" {
                table {
                    thead { tr { th { "Check" } th { "Command / action" } th { "Use" } } }
                    tbody {
                        tr { td { "TCP latency" } td { code { (format!("ping -c 5 {ip}")) } } td { "Quick packet loss and RTT baseline." } }
                        tr { td { "HTTP download" } td { code { "curl -L -o /dev/null -w 'time=%{time_total} speed=%{speed_download}\\n' <test-file-url>" } } td { "Measure throughput against a chosen regional endpoint." } }
                        tr { td { "iperf3" } td { code { "iperf3 -c <trusted-server> -P 4 -t 15" } } td { "Controlled bandwidth measurement." } }
                        tr { td { "MTR" } td { code { (format!("mtr -rwzc 50 {ip}")) } } td { "Find packet loss or bad transit hops." } }
                    }
                }
            }
        }
    }
}

fn command_step(title: &'static str, step: &CommandStep) -> Markup {
    html! {
        div class="config-row" {
            div class="config-row-head" {
                h3 { (title) }
                @if step.success { span class="badge ok" { "ok" } }
                @else { span class="badge neutral" { "unavailable" } }
            }
            div class="command-output compact-output" {
                code { (&step.command) }
                @if !step.stdout.is_empty() { pre { (&step.stdout) } }
                @else if !step.stderr.is_empty() { pre { (&step.stderr) } }
                @else { small { "No output." } }
            }
        }
    }
}
