//! IP reputation and diagnostics page.
//!
//! The panel does not call third-party reputation providers automatically. It
//! classifies the submitted IP locally and renders operator links to external
//! databases so checks stay explicit, cache-free and API-key-free by default.

use axum::{
    extract::{Query, State},
    http::HeaderMap,
    response::{Html, IntoResponse, Response},
};
use maud::{html, Markup};
use serde::Deserialize;
use std::net::IpAddr;

use crate::{
    admin_bar,
    ops::{run_first_success_owned, CommandStep, IP_REPUTATION_SOURCES},
    percent_encode, require_admin,
    ui::layout,
    AppState,
};

#[derive(Debug, Deserialize)]
pub(crate) struct IpCheckQuery {
    ip: Option<String>,
}

pub(crate) async fn ip_check_page(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<IpCheckQuery>,
) -> Response {
    let auth = match require_admin(&state, &headers).await {
        Ok(value) => value,
        Err(response) => return response,
    };

    let raw_ip = query.ip.unwrap_or_default();
    let trimmed_ip = raw_ip.trim();
    let parsed_ip = if trimmed_ip.is_empty() {
        None
    } else {
        Some(trimmed_ip.parse::<IpAddr>())
    };

    Html(
        layout(
            "IP Check",
            html! {
                (admin_bar(&auth))
                h1 { "IP Check" }

                section {
                    h2 { "Address lookup" }
                    form method="get" action="/admin/ip" class="form" {
                        label {
                            span { "IP address" }
                            input type="text" name="ip" value=(trimmed_ip) placeholder="203.0.113.10 or 2001:db8::1" required;
                        }
                        button type="submit" { "Analyze IP" }
                    }
                }

                @match parsed_ip {
                    Some(Ok(ip)) => {
                        (ip_summary_panel(ip))
                        (ip_reputation_panel(ip))
                        (ip_speed_panel(ip))
                    },
                    Some(Err(_)) => {
                        section {
                            h2 { "Result" }
                            div class="notice error" {
                                "Invalid IP address. Enter a valid IPv4 or IPv6 literal."
                            }
                        }
                    },
                    None => {
                        section {
                            h2 { "Workflow" }
                            div class="notice" {
                                "Enter a server IP to get local classification, PTR lookup, routing context links, reputation database links and speed-test runbooks."
                            }
                        }
                    },
                }
            },
        )
        .into_string(),
    )
    .into_response()
}

fn ip_summary_panel(ip: IpAddr) -> Markup {
    let ptr = reverse_lookup_step(ip);
    let route = route_lookup_step(ip);

    html! {
        section {
            h2 { "Local diagnostics" }
            div class="status-strip compact-status" {
                div class="metric" {
                    span { "Address" }
                    strong { (ip.to_string()) }
                }
                div class="metric" {
                    span { "Version" }
                    strong { (ip_version(ip)) }
                }
                div class="metric" {
                    span { "Scope" }
                    strong { (ip_scope(ip)) }
                }
                div class="metric" {
                    span { "Risk note" }
                    strong { (ip_risk_note(ip)) }
                }
            }
            div class="config-list" {
                (command_step_view("Reverse DNS", &ptr))
                (command_step_view("Route selection", &route))
            }
        }
    }
}

fn ip_reputation_panel(ip: IpAddr) -> Markup {
    let ip = ip.to_string();
    let encoded = percent_encode(&ip);

    html! {
        section {
            h2 { "Reputation databases" }
            div class="notice" {
                "These links open third-party databases in your browser. Automated checks require provider API keys and should be cached server-side to avoid rate limits."
            }
            div class="table-wrap" {
                table {
                    thead {
                        tr {
                            th { "Source" }
                            th { "Scope" }
                            th { "Lookup" }
                        }
                    }
                    tbody {
                        @for source in IP_REPUTATION_SOURCES {
                            tr {
                                td { strong { (source.name) } }
                                td { (source.scope) }
                                td {
                                    a class="button compact" href=(source.url_template.replace("{ip}", &encoded)) rel="noreferrer" {
                                        "Open"
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

fn ip_speed_panel(ip: IpAddr) -> Markup {
    html! {
        section {
            h2 { "Speed diagnostics" }
            div class="notice" {
                "Speed tests are intentionally operator-run. This avoids background traffic spikes and lets you choose the closest test endpoint."
            }
            div class="table-wrap" {
                table {
                    thead {
                        tr {
                            th { "Check" }
                            th { "Command / action" }
                            th { "Use" }
                        }
                    }
                    tbody {
                        tr {
                            td { "TCP latency" }
                            td { code { (format!("ping -c 5 {}", ip)) } }
                            td { "Quick packet loss and RTT baseline." }
                        }
                        tr {
                            td { "HTTP download" }
                            td { code { "curl -L -o /dev/null -w 'time=%{time_total} speed=%{speed_download}\\n' <test-file-url>" } }
                            td { "Measure throughput against a chosen regional endpoint." }
                        }
                        tr {
                            td { "iperf3" }
                            td { code { "iperf3 -c <trusted-server> -P 4 -t 15" } }
                            td { "Best controlled bandwidth measurement when you own both sides." }
                        }
                        tr {
                            td { "MTR" }
                            td { code { (format!("mtr -rwzc 50 {}", ip)) } }
                            td { "Find packet loss or bad transit hops." }
                        }
                    }
                }
            }
        }
    }
}

fn command_step_view(title: &'static str, step: &CommandStep) -> Markup {
    html! {
        div class="config-row" {
            div class="config-row-head" {
                h3 { (title) }
                @if step.success {
                    span class="badge ok" { "ok" }
                } @else {
                    span class="badge neutral" { "unavailable" }
                }
            }
            div class="command-output compact-output" {
                code { (&step.command) }
                @if !step.stdout.is_empty() {
                    pre { (&step.stdout) }
                } @else if !step.stderr.is_empty() {
                    pre { (&step.stderr) }
                } @else {
                    small { "No output." }
                }
            }
        }
    }
}

fn reverse_lookup_step(ip: IpAddr) -> CommandStep {
    run_first_success_owned(&[
        ("host", vec![ip.to_string()]),
        (
            "dig",
            vec!["+short".to_string(), "-x".to_string(), ip.to_string()],
        ),
    ])
}

fn route_lookup_step(ip: IpAddr) -> CommandStep {
    run_first_success_owned(&[
        (
            "ip",
            vec!["route".to_string(), "get".to_string(), ip.to_string()],
        ),
        (
            "route",
            vec!["-n".to_string(), "get".to_string(), ip.to_string()],
        ),
    ])
}

fn ip_version(ip: IpAddr) -> &'static str {
    match ip {
        IpAddr::V4(_) => "IPv4",
        IpAddr::V6(_) => "IPv6",
    }
}

pub(crate) fn ip_scope(ip: IpAddr) -> &'static str {
    match ip {
        IpAddr::V4(value) if value.is_private() => "private",
        IpAddr::V4(value) if value.is_loopback() => "loopback",
        IpAddr::V4(value) if value.is_link_local() => "link-local",
        IpAddr::V4(value) if value.is_multicast() => "multicast",
        IpAddr::V4(value) if value.is_documentation() => "documentation",
        IpAddr::V4(value) if value.is_unspecified() => "unspecified",
        IpAddr::V6(value) if value.is_loopback() => "loopback",
        IpAddr::V6(value) if value.is_unique_local() => "unique-local",
        IpAddr::V6(value) if value.is_unicast_link_local() => "link-local",
        IpAddr::V6(value) if value.is_multicast() => "multicast",
        IpAddr::V6(value) if value.is_unspecified() => "unspecified",
        _ => "public",
    }
}

fn ip_risk_note(ip: IpAddr) -> &'static str {
    match ip_scope(ip) {
        "public" => "check reputation",
        "private" | "unique-local" | "loopback" | "link-local" => "local-only",
        "documentation" => "test range",
        _ => "not routable",
    }
}
