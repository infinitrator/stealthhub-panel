//! IP reputation and diagnostics page.
//!
//! The panel does not call third-party reputation providers automatically. It
//! classifies the submitted IP locally and renders operator links to external
//! databases so checks stay explicit, cache-free and API-key-free by default.

use axum::{
    extract::{Query, State},
    http::HeaderMap,
    response::Response,
};
use serde::Deserialize;
use std::net::IpAddr;

use crate::{
    ops::{run_first_success_owned, CommandStep},
    require_admin, views, AppState,
};

#[derive(Debug, Deserialize)]
pub(crate) struct IpCheckQuery {
    ip: Option<String>,
}

#[derive(Debug)]
pub(crate) struct Diagnostics {
    pub(crate) ip: IpAddr,
    pub(crate) ptr: CommandStep,
    pub(crate) route: CommandStep,
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
    let result = if trimmed_ip.is_empty() {
        None
    } else {
        Some(
            trimmed_ip
                .parse::<IpAddr>()
                .map(|ip| Diagnostics {
                    ip,
                    ptr: reverse_lookup_step(ip),
                    route: route_lookup_step(ip),
                })
                .map_err(|_| ()),
        )
    };
    views::ip::render(&auth, trimmed_ip, result)
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

pub(crate) fn ip_version(ip: IpAddr) -> &'static str {
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

pub(crate) fn ip_risk_note(ip: IpAddr) -> &'static str {
    match ip_scope(ip) {
        "public" => "check reputation",
        "private" | "unique-local" | "loopback" | "link-local" => "local-only",
        "documentation" => "test range",
        _ => "not routable",
    }
}
