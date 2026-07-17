//! Unit tests for panel security boundaries and formatting helpers.
//!
//! Tests live outside `main.rs` so route handlers remain readable while private
//! module items can still be exercised through Rust's sibling test module rules.

#![cfg(test)]

use super::*;
use crate::{health, ip, modules};
use axum::http::{header, HeaderMap};
use chrono::{Duration, Utc};
use std::collections::HashSet;
use stealthhub_core::storage::{AdminRecord, UserRecord};

fn test_user() -> UserRecord {
    let now = Utc::now();

    UserRecord {
        id: 1,
        username: "alice".to_string(),
        uuid: "11111111-1111-4111-8111-111111111111".to_string(),
        subscription_token: "token".to_string(),
        enabled: true,
        traffic_limit_bytes: None,
        traffic_used_bytes: 0,
        expires_at: None,
        created_at: now,
        updated_at: now,
    }
}

fn test_admin(id: i64) -> AdminRecord {
    let now = Utc::now();

    AdminRecord {
        id,
        username: format!("admin-{id}"),
        password_hash: "hash".to_string(),
        created_at: now,
        updated_at: now,
    }
}

#[test]
fn csrf_token_is_derived_from_session_token() {
    let session_token = "session-token";
    let csrf_token = csrf_token_for_session_token(session_token);

    assert_eq!(csrf_token, csrf_token_for_session_token(session_token));
    assert_ne!(csrf_token, session_token);
    assert_ne!(
        csrf_token,
        csrf_token_for_session_token("other-session-token")
    );
}

#[test]
fn owner_admin_is_first_created_admin() {
    let owner = AuthenticatedAdmin {
        admin: test_admin(1),
        csrf_token: "csrf".to_string(),
        update_notice: None,
    };
    let regular = AuthenticatedAdmin {
        admin: test_admin(2),
        csrf_token: "csrf".to_string(),
        update_notice: None,
    };

    assert!(is_owner_admin(&owner));
    assert!(!is_owner_admin(&regular));
}

#[test]
fn login_rate_limiter_blocks_after_failures_and_clears_on_success() {
    let limiter = LoginRateLimiter::default();
    let keys = vec!["username:admin".to_string()];

    for _ in 0..LOGIN_RATE_LIMIT_MAX_FAILURES {
        assert!(limiter.retry_after(&keys).is_none());
        limiter.record_failure(&keys);
    }

    assert!(limiter.retry_after(&keys).is_some());
    limiter.record_success(&keys);
    assert!(limiter.retry_after(&keys).is_none());
}

#[test]
fn login_rate_limit_keys_normalize_username_and_source() {
    let mut headers = HeaderMap::new();
    headers.insert(
        "x-forwarded-for",
        " 203.0.113.10, 10.0.0.1".parse().unwrap(),
    );

    let peer_addr = "127.0.0.1:42300".parse().unwrap();

    assert_eq!(
        login_rate_limit_keys(&headers, peer_addr, " Admin "),
        vec![
            "username:admin".to_string(),
            "source:203.0.113.10".to_string()
        ]
    );
}

#[test]
fn login_rate_limit_keys_ignore_forwarded_source_from_non_loopback_peer() {
    let mut headers = HeaderMap::new();
    headers.insert("x-real-ip", "203.0.113.10".parse().unwrap());
    let peer_addr = "198.51.100.20:42300".parse().unwrap();

    assert_eq!(
        login_rate_limit_keys(&headers, peer_addr, "admin"),
        vec![
            "username:admin".to_string(),
            "source:198.51.100.20".to_string()
        ]
    );
}

#[test]
fn login_rate_limit_keys_ignore_invalid_forwarded_source() {
    let mut headers = HeaderMap::new();
    headers.insert("x-forwarded-for", "not-an-ip".parse().unwrap());
    let peer_addr = "127.0.0.1:42300".parse().unwrap();

    assert_eq!(
        login_rate_limit_keys(&headers, peer_addr, "admin"),
        vec!["username:admin".to_string(), "source:127.0.0.1".to_string()]
    );
}

#[test]
fn subscription_block_reason_enforces_user_state() {
    let mut user = test_user();
    assert!(subscription_block_reason(&user).is_none());

    user.enabled = false;
    assert_eq!(
        subscription_block_reason(&user),
        Some("subscription disabled")
    );

    user.enabled = true;
    user.expires_at = Some(Utc::now() - Duration::days(1));
    assert_eq!(
        subscription_block_reason(&user),
        Some("subscription expired")
    );

    user.expires_at = None;
    user.traffic_limit_bytes = Some(1024);
    user.traffic_used_bytes = 1024;
    assert_eq!(
        subscription_block_reason(&user),
        Some("traffic limit reached")
    );
}

#[test]
fn mihomo_import_url_percent_encodes_values() {
    let import_url = mihomo_import_url(
        "Infiproxy",
        "alice phone",
        "https://sub.example.test/sub/token/mihomo.yaml",
    );

    assert!(import_url.starts_with("clash://install-config?url=https%3A%2F%2F"));
    assert!(import_url.contains("&name=Infiproxy%20-%20alice%20phone"));
}

#[test]
fn system_helpers_format_safe_values() {
    assert_eq!(percent(50, 100), Some(50));
    assert_eq!(percent(1, 0), None);
    assert_eq!(format_duration(65), "1m");
    assert_eq!(format_duration(3_900), "1h 5m");
    assert_eq!(format_duration(90_000), "1d 1h 0m");
}

#[test]
fn update_schedule_accepts_only_complete_24_hour_times() {
    assert_eq!(update::parse_schedule_time("05:00"), Some((5, 0)));
    assert_eq!(update::parse_schedule_time("23:59"), Some((23, 59)));
    assert_eq!(update::parse_schedule_time("5:00"), None);
    assert_eq!(update::parse_schedule_time("24:00"), None);
    assert_eq!(update::parse_schedule_time("12:60"), None);
}

#[test]
fn command_output_trimming_preserves_utf8() {
    let input = "ж".repeat(4_200);
    let output = trim_command_output(&input);

    assert!(output.ends_with("... <truncated>"));
    assert!(output.is_char_boundary(output.len()));
}

#[test]
fn health_content_negotiation_only_html_for_browsers() {
    let mut headers = HeaderMap::new();
    assert!(!health::wants_html(&headers));

    headers.insert(header::ACCEPT, "*/*".parse().unwrap());
    assert!(!health::wants_html(&headers));

    headers.insert(
        header::ACCEPT,
        "text/html,application/xhtml+xml".parse().unwrap(),
    );
    assert!(health::wants_html(&headers));
}

#[test]
fn console_commands_are_allowlisted_without_shell() {
    assert!(CONSOLE_COMMANDS
        .iter()
        .all(|command| command.program != "sh"));
    assert!(CONSOLE_COMMANDS
        .iter()
        .all(|command| command.program != "bash"));
    assert!(CONSOLE_COMMANDS
        .iter()
        .all(|command| !command.args.iter().any(|arg| arg.contains(';'))));
}

#[test]
fn uninstall_plans_are_preview_runbooks() {
    let panel = uninstall_plan("panel").expect("panel plan exists");
    let full = uninstall_plan("full").expect("full plan exists");
    let factory = uninstall_plan("factory").expect("factory plan exists");

    assert!(panel.title.contains("Panel-only"));
    assert!(full.title.contains("Full"));
    assert!(factory.title.contains("Factory"));
    assert!(full.shell_script().contains("infiproxy-mtproto.service"));
    assert!(factory.shell_script().contains("infiproxy-mtproto.service"));
    assert!(full.shell_script().contains("headscale.service"));
    assert!(factory.shell_script().contains("headscale.service"));
    assert!(factory.shell_script().contains("infiproxy-manager"));
    assert!(uninstall_plan("unknown").is_none());
}

#[test]
fn app_uptime_has_safe_fallback() {
    assert!(!health::app_uptime_label().is_empty());
}

#[test]
fn ip_scope_classifies_common_ranges() {
    assert_eq!(ip::ip_scope("127.0.0.1".parse().unwrap()), "loopback");
    assert_eq!(ip::ip_scope("10.0.0.1".parse().unwrap()), "private");
    assert_eq!(ip::ip_scope("192.0.2.10".parse().unwrap()), "documentation");
    assert_eq!(ip::ip_scope("1.1.1.1".parse().unwrap()), "public");
}

#[test]
fn reputation_sources_have_ip_templates() {
    assert!(IP_REPUTATION_SOURCES.len() >= 10);
    assert!(IP_REPUTATION_SOURCES
        .iter()
        .all(|source| source.url_template.contains("{ip}")));
}

#[test]
fn config_editor_targets_are_allowlisted_and_unique() {
    let mut slugs = HashSet::new();

    for spec in CONFIG_FILES {
        assert!(slugs.insert(spec.slug));
        assert!(spec.path.starts_with("/etc/"));
        assert!(spec.max_bytes <= 256 * 1024);
    }

    assert!(CONFIG_FILES.len() >= modules::MODULES.len());
}

#[test]
fn mtproto_runtime_is_wired_into_panel_contracts() {
    assert!(modules::MODULES
        .iter()
        .any(|module| module.service == "infiproxy-mtproto.service"
            && module.binary_path.ends_with("/mtproto-proxy")));
    assert!(SYSTEM_TARGETS.iter().any(|target| target.slug == "mtproto"
        && target.units == ["infiproxy-mtproto.service"].as_slice()));
    assert!(CONFIG_FILES.iter().any(|spec| spec.slug == "mtproto-core"
        && spec.path == "/etc/infiproxy-cores/mtproto/mtproto.env"));
    assert!(CONSOLE_COMMANDS
        .iter()
        .any(|command| command.slug == "mtproto-logs"
            && command.args.contains(&"infiproxy-mtproto.service")));
}

#[test]
fn headscale_module_is_wired_into_panel_contracts() {
    assert!(modules::MODULES
        .iter()
        .any(|module| module.id == "headscale"
            && module.service == "headscale.service"
            && module.binary_path.ends_with("/headscale")));
    assert!(SYSTEM_TARGETS.iter().any(
        |target| target.slug == "headscale" && target.units == ["headscale.service"].as_slice()
    ));
    assert!(CONFIG_FILES
        .iter()
        .any(|spec| spec.slug == "headscale-config" && spec.path == "/etc/headscale/config.yaml"));
    assert!(CONFIG_FILES
        .iter()
        .any(|spec| spec.slug == "headscale-nginx"
            && spec.path == "/etc/nginx/sites-available/infiproxy-headscale.conf"));
    assert!(CONSOLE_COMMANDS
        .iter()
        .any(|command| command.slug == "headscale-logs"
            && command.args.contains(&"headscale.service")));
}

#[test]
fn config_editor_rejects_unknown_targets() {
    let report = write_config_file("../etc/passwd", "nope");

    assert!(!report.success);
    assert_eq!(report.message, "unknown config target");
}

#[tokio::test]
async fn danger_shell_rejects_empty_commands() {
    let step = run_danger_shell("   ").await;

    assert!(!step.success);
    assert_eq!(step.stderr, "command is empty");
}
