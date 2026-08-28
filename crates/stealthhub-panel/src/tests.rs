//! Unit tests for panel security boundaries and formatting helpers.
//!
//! Tests live outside `main.rs` so route handlers remain readable while private
//! module items can still be exercised through Rust's sibling test module rules.

#![cfg(test)]

use super::*;
use crate::{
    health, ip, modules,
    ops::{format_duration, percent, trim_command_output, IP_REPUTATION_SOURCES},
};
use axum::http::HeaderMap;
use chrono::{Duration, Utc};
use std::collections::{BTreeSet, HashSet};
use stealthhub_core::{
    inventory::{
        AdapterInventory, AdapterInventoryEntry, AdapterInventoryState, RuntimeInventoryEntry,
        RuntimeInventoryState,
    },
    storage::{AdminRecord, UserRecord},
};

fn fixture_user() -> UserRecord {
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
        is_owner: true,
        csrf_token: "csrf".to_string(),
        update_notice: None,
    };
    let regular = AuthenticatedAdmin {
        admin: test_admin(2),
        is_owner: false,
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
    headers.insert("x-real-ip", "203.0.113.10".parse().unwrap());

    let peer_addr = "127.0.0.1:42300".parse().unwrap();

    assert_eq!(
        login_rate_limit_keys(&headers, peer_addr, " Admin "),
        vec![
            "source:203.0.113.10".to_string(),
            "account-source:admin@203.0.113.10".to_string()
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
            "source:198.51.100.20".to_string(),
            "account-source:admin@198.51.100.20".to_string()
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
        vec![
            "source:127.0.0.1".to_string(),
            "account-source:admin@127.0.0.1".to_string()
        ]
    );
}

#[test]
fn login_rate_limit_keys_never_trust_x_forwarded_for() {
    let mut headers = HeaderMap::new();
    headers.insert("x-forwarded-for", "203.0.113.10".parse().unwrap());
    let peer_addr = "127.0.0.1:42300".parse().unwrap();

    assert_eq!(
        login_rate_limit_keys(&headers, peer_addr, "admin"),
        vec![
            "source:127.0.0.1".to_string(),
            "account-source:admin@127.0.0.1".to_string()
        ]
    );
}

#[test]
fn account_names_are_bounded_and_shell_safe() {
    assert!(valid_account_name("owner.admin-1", 3));
    assert!(valid_account_name("a", 1));
    assert!(!valid_account_name("-admin", 3));
    assert!(!valid_account_name("admin name", 3));
    assert!(!valid_account_name("админ", 3));
    assert!(!valid_account_name(&"a".repeat(65), 1));
}

#[test]
fn public_hosts_accept_urls_without_ambiguous_authority() {
    assert_eq!(
        normalize_public_host("Panel.Example.COM."),
        Ok("panel.example.com".to_string())
    );
    assert_eq!(
        normalize_public_host("127.0.0.1:8443"),
        Ok("127.0.0.1:8443".to_string())
    );
    assert_eq!(
        normalize_public_host("[2001:db8::1]:443"),
        Ok("[2001:db8::1]:443".to_string())
    );
    assert!(normalize_public_host("https://example.com").is_err());
    assert!(normalize_public_host("_service.example.com").is_err());
    assert!(normalize_public_host("-bad.example.com").is_err());
    assert!(normalize_public_host("example.com:0").is_err());
    assert!(normalize_public_host("2001:db8::1").is_err());
}

#[test]
fn protocol_servers_are_host_only_and_accept_bare_ipv6() {
    assert_eq!(
        normalize_profile_server("Node.Example.COM."),
        Ok("node.example.com".to_string())
    );
    assert_eq!(
        normalize_profile_server("2001:db8::1"),
        Ok("2001:db8::1".to_string())
    );
    assert!(normalize_profile_server("node.example.com:443").is_err());
    assert!(normalize_profile_server("https://node.example.com").is_err());
}

#[test]
fn protocol_secret_references_and_paths_fail_closed() {
    assert_eq!(
        SecretRef::parse("xray.reality.public_key")
            .unwrap()
            .as_str(),
        "xray.reality.public_key"
    );
    assert!(SecretRef::parse("../secret").is_err());
    assert_eq!(
        normalize_profile_server("WWW.Example.COM.").unwrap(),
        "www.example.com"
    );
    assert!(normalize_profile_server("example.com:443").is_err());
    assert!(normalize_profile_server("example com").is_err());
}

#[test]
fn server_only_secret_references_cannot_enter_web_storage() {
    let registry = stealthhub_core::adapters::protocol_registry().unwrap();
    let profiles = stealthhub_core::adapters::default_profiles();
    assert!(is_server_only_secret_reference(
        "xray.reality.private_key",
        &profiles,
        &registry
    ));
    assert!(!is_server_only_secret_reference(
        "xray.reality.public_key",
        &profiles,
        &registry
    ));
    assert!(!is_server_only_secret_reference(
        "hysteria.password",
        &profiles,
        &registry
    ));
}

#[test]
fn secret_names_are_bounded_and_path_independent() {
    assert!(valid_secret_name("xray.reality.private_key"));
    assert!(!valid_secret_name(""));
    assert!(!valid_secret_name("../secret"));
    assert!(!valid_secret_name("secret/name"));
}

#[test]
fn subscription_block_reason_enforces_user_state() {
    let mut user = fixture_user();
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
fn uninstall_plans_are_preview_runbooks() {
    let panel = uninstall_plan("panel").expect("panel plan exists");
    let full = uninstall_plan("full").expect("full plan exists");
    let factory = uninstall_plan("factory").expect("factory plan exists");

    assert!(panel.title.contains("Panel-only"));
    assert!(full.title.contains("Full"));
    assert!(factory.title.contains("Factory"));
    let full_commands = full.commands.join("\n");
    let factory_commands = factory.commands.join("\n");
    assert!(full_commands.contains("infiproxy-module-manifest read"));
    assert!(factory_commands.contains("infiproxy-module-manifest read"));
    assert!(full_commands.contains("infiproxy-reconcile"));
    assert!(factory_commands.contains("infiproxy-reconcile"));
    assert!(factory_commands.contains("infiproxy-manager"));
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

    let specs = config_files();
    for spec in &specs {
        assert!(slugs.insert(&spec.slug));
        assert!(spec.path.starts_with("/etc/"));
        assert!(spec.max_bytes <= 256 * 1024);
    }

    assert!(specs.len() >= modules::registry().unwrap().len());
    for module in modules::registry().unwrap() {
        assert!(specs.iter().any(|spec| spec.path == module.config_path));
    }
}

#[test]
fn mtproto_runtime_is_wired_into_panel_contracts() {
    assert!(modules::registry()
        .unwrap()
        .iter()
        .any(|module| module.service == "infiproxy-mtproto.service"
            && module.binary_path.ends_with("/mtproto-proxy")));
    assert!(config_files()
        .iter()
        .any(|spec| { spec.path == "/etc/infiproxy-cores/mtproto/mtproto.env" && !spec.editable }));
}

#[test]
fn retired_headscale_surface_is_absent_from_normal_ui_and_routes() {
    let shell = ui::layout("test", maud::html! { p { "content" } }).into_string();
    assert!(!shell.to_ascii_lowercase().contains("headscale"));
    assert!(!include_str!("main.rs").contains("/admin/headscale"));
    assert!(!modules::registry()
        .unwrap()
        .iter()
        .any(|module| module.id == "headscale"));
}

#[test]
fn content_etags_are_stable_and_change_with_the_payload() {
    let first = content_etag("payload:\n  - DOMAIN,example.com\n");
    assert_eq!(first, content_etag("payload:\n  - DOMAIN,example.com\n"));
    assert_ne!(first, content_etag("payload:\n  - DOMAIN,example.net\n"));
    assert!(first.starts_with('"') && first.ends_with('"'));
}

#[test]
fn transport_pool_member_input_is_typed_and_rejects_ambiguous_values() {
    assert_eq!(
        parse_pool_member("profile:FAST").unwrap(),
        PoolMember::Profile("FAST".to_string())
    );
    assert_eq!(
        parse_pool_member("capability:hysteria2").unwrap(),
        PoolMember::Capability("hysteria2".to_string())
    );
    assert_eq!(
        parse_pool_member("pool:AUTO").unwrap(),
        PoolMember::Pool("AUTO".to_string())
    );
    assert!(parse_pool_member("AUTO").is_err());
    assert!(parse_pool_member("profile:").is_err());
    assert!(parse_pool_member("shell:command").is_err());
}

#[test]
fn argon2_upgrade_preserves_existing_phc_password_hashes() {
    const LEGACY_HASH: &str =
        "$argon2id$v=19$m=65536,t=2,p=1$c29tZXNhbHQ$CTFhFdXPJO1aFaMaO6Mm5c8y7cJHAph8ArZWb2GRPPc";

    assert!(verify_password("password", LEGACY_HASH).expect("legacy hash is valid"));
    assert!(!verify_password("incorrect", LEGACY_HASH).expect("legacy hash is valid"));

    let first = hash_password("new-password").expect("password hashes");
    let second = hash_password("new-password").expect("password hashes");
    assert_ne!(first, second, "password salts must be unique");
    assert!(verify_password("new-password", &first).expect("new hash verifies"));
}

#[test]
fn config_editor_rejects_unknown_targets() {
    let report = write_config_file("../etc/passwd", "nope");

    assert!(!report.success);
    assert_eq!(report.message, "unknown config target");
}

#[test]
fn config_editor_rejects_root_only_targets() {
    let report = write_config_file("ssh-daemon", "Port 22\n");

    assert!(!report.success);
    assert!(report.message.contains("read-only"));
}

#[test]
fn shared_inventory_components_render_dynamic_and_historical_entries() {
    let inventory = AdapterInventory {
        adapters: vec![AdapterInventoryEntry {
            id: "detached-adapter".to_string(),
            kind: "protocol".to_string(),
            display_name: "Detached adapter".to_string(),
            state: AdapterInventoryState::Historical,
            present: false,
            configured: true,
            schema_version: Some(7),
            capabilities: BTreeSet::new(),
            detail: "Configuration preserved; adapter currently unavailable".to_string(),
        }],
        runtimes: vec![RuntimeInventoryEntry {
            id: "runtime-from-manifest".to_string(),
            display_name: "Manifest runtime".to_string(),
            state: RuntimeInventoryState::InstalledInactive,
            adapter_present: true,
            installed: Some(true),
            desired: false,
            applied: false,
            active: Some(false),
            healthy: None,
            listeners_healthy: None,
            service: Some("manifest-runtime.service".to_string()),
            version: Some("1.2.3".to_string()),
            capabilities: BTreeSet::new(),
            detail: "Core installed but unused".to_string(),
        }],
        ..AdapterInventory::default()
    };

    let adapters = views::components::adapter_inventory_table(&inventory, None).into_string();
    let runtimes = views::components::runtime_inventory_table(&inventory).into_string();
    assert!(adapters.contains("detached-adapter"));
    assert!(adapters.contains("historical"));
    assert!(runtimes.contains("runtime-from-manifest"));
    assert!(runtimes.contains("installed inactive"));
}

#[test]
fn runtime_views_do_not_restore_the_legacy_static_target_array() {
    let sources = [
        include_str!("ops.rs"),
        include_str!("views/health.rs"),
        include_str!("views/system.rs"),
    ];
    assert!(sources
        .iter()
        .all(|source| !source.contains("SYSTEM_TARGETS")));
}
