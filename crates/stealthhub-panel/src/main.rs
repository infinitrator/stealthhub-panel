//! Axum web control plane for Infiproxy.
//!
//! The binary wires routes, authentication, CSRF protection, settings, users,
//! protocol editors, routing editors and owner-only danger operations. Heavy
//! host helpers and UI layout live in sibling modules to keep this file focused
//! on request/response flow.

mod atomic_file;
mod health;
mod inventory;
mod ip;
mod modules;
mod ops;
mod reconcile_request;
mod rule_sources;
mod ui;
mod update;
mod views;

pub(crate) use crate::views::components::{admin_bar, csrf_field};
use crate::{
    health::{admin_health, health, readiness},
    ip::ip_check_page,
    ops::{
        config_files, control_plane_service_states, host_snapshot, read_config_spec,
        uninstall_plan, write_config_file,
    },
    ui::{APP_NAME, PANEL_CSS},
};
use argon2::{
    password_hash::{phc::PasswordHash, PasswordHasher, PasswordVerifier},
    Argon2,
};
use axum::{
    body::Body,
    extract::{connect_info::ConnectInfo, DefaultBodyLimit, Form, MatchedPath, Path, Query, State},
    http::{header, HeaderMap, HeaderValue, Request, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Redirect, Response},
    routing::{get, post},
    Router,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chrono::{Duration, Utc};
use cookie::{time::Duration as CookieDuration, Cookie, SameSite};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use sqlx::SqlitePool;
use std::{
    collections::{BTreeMap, HashMap},
    net::{IpAddr, SocketAddr},
    sync::{Arc, Mutex},
    time::{Duration as StdDuration, Instant},
};
use stealthhub_core::{
    adapter::{ConfigFieldKind, CoreRegistry, ProtocolRegistry, RuntimeLifecycleAction, SecretRef},
    adapters::{core_registry, protocol_registry},
    audit::{AuditAction, AuditActor, AuditMetadata, AuditObjectType, AuditOutcome, NewAuditEvent},
    mihomo::{generate_mihomo_yaml_detailed, MihomoGenerationInput},
    models::{ProtocolProfile, SubscriptionUser},
    policy::{parse_role, PoolKind, PoolMember, RoutingPolicyRule, TransportPool},
    rules::{
        routing_rule_payload_yaml, RoutingRuleSet, RuleEntry, RuleKind, RuleSetSource,
        RuleSourceFormat,
    },
    storage::{
        admin_count, append_audit_event, audit_event_count, bulk_add_rule_entries,
        clone_routing_rule_set, compiled_rule_set_payload, create_admin_session,
        create_first_admin_audited, create_routing_rule_set, create_user_audited,
        deduplicate_rule_entries, delete_admin_session, delete_expired_admin_sessions,
        delete_routing_policy, delete_routing_rule_set, delete_rule_entry, delete_rule_source,
        delete_secret_audited, delete_transport_pool, delete_user_audited,
        ensure_default_protocol_profiles, ensure_default_routing_rule_sets,
        ensure_default_settings, get_admin_by_id, get_admin_by_username, get_reconcile_state,
        get_secret, get_user_by_id, get_user_by_token, get_valid_admin_session, init_db,
        is_owner_admin_id, list_audit_events, list_protocol_profiles_decoded,
        list_runtime_user_sync, list_secret_names, list_users, load_client_policy, load_dns_policy,
        load_panel_settings, load_routing_rule_sets, load_rule_entries, load_rule_sources,
        migrate_available_adapter_states, migrate_protocol_adapter_configs, open_pool,
        reset_user_subscription_token_audited, save_routing_rule_set, set_user_enabled_audited,
        touch_admin_session, update_admin_password_and_revoke_sessions_audited, update_dns_policy,
        update_protocol_profile_audited, update_routing_rule_set, upsert_routing_policy,
        upsert_rule_entry, upsert_rule_source, upsert_secret_audited, upsert_setting,
        upsert_settings_with_runtime_keys_audited, upsert_transport_pool, AdminRecord, NewUser,
        UpdateProtocolProfile, UpdateRoutingRuleSet, UserRecord,
    },
};
use subtle::ConstantTimeEq;
use tokio::sync::Semaphore;
use tower_http::trace::TraceLayer;
use tracing_subscriber::EnvFilter;
use uuid::Uuid;

const ADMIN_SESSION_COOKIE: &str = "infiproxy_admin_session";
const ADMIN_SESSION_TTL_DAYS: i64 = 7;
const MIN_ADMIN_PASSWORD_LEN: usize = 12;
const MAX_ADMIN_PASSWORD_LEN: usize = 1024;
const LOGIN_FAILURE_DELAY_MS: u64 = 500;
const DUMMY_PASSWORD_HASH: &str = "$argon2id$v=19$m=19456,t=2,p=1$gTSHLOLVD71RNAjjkqaKvQ$cCpCPgJOl06K2/RHtedp/MTm/4u+0n4JeNlYF00eQj4";
pub(crate) const DEPLOYMENT_MODE: &str = "bare-metal systemd";
const LOGIN_RATE_LIMIT_WINDOW: StdDuration = StdDuration::from_mins(15);
const LOGIN_RATE_LIMIT_MAX_FAILURES: u32 = 5;
const LOGIN_RATE_LIMIT_MAX_KEYS: usize = 2048;
const SESSION_TOUCH_INTERVAL_MINUTES: i64 = 5;
const DEFAULT_FORM_LIMIT_BYTES: usize = 64 * 1024;
const CONFIG_FORM_LIMIT_BYTES: usize = 1024 * 1024;
const MIN_SETUP_TOKEN_LEN: usize = 32;
const PASSWORD_WORKER_LIMIT: usize = 2;

#[derive(Clone)]
pub(crate) struct AppState {
    pub(crate) pool: SqlitePool,
    pub(crate) protocol_registry: Arc<ProtocolRegistry>,
    pub(crate) core_registry: Arc<CoreRegistry>,
    cookie_secure: bool,
    setup_token: Arc<str>,
    login_limiter: Arc<LoginRateLimiter>,
    password_workers: Arc<Semaphore>,
}

#[derive(Debug, Default)]
struct LoginRateLimiter {
    attempts: Mutex<HashMap<String, LoginAttempt>>,
}

#[derive(Debug, Clone)]
struct LoginAttempt {
    failures: u32,
    window_started_at: Instant,
}

#[derive(Debug, Deserialize)]
struct CreateUserForm {
    username: String,
    #[serde(default)]
    traffic_limit_gb: String,
    #[serde(default)]
    expires_in_days: String,
    #[serde(default)]
    csrf_token: String,
}

#[derive(Debug, Deserialize)]
struct CsrfForm {
    #[serde(default)]
    csrf_token: String,
}

#[derive(Debug, Deserialize)]
struct ModuleAutoUpdateForm {
    #[serde(default)]
    csrf_token: String,
    #[serde(default)]
    enabled: String,
}

#[derive(Debug, Deserialize)]
struct ModuleRemovalForm {
    #[serde(default)]
    csrf_token: String,
    confirm: String,
}

#[derive(Debug, Deserialize)]
struct RoutingRuleSetForm {
    #[serde(default)]
    csrf_token: String,
    slug: String,
    #[serde(default)]
    enabled: String,
    target: String,
    payload: String,
}

#[derive(Debug, Deserialize)]
struct DnsPolicyForm {
    #[serde(default)]
    csrf_token: String,
    #[serde(default)]
    enabled: String,
    #[serde(default)]
    ipv6: String,
    #[serde(default)]
    respect_rules: String,
    enhanced_mode: String,
    bootstrap_resolvers: String,
    remote_resolvers: String,
    direct_resolvers: String,
}

#[derive(Debug, Deserialize)]
struct TransportPoolForm {
    #[serde(default)]
    csrf_token: String,
    #[serde(default)]
    original_id: String,
    id: String,
    display_name: String,
    kind: String,
    #[serde(default)]
    enabled: String,
    members: String,
    #[serde(default)]
    test_url: String,
    #[serde(default)]
    interval_seconds: String,
    #[serde(default)]
    timeout_ms: String,
    #[serde(default)]
    tolerance_ms: String,
    #[serde(default)]
    max_failures: String,
    #[serde(default)]
    lazy: String,
    #[serde(default)]
    minimum_healthy_count: String,
    #[serde(default)]
    fallback_pool: String,
    priority: i32,
    #[serde(default)]
    strategy: String,
}

#[derive(Debug, Deserialize)]
struct DeleteTransportPoolForm {
    #[serde(default)]
    csrf_token: String,
    id: String,
    #[serde(default)]
    replacement: String,
}

#[derive(Debug, Deserialize)]
struct RoutingPolicyForm {
    #[serde(default)]
    csrf_token: String,
    #[serde(default)]
    original_id: String,
    id: String,
    display_name: String,
    #[serde(default)]
    enabled: String,
    priority: i32,
    condition: String,
    target: String,
}

#[derive(Debug, Deserialize)]
struct DeleteRoutingPolicyForm {
    #[serde(default)]
    csrf_token: String,
    id: String,
}

#[derive(Debug, Deserialize)]
struct RuleSetForm {
    #[serde(default)]
    csrf_token: String,
    #[serde(default)]
    create: String,
    slug: String,
    title: String,
    effect: String,
    target: String,
    #[serde(default)]
    enabled: String,
    #[serde(default)]
    payload: String,
}

#[derive(Debug, Deserialize)]
struct RuleSetIdentityForm {
    #[serde(default)]
    csrf_token: String,
    slug: String,
    #[serde(default)]
    new_slug: String,
}

#[derive(Debug, Deserialize)]
struct RuleEntryForm {
    #[serde(default)]
    csrf_token: String,
    #[serde(default)]
    id: String,
    rule_set_id: String,
    #[serde(default)]
    enabled: String,
    kind: String,
    value: String,
    #[serde(default)]
    comment: String,
    #[serde(default)]
    source_tag: String,
    priority: i32,
}

#[derive(Debug, Deserialize)]
struct RuleEntryIdentityForm {
    #[serde(default)]
    csrf_token: String,
    id: String,
    #[serde(default)]
    rule_set_id: String,
}

#[derive(Debug, Deserialize)]
struct BulkRuleEntryForm {
    #[serde(default)]
    csrf_token: String,
    rule_set_id: String,
    kind: String,
    input: String,
    #[serde(default)]
    source_tag: String,
}

#[derive(Debug, Deserialize)]
struct RuleSourceForm {
    #[serde(default)]
    csrf_token: String,
    #[serde(default)]
    id: String,
    rule_set_id: String,
    url: String,
    format: String,
    #[serde(default)]
    enabled: String,
    refresh_interval_seconds: u32,
}

#[derive(Debug, Default, Deserialize)]
struct RoutingFilter {
    #[serde(default)]
    search: String,
    #[serde(default)]
    kind: String,
}

#[derive(Debug, Deserialize)]
struct UninstallPreviewForm {
    #[serde(default)]
    csrf_token: String,
    mode: String,
}

#[derive(Debug, Deserialize)]
struct ConfigEditorForm {
    #[serde(default)]
    csrf_token: String,
    target: String,
    content: String,
}

#[derive(Debug, Deserialize)]
struct SecretForm {
    #[serde(default)]
    csrf_token: String,
    name: String,
    value: String,
}

#[derive(Debug, Deserialize)]
struct SecretDeleteForm {
    #[serde(default)]
    csrf_token: String,
    name: String,
    confirm: String,
}

#[derive(Debug, Deserialize)]
struct PanelSettingsForm {
    #[serde(default)]
    csrf_token: String,
    panel_name: String,
    subscription_domain: String,
    node_domain: String,
    #[serde(default)]
    panel_update_enabled: String,
    #[serde(default)]
    panel_update_time: String,
}

#[derive(Debug, Deserialize)]
struct SetupAdminForm {
    setup_token: String,
    username: String,
    password: String,
    password_confirm: String,
}

#[derive(Debug, Deserialize)]
struct LoginForm {
    username: String,
    password: String,
}

#[derive(Debug, Deserialize)]
struct PasswordChangeForm {
    #[serde(default)]
    csrf_token: String,
    current_password: String,
    new_password: String,
    new_password_confirm: String,
}

#[derive(Debug, Deserialize, Default)]
struct AuditPageQuery {
    page: Option<u32>,
}

#[derive(Debug, Clone)]
pub(crate) struct AuthenticatedAdmin {
    admin: AdminRecord,
    is_owner: bool,
    csrf_token: String,
    update_notice: Option<update::Notice>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    rustls::crypto::ring::default_provider()
        .install_default()
        .map_err(|_| anyhow::anyhow!("could not install the Ring TLS provider"))?;
    health::mark_started();
    let env_filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info,stealthhub_panel=info,tower_http=warn"));
    tracing_subscriber::fmt().with_env_filter(env_filter).init();

    let bind = env_value("INFIPROXY_BIND", "STEALTHHUB_BIND")
        .unwrap_or_else(|| "127.0.0.1:8080".to_string());
    let db_url = env_value("INFIPROXY_DB", "STEALTHHUB_DB")
        .unwrap_or_else(|| "sqlite://./infiproxy.sqlite?mode=rwc".to_string());
    let cookie_secure = env_value("INFIPROXY_COOKIE_SECURE", "STEALTHHUB_COOKIE_SECURE")
        .is_some_and(|value| matches!(value.as_str(), "1" | "true" | "yes" | "on"));
    if !cookie_secure && !bind.starts_with("127.0.0.1:") && !bind.starts_with("localhost:") {
        tracing::warn!(
            "admin session cookie Secure flag is disabled; set INFIPROXY_COOKIE_SECURE=true behind HTTPS"
        );
    }

    let pool = open_pool(&db_url).await?;
    let protocol_registry = Arc::new(protocol_registry()?);
    let core_registry = Arc::new(core_registry()?);
    init_db(&pool).await?;
    ensure_default_settings(&pool).await?;
    ensure_default_protocol_profiles(&pool).await?;
    migrate_protocol_adapter_configs(&pool, &protocol_registry).await?;
    migrate_available_adapter_states(&pool, &protocol_registry, &core_registry).await?;
    ensure_default_routing_rule_sets(&pool).await?;
    delete_expired_admin_sessions(&pool).await?;
    let admin_total = admin_count(&pool).await?;
    let setup_token = if admin_total == 0 {
        env_value("INFIPROXY_SETUP_TOKEN", "STEALTHHUB_SETUP_TOKEN").unwrap_or_default()
    } else {
        String::new()
    };
    if admin_total == 0 && setup_token.len() < MIN_SETUP_TOKEN_LEN {
        anyhow::bail!(
            "INFIPROXY_SETUP_TOKEN must contain at least {MIN_SETUP_TOKEN_LEN} characters before first-admin setup"
        );
    }
    update::spawn_checker(pool.clone());
    modules::spawn_checker(pool.clone());
    rule_sources::spawn_checker(pool.clone());

    let state = AppState {
        pool,
        protocol_registry,
        core_registry,
        cookie_secure,
        setup_token: Arc::from(setup_token),
        login_limiter: Arc::new(LoginRateLimiter::default()),
        password_workers: Arc::new(Semaphore::new(PASSWORD_WORKER_LIMIT)),
    };

    let app = Router::new()
        .route("/", get(index))
        .route("/assets/panel.css", get(panel_css))
        .route(
            "/admin/setup",
            get(setup_admin_page).post(setup_admin_action),
        )
        .route("/admin/login", get(login_page).post(login_action))
        .route("/admin/logout", post(logout_action))
        .route(
            "/admin/account",
            get(account_page).post(change_password_action),
        )
        .route("/admin", get(admin_dashboard))
        .route("/admin/audit", get(audit_page))
        .route("/admin/users", get(users_page))
        .route(
            "/admin/settings",
            get(settings_page).post(update_settings_action),
        )
        .route("/admin/panel-update-now", post(panel_update_now_action))
        .route("/admin/modules/check", post(check_all_modules_action))
        .route(
            "/admin/modules/{module_id}/check",
            post(check_module_action),
        )
        .route(
            "/admin/modules/{module_id}/update",
            post(update_module_action),
        )
        .route(
            "/admin/modules/{module_id}/auto",
            post(module_auto_update_action),
        )
        .route(
            "/admin/modules/{module_id}/remove",
            post(remove_module_action),
        )
        .route(
            "/admin/modules/{module_id}/install",
            post(register_module_action),
        )
        .route(
            "/admin/modules/{module_id}/start",
            post(start_module_action),
        )
        .route("/admin/modules/{module_id}/stop", post(stop_module_action))
        .route(
            "/admin/modules/{module_id}/restart",
            post(restart_module_action),
        )
        .route("/admin/protocols", get(protocols_page))
        .route("/admin/secrets", get(secrets_page).post(secret_save_action))
        .route("/admin/secrets/delete", post(secret_delete_action))
        .route(
            "/admin/protocols/{name}/update",
            post(update_protocol_action),
        )
        .route(
            "/admin/routing",
            get(routing_page).post(update_routing_rule_action),
        )
        .route("/admin/routing/dns", post(update_dns_policy_action))
        .route(
            "/admin/routing/pools/save",
            post(save_transport_pool_action),
        )
        .route(
            "/admin/routing/pools/delete",
            post(delete_transport_pool_action),
        )
        .route(
            "/admin/routing/policies/save",
            post(save_routing_policy_action),
        )
        .route(
            "/admin/routing/policies/delete",
            post(delete_routing_policy_action),
        )
        .route("/admin/routing/rule-sets/save", post(save_rule_set_action))
        .route(
            "/admin/routing/rule-sets/delete",
            post(delete_rule_set_action),
        )
        .route(
            "/admin/routing/rule-sets/clone",
            post(clone_rule_set_action),
        )
        .route("/admin/routing/entries/save", post(save_rule_entry_action))
        .route(
            "/admin/routing/entries/delete",
            post(delete_rule_entry_action),
        )
        .route(
            "/admin/routing/entries/bulk",
            post(bulk_rule_entries_action),
        )
        .route(
            "/admin/routing/entries/deduplicate",
            post(deduplicate_rule_entries_action),
        )
        .route("/admin/routing/sources/save", post(save_rule_source_action))
        .route(
            "/admin/routing/sources/delete",
            post(delete_rule_source_action),
        )
        .route(
            "/admin/routing/sources/refresh",
            post(refresh_rule_source_action),
        )
        .route("/admin/system", get(system_page))
        .route(
            "/admin/configs",
            get(configs_page)
                .post(config_save_action)
                .layer(DefaultBodyLimit::max(CONFIG_FORM_LIMIT_BYTES)),
        )
        .route(
            "/admin/system/uninstall-preview",
            post(uninstall_preview_action),
        )
        .route("/admin/cores", get(cores_page))
        .route("/admin/ip", get(ip_check_page))
        .route("/admin/credits", get(credits_page))
        .route("/admin/health", get(admin_health))
        .route("/admin/users/create", post(create_user_action))
        .route("/admin/users/{id}/toggle", post(toggle_user_action))
        .route(
            "/admin/users/{id}/reset-token",
            get(reset_user_token_page).post(reset_user_token_action),
        )
        .route(
            "/admin/users/{id}/delete",
            get(delete_user_page).post(delete_user_action),
        )
        .route("/health", get(health))
        .route("/ready", get(readiness))
        .route("/sub/{token}", get(subscription_page))
        .route("/sub/{token}/mihomo.yaml", get(mihomo_subscription))
        .route("/rules/{name}", get(rule_provider))
        .with_state(state)
        .layer(DefaultBodyLimit::max(DEFAULT_FORM_LIMIT_BYTES))
        .layer(middleware::from_fn(security_headers))
        .layer(
            TraceLayer::new_for_http().make_span_with(|request: &Request<Body>| {
                let route = request
                    .extensions()
                    .get::<MatchedPath>()
                    .map_or("<unmatched>", MatchedPath::as_str);
                tracing::info_span!("http_request", method = %request.method(), route)
            }),
        );

    tracing::info!("{APP_NAME} listening on http://{}", bind);

    let listener = tokio::net::TcpListener::bind(&bind).await?;
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await?;

    Ok(())
}

fn env_value(primary: &str, legacy: &str) -> Option<String> {
    std::env::var(primary)
        .ok()
        .or_else(|| std::env::var(legacy).ok())
}

async fn mihomo_subscription(State(state): State<AppState>, Path(token): Path<String>) -> Response {
    let user = match get_user_by_token(&state.pool, &token).await {
        Ok(value) => value,
        Err(_) => {
            return (StatusCode::UNAUTHORIZED, "invalid subscription token\n").into_response()
        }
    };

    if let Some(reason) = subscription_block_reason(&user) {
        return (StatusCode::FORBIDDEN, format!("{reason}\n")).into_response();
    }

    let subscription_user: SubscriptionUser = user.clone().into();
    let settings = match load_panel_settings(&state.pool).await {
        Ok(value) => value,
        Err(error) => return subscription_internal_error("load settings", error),
    };
    let profiles = match list_protocol_profiles_decoded(&state.pool).await {
        Ok(value) => value,
        Err(error) => return subscription_internal_error("load profiles", error),
    };
    let secrets =
        match load_secret_values_map(&state.pool, &profiles, &state.protocol_registry).await {
            Ok(value) => value,
            Err(error) => return subscription_internal_error("load secrets", error),
        };
    let routing_rule_sets = match load_routing_rule_sets(&state.pool).await {
        Ok(value) => value,
        Err(error) => return subscription_internal_error("load routing", error),
    };
    let client_policy = match load_client_policy(&state.pool).await {
        Ok(value) => value,
        Err(error) => return subscription_internal_error("load client policy", error),
    };
    let dns_policy = match load_dns_policy(&state.pool).await {
        Ok(value) => value,
        Err(error) => return subscription_internal_error("load DNS policy", error),
    };

    let runtime_capabilities = state
        .core_registry
        .observations()
        .into_iter()
        .filter(|observation| observation.probe.installed == Some(true))
        .flat_map(|observation| observation.manifest.capabilities)
        .collect::<std::collections::BTreeSet<_>>();
    let generated = match generate_mihomo_yaml_detailed(
        MihomoGenerationInput {
            settings: &settings,
            user: &subscription_user,
            profiles: &profiles,
            secrets: &secrets,
            routing_rule_sets: &routing_rule_sets,
            policy: &client_policy,
            dns_policy: &dns_policy,
            available_core_capabilities: Some(&runtime_capabilities),
        },
        &state.protocol_registry,
    ) {
        Ok(value) => value,
        Err(error) => {
            tracing::warn!("subscription config is incomplete: {error}");
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                "subscription is not configured\n",
            )
                .into_response();
        }
    };
    for warning in generated.warnings {
        tracing::warn!("subscription generation warning: {warning}");
    }
    let yaml = generated.yaml;

    let mut headers = HeaderMap::new();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/yaml; charset=utf-8"),
    );
    headers.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("no-cache, no-store, must-revalidate"),
    );
    headers.insert("Subscription-Userinfo", subscription_userinfo_header(&user));

    (headers, yaml).into_response()
}

async fn subscription_page(State(state): State<AppState>, Path(token): Path<String>) -> Response {
    let user = match get_user_by_token(&state.pool, &token).await {
        Ok(value) => value,
        Err(_) => return views::subscription::render_invalid(),
    };

    let settings = match load_panel_settings(&state.pool).await {
        Ok(value) => value,
        Err(error) => return internal_error("load subscription settings", error),
    };

    let yaml_url = mihomo_subscription_url(&settings.subscription_domain, &user.subscription_token);
    let import_url = mihomo_import_url(&settings.panel_name, &user.username, &yaml_url);
    let block_reason = subscription_block_reason(&user);

    views::subscription::render(
        &user,
        block_reason,
        &format_user_traffic(&user),
        &format_user_expiry(&user),
        &yaml_url,
        &import_url,
    )
}

async fn rule_provider(
    State(state): State<AppState>,
    Path(name): Path<String>,
    request_headers: HeaderMap,
) -> Response {
    if name.ends_with(".mrs") {
        return (
            StatusCode::NOT_IMPLEMENTED,
            "MRS generation is unsupported for mixed classical rule sets; use the YAML provider\n",
        )
            .into_response();
    }
    let slug = name.trim_end_matches(".yaml");
    let rule_sets = match load_routing_rule_sets(&state.pool).await {
        Ok(value) => value,
        Err(error) => return subscription_internal_error("load routing provider", error),
    };

    let Some(rule_set) = rule_sets
        .into_iter()
        .find(|rule_set| rule_set.slug == slug && rule_set.enabled)
    else {
        return (StatusCode::NOT_FOUND, "rule not found\n").into_response();
    };

    let compiled = match compiled_rule_set_payload(&state.pool, &rule_set).await {
        Ok(value) => value,
        Err(error) => return subscription_internal_error("compile routing provider", error),
    };
    let body = match routing_rule_payload_yaml(&compiled) {
        Ok(value) => value,
        Err(error) => return subscription_internal_error("render routing provider", error),
    };

    let etag = content_etag(&body);
    let mut response_headers = HeaderMap::new();
    response_headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/yaml; charset=utf-8"),
    );
    response_headers.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("public, max-age=300"),
    );
    if let Ok(value) = HeaderValue::from_str(&etag) {
        response_headers.insert(header::ETAG, value);
    }

    if request_headers
        .get(header::IF_NONE_MATCH)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.split(',').any(|candidate| candidate.trim() == etag))
    {
        return (StatusCode::NOT_MODIFIED, response_headers).into_response();
    }

    (response_headers, body).into_response()
}

fn content_etag(content: &str) -> String {
    format!(
        "\"{}\"",
        URL_SAFE_NO_PAD.encode(Sha256::digest(content.as_bytes()))
    )
}

async fn index() -> impl IntoResponse {
    views::public::render_home()
}

async fn panel_css() -> impl IntoResponse {
    (
        [
            (header::CONTENT_TYPE, "text/css; charset=utf-8"),
            (header::CACHE_CONTROL, "no-cache"),
        ],
        PANEL_CSS,
    )
}

async fn setup_admin_page(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if let Ok(Some(_)) = current_admin(&state, &headers).await {
        return Redirect::to("/admin").into_response();
    }

    match admin_count(&state.pool).await {
        Ok(0) => views::public::render_setup(),
        Ok(_) => Redirect::to("/admin/login").into_response(),
        Err(error) => internal_error("inspect initial admin state", error),
    }
}

async fn setup_admin_action(
    State(state): State<AppState>,
    Form(form): Form<SetupAdminForm>,
) -> Response {
    match admin_count(&state.pool).await {
        Ok(0) => {}
        Ok(_) => return Redirect::to("/admin/login").into_response(),
        Err(error) => return internal_error("inspect initial admin state", error),
    }

    if !setup_token_matches(&state, &form.setup_token) {
        return html_error_response_with_back(
            StatusCode::FORBIDDEN,
            "Setup blocked",
            "The one-time setup token is missing or invalid.",
            "/admin/setup",
            "Back to Setup",
        );
    }

    let username = form.username.trim().to_string();
    if !valid_account_name(&username, 3) {
        return html_error_response_with_back(
            StatusCode::BAD_REQUEST,
            "Setup failed",
            "Username must be 3-64 ASCII letters, digits, dots, underscores or hyphens and must start with a letter or digit.",
            "/admin/setup",
            "Back to Setup",
        );
    }

    if !(MIN_ADMIN_PASSWORD_LEN..=MAX_ADMIN_PASSWORD_LEN).contains(&form.password.len()) {
        return html_error_response_with_back(
            StatusCode::BAD_REQUEST,
            "Setup failed",
            format!(
                "Password must be {MIN_ADMIN_PASSWORD_LEN}-{MAX_ADMIN_PASSWORD_LEN} characters long"
            ),
            "/admin/setup",
            "Back to Setup",
        );
    }

    if form.password != form.password_confirm {
        return html_error_response_with_back(
            StatusCode::BAD_REQUEST,
            "Setup failed",
            "Password confirmation does not match",
            "/admin/setup",
            "Back to Setup",
        );
    }

    let password_hash = match hash_password_limited(&state, form.password).await {
        Ok(value) => value,
        Err(error) => return internal_error("hash initial admin password", error),
    };

    let owner_event = NewAuditEvent {
        actor: AuditActor::initial_owner(username.clone()),
        action: AuditAction::OwnerCreated,
        object_type: AuditObjectType::Owner,
        object_id: username.clone(),
        outcome: AuditOutcome::Succeeded,
        metadata: AuditMetadata::none(),
    };
    let admin = match create_first_admin_audited(
        &state.pool,
        &username,
        &password_hash,
        &owner_event,
    )
    .await
    {
        Ok(value) => value,
        Err(error) => {
            tracing::warn!("initial administrator creation rejected: {error}");
            return html_error_response_with_back(
                StatusCode::CONFLICT,
                "Setup failed",
                "Initial setup has already been completed or the username is unavailable.",
                "/admin/setup",
                "Back to Setup",
            );
        }
    };

    create_session_redirect(&state, admin.id, "/admin").await
}

async fn login_page(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if matches!(admin_count(&state.pool).await, Ok(0)) {
        return Redirect::to("/admin/setup").into_response();
    }

    if let Ok(Some(_)) = current_admin(&state, &headers).await {
        return Redirect::to("/admin").into_response();
    }

    views::public::render_login()
}

async fn login_action(
    State(state): State<AppState>,
    ConnectInfo(peer_addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Form(form): Form<LoginForm>,
) -> Response {
    if matches!(admin_count(&state.pool).await, Ok(0)) {
        return Redirect::to("/admin/setup").into_response();
    }

    let rate_limit_keys = login_rate_limit_keys(&headers, peer_addr, &form.username);
    if let Some(retry_after) = state.login_limiter.retry_after(&rate_limit_keys) {
        return rate_limited_response(retry_after);
    }
    if form.password.len() > MAX_ADMIN_PASSWORD_LEN {
        state.login_limiter.record_failure(&rate_limit_keys);
        return login_failed_response().await;
    }

    let admin = match get_admin_by_username(&state.pool, &form.username).await {
        Ok(Some(value)) => value,
        Ok(None) => {
            match verify_password_limited(&state, form.password, DUMMY_PASSWORD_HASH.to_string())
                .await
            {
                Ok(Some(_)) => {}
                Ok(None) => return password_workers_busy_response(),
                Err(error) => return internal_error("verify dummy administrator password", error),
            }
            state.login_limiter.record_failure(&rate_limit_keys);
            return login_failed_response().await;
        }
        Err(error) => return internal_error("load administrator for login", error),
    };

    match verify_password_limited(&state, form.password, admin.password_hash.clone()).await {
        Ok(Some(true)) => {
            state.login_limiter.record_success(&rate_limit_keys);
            create_session_redirect(&state, admin.id, "/admin").await
        }
        Ok(Some(false)) => {
            state.login_limiter.record_failure(&rate_limit_keys);
            login_failed_response().await
        }
        Ok(None) => password_workers_busy_response(),
        Err(error) => internal_error("verify administrator password", error),
    }
}

async fn logout_action(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<CsrfForm>,
) -> Response {
    let auth = match require_admin(&state, &headers).await {
        Ok(value) => value,
        Err(response) => return response,
    };

    if let Some(response) = csrf_error_response(&auth, &form.csrf_token) {
        return response;
    }

    if let Some(token) = session_token_from_headers(&headers) {
        let token_hash = hash_session_token(&token);
        if let Err(err) = delete_admin_session(&state.pool, &token_hash).await {
            tracing::warn!("failed to delete admin session: {err}");
        }
    }

    let mut response = Redirect::to("/admin/login").into_response();
    append_session_cookie(&mut response, expired_session_cookie(&state));
    append_session_cookie(&mut response, expired_legacy_session_cookie(&state));
    response
}

async fn account_page(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let auth = match require_admin(&state, &headers).await {
        Ok(value) => value,
        Err(response) => return response,
    };

    views::account::render(&auth)
}

async fn change_password_action(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<PasswordChangeForm>,
) -> Response {
    let auth = match require_admin(&state, &headers).await {
        Ok(value) => value,
        Err(response) => return response,
    };
    if let Some(response) = csrf_error_response(&auth, &form.csrf_token) {
        return response;
    }
    if form.current_password.len() > MAX_ADMIN_PASSWORD_LEN {
        return account_password_error(StatusCode::FORBIDDEN, "Current password is incorrect.");
    }
    if !(MIN_ADMIN_PASSWORD_LEN..=MAX_ADMIN_PASSWORD_LEN).contains(&form.new_password.len()) {
        return account_password_error(
            StatusCode::BAD_REQUEST,
            "New password must be 12-1024 characters long.",
        );
    }
    if form.new_password != form.new_password_confirm {
        return account_password_error(
            StatusCode::BAD_REQUEST,
            "New password confirmation does not match.",
        );
    }

    match verify_password_limited(
        &state,
        form.current_password,
        auth.admin.password_hash.clone(),
    )
    .await
    {
        Ok(Some(true)) => {}
        Ok(Some(false)) => {
            tokio::time::sleep(std::time::Duration::from_millis(LOGIN_FAILURE_DELAY_MS)).await;
            return account_password_error(StatusCode::FORBIDDEN, "Current password is incorrect.");
        }
        Ok(None) => return password_workers_busy_response(),
        Err(error) => return internal_error("verify current administrator password", error),
    }

    let password_hash = match hash_password_limited(&state, form.new_password).await {
        Ok(value) => value,
        Err(error) => return internal_error("hash replacement administrator password", error),
    };
    let event = audit_event(
        &auth,
        AuditAction::PasswordChanged,
        AuditObjectType::AdminAccount,
        auth.admin.username.clone(),
        AuditOutcome::Succeeded,
        AuditMetadata::none(),
    );
    if let Err(error) = update_admin_password_and_revoke_sessions_audited(
        &state.pool,
        auth.admin.id,
        &password_hash,
        &event,
    )
    .await
    {
        return internal_error("rotate administrator password", error);
    }

    let mut response = Redirect::to("/admin/login").into_response();
    append_session_cookie(&mut response, expired_session_cookie(&state));
    append_session_cookie(&mut response, expired_legacy_session_cookie(&state));
    response
}

fn account_password_error(status: StatusCode, message: &'static str) -> Response {
    html_error_response_with_back(
        status,
        "Password not changed",
        message,
        "/admin/account",
        "Back to Account",
    )
}

async fn admin_dashboard(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let auth = match require_admin(&state, &headers).await {
        Ok(value) => value,
        Err(response) => return response,
    };

    let reconcile = match get_reconcile_state(&state.pool).await {
        Ok(value) => value,
        Err(error) => return internal_error("load reconciliation state", error),
    };
    let inventory =
        match inventory::load(&state.pool, &state.protocol_registry, &state.core_registry).await {
            Ok(value) => value,
            Err(error) => return internal_error("load runtime inventory", error),
        };
    views::dashboard::render(&auth, &reconcile, &inventory.inventory)
}

async fn settings_page(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let auth = match require_admin(&state, &headers).await {
        Ok(value) => value,
        Err(response) => return response,
    };

    let settings = match load_panel_settings(&state.pool).await {
        Ok(value) => value,
        Err(error) => {
            return logged_error_with_back(
                StatusCode::INTERNAL_SERVER_ERROR,
                "load panel settings",
                error,
                "Settings unavailable",
                "Panel settings could not be loaded. Review the server journal.",
                "/admin",
                "Back to Dashboard",
            );
        }
    };
    let update_status = match update::load_status(&state.pool).await {
        Ok(value) => value,
        Err(error) => {
            return logged_error_with_back(
                StatusCode::INTERNAL_SERVER_ERROR,
                "load panel update settings",
                error,
                "Update state unavailable",
                "Panel update state could not be loaded. Review the server journal.",
                "/admin",
                "Back to Dashboard",
            );
        }
    };

    views::settings::render(&auth, &settings, &update_status)
}

async fn update_settings_action(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<PanelSettingsForm>,
) -> Response {
    let auth = match require_admin(&state, &headers).await {
        Ok(value) => value,
        Err(response) => return response,
    };

    if let Some(response) = csrf_error_response(&auth, &form.csrf_token) {
        return response;
    }

    let panel_name = form.panel_name.trim();
    if panel_name.len() < 2 || panel_name.len() > 80 || panel_name.chars().any(char::is_control) {
        return html_error_response_with_back(
            StatusCode::BAD_REQUEST,
            "Invalid settings",
            "Panel name must be between 2 and 80 characters.",
            "/admin/settings",
            "Back to Settings",
        );
    }

    let subscription_domain = match normalize_public_host(&form.subscription_domain) {
        Ok(value) => value,
        Err(message) => {
            return html_error_response_with_back(
                StatusCode::BAD_REQUEST,
                "Invalid subscription host",
                message,
                "/admin/settings",
                "Back to Settings",
            );
        }
    };

    let node_domain = match normalize_public_host(&form.node_domain) {
        Ok(value) => value,
        Err(message) => {
            return html_error_response_with_back(
                StatusCode::BAD_REQUEST,
                "Invalid node host",
                message,
                "/admin/settings",
                "Back to Settings",
            );
        }
    };
    let mut settings_to_save = vec![
        ("panel_name", panel_name.to_string()),
        ("subscription_domain", subscription_domain),
        ("node_domain", node_domain),
    ];

    if is_owner_admin(&auth) {
        let update_enabled = match form.panel_update_enabled.trim() {
            "true" => true,
            "false" => false,
            _ => {
                return html_error_response_with_back(
                    StatusCode::BAD_REQUEST,
                    "Invalid update policy",
                    "Panel auto-update must be enabled or disabled explicitly.",
                    "/admin/settings",
                    "Back to Settings",
                );
            }
        };
        let update_time = update::non_empty_or_default(&form.panel_update_time, "05:00");
        let update_hour = match update::parse_schedule_time(update_time) {
            Some((hour, _)) => hour,
            None => {
                return html_error_response_with_back(
                    StatusCode::BAD_REQUEST,
                    "Invalid update window",
                    "Maintenance time must use 24-hour HH:MM format.",
                    "/admin/settings",
                    "Back to Settings",
                );
            }
        };
        settings_to_save.extend([
            ("panel_update_enabled", update_enabled.to_string()),
            ("panel_update_time", update_time.to_string()),
            ("panel_update_hour", update_hour.to_string()),
        ]);
    }

    let settings_to_save = settings_to_save
        .into_iter()
        .map(|(key, value)| (key.to_string(), value))
        .collect::<Vec<_>>();
    let settings_event = audit_event(
        &auth,
        AuditAction::SettingsSaved,
        AuditObjectType::Settings,
        "panel",
        AuditOutcome::Succeeded,
        AuditMetadata::none(),
    );
    let runtime_changed = match upsert_settings_with_runtime_keys_audited(
        &state.pool,
        &settings_to_save,
        &["subscription_domain", "node_domain"],
        &settings_event,
    )
    .await
    {
        Ok(generation) => generation.is_some(),
        Err(error) => {
            return logged_error_with_back(
                StatusCode::INTERNAL_SERVER_ERROR,
                "save panel settings",
                error,
                "Settings not saved",
                "The settings transaction failed. Review the server journal.",
                "/admin/settings",
                "Back to Settings",
            )
        }
    };
    if runtime_changed {
        queue_latest_reconcile(&state).await;
    }
    if is_owner_admin(&auth) {
        let pool = state.pool.clone();
        tokio::spawn(async move {
            if let Err(err) = update::refresh_state(&pool).await {
                tracing::warn!("panel update check after settings save failed: {err}");
            }
        });
    }

    Redirect::to("/admin/settings").into_response()
}

async fn panel_update_now_action(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<CsrfForm>,
) -> Response {
    let auth = match require_admin(&state, &headers).await {
        Ok(value) => value,
        Err(response) => return response,
    };

    if let Some(response) = csrf_error_response(&auth, &form.csrf_token) {
        return response;
    }
    if !is_owner_admin(&auth) {
        return owner_only_response();
    }

    if let Err(error) = upsert_setting(&state.pool, "panel_update_status", "requested").await {
        return logged_error_with_back(
            StatusCode::INTERNAL_SERVER_ERROR,
            "persist panel update request",
            error,
            "Update not requested",
            "The update request could not be persisted. Review the server journal.",
            "/admin/settings",
            "Back to Settings",
        );
    }

    if let Err(error) = update::request_now() {
        return logged_error_with_back(
            StatusCode::INTERNAL_SERVER_ERROR,
            "notify root panel updater",
            error,
            "Update not requested",
            "The root updater could not be notified. Review the server journal.",
            "/admin/settings",
            "Back to Settings",
        );
    }
    record_audit(
        &state,
        audit_event(
            &auth,
            AuditAction::PanelUpdateRequested,
            AuditObjectType::PanelUpdate,
            "panel",
            AuditOutcome::Requested,
            AuditMetadata::none(),
        ),
    )
    .await;

    Redirect::to("/admin/settings").into_response()
}

async fn cores_page(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let auth = match require_admin(&state, &headers).await {
        Ok(value) => value,
        Err(response) => return response,
    };
    let page =
        match inventory::load(&state.pool, &state.protocol_registry, &state.core_registry).await {
            Ok(value) => value,
            Err(error) => {
                return logged_error_with_back(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "load module state",
                    error,
                    "Module state unavailable",
                    "Module state could not be loaded. Review the server journal.",
                    "/admin",
                    "Back to Dashboard",
                );
            }
        };
    let user_sync = match list_runtime_user_sync(&state.pool).await {
        Ok(value) => value,
        Err(error) => return internal_error("load runtime user synchronization", error),
    };
    views::modules::render(
        &auth,
        &page.inventory,
        &page.module_statuses,
        &page.available_modules,
        &page.diagnostics,
        &user_sync,
    )
}

async fn check_all_modules_action(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<CsrfForm>,
) -> Response {
    let auth = match require_admin(&state, &headers).await {
        Ok(value) => value,
        Err(response) => return response,
    };
    if let Some(response) = csrf_error_response(&auth, &form.csrf_token) {
        return response;
    }
    if !is_owner_admin(&auth) {
        return owner_only_response();
    }
    if let Err(error) = modules::refresh_all(&state.pool).await {
        return logged_error_with_back(
            StatusCode::BAD_GATEWAY,
            "refresh all module versions",
            error,
            "Module check failed",
            "Upstream module versions could not be refreshed. Review the server journal.",
            "/admin/cores",
            "Back to Modules",
        );
    }
    Redirect::to("/admin/cores").into_response()
}

async fn check_module_action(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(module_id): Path<String>,
    Form(form): Form<CsrfForm>,
) -> Response {
    let auth = match require_admin(&state, &headers).await {
        Ok(value) => value,
        Err(response) => return response,
    };
    if let Some(response) = csrf_error_response(&auth, &form.csrf_token) {
        return response;
    }
    if !is_owner_admin(&auth) {
        return owner_only_response();
    }
    match modules::find(&module_id) {
        Ok(Some(_)) => {}
        Ok(None) => return (StatusCode::NOT_FOUND, "unknown module\n").into_response(),
        Err(error) => {
            return logged_error_with_back(
                StatusCode::INTERNAL_SERVER_ERROR,
                "load module registry",
                error,
                "Module registry unavailable",
                "The module registry could not be loaded. Review the server journal.",
                "/admin/cores",
                "Back to Modules",
            );
        }
    }
    if let Err(error) = modules::refresh_one(&state.pool, &module_id).await {
        return logged_error_with_back(
            StatusCode::BAD_GATEWAY,
            "refresh one module version",
            error,
            "Module check failed",
            "The upstream module version could not be refreshed. Review the server journal.",
            "/admin/cores",
            "Back to Modules",
        );
    }
    Redirect::to("/admin/cores").into_response()
}

async fn update_module_action(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(module_id): Path<String>,
    Form(form): Form<CsrfForm>,
) -> Response {
    let auth = match require_admin(&state, &headers).await {
        Ok(value) => value,
        Err(response) => return response,
    };
    if let Some(response) = csrf_error_response(&auth, &form.csrf_token) {
        return response;
    }
    if !is_owner_admin(&auth) {
        return owner_only_response();
    }
    let spec = match modules::find(&module_id) {
        Ok(Some(spec)) => spec,
        Ok(None) => return (StatusCode::NOT_FOUND, "unknown module\n").into_response(),
        Err(error) => {
            return logged_error_with_back(
                StatusCode::INTERNAL_SERVER_ERROR,
                "load module registry",
                error,
                "Module registry unavailable",
                "The module registry could not be loaded. Review the server journal.",
                "/admin/cores",
                "Back to Modules",
            );
        }
    };
    if let Err(error) = modules::request_update(&spec.id) {
        return logged_error_with_back(
            StatusCode::INTERNAL_SERVER_ERROR,
            "queue module update",
            error,
            "Module update not requested",
            "The root module updater could not be notified. Review the server journal.",
            "/admin/cores",
            "Back to Modules",
        );
    }
    record_audit(
        &state,
        audit_event(
            &auth,
            AuditAction::ModuleUpdateRequested,
            AuditObjectType::Module,
            spec.id.clone(),
            AuditOutcome::Requested,
            AuditMetadata::none(),
        ),
    )
    .await;
    let status_key = format!("module_{}_status", spec.id);
    let _ = upsert_setting(&state.pool, &status_key, "update requested").await;
    Redirect::to("/admin/cores").into_response()
}

async fn module_auto_update_action(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(module_id): Path<String>,
    Form(form): Form<ModuleAutoUpdateForm>,
) -> Response {
    let auth = match require_admin(&state, &headers).await {
        Ok(value) => value,
        Err(response) => return response,
    };
    if let Some(response) = csrf_error_response(&auth, &form.csrf_token) {
        return response;
    }
    if !is_owner_admin(&auth) {
        return owner_only_response();
    }
    let enabled = update::parse_bool_setting(&form.enabled);
    if let Err(error) = modules::set_auto_update(&state.pool, &module_id, enabled).await {
        return logged_error_with_back(
            StatusCode::BAD_REQUEST,
            "change module update policy",
            error,
            "Module policy not saved",
            "The module update policy could not be changed. Review the server journal.",
            "/admin/cores",
            "Back to Modules",
        );
    }
    record_audit(
        &state,
        audit_event(
            &auth,
            AuditAction::ModuleAutoUpdatePolicyChanged,
            AuditObjectType::Module,
            module_id,
            AuditOutcome::Succeeded,
            AuditMetadata::enabled(enabled),
        ),
    )
    .await;
    Redirect::to("/admin/cores").into_response()
}

async fn register_module_action(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(module_id): Path<String>,
    Form(form): Form<CsrfForm>,
) -> Response {
    let auth = match require_admin(&state, &headers).await {
        Ok(value) => value,
        Err(response) => return response,
    };
    if let Some(response) = csrf_error_response(&auth, &form.csrf_token) {
        return response;
    }
    if !is_owner_admin(&auth) {
        return owner_only_response();
    }

    if let Err(error) = modules::request_register(&module_id) {
        return logged_error_with_back(
            StatusCode::BAD_REQUEST,
            "queue module registration",
            error,
            "Module registration rejected",
            "The module is unavailable, already registered, or its request could not be written.",
            "/admin/cores",
            "Back to Modules",
        );
    }
    record_audit(
        &state,
        audit_event(
            &auth,
            AuditAction::ModuleInstallRequested,
            AuditObjectType::Module,
            module_id,
            AuditOutcome::Requested,
            AuditMetadata::none(),
        ),
    )
    .await;
    Redirect::to("/admin/cores").into_response()
}

async fn remove_module_action(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(module_id): Path<String>,
    Form(form): Form<ModuleRemovalForm>,
) -> Response {
    let auth = match require_admin(&state, &headers).await {
        Ok(value) => value,
        Err(response) => return response,
    };
    if let Some(response) = csrf_error_response(&auth, &form.csrf_token) {
        return response;
    }
    if !is_owner_admin(&auth) {
        return owner_only_response();
    }
    if form.confirm.trim() != module_id {
        return html_error_response_with_back(
            StatusCode::BAD_REQUEST,
            "Module removal confirmation failed",
            format!("Type exactly: {module_id}"),
            "/admin/cores",
            "Back to Modules",
        );
    }
    let page =
        match inventory::load(&state.pool, &state.protocol_registry, &state.core_registry).await {
            Ok(page) => page,
            Err(error) => {
                return logged_error_with_back(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "validate runtime dependencies",
                    error,
                    "Runtime removal not requested",
                    "Dependencies could not be verified, so removal was blocked.",
                    "/admin/cores",
                    "Back to Runtimes",
                );
            }
        };
    let dependent_resources = page
        .inventory
        .resources
        .iter()
        .filter(|resource| {
            resource.enabled
                && resource.desired
                && resource.runtime_id.as_deref() == Some(module_id.as_str())
        })
        .map(|resource| resource.display_name.as_str())
        .collect::<Vec<_>>();
    if !dependent_resources.is_empty() {
        return html_error_response_with_back(
            StatusCode::CONFLICT,
            "Runtime is still required",
            format!(
                "Migrate or disable these desired resources first: {}",
                dependent_resources.join(", ")
            ),
            "/admin/cores",
            "Back to Runtimes",
        );
    }
    if let Err(error) = modules::request_remove(&module_id) {
        return logged_error_with_back(
            StatusCode::BAD_REQUEST,
            "queue module removal",
            error,
            "Module removal rejected",
            "The module is unavailable or its removal request could not be written.",
            "/admin/cores",
            "Back to Modules",
        );
    }
    record_audit(
        &state,
        audit_event(
            &auth,
            AuditAction::ModuleRemoveRequested,
            AuditObjectType::Module,
            module_id,
            AuditOutcome::Requested,
            AuditMetadata::none(),
        ),
    )
    .await;
    Redirect::to("/admin/cores").into_response()
}

async fn start_module_action(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(module_id): Path<String>,
    Form(form): Form<CsrfForm>,
) -> Response {
    runtime_service_action(
        &state,
        &headers,
        &module_id,
        &form.csrf_token,
        RuntimeLifecycleAction::Start,
    )
    .await
}

async fn stop_module_action(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(module_id): Path<String>,
    Form(form): Form<CsrfForm>,
) -> Response {
    runtime_service_action(
        &state,
        &headers,
        &module_id,
        &form.csrf_token,
        RuntimeLifecycleAction::Stop,
    )
    .await
}

async fn restart_module_action(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(module_id): Path<String>,
    Form(form): Form<CsrfForm>,
) -> Response {
    runtime_service_action(
        &state,
        &headers,
        &module_id,
        &form.csrf_token,
        RuntimeLifecycleAction::Restart,
    )
    .await
}

async fn runtime_service_action(
    state: &AppState,
    headers: &HeaderMap,
    module_id: &str,
    csrf_token: &str,
    action: RuntimeLifecycleAction,
) -> Response {
    let auth = match require_admin(state, headers).await {
        Ok(value) => value,
        Err(response) => return response,
    };
    if let Some(response) = csrf_error_response(&auth, csrf_token) {
        return response;
    }
    if !is_owner_admin(&auth) {
        return owner_only_response();
    }
    if let Err(error) = modules::request_lifecycle(module_id, action) {
        return logged_error_with_back(
            StatusCode::BAD_REQUEST,
            "queue runtime service action",
            error,
            "Runtime action rejected",
            "The runtime is unavailable or the typed request could not be queued.",
            "/admin/cores",
            "Back to Runtimes",
        );
    }
    let audit_action = match action {
        RuntimeLifecycleAction::Install => AuditAction::ModuleInstallRequested,
        RuntimeLifecycleAction::Update => AuditAction::ModuleUpdateRequested,
        RuntimeLifecycleAction::Remove => AuditAction::ModuleRemoveRequested,
        RuntimeLifecycleAction::Start => AuditAction::ModuleStartRequested,
        RuntimeLifecycleAction::Stop => AuditAction::ModuleStopRequested,
        RuntimeLifecycleAction::Restart => AuditAction::ModuleRestartRequested,
    };
    record_audit(
        state,
        audit_event(
            &auth,
            audit_action,
            AuditObjectType::Module,
            module_id,
            AuditOutcome::Requested,
            AuditMetadata::none(),
        ),
    )
    .await;
    Redirect::to("/admin/cores").into_response()
}

async fn routing_page(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(filter): Query<RoutingFilter>,
) -> Response {
    let auth = match require_admin(&state, &headers).await {
        Ok(value) => value,
        Err(response) => return response,
    };

    let rule_sets = match load_routing_rule_sets(&state.pool).await {
        Ok(value) => value,
        Err(error) => {
            return logged_error_with_back(
                StatusCode::INTERNAL_SERVER_ERROR,
                "load routing rules",
                error,
                "Routing unavailable",
                "Routing rules could not be loaded. Review the server journal.",
                "/admin",
                "Back to Dashboard",
            );
        }
    };
    let policy = match load_client_policy(&state.pool).await {
        Ok(value) => value,
        Err(error) => {
            return logged_error_with_back(
                StatusCode::INTERNAL_SERVER_ERROR,
                "load client policy",
                error,
                "Routing unavailable",
                "Client transport policy could not be loaded. Review the server journal.",
                "/admin",
                "Back to Dashboard",
            );
        }
    };
    let dns_policy = match load_dns_policy(&state.pool).await {
        Ok(value) => value,
        Err(error) => {
            return logged_error_with_back(
                StatusCode::INTERNAL_SERVER_ERROR,
                "load DNS policy",
                error,
                "Routing unavailable",
                "DNS policy could not be loaded. Review the server journal.",
                "/admin",
                "Back to Dashboard",
            );
        }
    };
    let profiles = match list_protocol_profiles_decoded(&state.pool).await {
        Ok(value) => value,
        Err(error) => return internal_error("load routing profiles", error),
    };
    let mut entries = BTreeMap::new();
    let mut sources = BTreeMap::new();
    for rule_set in &rule_sets {
        let mut rule_entries = match load_rule_entries(&state.pool, &rule_set.slug).await {
            Ok(value) => value,
            Err(error) => return internal_error("load normalized rules", error),
        };
        let search = filter.search.trim().to_ascii_lowercase();
        let kind = filter.kind.trim().to_ascii_uppercase();
        rule_entries.retain(|entry| {
            (search.is_empty()
                || entry.value.to_ascii_lowercase().contains(&search)
                || entry
                    .comment
                    .as_deref()
                    .is_some_and(|value| value.to_ascii_lowercase().contains(&search)))
                && (kind.is_empty() || entry.kind.mihomo_name() == kind)
        });
        let rule_sources = match load_rule_sources(&state.pool, &rule_set.slug).await {
            Ok(value) => value,
            Err(error) => return internal_error("load remote rule sources", error),
        };
        entries.insert(rule_set.slug.clone(), rule_entries);
        sources.insert(rule_set.slug.clone(), rule_sources);
    }

    views::routing::render(
        &auth,
        views::routing::RoutingPageData {
            rule_sets: &rule_sets,
            policy: &policy,
            dns: &dns_policy,
            profiles: &profiles,
            entries: &entries,
            sources: &sources,
            search: &filter.search,
            kind_filter: &filter.kind,
        },
    )
}

async fn update_routing_rule_action(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<RoutingRuleSetForm>,
) -> Response {
    let auth = match require_admin(&state, &headers).await {
        Ok(value) => value,
        Err(response) => return response,
    };

    if let Some(response) = csrf_error_response(&auth, &form.csrf_token) {
        return response;
    }
    if !is_owner_admin(&auth) {
        return owner_only_response();
    }
    if let Err(error) = routing_rule_payload_yaml(&form.payload) {
        return html_error_response_with_back(
            StatusCode::BAD_REQUEST,
            "Routing update failed",
            error.to_string(),
            "/admin/routing",
            "Back to Routing",
        );
    }

    let input = UpdateRoutingRuleSet {
        slug: form.slug,
        enabled: checkbox_enabled(&form.enabled),
        target: form.target,
        payload: form.payload,
    };

    match update_routing_rule_set(&state.pool, input).await {
        Ok(()) => Redirect::to("/admin/routing").into_response(),
        Err(error) => html_error_response_with_back(
            StatusCode::BAD_REQUEST,
            "Routing update failed",
            error.to_string(),
            "/admin/routing",
            "Back to Routing",
        ),
    }
}

async fn update_dns_policy_action(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<DnsPolicyForm>,
) -> Response {
    let auth = match require_admin(&state, &headers).await {
        Ok(value) => value,
        Err(response) => return response,
    };
    if let Some(response) = csrf_error_response(&auth, &form.csrf_token) {
        return response;
    }
    if !is_owner_admin(&auth) {
        return owner_only_response();
    }
    let resolvers = |value: &str| {
        value
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty())
            .map(str::to_string)
            .collect::<Vec<_>>()
    };
    let policy = stealthhub_core::policy::DnsPolicy {
        enabled: checkbox_enabled(&form.enabled),
        ipv6: checkbox_enabled(&form.ipv6),
        enhanced_mode: form.enhanced_mode,
        respect_rules: checkbox_enabled(&form.respect_rules),
        bootstrap_resolvers: resolvers(&form.bootstrap_resolvers),
        remote_resolvers: resolvers(&form.remote_resolvers),
        direct_resolvers: resolvers(&form.direct_resolvers),
    };
    match update_dns_policy(&state.pool, &policy).await {
        Ok(()) => {
            record_audit(
                &state,
                audit_event(
                    &auth,
                    AuditAction::DnsPolicySaved,
                    AuditObjectType::DnsPolicy,
                    "client",
                    AuditOutcome::Succeeded,
                    AuditMetadata::enabled(policy.enabled),
                ),
            )
            .await;
            Redirect::to("/admin/routing").into_response()
        }
        Err(error) => html_error_response_with_back(
            StatusCode::BAD_REQUEST,
            "DNS policy update failed",
            error.to_string(),
            "/admin/routing",
            "Back to Routing",
        ),
    }
}

async fn save_transport_pool_action(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<TransportPoolForm>,
) -> Response {
    let auth = match require_admin(&state, &headers).await {
        Ok(value) => value,
        Err(response) => return response,
    };
    if let Some(response) = csrf_error_response(&auth, &form.csrf_token) {
        return response;
    }
    if !is_owner_admin(&auth) {
        return owner_only_response();
    }
    let value = match transport_pool_from_form(&form) {
        Ok(value) => value,
        Err(error) => return routing_input_error("Transport pool rejected", error),
    };
    let profiles = match list_protocol_profiles_decoded(&state.pool).await {
        Ok(value) => value,
        Err(error) => return internal_error("load profiles for transport pool", error),
    };
    let original_id = (!form.original_id.trim().is_empty()).then_some(form.original_id.trim());
    let object_id = value.id.clone();
    match upsert_transport_pool(&state.pool, original_id, value, &profiles).await {
        Ok(()) => {
            record_audit(
                &state,
                audit_event(
                    &auth,
                    AuditAction::TransportPoolSaved,
                    AuditObjectType::TransportPool,
                    object_id,
                    AuditOutcome::Succeeded,
                    AuditMetadata::none(),
                ),
            )
            .await;
            Redirect::to("/admin/routing").into_response()
        }
        Err(error) => routing_input_error("Transport pool rejected", error),
    }
}

async fn delete_transport_pool_action(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<DeleteTransportPoolForm>,
) -> Response {
    let auth = match require_admin(&state, &headers).await {
        Ok(value) => value,
        Err(response) => return response,
    };
    if let Some(response) = csrf_error_response(&auth, &form.csrf_token) {
        return response;
    }
    if !is_owner_admin(&auth) {
        return owner_only_response();
    }
    let profiles = match list_protocol_profiles_decoded(&state.pool).await {
        Ok(value) => value,
        Err(error) => return internal_error("load profiles for pool deletion", error),
    };
    let replacement = (!form.replacement.trim().is_empty()).then_some(form.replacement.trim());
    match delete_transport_pool(&state.pool, form.id.trim(), replacement, &profiles).await {
        Ok(()) => {
            record_audit(
                &state,
                audit_event(
                    &auth,
                    AuditAction::TransportPoolDeleted,
                    AuditObjectType::TransportPool,
                    form.id.trim(),
                    AuditOutcome::Succeeded,
                    AuditMetadata::none(),
                ),
            )
            .await;
            Redirect::to("/admin/routing").into_response()
        }
        Err(error) => routing_input_error("Transport pool deletion rejected", error),
    }
}

async fn save_routing_policy_action(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<RoutingPolicyForm>,
) -> Response {
    let auth = match require_admin(&state, &headers).await {
        Ok(value) => value,
        Err(response) => return response,
    };
    if let Some(response) = csrf_error_response(&auth, &form.csrf_token) {
        return response;
    }
    if !is_owner_admin(&auth) {
        return owner_only_response();
    }
    let profiles = match list_protocol_profiles_decoded(&state.pool).await {
        Ok(value) => value,
        Err(error) => return internal_error("load profiles for routing policy", error),
    };
    let value = RoutingPolicyRule {
        id: form.id.trim().to_string(),
        display_name: form.display_name.trim().to_string(),
        enabled: checkbox_enabled(&form.enabled),
        priority: form.priority,
        condition: form.condition.trim().to_string(),
        target: form.target.trim().to_string(),
    };
    let original_id = (!form.original_id.trim().is_empty()).then_some(form.original_id.trim());
    let object_id = value.id.clone();
    match upsert_routing_policy(&state.pool, original_id, value, &profiles).await {
        Ok(()) => {
            record_audit(
                &state,
                audit_event(
                    &auth,
                    AuditAction::RoutingPolicySaved,
                    AuditObjectType::RoutingPolicy,
                    object_id,
                    AuditOutcome::Succeeded,
                    AuditMetadata::none(),
                ),
            )
            .await;
            Redirect::to("/admin/routing").into_response()
        }
        Err(error) => routing_input_error("Routing policy rejected", error),
    }
}

async fn delete_routing_policy_action(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<DeleteRoutingPolicyForm>,
) -> Response {
    let auth = match require_admin(&state, &headers).await {
        Ok(value) => value,
        Err(response) => return response,
    };
    if let Some(response) = csrf_error_response(&auth, &form.csrf_token) {
        return response;
    }
    if !is_owner_admin(&auth) {
        return owner_only_response();
    }
    match delete_routing_policy(&state.pool, form.id.trim()).await {
        Ok(()) => {
            record_audit(
                &state,
                audit_event(
                    &auth,
                    AuditAction::RoutingPolicyDeleted,
                    AuditObjectType::RoutingPolicy,
                    form.id.trim(),
                    AuditOutcome::Succeeded,
                    AuditMetadata::none(),
                ),
            )
            .await;
            Redirect::to("/admin/routing").into_response()
        }
        Err(error) => routing_input_error("Routing policy deletion rejected", error),
    }
}

fn transport_pool_from_form(form: &TransportPoolForm) -> anyhow::Result<TransportPool> {
    let optional_u32 = |label: &str, value: &str| -> anyhow::Result<Option<u32>> {
        let value = value.trim();
        if value.is_empty() {
            return Ok(None);
        }
        value
            .parse::<u32>()
            .map(Some)
            .map_err(|_| anyhow::anyhow!("{label} must be an unsigned integer"))
    };
    let kind = match form.kind.as_str() {
        "manual" | "select" => PoolKind::Select,
        "url-test" => PoolKind::UrlTest,
        "fallback" => PoolKind::Fallback,
        "load-balance" => PoolKind::LoadBalance,
        _ => anyhow::bail!("unknown transport pool strategy"),
    };
    let members = form
        .members
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(parse_pool_member)
        .collect::<anyhow::Result<Vec<_>>>()?;
    Ok(TransportPool {
        id: form.id.trim().to_string(),
        display_name: form.display_name.trim().to_string(),
        kind,
        enabled: checkbox_enabled(&form.enabled),
        members,
        test_url: (!form.test_url.trim().is_empty()).then(|| form.test_url.trim().to_string()),
        interval_seconds: optional_u32("interval", &form.interval_seconds)?,
        timeout_ms: optional_u32("timeout", &form.timeout_ms)?,
        tolerance_ms: optional_u32("tolerance", &form.tolerance_ms)?,
        max_failures: optional_u32("maximum failures", &form.max_failures)?,
        lazy: checkbox_enabled(&form.lazy),
        minimum_healthy_count: optional_u32("minimum healthy count", &form.minimum_healthy_count)?,
        fallback_pool: (!form.fallback_pool.trim().is_empty())
            .then(|| form.fallback_pool.trim().to_string()),
        priority: form.priority,
        strategy: (!form.strategy.trim().is_empty()).then(|| form.strategy.trim().to_string()),
    })
}

fn parse_pool_member(value: &str) -> anyhow::Result<PoolMember> {
    if value == "all-profiles" {
        return Ok(PoolMember::AllProfiles);
    }
    if value == "DIRECT" {
        return Ok(PoolMember::Direct);
    }
    if value == "REJECT" {
        return Ok(PoolMember::Reject);
    }
    let (kind, value) = value
        .split_once(':')
        .ok_or_else(|| anyhow::anyhow!("member must use kind:value syntax"))?;
    if value.trim().is_empty() {
        anyhow::bail!("transport pool member value is empty");
    }
    match kind {
        "profile" => Ok(PoolMember::Profile(value.trim().to_string())),
        "capability" => Ok(PoolMember::Capability(value.trim().to_string())),
        "role" => Ok(PoolMember::Role(parse_role(value.trim())?)),
        "pool" => Ok(PoolMember::Pool(value.trim().to_string())),
        _ => anyhow::bail!("unknown transport pool member kind"),
    }
}

fn routing_input_error(title: &'static str, error: anyhow::Error) -> Response {
    html_error_response_with_back(
        StatusCode::BAD_REQUEST,
        title,
        error.to_string(),
        "/admin/routing",
        "Back to Routing",
    )
}

async fn save_rule_set_action(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<RuleSetForm>,
) -> Response {
    let auth = match require_admin(&state, &headers).await {
        Ok(value) => value,
        Err(response) => return response,
    };
    if let Some(response) = csrf_error_response(&auth, &form.csrf_token) {
        return response;
    }
    if !is_owner_admin(&auth) {
        return owner_only_response();
    }
    let value = RoutingRuleSet {
        slug: form.slug.trim().to_string(),
        title: form.title.trim().to_string(),
        effect: form.effect.trim().to_string(),
        target: form.target.trim().to_string(),
        enabled: checkbox_enabled(&form.enabled),
        payload: form.payload,
    };
    let result = if checkbox_enabled(&form.create) {
        create_routing_rule_set(&state.pool, &value).await
    } else {
        save_routing_rule_set(&state.pool, &value).await
    };
    match result {
        Ok(()) => {
            record_audit(
                &state,
                audit_event(
                    &auth,
                    AuditAction::RuleSetSaved,
                    AuditObjectType::RuleSet,
                    value.slug,
                    AuditOutcome::Succeeded,
                    AuditMetadata::enabled(value.enabled),
                ),
            )
            .await;
            Redirect::to("/admin/routing").into_response()
        }
        Err(error) => routing_input_error("Rule set rejected", error),
    }
}

async fn delete_rule_set_action(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<RuleSetIdentityForm>,
) -> Response {
    let auth = match require_admin(&state, &headers).await {
        Ok(value) => value,
        Err(response) => return response,
    };
    if let Some(response) = csrf_error_response(&auth, &form.csrf_token) {
        return response;
    }
    if !is_owner_admin(&auth) {
        return owner_only_response();
    }
    match delete_routing_rule_set(&state.pool, form.slug.trim()).await {
        Ok(()) => {
            record_audit(
                &state,
                audit_event(
                    &auth,
                    AuditAction::RuleSetDeleted,
                    AuditObjectType::RuleSet,
                    form.slug.trim(),
                    AuditOutcome::Succeeded,
                    AuditMetadata::none(),
                ),
            )
            .await;
            Redirect::to("/admin/routing").into_response()
        }
        Err(error) => routing_input_error("Rule set deletion rejected", error),
    }
}

async fn clone_rule_set_action(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<RuleSetIdentityForm>,
) -> Response {
    let auth = match require_admin(&state, &headers).await {
        Ok(value) => value,
        Err(response) => return response,
    };
    if let Some(response) = csrf_error_response(&auth, &form.csrf_token) {
        return response;
    }
    if !is_owner_admin(&auth) {
        return owner_only_response();
    }
    match clone_routing_rule_set(&state.pool, form.slug.trim(), form.new_slug.trim()).await {
        Ok(()) => {
            record_audit(
                &state,
                audit_event(
                    &auth,
                    AuditAction::RuleSetCloned,
                    AuditObjectType::RuleSet,
                    form.new_slug.trim(),
                    AuditOutcome::Succeeded,
                    AuditMetadata::none(),
                ),
            )
            .await;
            Redirect::to("/admin/routing").into_response()
        }
        Err(error) => routing_input_error("Rule set clone rejected", error),
    }
}

async fn save_rule_entry_action(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<RuleEntryForm>,
) -> Response {
    let auth = match require_admin(&state, &headers).await {
        Ok(value) => value,
        Err(response) => return response,
    };
    if let Some(response) = csrf_error_response(&auth, &form.csrf_token) {
        return response;
    }
    if !is_owner_admin(&auth) {
        return owner_only_response();
    }
    let kind = match RuleKind::parse(&form.kind) {
        Ok(value) => value,
        Err(error) => return routing_input_error("Rule entry rejected", error),
    };
    let entry = RuleEntry {
        id: if form.id.trim().is_empty() {
            Uuid::new_v4().simple().to_string()
        } else {
            form.id.trim().to_string()
        },
        rule_set_id: form.rule_set_id.trim().to_string(),
        enabled: checkbox_enabled(&form.enabled),
        kind,
        value: form.value.trim().to_string(),
        comment: nonempty(&form.comment),
        source_tag: nonempty(&form.source_tag),
        priority: form.priority,
    };
    match upsert_rule_entry(&state.pool, &entry).await {
        Ok(()) => {
            record_audit(
                &state,
                audit_event(
                    &auth,
                    AuditAction::RuleEntrySaved,
                    AuditObjectType::RuleEntry,
                    &entry.id,
                    AuditOutcome::Succeeded,
                    AuditMetadata::enabled(entry.enabled),
                ),
            )
            .await;
            Redirect::to("/admin/routing").into_response()
        }
        Err(error) => routing_input_error("Rule entry rejected", error),
    }
}

async fn delete_rule_entry_action(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<RuleEntryIdentityForm>,
) -> Response {
    let auth = match require_admin(&state, &headers).await {
        Ok(value) => value,
        Err(response) => return response,
    };
    if let Some(response) = csrf_error_response(&auth, &form.csrf_token) {
        return response;
    }
    if !is_owner_admin(&auth) {
        return owner_only_response();
    }
    let _ = &form.rule_set_id;
    match delete_rule_entry(&state.pool, form.id.trim()).await {
        Ok(()) => {
            record_audit(
                &state,
                audit_event(
                    &auth,
                    AuditAction::RuleEntryDeleted,
                    AuditObjectType::RuleEntry,
                    form.id.trim(),
                    AuditOutcome::Succeeded,
                    AuditMetadata::none(),
                ),
            )
            .await;
            Redirect::to("/admin/routing").into_response()
        }
        Err(error) => routing_input_error("Rule entry deletion rejected", error),
    }
}

async fn bulk_rule_entries_action(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<BulkRuleEntryForm>,
) -> Response {
    let auth = match require_admin(&state, &headers).await {
        Ok(value) => value,
        Err(response) => return response,
    };
    if let Some(response) = csrf_error_response(&auth, &form.csrf_token) {
        return response;
    }
    if !is_owner_admin(&auth) {
        return owner_only_response();
    }
    let kind = match RuleKind::parse(&form.kind) {
        Ok(value) => value,
        Err(error) => return routing_input_error("Bulk rules rejected", error),
    };
    match bulk_add_rule_entries(
        &state.pool,
        form.rule_set_id.trim(),
        kind,
        &form.input,
        nonempty(&form.source_tag).as_deref(),
    )
    .await
    {
        Ok(count) => {
            record_audit(
                &state,
                audit_event(
                    &auth,
                    AuditAction::RuleEntriesBulkAdded,
                    AuditObjectType::RuleSet,
                    form.rule_set_id.trim(),
                    AuditOutcome::Succeeded,
                    AuditMetadata::count(count),
                ),
            )
            .await;
            Redirect::to("/admin/routing").into_response()
        }
        Err(error) => routing_input_error("Bulk rules rejected", error),
    }
}

async fn deduplicate_rule_entries_action(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<RuleEntryIdentityForm>,
) -> Response {
    let auth = match require_admin(&state, &headers).await {
        Ok(value) => value,
        Err(response) => return response,
    };
    if let Some(response) = csrf_error_response(&auth, &form.csrf_token) {
        return response;
    }
    if !is_owner_admin(&auth) {
        return owner_only_response();
    }
    match deduplicate_rule_entries(&state.pool, form.rule_set_id.trim()).await {
        Ok(count) => {
            record_audit(
                &state,
                audit_event(
                    &auth,
                    AuditAction::RuleEntriesDeduplicated,
                    AuditObjectType::RuleSet,
                    form.rule_set_id.trim(),
                    AuditOutcome::Succeeded,
                    AuditMetadata::count(count),
                ),
            )
            .await;
            Redirect::to("/admin/routing").into_response()
        }
        Err(error) => routing_input_error("Rule deduplication rejected", error),
    }
}

async fn save_rule_source_action(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<RuleSourceForm>,
) -> Response {
    let auth = match require_admin(&state, &headers).await {
        Ok(value) => value,
        Err(response) => return response,
    };
    if let Some(response) = csrf_error_response(&auth, &form.csrf_token) {
        return response;
    }
    if !is_owner_admin(&auth) {
        return owner_only_response();
    }
    let format = match RuleSourceFormat::parse(&form.format) {
        Ok(value) => value,
        Err(error) => return routing_input_error("Rule source rejected", error),
    };
    let source = RuleSetSource {
        id: if form.id.trim().is_empty() {
            Uuid::new_v4().simple().to_string()
        } else {
            form.id.trim().to_string()
        },
        rule_set_id: form.rule_set_id.trim().to_string(),
        url: form.url.trim().to_string(),
        format,
        enabled: checkbox_enabled(&form.enabled),
        refresh_interval_seconds: form.refresh_interval_seconds,
        etag: None,
        last_modified: None,
        last_successful_fetch: None,
        checksum: None,
        entry_count: 0,
        last_error: None,
        cached_payload: String::new(),
    };
    match upsert_rule_source(&state.pool, &source).await {
        Ok(()) => {
            record_audit(
                &state,
                audit_event(
                    &auth,
                    AuditAction::RuleSourceSaved,
                    AuditObjectType::RuleSource,
                    &source.id,
                    AuditOutcome::Succeeded,
                    AuditMetadata::enabled(source.enabled),
                ),
            )
            .await;
            Redirect::to("/admin/routing").into_response()
        }
        Err(error) => routing_input_error("Rule source rejected", error),
    }
}

async fn delete_rule_source_action(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<RuleEntryIdentityForm>,
) -> Response {
    let auth = match require_admin(&state, &headers).await {
        Ok(value) => value,
        Err(response) => return response,
    };
    if let Some(response) = csrf_error_response(&auth, &form.csrf_token) {
        return response;
    }
    if !is_owner_admin(&auth) {
        return owner_only_response();
    }
    match delete_rule_source(&state.pool, form.id.trim()).await {
        Ok(()) => {
            record_audit(
                &state,
                audit_event(
                    &auth,
                    AuditAction::RuleSourceDeleted,
                    AuditObjectType::RuleSource,
                    form.id.trim(),
                    AuditOutcome::Succeeded,
                    AuditMetadata::none(),
                ),
            )
            .await;
            Redirect::to("/admin/routing").into_response()
        }
        Err(error) => routing_input_error("Rule source deletion rejected", error),
    }
}

async fn refresh_rule_source_action(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<RuleEntryIdentityForm>,
) -> Response {
    let auth = match require_admin(&state, &headers).await {
        Ok(value) => value,
        Err(response) => return response,
    };
    if let Some(response) = csrf_error_response(&auth, &form.csrf_token) {
        return response;
    }
    if !is_owner_admin(&auth) {
        return owner_only_response();
    }
    match rule_sources::refresh(&state.pool, form.id.trim()).await {
        Ok(_) => {
            record_audit(
                &state,
                audit_event(
                    &auth,
                    AuditAction::RuleSourceRefreshRequested,
                    AuditObjectType::RuleSource,
                    form.id.trim(),
                    AuditOutcome::Requested,
                    AuditMetadata::none(),
                ),
            )
            .await;
            Redirect::to("/admin/routing").into_response()
        }
        Err(error) => routing_input_error("Rule source refresh failed", error),
    }
}

fn nonempty(value: &str) -> Option<String> {
    (!value.trim().is_empty()).then(|| value.trim().to_string())
}

async fn system_page(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let auth = match require_admin(&state, &headers).await {
        Ok(value) => value,
        Err(response) => return response,
    };
    let db_ready = sqlx::query_scalar::<_, i64>("SELECT 1")
        .fetch_one(&state.pool)
        .await
        .is_ok();
    let host = host_snapshot().await;
    let service_states = control_plane_service_states().await;
    let inventory =
        match inventory::load(&state.pool, &state.protocol_registry, &state.core_registry).await {
            Ok(value) => value.inventory,
            Err(error) => return internal_error("load system inventory", error),
        };

    views::system::render(
        &auth,
        db_ready,
        state.cookie_secure,
        &host,
        &service_states,
        &inventory,
    )
}

async fn configs_page(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let auth = match require_admin(&state, &headers).await {
        Ok(value) => value,
        Err(response) => return response,
    };
    if !is_owner_admin(&auth) {
        return owner_only_response();
    }

    let snapshots = config_files()
        .into_iter()
        .map(read_config_spec)
        .collect::<Vec<_>>();
    let inventory =
        match inventory::load(&state.pool, &state.protocol_registry, &state.core_registry).await {
            Ok(value) => value.inventory,
            Err(error) => return internal_error("load config resource inventory", error),
        };

    views::configs::render_index(&auth, &snapshots, &inventory)
}

async fn config_save_action(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<ConfigEditorForm>,
) -> Response {
    let auth = match require_admin(&state, &headers).await {
        Ok(value) => value,
        Err(response) => return response,
    };

    if let Some(response) = csrf_error_response(&auth, &form.csrf_token) {
        return response;
    }
    if !is_owner_admin(&auth) {
        return owner_only_response();
    }

    let report = write_config_file(&form.target, &form.content);
    let status = if report.success {
        StatusCode::OK
    } else {
        StatusCode::BAD_REQUEST
    };

    views::configs::render_save(&auth, &report, status)
}

async fn uninstall_preview_action(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<UninstallPreviewForm>,
) -> Response {
    let auth = match require_admin(&state, &headers).await {
        Ok(value) => value,
        Err(response) => return response,
    };

    if let Some(response) = csrf_error_response(&auth, &form.csrf_token) {
        return response;
    }
    if !is_owner_admin(&auth) {
        return owner_only_response();
    }

    let Some(plan) = uninstall_plan(&form.mode) else {
        return html_error_response_with_back(
            StatusCode::BAD_REQUEST,
            "Uninstall preview failed",
            "Unknown uninstall mode",
            "/admin/system",
            "Back to System",
        );
    };

    views::system::render_uninstall(&auth, &plan)
}

async fn credits_page(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let auth = match require_admin(&state, &headers).await {
        Ok(value) => value,
        Err(response) => return response,
    };

    views::credits::render(&auth)
}

async fn secrets_page(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let auth = match require_admin(&state, &headers).await {
        Ok(value) => value,
        Err(response) => return response,
    };
    if !is_owner_admin(&auth) {
        return owner_only_response();
    }
    let secret_names = match list_secret_names(&state.pool).await {
        Ok(value) => value,
        Err(error) => return internal_error("load secret names", error),
    };
    let profiles = match list_protocol_profiles_decoded(&state.pool).await {
        Ok(value) => value,
        Err(error) => return internal_error("load protocol profiles", error),
    };

    views::secrets::render(&auth, &secret_names, &profiles, &state.protocol_registry)
}

async fn secret_save_action(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<SecretForm>,
) -> Response {
    let auth = match require_admin(&state, &headers).await {
        Ok(value) => value,
        Err(response) => return response,
    };
    if let Some(response) = csrf_error_response(&auth, &form.csrf_token) {
        return response;
    }
    if !is_owner_admin(&auth) {
        return owner_only_response();
    }
    let name = form.name.trim();
    if !valid_secret_name(name) {
        return html_error_response_with_back(
            StatusCode::BAD_REQUEST,
            "Secret not saved",
            "Secret name must be 1-128 characters using letters, digits, dot, underscore or dash.",
            "/admin/secrets",
            "Back to Secrets",
        );
    }
    if form.value.is_empty() || form.value.len() > 8 * 1024 || form.value.contains('\0') {
        return html_error_response_with_back(
            StatusCode::BAD_REQUEST,
            "Secret not saved",
            "Secret value must contain 1-8192 bytes and no NUL characters.",
            "/admin/secrets",
            "Back to Secrets",
        );
    }
    let profiles = match list_protocol_profiles_decoded(&state.pool).await {
        Ok(profiles) => profiles,
        Err(error) => return internal_error("classify protocol secret", error),
    };
    if is_server_only_secret_reference(name, &profiles, &state.protocol_registry) {
        return html_error_response_with_back(
            StatusCode::BAD_REQUEST,
            "Secret not saved",
            "This reference is server-only. Store it with sudo infiproxy-manager so the web process never receives the value.",
            "/admin/secrets",
            "Back to Secrets",
        );
    }
    let existed = matches!(get_secret(&state.pool, name).await, Ok(Some(_)));
    let action = if existed {
        AuditAction::SecretReplaced
    } else {
        AuditAction::SecretCreated
    };
    let event = audit_event(
        &auth,
        action,
        AuditObjectType::SecretReference,
        name,
        AuditOutcome::Succeeded,
        AuditMetadata::none(),
    );
    if let Err(error) = upsert_secret_audited(&state.pool, name, &form.value, &event).await {
        return internal_error("store protocol secret", error);
    }
    queue_latest_reconcile(&state).await;

    Redirect::to("/admin/secrets").into_response()
}

async fn secret_delete_action(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<SecretDeleteForm>,
) -> Response {
    let auth = match require_admin(&state, &headers).await {
        Ok(value) => value,
        Err(response) => return response,
    };
    if let Some(response) = csrf_error_response(&auth, &form.csrf_token) {
        return response;
    }
    if !is_owner_admin(&auth) {
        return owner_only_response();
    }
    let name = form.name.trim();
    if !valid_secret_name(name) || form.confirm.trim() != name {
        return html_error_response_with_back(
            StatusCode::BAD_REQUEST,
            "Secret not deleted",
            "Type the exact secret name to confirm deletion.",
            "/admin/secrets",
            "Back to Secrets",
        );
    }
    let event = audit_event(
        &auth,
        AuditAction::SecretDeleted,
        AuditObjectType::SecretReference,
        name,
        AuditOutcome::Succeeded,
        AuditMetadata::none(),
    );
    if let Err(error) = delete_secret_audited(&state.pool, name, &event).await {
        tracing::warn!(secret_name = name, "secret deletion failed: {error}");
        return html_error_response_with_back(
            StatusCode::NOT_FOUND,
            "Secret not deleted",
            "The requested secret does not exist.",
            "/admin/secrets",
            "Back to Secrets",
        );
    }
    queue_latest_reconcile(&state).await;

    Redirect::to("/admin/secrets").into_response()
}

fn valid_secret_name(value: &str) -> bool {
    (1..=128).contains(&value.len())
        && value
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '-'))
}

fn is_server_only_secret_reference(
    name: &str,
    profiles: &[ProtocolProfile],
    registry: &ProtocolRegistry,
) -> bool {
    for profile in profiles {
        let Some(adapter) = registry.get(&profile.protocol_id) else {
            continue;
        };
        if adapter
            .server_only_secret_references(&profile.config)
            .is_ok_and(|references| {
                references
                    .iter()
                    .any(|reference| reference.as_str() == name)
            })
        {
            return true;
        }
    }
    false
}

async fn protocols_page(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let auth = match require_admin(&state, &headers).await {
        Ok(value) => value,
        Err(response) => return response,
    };

    let settings = match load_panel_settings(&state.pool).await {
        Ok(value) => value,
        Err(error) => {
            return logged_error_with_back(
                StatusCode::INTERNAL_SERVER_ERROR,
                "load protocol panel settings",
                error,
                "Protocols unavailable",
                "Panel settings could not be loaded. Review the server journal.",
                "/admin",
                "Back to Dashboard",
            );
        }
    };

    let profiles = match list_protocol_profiles_decoded(&state.pool).await {
        Ok(value) => value,
        Err(error) => {
            return logged_error_with_back(
                StatusCode::INTERNAL_SERVER_ERROR,
                "load protocol profiles",
                error,
                "Protocols unavailable",
                "Protocol profiles could not be loaded. Review the server journal.",
                "/admin",
                "Back to Dashboard",
            );
        }
    };

    let secret_names = match list_secret_names(&state.pool).await {
        Ok(value) => value,
        Err(error) => {
            return logged_error_with_back(
                StatusCode::INTERNAL_SERVER_ERROR,
                "load protocol secret names",
                error,
                "Protocols unavailable",
                "Protocol secret names could not be loaded. Review the server journal.",
                "/admin",
                "Back to Dashboard",
            );
        }
    };
    let inventory =
        match inventory::load(&state.pool, &state.protocol_registry, &state.core_registry).await {
            Ok(value) => value.inventory,
            Err(error) => return internal_error("load protocol inventory", error),
        };
    let user_sync = match list_runtime_user_sync(&state.pool).await {
        Ok(value) => value,
        Err(error) => return internal_error("load protocol user synchronization", error),
    };

    views::protocols::render(
        &auth,
        &settings,
        &profiles,
        &secret_names,
        &state.protocol_registry,
        &inventory,
        &user_sync,
    )
}

async fn update_protocol_action(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(name): Path<String>,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    let auth = match require_admin(&state, &headers).await {
        Ok(value) => value,
        Err(response) => return response,
    };

    if let Some(response) =
        csrf_error_response(&auth, form.get("csrf_token").map_or("", String::as_str))
    {
        return response;
    }
    if !is_owner_admin(&auth) {
        return owner_only_response();
    }

    let profiles = match list_protocol_profiles_decoded(&state.pool).await {
        Ok(value) => value,
        Err(error) => {
            return logged_error_with_back(
                StatusCode::INTERNAL_SERVER_ERROR,
                "load protocol profile for update",
                error,
                "Protocol update failed",
                "Protocol profiles could not be loaded. Review the server journal.",
                "/admin/protocols",
                "Back to Protocols",
            )
        }
    };
    let Some(existing) = profiles.into_iter().find(|profile| profile.name == name) else {
        return html_error_response(
            StatusCode::NOT_FOUND,
            "Protocol update failed",
            "Profile not found",
        );
    };

    let server = match normalize_profile_server(form.get("server").map_or("", String::as_str)) {
        Ok(value) => value,
        Err(message) => {
            return html_error_response(StatusCode::BAD_REQUEST, "Protocol update failed", message)
        }
    };
    let port = match form.get("port").and_then(|value| value.parse::<u16>().ok()) {
        Some(port) if port > 0 => port,
        _ => {
            return html_error_response(
                StatusCode::BAD_REQUEST,
                "Protocol update failed",
                "Server port must be between 1 and 65535.",
            )
        }
    };

    let config = match protocol_config_from_form(&existing, &form, &state.protocol_registry) {
        Ok(value) => value,
        Err(err) => {
            return html_error_response(
                StatusCode::BAD_REQUEST,
                "Protocol update failed",
                err.to_string(),
            )
        }
    };

    let previous_enabled = existing.enabled;
    let profile_name = existing.name.clone();
    let input = UpdateProtocolProfile {
        name: existing.name,
        enabled: form
            .get("enabled")
            .is_some_and(|value| checkbox_enabled(value)),
        server,
        port,
        preferred_core_id: existing.preferred_core_id,
        managed_resource_id: existing.managed_resource_id,
        config,
    };

    let enabled = form
        .get("enabled")
        .is_some_and(|value| checkbox_enabled(value));
    let action = if enabled != previous_enabled {
        if enabled {
            AuditAction::ProtocolProfileEnabled
        } else {
            AuditAction::ProtocolProfileDisabled
        }
    } else {
        AuditAction::ProtocolProfileSaved
    };
    let event = audit_event(
        &auth,
        action,
        AuditObjectType::ProtocolProfile,
        profile_name,
        AuditOutcome::Succeeded,
        AuditMetadata::enabled(enabled),
    );
    match update_protocol_profile_audited(&state.pool, input, &event).await {
        Ok(_) => {
            queue_latest_reconcile(&state).await;
            Redirect::to("/admin/protocols").into_response()
        }
        Err(error) => logged_error_with_back(
            StatusCode::INTERNAL_SERVER_ERROR,
            "update protocol profile",
            error,
            "Protocol update failed",
            "The protocol profile could not be saved. Review the server journal.",
            "/admin/protocols",
            "Back to Protocols",
        ),
    }
}

fn protocol_config_from_form(
    existing: &ProtocolProfile,
    form: &HashMap<String, String>,
    registry: &ProtocolRegistry,
) -> anyhow::Result<serde_json::Value> {
    let adapter = registry
        .get(&existing.protocol_id)
        .ok_or_else(|| anyhow::anyhow!("protocol adapter is not installed"))?;
    let mut config = existing
        .config
        .as_object()
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("stored adapter configuration is invalid"))?;
    for field in adapter.fields() {
        let value = form.get(&field.name).map_or("", String::as_str).trim();
        if value.is_empty() {
            if field.required {
                return Err(anyhow::anyhow!("{} is required", field.label));
            }
            config.remove(&field.name);
            continue;
        }
        let value = required_profile_field(value, &field.label, 2_048)?;
        if field.kind == ConfigFieldKind::SecretRef {
            SecretRef::parse(&value)?;
        }
        config.insert(field.name.clone(), serde_json::Value::String(value));
    }
    let config = serde_json::Value::Object(config);
    adapter.validate_config(existing.schema_version, &config)?;
    Ok(config)
}

fn required_profile_field(value: &str, label: &str, maximum: usize) -> anyhow::Result<String> {
    let value = value.trim();
    if value.is_empty() {
        return Err(anyhow::anyhow!("{label} is required"));
    }
    if value.len() > maximum || value.chars().any(char::is_control) {
        return Err(anyhow::anyhow!("{label} is invalid or too long"));
    }
    Ok(value.to_string())
}

fn normalize_profile_server(value: &str) -> Result<String, &'static str> {
    let value = value.trim().trim_end_matches('.');
    if let Ok(address) = value.parse::<IpAddr>() {
        return Ok(address.to_string());
    }
    if let Some(address) = value
        .strip_prefix('[')
        .and_then(|value| value.strip_suffix(']'))
    {
        let address = address
            .parse::<IpAddr>()
            .map_err(|_| "Server must be a valid DNS name or IP address.")?;
        if address.is_ipv6() {
            return Ok(address.to_string());
        }
    }
    if value.contains(':') {
        return Err("Do not include a port in the server field; use the separate port field.");
    }
    normalize_public_host(value)
}

fn normalize_public_host(value: &str) -> Result<String, &'static str> {
    let value = value.trim().trim_end_matches('.');
    if value.is_empty() {
        return Err("Host must not be empty.");
    }

    if value.contains("://") || value.contains('/') || value.contains('\\') {
        return Err("Use host only, without scheme, path, or trailing slash.");
    }

    if value.len() > 261 {
        return Err("Host is too long.");
    }

    if let Some(bracketed) = value.strip_prefix('[') {
        let Some(closing) = bracketed.find(']') else {
            return Err("Bracketed IPv6 host is incomplete.");
        };
        let address = &bracketed[..closing];
        let suffix = &bracketed[closing + 1..];
        let ip = address
            .parse::<IpAddr>()
            .map_err(|_| "Bracketed host must be a valid IPv6 address.")?;
        if !ip.is_ipv6() {
            return Err("Brackets are only valid around an IPv6 address.");
        }
        let port = normalize_optional_port(suffix)?;
        return Ok(format!("[{ip}]{port}"));
    }

    if value.matches(':').count() > 1 {
        return Err("IPv6 addresses must be enclosed in brackets.");
    }

    let (host, port_suffix) = match value.rsplit_once(':') {
        Some((host, port)) => (host, normalize_optional_port(&format!(":{port}"))?),
        None => (value, String::new()),
    };
    let host = host.trim_end_matches('.');
    if host.is_empty() || host.len() > 253 {
        return Err("Host is empty or too long.");
    }

    if let Ok(ip) = host.parse::<IpAddr>() {
        if ip.is_ipv6() {
            return Err("IPv6 addresses must be enclosed in brackets.");
        }
        return Ok(format!("{ip}{port_suffix}"));
    }

    if !host.eq_ignore_ascii_case("localhost")
        && host.split('.').any(|label| {
            label.is_empty()
                || label.len() > 63
                || !label
                    .chars()
                    .all(|ch| ch.is_ascii_alphanumeric() || ch == '-')
                || !label
                    .as_bytes()
                    .first()
                    .is_some_and(u8::is_ascii_alphanumeric)
                || !label
                    .as_bytes()
                    .last()
                    .is_some_and(u8::is_ascii_alphanumeric)
        })
    {
        return Err("Host must be a valid DNS name, IPv4 address, or bracketed IPv6 address.");
    }

    Ok(format!("{}{port_suffix}", host.to_ascii_lowercase()))
}

fn normalize_optional_port(value: &str) -> Result<String, &'static str> {
    if value.is_empty() {
        return Ok(String::new());
    }
    let Some(port) = value.strip_prefix(':') else {
        return Err("Unexpected data after host.");
    };
    let port = port
        .parse::<u16>()
        .ok()
        .filter(|port| *port != 0)
        .ok_or("Port must be a number from 1 to 65535.")?;
    Ok(format!(":{port}"))
}

fn valid_account_name(value: &str, minimum_length: usize) -> bool {
    (minimum_length..=64).contains(&value.len())
        && value
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphanumeric)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

fn checkbox_enabled(value: &str) -> bool {
    matches!(value, "1" | "true" | "yes" | "on")
}

async fn users_page(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let auth = match require_admin(&state, &headers).await {
        Ok(value) => value,
        Err(response) => return response,
    };

    let users = match list_users(&state.pool).await {
        Ok(value) => value,
        Err(error) => {
            return logged_error_with_back(
                StatusCode::INTERNAL_SERVER_ERROR,
                "load users",
                error,
                "Users unavailable",
                "Users could not be loaded. Review the server journal.",
                "/admin",
                "Back to Dashboard",
            );
        }
    };
    let user_sync = match list_runtime_user_sync(&state.pool).await {
        Ok(value) => value,
        Err(error) => return internal_error("load user synchronization summary", error),
    };

    views::users::render_index(&auth, &users, &user_sync)
}

async fn audit_page(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<AuditPageQuery>,
) -> Response {
    const PAGE_SIZE: u32 = 50;
    let auth = match require_admin(&state, &headers).await {
        Ok(value) => value,
        Err(response) => return response,
    };
    if !can_view_audit(&auth) {
        return owner_only_response();
    }
    let page = query.page.unwrap_or(0).min(2_000);
    let offset = u64::from(page) * u64::from(PAGE_SIZE);
    let events = match list_audit_events(&state.pool, PAGE_SIZE, offset).await {
        Ok(value) => value,
        Err(error) => return internal_error("load administrative audit history", error),
    };
    let total = match audit_event_count(&state.pool).await {
        Ok(value) => value.max(0) as u64,
        Err(error) => return internal_error("count administrative audit history", error),
    };
    views::audit::render(&auth, &events, page, offset + u64::from(PAGE_SIZE) < total)
}

async fn create_user_action(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<CreateUserForm>,
) -> Response {
    let auth = match require_admin(&state, &headers).await {
        Ok(value) => value,
        Err(response) => return response,
    };

    if let Some(response) = csrf_error_response(&auth, &form.csrf_token) {
        return response;
    }

    let username = form.username.trim().to_string();

    if !valid_account_name(&username, 1) {
        return html_error_response(
            StatusCode::BAD_REQUEST,
            "Bad request",
            "Username must be 1-64 ASCII letters, digits, dots, underscores or hyphens and must start with a letter or digit.",
        );
    }

    let traffic_limit_bytes = match form.traffic_limit_gb.trim() {
        "" | "0" => None,
        value => {
            let gb = match value.parse::<i64>() {
                Ok(value) if value > 0 => value,
                Ok(_) => {
                    return html_error_response(
                        StatusCode::BAD_REQUEST,
                        "Bad request",
                        "Traffic limit must be positive",
                    );
                }
                Err(_) => {
                    return html_error_response(
                        StatusCode::BAD_REQUEST,
                        "Bad request",
                        "Traffic limit must be a number",
                    );
                }
            };

            match gb.checked_mul(1024 * 1024 * 1024) {
                Some(bytes) => Some(bytes),
                None => {
                    return html_error_response(
                        StatusCode::BAD_REQUEST,
                        "Bad request",
                        "Traffic limit is too large",
                    );
                }
            }
        }
    };
    let expires_at = match form.expires_in_days.trim() {
        "" | "0" => None,
        value => {
            let days = match value.parse::<i64>() {
                Ok(value) if (1..=3650).contains(&value) => value,
                Ok(_) => {
                    return html_error_response(
                        StatusCode::BAD_REQUEST,
                        "Bad request",
                        "Expiry must be between 1 and 3650 days",
                    );
                }
                Err(_) => {
                    return html_error_response(
                        StatusCode::BAD_REQUEST,
                        "Bad request",
                        "Expiry must be a number",
                    );
                }
            };

            Some(Utc::now() + Duration::days(days))
        }
    };

    let input = NewUser {
        username,
        traffic_limit_bytes,
        expires_at,
    };

    let event = audit_event(
        &auth,
        AuditAction::UserCreated,
        AuditObjectType::User,
        input.username.clone(),
        AuditOutcome::Succeeded,
        AuditMetadata::none(),
    );
    match create_user_audited(&state.pool, input, &event).await {
        Ok(_) => {
            queue_latest_reconcile(&state).await;
            Redirect::to("/admin/users").into_response()
        }
        Err(error) => logged_error_with_back(
            StatusCode::CONFLICT,
            "create subscription user",
            error,
            "Create user failed",
            "The username is already used or the user could not be created.",
            "/admin/users",
            "Back to Users",
        ),
    }
}
async fn toggle_user_action(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<i64>,
    Form(form): Form<CsrfForm>,
) -> Response {
    let auth = match require_admin(&state, &headers).await {
        Ok(value) => value,
        Err(response) => return response,
    };

    if let Some(response) = csrf_error_response(&auth, &form.csrf_token) {
        return response;
    }

    let user = match get_user_by_id(&state.pool, id).await {
        Ok(value) => value,
        Err(error) => {
            return logged_error_with_back(
                StatusCode::NOT_FOUND,
                "load user for toggle",
                error,
                "User not found",
                "The requested user does not exist.",
                "/admin/users",
                "Back to Users",
            );
        }
    };

    let enabled = !user.enabled;
    let event = audit_event(
        &auth,
        if enabled {
            AuditAction::UserEnabled
        } else {
            AuditAction::UserDisabled
        },
        AuditObjectType::User,
        user.username,
        AuditOutcome::Succeeded,
        AuditMetadata::enabled(enabled),
    );
    match set_user_enabled_audited(&state.pool, id, enabled, &event).await {
        Ok(()) => {
            queue_latest_reconcile(&state).await;
            Redirect::to("/admin/users").into_response()
        }
        Err(error) => logged_error_with_back(
            StatusCode::INTERNAL_SERVER_ERROR,
            "toggle user",
            error,
            "Toggle user failed",
            "The user state could not be changed. Review the server journal.",
            "/admin/users",
            "Back to Users",
        ),
    }
}

async fn reset_user_token_page(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<i64>,
) -> Response {
    let auth = match require_admin(&state, &headers).await {
        Ok(value) => value,
        Err(response) => return response,
    };

    let user = match get_user_by_id(&state.pool, id).await {
        Ok(value) => value,
        Err(error) => {
            return logged_error_with_back(
                StatusCode::NOT_FOUND,
                "load user for token reset",
                error,
                "User not found",
                "The requested user does not exist.",
                "/admin/users",
                "Back to Users",
            );
        }
    };

    views::users::render_reset(&auth, &user)
}

async fn reset_user_token_action(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<i64>,
    Form(form): Form<CsrfForm>,
) -> Response {
    let auth = match require_admin(&state, &headers).await {
        Ok(value) => value,
        Err(response) => return response,
    };

    if let Some(response) = csrf_error_response(&auth, &form.csrf_token) {
        return response;
    }

    let user = match get_user_by_id(&state.pool, id).await {
        Ok(value) => value,
        Err(error) => return internal_error("load user for token reset", error),
    };
    let event = audit_event(
        &auth,
        AuditAction::UserSubscriptionTokenReset,
        AuditObjectType::User,
        user.username,
        AuditOutcome::Succeeded,
        AuditMetadata::none(),
    );
    match reset_user_subscription_token_audited(&state.pool, id, &event).await {
        Ok(_) => Redirect::to("/admin/users").into_response(),
        Err(error) => logged_error_with_back(
            StatusCode::INTERNAL_SERVER_ERROR,
            "reset subscription token",
            error,
            "Reset token failed",
            "The subscription token could not be reset. Review the server journal.",
            "/admin/users",
            "Back to Users",
        ),
    }
}

async fn delete_user_page(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<i64>,
) -> Response {
    let auth = match require_admin(&state, &headers).await {
        Ok(value) => value,
        Err(response) => return response,
    };

    let user = match get_user_by_id(&state.pool, id).await {
        Ok(value) => value,
        Err(error) => {
            return logged_error_with_back(
                StatusCode::NOT_FOUND,
                "load user for deletion",
                error,
                "User not found",
                "The requested user does not exist.",
                "/admin/users",
                "Back to Users",
            );
        }
    };

    views::users::render_delete(&auth, &user)
}

async fn delete_user_action(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<i64>,
    Form(form): Form<CsrfForm>,
) -> Response {
    let auth = match require_admin(&state, &headers).await {
        Ok(value) => value,
        Err(response) => return response,
    };

    if let Some(response) = csrf_error_response(&auth, &form.csrf_token) {
        return response;
    }

    let user = match get_user_by_id(&state.pool, id).await {
        Ok(value) => value,
        Err(error) => return internal_error("load user for deletion", error),
    };
    let event = audit_event(
        &auth,
        AuditAction::UserDeleted,
        AuditObjectType::User,
        user.username,
        AuditOutcome::Succeeded,
        AuditMetadata::none(),
    );
    match delete_user_audited(&state.pool, id, &event).await {
        Ok(()) => {
            queue_latest_reconcile(&state).await;
            Redirect::to("/admin/users").into_response()
        }
        Err(error) => logged_error_with_back(
            StatusCode::INTERNAL_SERVER_ERROR,
            "delete user",
            error,
            "Delete user failed",
            "The user could not be deleted. Review the server journal.",
            "/admin/users",
            "Back to Users",
        ),
    }
}

pub(crate) async fn require_admin(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<AuthenticatedAdmin, Response> {
    match current_admin(state, headers).await {
        Ok(Some(admin)) => Ok(admin),
        Ok(None) => match admin_count(&state.pool).await {
            Ok(0) => Err(Redirect::to("/admin/setup").into_response()),
            Ok(_) => Err(Redirect::to("/admin/login").into_response()),
            Err(error) => Err(internal_error("inspect administrator state", error)),
        },
        Err(error) => Err(internal_error("validate administrator session", error)),
    }
}

async fn current_admin(
    state: &AppState,
    headers: &HeaderMap,
) -> anyhow::Result<Option<AuthenticatedAdmin>> {
    let Some(token) = session_token_from_headers(headers) else {
        return Ok(None);
    };

    let token_hash = hash_session_token(&token);
    let Some(session) = get_valid_admin_session(&state.pool, &token_hash).await? else {
        return Ok(None);
    };

    let admin = get_admin_by_id(&state.pool, session.admin_id).await?;
    if admin.is_some()
        && session.last_seen_at <= Utc::now() - Duration::minutes(SESSION_TOUCH_INTERVAL_MINUTES)
    {
        touch_admin_session(&state.pool, &token_hash).await?;
    } else if admin.is_none() {
        delete_admin_session(&state.pool, &token_hash).await?;
    }

    let update_notice = update::load_notice(&state.pool).await?;
    let Some(admin) = admin else {
        return Ok(None);
    };
    let is_owner = is_owner_admin_id(&state.pool, admin.id).await?;

    Ok(Some(AuthenticatedAdmin {
        admin,
        is_owner,
        csrf_token: csrf_token_for_session_token(&token),
        update_notice,
    }))
}

async fn create_session_redirect(state: &AppState, admin_id: i64, location: &str) -> Response {
    if let Err(error) = delete_expired_admin_sessions(&state.pool).await {
        tracing::warn!(%error, "failed to prune expired administrator sessions");
    }

    let token = match generate_session_token() {
        Ok(token) => token,
        Err(error) => return internal_error("generate administrator session", error),
    };
    let token_hash = hash_session_token(&token);
    let expires_at = Utc::now() + Duration::days(ADMIN_SESSION_TTL_DAYS);

    match create_admin_session(&state.pool, admin_id, &token_hash, expires_at).await {
        Ok(()) => {
            let mut response = Redirect::to(location).into_response();
            append_session_cookie(&mut response, expired_legacy_session_cookie(state));
            append_session_cookie(&mut response, active_session_cookie(state, token));
            response
        }
        Err(error) => internal_error("create administrator session", error),
    }
}

fn hash_password(password: &str) -> anyhow::Result<String> {
    let password_hash = Argon2::default()
        .hash_password(password.as_bytes())
        .map_err(|err| anyhow::anyhow!("argon2 password hash failed: {err}"))?;

    Ok(password_hash.to_string())
}

fn verify_password(password: &str, password_hash: &str) -> anyhow::Result<bool> {
    let parsed_hash = PasswordHash::new(password_hash)
        .map_err(|err| anyhow::anyhow!("stored password hash is invalid: {err}"))?;

    match Argon2::default().verify_password(password.as_bytes(), &parsed_hash) {
        Ok(()) => Ok(true),
        Err(argon2::password_hash::Error::PasswordInvalid) => Ok(false),
        Err(err) => Err(anyhow::anyhow!(
            "argon2 password verification failed: {err}"
        )),
    }
}

async fn hash_password_limited(state: &AppState, password: String) -> anyhow::Result<String> {
    let permit = state
        .password_workers
        .clone()
        .acquire_owned()
        .await
        .map_err(|error| anyhow::anyhow!("password worker semaphore closed: {error}"))?;
    tokio::task::spawn_blocking(move || {
        let result = hash_password(&password);
        drop(permit);
        result
    })
    .await
    .map_err(|error| anyhow::anyhow!("password worker failed: {error}"))?
}

async fn verify_password_limited(
    state: &AppState,
    password: String,
    password_hash: String,
) -> anyhow::Result<Option<bool>> {
    let Ok(permit) = state.password_workers.clone().try_acquire_owned() else {
        return Ok(None);
    };
    let result = tokio::task::spawn_blocking(move || {
        let result = verify_password(&password, &password_hash);
        drop(permit);
        result
    })
    .await
    .map_err(|error| anyhow::anyhow!("password worker failed: {error}"))??;
    Ok(Some(result))
}

fn generate_session_token() -> anyhow::Result<String> {
    let mut token = [0_u8; 32];
    getrandom::fill(&mut token)?;
    Ok(URL_SAFE_NO_PAD.encode(token))
}

fn hash_session_token(token: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(token.as_bytes()))
}

fn csrf_token_for_session_token(token: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"infiproxy-admin-csrf-v1:");
    hasher.update(token.as_bytes());
    URL_SAFE_NO_PAD.encode(hasher.finalize())
}

fn setup_token_matches(state: &AppState, candidate: &str) -> bool {
    let expected = state.setup_token.as_bytes();
    let candidate = candidate.trim().as_bytes();
    expected.len() >= MIN_SETUP_TOKEN_LEN
        && expected.len() == candidate.len()
        && bool::from(expected.ct_eq(candidate))
}

fn session_token_from_headers(headers: &HeaderMap) -> Option<String> {
    let cookie_header = headers.get(header::COOKIE)?.to_str().ok()?;

    cookie_header.split(';').find_map(|value| {
        let cookie = Cookie::parse(value.trim().to_string()).ok()?;
        (cookie.name() == ADMIN_SESSION_COOKIE).then(|| cookie.value().to_string())
    })
}

fn active_session_cookie(state: &AppState, token: String) -> Cookie<'static> {
    Cookie::build((ADMIN_SESSION_COOKIE, token))
        .path("/admin")
        .http_only(true)
        .secure(state.cookie_secure)
        .same_site(SameSite::Lax)
        .max_age(CookieDuration::days(ADMIN_SESSION_TTL_DAYS))
        .build()
}

fn expired_session_cookie(state: &AppState) -> Cookie<'static> {
    Cookie::build((ADMIN_SESSION_COOKIE, ""))
        .path("/admin")
        .http_only(true)
        .secure(state.cookie_secure)
        .same_site(SameSite::Lax)
        .max_age(CookieDuration::seconds(0))
        .build()
}

fn expired_legacy_session_cookie(state: &AppState) -> Cookie<'static> {
    Cookie::build((ADMIN_SESSION_COOKIE, ""))
        .path("/")
        .http_only(true)
        .secure(state.cookie_secure)
        .same_site(SameSite::Lax)
        .max_age(CookieDuration::seconds(0))
        .build()
}

fn append_session_cookie(response: &mut Response, cookie: Cookie<'static>) {
    if let Ok(value) = HeaderValue::from_str(&cookie.to_string()) {
        response.headers_mut().append(header::SET_COOKIE, value);
    }
}

async fn login_failed_response() -> Response {
    tokio::time::sleep(std::time::Duration::from_millis(LOGIN_FAILURE_DELAY_MS)).await;

    html_error_response_with_back(
        StatusCode::UNAUTHORIZED,
        "Login failed",
        "Username or password is incorrect",
        "/admin/login",
        "Back to Login",
    )
}

fn rate_limited_response(retry_after: StdDuration) -> Response {
    let retry_after_secs = retry_after.as_secs().max(1).to_string();
    let mut response = html_error_response_with_back(
        StatusCode::TOO_MANY_REQUESTS,
        "Login temporarily blocked",
        "Too many failed login attempts. Please wait and try again.",
        "/admin/login",
        "Back to Login",
    );

    if let Ok(value) = HeaderValue::from_str(&retry_after_secs) {
        response.headers_mut().insert(header::RETRY_AFTER, value);
    }

    response
}

fn password_workers_busy_response() -> Response {
    let mut response = html_error_response_with_back(
        StatusCode::TOO_MANY_REQUESTS,
        "Login capacity reached",
        "Password verification is busy. Wait a few seconds and try again.",
        "/admin/login",
        "Back to Login",
    );
    response
        .headers_mut()
        .insert(header::RETRY_AFTER, HeaderValue::from_static("3"));
    response
}

fn login_rate_limit_keys(
    headers: &HeaderMap,
    peer_addr: SocketAddr,
    username: &str,
) -> Vec<String> {
    let username: String = username
        .trim()
        .to_ascii_lowercase()
        .chars()
        .take(128)
        .collect();
    let username = if username.is_empty() {
        "<empty>".to_string()
    } else {
        username
    };

    let source = login_source_hint(headers, peer_addr);
    vec![
        format!("source:{source}"),
        format!("account-source:{username}@{source}"),
    ]
}

fn login_source_hint(headers: &HeaderMap, peer_addr: SocketAddr) -> String {
    if peer_addr.ip().is_loopback() {
        if let Some(forwarded) = trusted_forwarded_source(headers) {
            return forwarded;
        }
    }

    peer_addr.ip().to_string()
}

fn trusted_forwarded_source(headers: &HeaderMap) -> Option<String> {
    headers
        .get("x-real-ip")
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .and_then(|value| value.parse::<IpAddr>().ok())
        .map(|ip| ip.to_string())
}

impl LoginRateLimiter {
    fn retry_after(&self, keys: &[String]) -> Option<StdDuration> {
        let now = Instant::now();
        let mut attempts = self
            .attempts
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        prune_login_attempts(&mut attempts, now);

        keys.iter()
            .filter_map(|key| {
                let attempt = attempts.get_mut(key)?;
                if now.duration_since(attempt.window_started_at) >= LOGIN_RATE_LIMIT_WINDOW {
                    attempts.remove(key);
                    return None;
                }

                (attempt.failures >= LOGIN_RATE_LIMIT_MAX_FAILURES).then(|| {
                    LOGIN_RATE_LIMIT_WINDOW
                        .saturating_sub(now.duration_since(attempt.window_started_at))
                })
            })
            .max()
    }

    fn record_failure(&self, keys: &[String]) {
        let now = Instant::now();
        let mut attempts = self
            .attempts
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        prune_login_attempts(&mut attempts, now);

        for key in keys {
            if !attempts.contains_key(key) && attempts.len() >= LOGIN_RATE_LIMIT_MAX_KEYS {
                continue;
            }

            let attempt = attempts.entry(key.clone()).or_insert(LoginAttempt {
                failures: 0,
                window_started_at: now,
            });

            if now.duration_since(attempt.window_started_at) >= LOGIN_RATE_LIMIT_WINDOW {
                attempt.failures = 0;
                attempt.window_started_at = now;
            }

            attempt.failures = attempt.failures.saturating_add(1);
        }
    }

    fn record_success(&self, keys: &[String]) {
        let mut attempts = self
            .attempts
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        for key in keys {
            attempts.remove(key);
        }
    }
}

fn prune_login_attempts(attempts: &mut HashMap<String, LoginAttempt>, now: Instant) {
    attempts.retain(|_, attempt| {
        now.duration_since(attempt.window_started_at) < LOGIN_RATE_LIMIT_WINDOW
    });
}

fn csrf_error_response(auth: &AuthenticatedAdmin, csrf_token: &str) -> Option<Response> {
    if csrf_token
        .as_bytes()
        .ct_eq(auth.csrf_token.as_bytes())
        .into()
    {
        return None;
    }

    Some(html_error_response_with_back(
        StatusCode::FORBIDDEN,
        "Request blocked",
        "Security token is missing or invalid. Please reload the page and try again.",
        "/admin",
        "Back to Dashboard",
    ))
}

async fn load_secret_values_map(
    pool: &SqlitePool,
    profiles: &[ProtocolProfile],
    registry: &ProtocolRegistry,
) -> anyhow::Result<HashMap<String, String>> {
    let mut secrets = HashMap::new();

    for profile in profiles {
        let adapter = registry
            .get(&profile.protocol_id)
            .ok_or_else(|| anyhow::anyhow!("protocol adapter is unavailable"))?;
        for reference in adapter.client_secret_references(&profile.config)? {
            if secrets.contains_key(reference.as_str()) {
                continue;
            }
            if let Some(secret) = get_secret(pool, reference.as_str()).await? {
                secrets.insert(reference.as_str().to_string(), secret.value);
            }
        }
    }

    Ok(secrets)
}

async fn queue_latest_reconcile(state: &AppState) {
    let result = async {
        let status = get_reconcile_state(&state.pool).await?;
        let generation = u64::try_from(status.desired_generation)
            .map_err(|_| anyhow::anyhow!("invalid desired generation"))?;
        reconcile_request::publish(generation)
    }
    .await;
    if let Err(error) = result {
        tracing::error!(
            "desired state is pending but the root reconcile request could not be queued: {error}"
        );
    }
}

const fn is_owner_admin(auth: &AuthenticatedAdmin) -> bool {
    auth.is_owner
}

const fn can_view_audit(auth: &AuthenticatedAdmin) -> bool {
    auth.is_owner
}

fn audit_event(
    auth: &AuthenticatedAdmin,
    action: AuditAction,
    object_type: AuditObjectType,
    object_id: impl Into<String>,
    outcome: AuditOutcome,
    metadata: AuditMetadata,
) -> NewAuditEvent {
    let actor = if auth.is_owner {
        AuditActor::owner(auth.admin.id, auth.admin.username.clone())
    } else {
        AuditActor::admin(auth.admin.id, auth.admin.username.clone())
    };
    NewAuditEvent {
        actor,
        action,
        object_type,
        object_id: object_id.into(),
        outcome,
        metadata,
    }
}

async fn record_audit(state: &AppState, event: NewAuditEvent) {
    if let Err(error) = append_audit_event(&state.pool, &event).await {
        tracing::error!(
            action = event.action.as_str(),
            "could not append audit event: {error}"
        );
    }
}

fn owner_only_response() -> Response {
    html_error_response_with_back(
        StatusCode::FORBIDDEN,
        "Owner-only action",
        "This break-glass operation is available only to the first admin created during initial setup.",
        "/admin/system",
        "Back to System",
    )
}

async fn security_headers(request: Request<Body>, next: Next) -> Response {
    let path = request.uri().path();
    let is_sensitive_path = path.starts_with("/admin") || path.starts_with("/sub/");
    let mut response = next.run(request).await;
    let headers = response.headers_mut();

    headers.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(
            "default-src 'none'; style-src 'self'; img-src 'self' data:; form-action 'self'; base-uri 'none'; frame-ancestors 'none'",
        ),
    );
    headers.insert(
        "Permissions-Policy",
        HeaderValue::from_static("camera=(), microphone=(), geolocation=(), payment=()"),
    );

    if is_sensitive_path {
        headers.insert(
            header::CACHE_CONTROL,
            HeaderValue::from_static("no-store, max-age=0"),
        );
        headers.insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
    }

    response
}

fn internal_error(context: &'static str, error: impl std::fmt::Display) -> Response {
    tracing::error!(context, "request failed: {error}");
    html_error_response_with_back(
        StatusCode::INTERNAL_SERVER_ERROR,
        "Request failed",
        "An internal error occurred. Review the server journal for the request context.",
        "/",
        "Back to Home",
    )
}

fn logged_error_with_back(
    status: StatusCode,
    context: &'static str,
    error: impl std::fmt::Display,
    title: &'static str,
    public_message: &str,
    back_href: &'static str,
    back_label: &'static str,
) -> Response {
    tracing::error!(context, "request failed: {error}");
    html_error_response_with_back(status, title, public_message, back_href, back_label)
}

fn subscription_internal_error(context: &'static str, error: impl std::fmt::Display) -> Response {
    tracing::error!(context, "subscription request failed: {error}");
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        "subscription temporarily unavailable\n",
    )
        .into_response()
}

fn html_error_response(
    status: StatusCode,
    title: &'static str,
    message: impl Into<String>,
) -> Response {
    html_error_response_with_back(status, title, message, "/admin/users", "Back to Users")
}

fn html_error_response_with_back(
    status: StatusCode,
    title: &'static str,
    message: impl Into<String>,
    back_href: &'static str,
    back_label: &'static str,
) -> Response {
    views::components::error_response(status, title, message, back_href, back_label)
}

fn subscription_block_reason(user: &UserRecord) -> Option<&'static str> {
    if !user.enabled {
        return Some("subscription disabled");
    }

    if user
        .expires_at
        .is_some_and(|expires_at| expires_at <= Utc::now())
    {
        return Some("subscription expired");
    }

    if user
        .traffic_limit_bytes
        .is_some_and(|limit| limit > 0 && user.traffic_used_bytes >= limit)
    {
        return Some("traffic limit reached");
    }

    None
}

fn subscription_userinfo_header(user: &UserRecord) -> HeaderValue {
    let total = user.traffic_limit_bytes.unwrap_or(0).max(0);
    let used = user.traffic_used_bytes.max(0);
    let expire = user.expires_at.map_or(0, |value| value.timestamp().max(0));
    let value = format!("upload=0; download={used}; total={total}; expire={expire}");

    HeaderValue::from_str(&value)
        .unwrap_or_else(|_| HeaderValue::from_static("upload=0; download=0; total=0; expire=0"))
}

fn mihomo_subscription_url(host: &str, token: &str) -> String {
    format!(
        "https://{}/sub/{}/mihomo.yaml",
        host.trim().trim_end_matches('/'),
        token
    )
}

fn mihomo_import_url(panel_name: &str, username: &str, yaml_url: &str) -> String {
    let name = format!("{panel_name} - {username}");
    format!(
        "clash://install-config?url={}&name={}",
        percent_encode(yaml_url),
        percent_encode(&name)
    )
}

pub(crate) fn percent_encode(value: &str) -> String {
    let mut encoded = String::with_capacity(value.len());

    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                encoded.push(byte as char);
            }
            _ => {
                const HEX: &[u8; 16] = b"0123456789ABCDEF";
                encoded.push('%');
                encoded.push(HEX[(byte >> 4) as usize] as char);
                encoded.push(HEX[(byte & 0x0f) as usize] as char);
            }
        }
    }

    encoded
}

fn format_user_traffic(user: &UserRecord) -> String {
    user.traffic_limit_bytes.map_or_else(
        || format!("{} / unlimited", format_bytes(user.traffic_used_bytes)),
        |limit| {
            format!(
                "{} / {}",
                format_bytes(user.traffic_used_bytes),
                format_bytes(limit)
            )
        },
    )
}

fn format_user_expiry(user: &UserRecord) -> String {
    user.expires_at.map_or_else(
        || "never".to_string(),
        |value| value.format("%Y-%m-%d %H:%M UTC").to_string(),
    )
}

fn format_bytes(value: i64) -> String {
    const GB: f64 = 1024.0 * 1024.0 * 1024.0;
    if value <= 0 {
        return "0 GB".to_string();
    }

    format!("{:.2} GB", value as f64 / GB)
}

#[cfg(test)]
mod tests;
