//! Axum web control plane for Infiproxy.
//!
//! The binary wires routes, authentication, CSRF protection, settings, users,
//! protocol editors, routing editors and owner-only danger operations. Heavy
//! host helpers and UI layout live in sibling modules to keep this file focused
//! on request/response flow.

mod health;
mod ip;
mod ops;
mod ui;

use crate::{
    health::{health, readiness},
    ip::ip_check_page,
    ops::*,
    ui::{layout, APP_NAME},
};
use argon2::{
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use axum::{
    body::Body,
    extract::{connect_info::ConnectInfo, Form, Path, State},
    http::{header, HeaderMap, HeaderValue, Request, StatusCode},
    middleware::{self, Next},
    response::{Html, IntoResponse, Redirect, Response},
    routing::{get, post},
    Router,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chrono::{Duration, Utc};
use cookie::{time::Duration as CookieDuration, Cookie, SameSite};
use maud::{html, Markup};
use rand_core::{OsRng, RngCore};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use sqlx::SqlitePool;
use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    sync::{Arc, Mutex},
    time::{Duration as StdDuration, Instant},
};
use stealthhub_core::{
    mihomo::generate_mihomo_yaml,
    models::{ProtocolConfig, ProtocolProfile, ProxyKind, ProxyRole, SubscriptionUser},
    rules::{routing_rule_payload_yaml, ROUTING_TARGETS},
    storage::{
        admin_count, create_admin, create_admin_session, create_user, delete_admin_session,
        delete_expired_admin_sessions, delete_user, ensure_default_protocol_profiles,
        ensure_default_routing_rule_sets, ensure_default_settings, ensure_demo_user,
        get_admin_by_id, get_admin_by_username, get_secret, get_user_by_id, get_user_by_token,
        get_valid_admin_session, init_db, list_protocol_profiles_decoded, list_secret_names,
        list_users, load_panel_settings, load_routing_rule_sets, open_pool,
        reset_user_subscription_token, set_user_enabled, touch_admin_session,
        update_protocol_profile, update_routing_rule_set, upsert_setting, AdminRecord, NewUser,
        UpdateProtocolProfile, UpdateRoutingRuleSet, UserRecord,
    },
};
use subtle::ConstantTimeEq;
use tower_http::trace::TraceLayer;
use tracing_subscriber::EnvFilter;

const ADMIN_SESSION_COOKIE: &str = "infiproxy_admin_session";
const ADMIN_SESSION_TTL_DAYS: i64 = 7;
const MIN_ADMIN_PASSWORD_LEN: usize = 12;
const LOGIN_FAILURE_DELAY_MS: u64 = 500;
const DUMMY_PASSWORD_HASH: &str = "$argon2id$v=19$m=19456,t=2,p=1$gTSHLOLVD71RNAjjkqaKvQ$cCpCPgJOl06K2/RHtedp/MTm/4u+0n4JeNlYF00eQj4";
pub(crate) const DEPLOYMENT_MODE: &str = "bare-metal systemd";
const LOGIN_RATE_LIMIT_WINDOW: StdDuration = StdDuration::from_secs(15 * 60);
const LOGIN_RATE_LIMIT_MAX_FAILURES: u32 = 5;
const LOGIN_RATE_LIMIT_MAX_KEYS: usize = 2048;

#[derive(Clone)]
pub(crate) struct AppState {
    pub(crate) pool: SqlitePool,
    cookie_secure: bool,
    danger_shell_enabled: bool,
    login_limiter: Arc<LoginRateLimiter>,
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
struct ProtocolProfileForm {
    #[serde(default)]
    csrf_token: String,
    #[serde(default)]
    enabled: String,
    server: String,
    port: u16,
    #[serde(default)]
    server_name: String,
    #[serde(default)]
    path: String,
    #[serde(default)]
    sni: String,
    #[serde(default)]
    public_key_secret: String,
    #[serde(default)]
    short_id_secret: String,
    #[serde(default)]
    password_secret: String,
    #[serde(default)]
    shadow_tls_password_secret: String,
    #[serde(default)]
    obfs_password_secret: String,
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
struct SystemActionForm {
    #[serde(default)]
    csrf_token: String,
    target: String,
}

#[derive(Debug, Deserialize)]
struct ConsoleCommandForm {
    #[serde(default)]
    csrf_token: String,
    command: String,
}

#[derive(Debug, Deserialize)]
struct DangerShellForm {
    #[serde(default)]
    csrf_token: String,
    command: String,
    confirm: String,
}

#[derive(Debug, Deserialize)]
struct UninstallPreviewForm {
    #[serde(default)]
    csrf_token: String,
    mode: String,
}

#[derive(Debug, Deserialize)]
struct UninstallExecuteForm {
    #[serde(default)]
    csrf_token: String,
    mode: String,
    confirm: String,
}

#[derive(Debug, Deserialize)]
struct ConfigEditorForm {
    #[serde(default)]
    csrf_token: String,
    target: String,
    content: String,
}

#[derive(Debug, Deserialize)]
struct PanelSettingsForm {
    #[serde(default)]
    csrf_token: String,
    panel_name: String,
    subscription_domain: String,
    node_domain: String,
}

#[derive(Debug, Deserialize)]
struct SetupAdminForm {
    username: String,
    password: String,
    password_confirm: String,
}

#[derive(Debug, Deserialize)]
struct LoginForm {
    username: String,
    password: String,
}

#[derive(Debug, Clone)]
pub(crate) struct AuthenticatedAdmin {
    admin: AdminRecord,
    csrf_token: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    health::mark_started();
    let env_filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info,stealthhub_panel=info,tower_http=warn"));
    tracing_subscriber::fmt().with_env_filter(env_filter).init();

    let bind = env_value("INFIPROXY_BIND", "STEALTHHUB_BIND")
        .unwrap_or_else(|| "127.0.0.1:8080".to_string());
    let db_url = env_value("INFIPROXY_DB", "STEALTHHUB_DB")
        .unwrap_or_else(|| "sqlite://./infiproxy.sqlite?mode=rwc".to_string());
    let cookie_secure = env_value("INFIPROXY_COOKIE_SECURE", "STEALTHHUB_COOKIE_SECURE")
        .map(|value| matches!(value.as_str(), "1" | "true" | "yes" | "on"))
        .unwrap_or(false);
    let enable_demo_user = env_value("INFIPROXY_ENABLE_DEMO_USER", "STEALTHHUB_ENABLE_DEMO_USER")
        .map(|value| matches!(value.as_str(), "1" | "true" | "yes" | "on"))
        .unwrap_or(false);
    let danger_shell_enabled = env_value(
        "INFIPROXY_ENABLE_DANGER_SHELL",
        "STEALTHHUB_ENABLE_DANGER_SHELL",
    )
    .map(|value| matches!(value.as_str(), "1" | "true" | "yes" | "on"))
    .unwrap_or(true);

    if !cookie_secure && !bind.starts_with("127.0.0.1:") && !bind.starts_with("localhost:") {
        tracing::warn!(
            "admin session cookie Secure flag is disabled; set INFIPROXY_COOKIE_SECURE=true behind HTTPS"
        );
    }
    if danger_shell_enabled {
        tracing::warn!(
            "danger shell is enabled; keep the panel behind HTTPS, strong auth and trusted network access"
        );
    }

    let pool = open_pool(&db_url).await?;
    init_db(&pool).await?;
    ensure_default_settings(&pool).await?;
    if enable_demo_user {
        ensure_demo_user(&pool).await?;
    }
    ensure_default_protocol_profiles(&pool).await?;
    ensure_default_routing_rule_sets(&pool).await?;
    delete_expired_admin_sessions(&pool).await?;

    let state = AppState {
        pool,
        cookie_secure,
        danger_shell_enabled,
        login_limiter: Arc::new(LoginRateLimiter::default()),
    };

    let app = Router::new()
        .route("/", get(index))
        .route(
            "/admin/setup",
            get(setup_admin_page).post(setup_admin_action),
        )
        .route("/admin/login", get(login_page).post(login_action))
        .route("/admin/logout", post(logout_action))
        .route("/admin", get(admin_dashboard))
        .route("/admin/users", get(users_page))
        .route(
            "/admin/settings",
            get(settings_page).post(update_settings_action),
        )
        .route("/admin/protocols", get(protocols_page))
        .route(
            "/admin/protocols/{name}/update",
            post(update_protocol_action),
        )
        .route(
            "/admin/routing",
            get(routing_page).post(update_routing_rule_action),
        )
        .route("/admin/system", get(system_page))
        .route("/admin/system/action", post(system_action))
        .route("/admin/system/console", post(system_console_action))
        .route("/admin/system/shell", post(danger_shell_action))
        .route("/admin/configs", get(configs_page).post(config_save_action))
        .route(
            "/admin/system/uninstall-preview",
            post(uninstall_preview_action),
        )
        .route(
            "/admin/system/uninstall-execute",
            post(uninstall_execute_action),
        )
        .route("/admin/cores", get(cores_page))
        .route("/admin/ip", get(ip_check_page))
        .route("/admin/credits", get(credits_page))
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
        .layer(middleware::from_fn(security_headers))
        .layer(TraceLayer::new_for_http());

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
        Err(err) => return (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()).into_response(),
    };
    let profiles = match list_protocol_profiles_decoded(&state.pool).await {
        Ok(value) => value,
        Err(err) => return (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()).into_response(),
    };
    let secrets = match load_secret_values_map(&state.pool, &profiles).await {
        Ok(value) => value,
        Err(err) => return (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()).into_response(),
    };
    let routing_rule_sets = match load_routing_rule_sets(&state.pool).await {
        Ok(value) => value,
        Err(err) => return (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()).into_response(),
    };

    let yaml = match generate_mihomo_yaml(
        &settings,
        &subscription_user,
        &profiles,
        &secrets,
        &routing_rule_sets,
    ) {
        Ok(value) => value,
        Err(err) => return (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()).into_response(),
    };

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
        Err(_) => {
            return (
                StatusCode::UNAUTHORIZED,
                Html(
                    layout(
                        "Subscription",
                        html! {
                            h1 { "Subscription" }
                            div class="notice error" { "Invalid subscription token." }
                        },
                    )
                    .into_string(),
                ),
            )
                .into_response()
        }
    };

    let settings = match load_panel_settings(&state.pool).await {
        Ok(value) => value,
        Err(err) => return (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()).into_response(),
    };

    let yaml_url = mihomo_subscription_url(&settings.subscription_domain, &user.subscription_token);
    let import_url = mihomo_import_url(&settings.panel_name, &user.username, &yaml_url);
    let block_reason = subscription_block_reason(&user);

    let mut headers = HeaderMap::new();
    headers.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("no-store, max-age=0"),
    );

    (
        headers,
        Html(
            layout(
                "Subscription",
                html! {
                    h1 { "Subscription" }

                    section {
                        h2 { "Account" }
                        dl class="details" {
                            dt { "User" }
                            dd { code { (&user.username) } }
                            dt { "Status" }
                            dd {
                                @if let Some(reason) = block_reason {
                                    span class="badge off" { (reason) }
                                } @else {
                                    span class="badge ok" { "active" }
                                }
                            }
                            dt { "Traffic" }
                            dd { (format_user_traffic(&user)) }
                            dt { "Expires" }
                            dd { (format_user_expiry(&user)) }
                        }
                    }

                    section {
                        h2 { "Client import" }
                        @if block_reason.is_none() {
                            div class="config-list" {
                                div class="config-row" {
                                    div class="config-row-head" {
                                        h3 { "Mihomo / Clash" }
                                        div class="config-row-meta" {
                                            a class="button compact" href=(&import_url) { "Import" }
                                            a class="button compact secondary" href=(&yaml_url) { "Download YAML" }
                                        }
                                    }
                                    div class="config-form wide" {
                                        label class="full-span" {
                                            span { "Subscription URL" }
                                            input type="text" readonly value=(&yaml_url);
                                            small { "Use this URL in Mihomo-compatible clients when one-click import is unavailable." }
                                        }
                                        label class="full-span" {
                                            span { "One-click import URL" }
                                            input type="text" readonly value=(&import_url);
                                            small { "Uses the standard Clash import scheme and points back to the YAML subscription." }
                                        }
                                    }
                                }
                            }
                        } @else {
                            div class="notice error" {
                                "Subscription is not available for import until the account state is fixed."
                            }
                        }
                    }
                },
            )
            .into_string(),
        ),
    )
        .into_response()
}

async fn rule_provider(State(state): State<AppState>, Path(name): Path<String>) -> Response {
    let slug = name.trim_end_matches(".yaml");
    let rule_sets = match load_routing_rule_sets(&state.pool).await {
        Ok(value) => value,
        Err(err) => return (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()).into_response(),
    };

    let Some(rule_set) = rule_sets
        .into_iter()
        .find(|rule_set| rule_set.slug == slug && rule_set.enabled)
    else {
        return (StatusCode::NOT_FOUND, "rule not found\n").into_response();
    };

    let body = match routing_rule_payload_yaml(&rule_set.payload) {
        Ok(value) => value,
        Err(err) => return (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()).into_response(),
    };

    let mut headers = HeaderMap::new();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/yaml; charset=utf-8"),
    );
    headers.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("public, max-age=300"),
    );

    (headers, body).into_response()
}

async fn index() -> impl IntoResponse {
    Html(
        layout(
            APP_NAME,
            html! {
                h1 { (APP_NAME) }
                div class="cards" {
                    a class="card" href="/admin" {
                        h2 { "Dashboard" }
                        p { "Admin session, storage, subscription status." }
                    }
                    a class="card" href="/admin/users" {
                        h2 { "Users" }
                        p { "UUID, subscription token, traffic limit." }
                    }
                    a class="card" href="/admin/protocols" {
                        h2 { "Protocols" }
                        p { "Proxy profile parameters for Mihomo YAML." }
                    }
                    a class="card" href="/admin/routing" {
                        h2 { "Routing" }
                        p { "Rule providers imported by the subscription." }
                    }
                }
            },
        )
        .into_string(),
    )
}

async fn setup_admin_page(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if let Ok(Some(_)) = current_admin(&state, &headers).await {
        return Redirect::to("/admin").into_response();
    }

    match admin_count(&state.pool).await {
        Ok(0) => Html(
            layout(
                "Initial admin setup",
                html! {
                    h1 { "Initial admin setup" }
                    div class="notice" {
                        "Create the first local administrator account. This page disappears after setup."
                    }
                    section {
                        h2 { "Admin account" }
                        form method="post" action="/admin/setup" class="form" {
                            label {
                                span { "Username" }
                                input type="text" name="username" minlength="3" maxlength="64" required autocomplete="username";
                            }
                            label {
                                span { "Password" }
                                input type="password" name="password" minlength=(MIN_ADMIN_PASSWORD_LEN) required autocomplete="new-password";
                            }
                            label {
                                span { "Confirm password" }
                                input type="password" name="password_confirm" minlength=(MIN_ADMIN_PASSWORD_LEN) required autocomplete="new-password";
                            }
                            button type="submit" { "Create admin" }
                        }
                    }
                },
            )
            .into_string(),
        )
        .into_response(),
        Ok(_) => Redirect::to("/admin/login").into_response(),
        Err(err) => html_error_response_with_back(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Setup unavailable",
            format!("Failed to inspect admin setup state: {err}"),
            "/",
            "Back to Home",
        ),
    }
}

async fn setup_admin_action(
    State(state): State<AppState>,
    Form(form): Form<SetupAdminForm>,
) -> Response {
    match admin_count(&state.pool).await {
        Ok(0) => {}
        Ok(_) => return Redirect::to("/admin/login").into_response(),
        Err(err) => {
            return html_error_response_with_back(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Setup failed",
                format!("Failed to inspect admin setup state: {err}"),
                "/admin/setup",
                "Back to Setup",
            );
        }
    }

    let username = form.username.trim();
    if username.len() < 3 || username.len() > 64 {
        return html_error_response_with_back(
            StatusCode::BAD_REQUEST,
            "Setup failed",
            "Username must be 3-64 characters long",
            "/admin/setup",
            "Back to Setup",
        );
    }

    if form.password.len() < MIN_ADMIN_PASSWORD_LEN {
        return html_error_response_with_back(
            StatusCode::BAD_REQUEST,
            "Setup failed",
            format!("Password must be at least {MIN_ADMIN_PASSWORD_LEN} characters long"),
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

    let password_hash = match hash_password(&form.password) {
        Ok(value) => value,
        Err(err) => {
            return html_error_response_with_back(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Setup failed",
                format!("Failed to hash password: {err}"),
                "/admin/setup",
                "Back to Setup",
            );
        }
    };

    let admin = match create_admin(&state.pool, username, &password_hash).await {
        Ok(value) => value,
        Err(err) => {
            return html_error_response_with_back(
                StatusCode::BAD_REQUEST,
                "Setup failed",
                format!("Failed to create admin: {err}"),
                "/admin/setup",
                "Back to Setup",
            );
        }
    };

    create_session_redirect(&state, admin.id, "/admin").await
}

async fn login_page(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if let Ok(0) = admin_count(&state.pool).await {
        return Redirect::to("/admin/setup").into_response();
    }

    if let Ok(Some(_)) = current_admin(&state, &headers).await {
        return Redirect::to("/admin").into_response();
    }

    Html(
        layout(
            "Admin login",
            html! {
                h1 { "Admin login" }
                section {
                    h2 { "Sign in" }
                    form method="post" action="/admin/login" class="form" {
                        label {
                            span { "Username" }
                            input type="text" name="username" required autocomplete="username";
                        }
                        label {
                            span { "Password" }
                            input type="password" name="password" required autocomplete="current-password";
                        }
                        button type="submit" { "Login" }
                    }
                }
            },
        )
        .into_string(),
    )
    .into_response()
}

async fn login_action(
    State(state): State<AppState>,
    ConnectInfo(peer_addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Form(form): Form<LoginForm>,
) -> Response {
    if let Ok(0) = admin_count(&state.pool).await {
        return Redirect::to("/admin/setup").into_response();
    }

    let rate_limit_keys = login_rate_limit_keys(&headers, peer_addr, &form.username);
    if let Some(retry_after) = state.login_limiter.retry_after(&rate_limit_keys) {
        return rate_limited_response(retry_after);
    }

    let admin = match get_admin_by_username(&state.pool, &form.username).await {
        Ok(Some(value)) => value,
        Ok(None) => {
            let _ = verify_password(&form.password, DUMMY_PASSWORD_HASH);
            state.login_limiter.record_failure(&rate_limit_keys);
            return login_failed_response().await;
        }
        Err(err) => {
            return html_error_response_with_back(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Login failed",
                format!("Failed to load admin: {err}"),
                "/admin/login",
                "Back to Login",
            );
        }
    };

    match verify_password(&form.password, &admin.password_hash) {
        Ok(true) => {
            state.login_limiter.record_success(&rate_limit_keys);
            create_session_redirect(&state, admin.id, "/admin").await
        }
        Ok(false) => {
            state.login_limiter.record_failure(&rate_limit_keys);
            login_failed_response().await
        }
        Err(err) => html_error_response_with_back(
            StatusCode::BAD_REQUEST,
            "Login failed",
            format!("Stored password hash is invalid: {err}"),
            "/admin/login",
            "Back to Login",
        ),
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
    response
}

async fn admin_dashboard(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let auth = match require_admin(&state, &headers).await {
        Ok(value) => value,
        Err(response) => return response,
    };

    Html(
        layout(
            "Dashboard",
            html! {
                (admin_bar(&auth))
                h1 { "Dashboard" }

                div class="status-strip" {
                    div class="metric" {
                        span { "Admin" }
                        strong { "protected" }
                    }
                    div class="metric" {
                        span { "Storage" }
                        strong { "SQLite" }
                    }
                    div class="metric" {
                        span { "Client" }
                        strong { "Mihomo YAML" }
                    }
                    div class="metric" {
                        span { "Mode" }
                        strong { "single-node" }
                    }
                }

                div class="grid" {
                    section {
                        h2 { "Users" }
                        p { "UUID, subscription token, enable flag, traffic limit." }
                        a class="button" href="/admin/users" { "Open Users" }
                    }

                    section {
                        h2 { "Settings" }
                        p { "Panel name, subscription host, node host." }
                        a class="button" href="/admin/settings" { "Open Settings" }
                    }

                    section {
                        h2 { "Protocols" }
                        p { "Enabled profiles, endpoint, SNI, transport path, secret names." }
                        a class="button" href="/admin/protocols" { "Open Protocols" }
                    }

                    section {
                        h2 { "Routing" }
                        p { "Mihomo rule providers, RULE-SET targets, classical payload." }
                        a class="button" href="/admin/routing" { "Open Routing" }
                    }

                    section {
                        h2 { "System" }
                        p { "Bind address, SQLite readiness, cookie mode, service paths." }
                        a class="button" href="/admin/system" { "Open System" }
                    }

                    section {
                        h2 { "Cores" }
                        p { "Binary paths, service names, config paths, local runtime state." }
                        a class="button" href="/admin/cores" { "Open Cores" }
                    }
                }
            },
        )
        .into_string(),
    )
    .into_response()
}

async fn settings_page(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let auth = match require_admin(&state, &headers).await {
        Ok(value) => value,
        Err(response) => return response,
    };

    let settings = match load_panel_settings(&state.pool).await {
        Ok(value) => value,
        Err(err) => {
            return html_error_response_with_back(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Settings unavailable",
                format!("Failed to load panel settings: {err}"),
                "/admin",
                "Back to Dashboard",
            );
        }
    };

    Html(
        layout(
            "Settings",
            html! {
                (admin_bar(&auth))
                h1 { "Settings" }

                div class="status-strip" {
                    div class="metric" {
                        span { "Panel name" }
                        strong { (&settings.panel_name) }
                    }
                    div class="metric" {
                        span { "Subscription host" }
                        strong { (&settings.subscription_domain) }
                    }
                    div class="metric" {
                        span { "Node host" }
                        strong { (&settings.node_domain) }
                    }
                    div class="metric" {
                        span { "Config source" }
                        strong { "SQLite settings" }
                    }
                }

                section {
                    h2 { "Global parameters" }
                    form method="post" action="/admin/settings" class="config-form" {
                        (csrf_field(&auth.csrf_token))
                        label {
                            span { "Panel name" }
                            input type="text" name="panel_name" value=(&settings.panel_name) minlength="2" maxlength="80" required;
                            small { "Displayed in generated metadata and admin screens." }
                        }
                        label {
                            span { "Subscription host" }
                            input type="text" name="subscription_domain" value=(&settings.subscription_domain) required;
                            small { "Public HTTPS host used by clients to fetch subscription and rule providers." }
                        }
                        label {
                            span { "Node host" }
                            input type="text" name="node_domain" value=(&settings.node_domain) required;
                            small { "Public host that Mihomo clients use to connect to proxy profiles." }
                        }
                        div class="full-span" {
                            button type="submit" { "Save Settings" }
                        }
                    }
                }

                section {
                    h2 { "Generated client endpoints" }
                    dl class="details" {
                        dt { "Subscription template" }
                        dd { code { (format!("https://{}/sub/{{token}}/mihomo.yaml", settings.subscription_domain)) } }
                        dt { "Rule provider template" }
                        dd { code { (format!("https://{}/rules/{{name}}", settings.subscription_domain)) } }
                        dt { "Proxy endpoint host" }
                        dd { code { (&settings.node_domain) } }
                    }
                }
            },
        )
        .into_string(),
    )
    .into_response()
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
    if panel_name.len() < 2 || panel_name.len() > 80 {
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

    for (key, value) in [
        ("panel_name", panel_name.to_string()),
        ("subscription_domain", subscription_domain),
        ("node_domain", node_domain),
    ] {
        if let Err(err) = upsert_setting(&state.pool, key, &value).await {
            return html_error_response_with_back(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Settings not saved",
                format!("Failed to save {key}: {err}"),
                "/admin/settings",
                "Back to Settings",
            );
        }
    }

    Redirect::to("/admin/settings").into_response()
}

async fn cores_page(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let auth = match require_admin(&state, &headers).await {
        Ok(value) => value,
        Err(response) => return response,
    };
    let installed_local_cores = CORE_RUNTIMES
        .iter()
        .filter(|core| std::path::Path::new(core.local_binary_path).is_file())
        .count();

    Html(
        layout(
            "Cores",
            html! {
                (admin_bar(&auth))
                h1 { "Cores" }

                div class="status-strip" {
                    div class="metric" {
                        span { "Local binaries" }
                        strong { (installed_local_cores) "/" (CORE_RUNTIMES.len()) }
                    }
                    div class="metric" {
                        span { "Supervisor" }
                        strong { "systemd" }
                    }
                    div class="metric" {
                        span { "Configured cores" }
                        strong { (CORE_RUNTIMES.len()) }
                    }
                    div class="metric" {
                        span { "Update policy" }
                        strong { "staged rollback" }
                    }
                }

                section {
                    h2 { "Runtime registry" }
                    div class="table-wrap" {
                        table {
                            thead {
                                tr {
                                    th { "Core" }
                                    th { "Priority" }
                                    th { "Role" }
                                    th { "Service" }
                                    th { "Local" }
                                    th { "Binary" }
                                    th { "Config" }
                                    th { "Updates" }
                                }
                            }
                            tbody {
                                @for core in CORE_RUNTIMES {
                                    tr {
                                        td { strong { (core.name) } }
                                        td { span class=(format!("badge {}", core_priority_class(core.priority))) { (core.priority) } }
                                        td { (core.role) }
                                        td { code { (core.service) } }
                                        td {
                                            @if std::path::Path::new(core.local_binary_path).is_file() {
                                                span class="badge ok" { "installed" }
                                                " "
                                                code { (core.local_binary_path) }
                                            } @else {
                                                span class="badge off" { "missing" }
                                                " "
                                                code { (core.local_binary_path) }
                                            }
                                        }
                                        td { code { (core.binary_path) } }
                                        td { code { (core.config_path) } }
                                        td { (core.update_channel) }
                                    }
                                }
                            }
                        }
                    }
                }

                section {
                    h2 { "Local install contract" }
                    dl class="details" {
                        dt { "Local dev root" }
                        dd { code { ".runtime/cores/{core}/{version}" } }
                        dt { "Core root" }
                        dd { code { "/opt/infiproxy/cores/{core}/{version}" } }
                        dt { "Active binary" }
                        dd { code { "/opt/infiproxy/cores/{core}/current" } }
                        dt { "Configs" }
                        dd { code { "/etc/infiproxy-cores/{core}" } }
                        dt { "Service templates" }
                        dd { code { "deploy/cores/systemd/*.service" } }
                    }
                }

                section {
                    h2 { "Safe core import" }
                    div class="table-wrap" {
                        table {
                            thead {
                                tr {
                                    th { "Step" }
                                    th { "Command / contract" }
                                }
                            }
                            tbody {
                                tr {
                                    td { "Download or import" }
                                    td { code { "sudo deploy/cores/install-core.sh --core xray --version 26.3.27 --url <release-archive-url> --sha256 <sha256> --binary xray --restart infiproxy-xray.service" } }
                                }
                                tr {
                                    td { "Staging" }
                                    td { code { "/var/lib/infiproxy/core-updates/{core}/{version}" } }
                                }
                                tr {
                                    td { "Activation" }
                                    td { code { "/opt/infiproxy/cores/{core}/current -> /opt/infiproxy/cores/{core}/{version}" } }
                                }
                                tr {
                                    td { "Validation" }
                                    td { code { "sha256sum -c, binary --version, optional systemctl restart/status" } }
                                }
                            }
                        }
                    }
                }
            },
        )
        .into_string(),
    )
    .into_response()
}

async fn routing_page(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let auth = match require_admin(&state, &headers).await {
        Ok(value) => value,
        Err(response) => return response,
    };

    let rule_sets = match load_routing_rule_sets(&state.pool).await {
        Ok(value) => value,
        Err(err) => {
            return html_error_response_with_back(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Routing unavailable",
                format!("Failed to load routing rules: {err}"),
                "/admin",
                "Back to Dashboard",
            );
        }
    };

    Html(
        layout(
            "Routing",
            html! {
                (admin_bar(&auth))
                h1 { "Routing" }

                div class="status-strip" {
                    div class="metric" {
                        span { "Rule sets" }
                        strong { (rule_sets.len()) }
                    }
                    div class="metric" {
                        span { "Enabled" }
                        strong { (rule_sets.iter().filter(|rule_set| rule_set.enabled).count()) }
                    }
                    div class="metric" {
                        span { "Provider type" }
                        strong { "http / classical / yaml" }
                    }
                    div class="metric" {
                        span { "Import" }
                        strong { "RULE-SET" }
                    }
                }

                section {
                    h2 { "Mihomo rule sets" }
                    div class="table-wrap" {
                        table {
                            thead {
                                tr {
                                    th { "Name" }
                                    th { "Target" }
                                    th { "Provider URL" }
                                    th { "Rules" }
                                    th { "State" }
                                }
                            }
                            tbody {
                                @for rule_set in &rule_sets {
                                    tr {
                                        td { strong { (&rule_set.title) } br; code { (&rule_set.slug) } }
                                        td { code { (&rule_set.target) } }
                                        td { code { (format!("/rules/{}.yaml", rule_set.slug)) } }
                                        td { (rule_set.payload.lines().filter(|line| !line.trim().is_empty()).count()) }
                                        td {
                                            @if rule_set.enabled {
                                                span class="badge ok" { "enabled" }
                                            } @else {
                                                span class="badge off" { "disabled" }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                section {
                    h2 { "Rule parameters" }
                    div class="config-list" {
                        @for rule_set in &rule_sets {
                            (routing_rule_editor(rule_set, &auth))
                        }
                    }
                }
            },
        )
        .into_string(),
    )
    .into_response()
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

    let input = UpdateRoutingRuleSet {
        slug: form.slug,
        enabled: checkbox_enabled(&form.enabled),
        target: form.target,
        payload: form.payload,
    };

    match update_routing_rule_set(&state.pool, input).await {
        Ok(()) => Redirect::to("/admin/routing").into_response(),
        Err(err) => html_error_response(
            StatusCode::BAD_REQUEST,
            "Routing update failed",
            format!("Failed to update rule set: {err}"),
        ),
    }
}

fn routing_rule_editor(
    rule_set: &stealthhub_core::rules::RoutingRuleSet,
    auth: &AuthenticatedAdmin,
) -> Markup {
    html! {
        section class="config-row" {
            div class="config-row-head" {
                h3 { (&rule_set.title) }
                div class="config-row-meta" {
                    span class=(format!("badge {}", if rule_set.enabled { "ok" } else { "off" })) {
                        @if rule_set.enabled { "enabled" } @else { "disabled" }
                    }
                    span class="badge neutral" { (&rule_set.target) }
                    code { (format!("/rules/{}.yaml", rule_set.slug)) }
                }
            }
            form method="post" action="/admin/routing" class="config-form wide" {
                (csrf_field(&auth.csrf_token))
                input type="hidden" name="slug" value=(&rule_set.slug);
                label class="switch-field" {
                    input type="checkbox" name="enabled" checked[rule_set.enabled];
                    span class="switch-ui" {}
                    span {
                        strong { "Enabled" }
                        small { "Include this rule provider and RULE-SET line in generated Mihomo YAML." }
                    }
                }
                label {
                    span { "Target group" }
                    select name="target" {
                        @for target in ROUTING_TARGETS {
                            option value=(target) selected[*target == rule_set.target] { (target) }
                        }
                    }
                    small { (&rule_set.effect) }
                }
                label class="full-span" {
                    span { "Classical payload" }
                    textarea name="payload" rows="10" spellcheck="false" { (&rule_set.payload) }
                    small { "One Mihomo classical rule per line, for example DOMAIN-SUFFIX,example.com or IP-CIDR,10.0.0.0/8,no-resolve." }
                }
                button type="submit" { "Save rule set" }
            }
        }
    }
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
    let host = host_snapshot();

    Html(
        layout(
            "System",
            html! {
                (admin_bar(&auth))
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
                            @if state.cookie_secure {
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
                    h2 { "Virtual console" }
                    div class="notice" {
                        "This is an operator console, not a raw shell. Commands are allowlisted, arguments are fixed in code, and output is capped."
                    }
                    form method="post" action="/admin/system/console" class="config-form wide" {
                        (csrf_field(&auth.csrf_token))
                        label {
                            span { "Command" }
                            select name="command" {
                                @for command in CONSOLE_COMMANDS {
                                    option value=(command.slug) { (command.name) }
                                }
                            }
                        }
                        label class="full-span" {
                            span { "Available operations" }
                            textarea readonly rows="6" {
                                @for command in CONSOLE_COMMANDS {
                                    (command.slug) " - " (command.description) "\n"
                                }
                            }
                        }
                        button type="submit" { "Run selected command" }
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
                    @if is_owner_admin(&auth) {
                        div class="notice error" {
                            "Execution buttons run through the danger shell as the panel service user. On production systemd installs this usually cannot remove root-owned system files; use "
                            code { "sudo infiproxy-manager" }
                            " over SSH for guaranteed root cleanup."
                        }
                        form method="post" action="/admin/system/uninstall-execute" class="config-form wide" {
                            (csrf_field(&auth.csrf_token))
                            label {
                                span { "Mode" }
                                select name="mode" {
                                    option value="panel" { "panel - remove panel only" }
                                    option value="full" { "full - remove panel-managed footprint" }
                                    option value="factory" { "factory - deepest Infiproxy cleanup" }
                                }
                                small { "Use Preview first. Web execution is limited by panel service permissions." }
                            }
                            label {
                                span { "Confirmation" }
                                input type="text" name="confirm" placeholder="DELETE INFIPROXY" required;
                                small { "Type exactly: DELETE INFIPROXY" }
                            }
                            button type="submit" class="danger" { "Execute uninstall plan" }
                        }
                    } @else {
                        div class="notice" { "Execution is hidden for non-owner admins." }
                    }
                }

                section class="danger-zone" {
                    h2 { "Danger shell" }
                    @if !is_owner_admin(&auth) {
                        div class="notice" { "Owner-only. This admin can use the allowlisted virtual console, but not the raw shell." }
                    } @else if state.danger_shell_enabled {
                        div class="notice error" {
                            "Break-glass shell is enabled. Commands run as the panel service user through sh -lc, with a 10s timeout, minimal environment and capped output."
                        }
                        form method="post" action="/admin/system/shell" class="config-form wide" {
                            (csrf_field(&auth.csrf_token))
                            label class="full-span" {
                                span { "Command" }
                                textarea class="code-editor" name="command" rows="6" spellcheck="false" placeholder="id && systemctl status infiproxy.service --no-pager" {}
                                small { "No interactive TTY. Use this only for emergency diagnostics or one-shot maintenance." }
                            }
                            label {
                                span { "Confirmation" }
                                input type="text" name="confirm" placeholder="I understand" required;
                                small { "Type exactly: I understand" }
                            }
                            button type="submit" class="danger" { "Run danger shell" }
                        }
                    } @else {
                        div class="notice" {
                            "Disabled. To expose this break-glass tool, set "
                            code { "INFIPROXY_ENABLE_DANGER_SHELL=true" }
                            " in the panel environment and restart "
                            code { "infiproxy.service" }
                            "."
                        }
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

async fn configs_page(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let auth = match require_admin(&state, &headers).await {
        Ok(value) => value,
        Err(response) => return response,
    };

    let snapshots = CONFIG_FILES
        .iter()
        .map(|spec| read_config_file(spec.slug))
        .collect::<Vec<_>>();

    Html(
        layout(
            "Configs",
            html! {
                (admin_bar(&auth))
                h1 { "Configs" }

                div class="status-strip" {
                    div class="metric" {
                        span { "Allowlisted files" }
                        strong { (CONFIG_FILES.len()) }
                    }
                    div class="metric" {
                        span { "Readable" }
                        strong { (snapshots.iter().filter(|item| item.status == "ready").count()) }
                    }
                    div class="metric" {
                        span { "Editor model" }
                        strong { "backup-first" }
                    }
                    div class="metric" {
                        span { "Shell access" }
                        strong { "none" }
                    }
                }

                section {
                    h2 { "Config workbench" }
                    div class="notice" {
                        "Only allowlisted files are editable. Every save creates a sibling backup before writing. Validation and reload stay explicit so one bad edit does not silently restart services."
                    }
                    div class="config-list" {
                        @for snapshot in &snapshots {
                            (config_editor_card(snapshot, &auth))
                        }
                    }
                }

                section {
                    h2 { "Operational checklist" }
                    div class="table-wrap" {
                        table {
                            thead {
                                tr {
                                    th { "Change" }
                                    th { "Validate" }
                                    th { "Apply" }
                                }
                            }
                            tbody {
                                @for spec in CONFIG_FILES {
                                    tr {
                                        td { strong { (spec.name) } br; code { (spec.path) } }
                                        td { code { (spec.validate_hint) } }
                                        td { code { (spec.reload_hint) } }
                                    }
                                }
                            }
                        }
                    }
                }
            },
        )
        .into_string(),
    )
    .into_response()
}

fn config_editor_card(snapshot: &ConfigFileSnapshot, auth: &AuthenticatedAdmin) -> Markup {
    let status_class = if snapshot.status == "ready" {
        "ok"
    } else if snapshot.exists {
        "warn"
    } else {
        "neutral"
    };

    html! {
        section class="config-row" {
            div class="config-row-head" {
                h3 { (snapshot.spec.name) }
                div class="config-row-meta" {
                    span class=(format!("badge {status_class}")) { (&snapshot.status) }
                    span class="badge neutral" { (snapshot.spec.category) }
                    span class="badge neutral" { (snapshot.spec.syntax) }
                }
            }
            form method="post" action="/admin/configs" class="config-form wide" {
                (csrf_field(&auth.csrf_token))
                input type="hidden" name="target" value=(snapshot.spec.slug);
                label {
                    span { "Path" }
                    input type="text" value=(snapshot.spec.path) readonly;
                    small { (snapshot.spec.description) }
                }
                label {
                    span { "Limits" }
                    input type="text" value=(format!("{} bytes now, {} bytes max", snapshot.bytes, snapshot.spec.max_bytes)) readonly;
                    small { "Large files are intentionally not loaded into the browser editor." }
                }
                label class="full-span" {
                    span { "Content" }
                    textarea class="code-editor" name="content" rows="18" spellcheck="false" {
                        (&snapshot.content)
                    }
                    small {
                        "Validate: " code { (snapshot.spec.validate_hint) }
                        " | Apply: " code { (snapshot.spec.reload_hint) }
                    }
                }
                button type="submit" { "Save with backup" }
            }
        }
    }
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

    let report = write_config_file(&form.target, &form.content);
    let status = if report.success {
        StatusCode::OK
    } else {
        StatusCode::BAD_REQUEST
    };

    (
        status,
        Html(
            layout(
                "Config save",
                html! {
                    (admin_bar(&auth))
                    h1 { "Config save" }

                    section class="config-row" {
                        div class="config-row-head" {
                            h3 { (report.spec.name) }
                            @if report.success {
                                span class="badge ok" { "saved" }
                            } @else {
                                span class="badge off" { "failed" }
                            }
                        }
                        dl class="details" {
                            dt { "Path" }
                            dd { code { (report.spec.path) } }
                            dt { "Result" }
                            dd { (report.message) }
                            @if let Some(path) = &report.backup_path {
                                dt { "Backup" }
                                dd { code { (path) } }
                            }
                            dt { "Validate" }
                            dd { code { (report.spec.validate_hint) } }
                            dt { "Apply" }
                            dd { code { (report.spec.reload_hint) } }
                        }
                        div class="actions" {
                            a class="button" href="/admin/configs" { "Back to Configs" }
                            a class="button" href="/admin/system" { "Open System actions" }
                        }
                    }
                },
            )
            .into_string(),
        ),
    )
        .into_response()
}

async fn system_action(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<SystemActionForm>,
) -> Response {
    let auth = match require_admin(&state, &headers).await {
        Ok(value) => value,
        Err(response) => return response,
    };

    if let Some(response) = csrf_error_response(&auth, &form.csrf_token) {
        return response;
    }

    let Some(target) = SYSTEM_TARGETS
        .iter()
        .find(|target| target.slug == form.target)
    else {
        return html_error_response_with_back(
            StatusCode::BAD_REQUEST,
            "System action failed",
            "Unknown system target",
            "/admin/system",
            "Back to System",
        );
    };

    let report = run_system_action(*target);
    let ok = report.steps.iter().all(|step| step.success);

    Html(
        layout(
            "System action",
            html! {
                (admin_bar(&auth))
                h1 { "System action" }

                section {
                    h2 { (target.name) }
                    div class=(if ok { "notice" } else { "notice error" }) {
                        @if ok {
                            "Action completed."
                        } @else {
                            "Action failed. Review command output below."
                        }
                    }
                    div class="config-list" {
                        @for step in &report.steps {
                            div class="config-row" {
                                div class="config-row-head" {
                                    h3 { code { (&step.command) } }
                                    @if step.success {
                                        span class="badge ok" { "ok" }
                                    } @else {
                                        span class="badge off" { "failed" }
                                    }
                                }
                                div class="command-output" {
                                    @if !step.stdout.is_empty() {
                                        strong { "stdout" }
                                        pre { (&step.stdout) }
                                    }
                                    @if !step.stderr.is_empty() {
                                        strong { "stderr" }
                                        pre { (&step.stderr) }
                                    }
                                    @if step.stdout.is_empty() && step.stderr.is_empty() {
                                        small { "No output." }
                                    }
                                }
                            }
                        }
                    }
                    a class="button" href="/admin/system" { "Back to System" }
                }
            },
        )
        .into_string(),
    )
    .into_response()
}

async fn system_console_action(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<ConsoleCommandForm>,
) -> Response {
    let auth = match require_admin(&state, &headers).await {
        Ok(value) => value,
        Err(response) => return response,
    };

    if let Some(response) = csrf_error_response(&auth, &form.csrf_token) {
        return response;
    }

    let Some(command) = CONSOLE_COMMANDS
        .iter()
        .find(|command| command.slug == form.command)
    else {
        return html_error_response_with_back(
            StatusCode::BAD_REQUEST,
            "Console command failed",
            "Unknown console command",
            "/admin/system",
            "Back to System",
        );
    };

    let step = run_command(command.program, command.args);

    Html(
        layout(
            "Console",
            html! {
                (admin_bar(&auth))
                h1 { "Virtual console" }

                section {
                    h2 { (command.name) }
                    p { (command.description) }
                    div class="config-row" {
                        div class="config-row-head" {
                            h3 { code { (&step.command) } }
                            @if step.success {
                                span class="badge ok" { "ok" }
                            } @else {
                                span class="badge off" { "failed" }
                            }
                        }
                        div class="command-output" {
                            @if !step.stdout.is_empty() {
                                strong { "stdout" }
                                pre { (&step.stdout) }
                            }
                            @if !step.stderr.is_empty() {
                                strong { "stderr" }
                                pre { (&step.stderr) }
                            }
                            @if step.stdout.is_empty() && step.stderr.is_empty() {
                                small { "No output." }
                            }
                        }
                    }
                    a class="button" href="/admin/system" { "Back to System" }
                }
            },
        )
        .into_string(),
    )
    .into_response()
}

async fn danger_shell_action(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<DangerShellForm>,
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

    if !state.danger_shell_enabled {
        return html_error_response_with_back(
            StatusCode::FORBIDDEN,
            "Danger shell disabled",
            "Set INFIPROXY_ENABLE_DANGER_SHELL=true and restart the panel before using this tool.",
            "/admin/system",
            "Back to System",
        );
    }

    if form.confirm.trim() != "I understand" {
        return html_error_response_with_back(
            StatusCode::BAD_REQUEST,
            "Danger shell confirmation failed",
            "Type exactly: I understand",
            "/admin/system",
            "Back to System",
        );
    }

    let step = run_danger_shell(&form.command).await;

    Html(
        layout(
            "Danger shell",
            html! {
                (admin_bar(&auth))
                h1 { "Danger shell" }

                section class="danger-zone" {
                    h2 { "Command result" }
                    div class="notice error" {
                        "This command used the break-glass shell path. Review output carefully and disable the env flag when finished."
                    }
                    div class="config-row" {
                        div class="config-row-head" {
                            h3 { code { (&step.command) } }
                            @if step.success {
                                span class="badge ok" { "ok" }
                            } @else {
                                span class="badge off" { "failed" }
                            }
                        }
                        div class="command-output" {
                            @if !step.stdout.is_empty() {
                                strong { "stdout" }
                                pre { (&step.stdout) }
                            }
                            @if !step.stderr.is_empty() {
                                strong { "stderr" }
                                pre { (&step.stderr) }
                            }
                            @if step.stdout.is_empty() && step.stderr.is_empty() {
                                small { "No output." }
                            }
                        }
                    }
                    a class="button" href="/admin/system" { "Back to System" }
                }
            },
        )
        .into_string(),
    )
    .into_response()
}

async fn uninstall_execute_action(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<UninstallExecuteForm>,
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

    if !state.danger_shell_enabled {
        return html_error_response_with_back(
            StatusCode::FORBIDDEN,
            "Uninstall executor disabled",
            "The web executor uses the danger shell. Enable INFIPROXY_ENABLE_DANGER_SHELL=true or use sudo infiproxy-manager over SSH.",
            "/admin/system",
            "Back to System",
        );
    }

    if form.confirm.trim() != "DELETE INFIPROXY" {
        return html_error_response_with_back(
            StatusCode::BAD_REQUEST,
            "Uninstall confirmation failed",
            "Type exactly: DELETE INFIPROXY",
            "/admin/system",
            "Back to System",
        );
    }

    let Some(plan) = uninstall_plan(&form.mode) else {
        return html_error_response_with_back(
            StatusCode::BAD_REQUEST,
            "Uninstall failed",
            "Unknown uninstall mode",
            "/admin/system",
            "Back to System",
        );
    };

    let step = run_danger_shell(&plan.shell_script()).await;

    Html(
        layout(
            "Uninstall execute",
            html! {
                (admin_bar(&auth))
                h1 { "Uninstall execute" }

                section class="danger-zone" {
                    h2 { (plan.title) }
                    div class="notice error" {
                        "Execution finished or was interrupted. If this panel is still reachable, review output and use sudo infiproxy-manager from SSH for root-level cleanup."
                    }
                    div class="config-row" {
                        div class="config-row-head" {
                            h3 { code { (&step.command) } }
                            @if step.success {
                                span class="badge ok" { "ok" }
                            } @else {
                                span class="badge off" { "failed" }
                            }
                        }
                        div class="command-output" {
                            @if !step.stdout.is_empty() {
                                strong { "stdout" }
                                pre { (&step.stdout) }
                            }
                            @if !step.stderr.is_empty() {
                                strong { "stderr" }
                                pre { (&step.stderr) }
                            }
                            @if step.stdout.is_empty() && step.stderr.is_empty() {
                                small { "No output." }
                            }
                        }
                    }
                    a class="button" href="/admin/system" { "Back to System" }
                }
            },
        )
        .into_string(),
    )
    .into_response()
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

    let Some(plan) = uninstall_plan(&form.mode) else {
        return html_error_response_with_back(
            StatusCode::BAD_REQUEST,
            "Uninstall preview failed",
            "Unknown uninstall mode",
            "/admin/system",
            "Back to System",
        );
    };

    Html(
        layout(
            "Uninstall preview",
            html! {
                (admin_bar(&auth))
                h1 { "Uninstall preview" }

                section class="danger-zone" {
                    h2 { (plan.title) }
                    div class="notice error" {
                        (plan.warning)
                    }
                    div class="command-output" {
                        strong { "review-only shell runbook" }
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

async fn credits_page(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let auth = match require_admin(&state, &headers).await {
        Ok(value) => value,
        Err(response) => return response,
    };

    Html(
        layout(
            "Credits",
            html! {
                (admin_bar(&auth))
                h1 { "Credits" }

                section class="product-card" {
                    div {
                        span class="eyebrow" { "commercial-grade control plane" }
                        h2 { (APP_NAME) }
                        p { "Rust, SQLite, systemd and Mihomo-compatible subscriptions with a conservative server-first UI." }
                    }
                }

                section {
                    h2 { "Project" }
                    dl class="details" {
                        dt { "Repository" }
                        dd { a href="https://github.com/infinitrator/stealthhub-panel" rel="noreferrer" { "github.com/infinitrator/stealthhub-panel" } }
                        dt { "License" }
                        dd { code { "AGPL-3.0-or-later" } }
                        dt { "Runtime" }
                        dd { code { "Rust + Axum + SQLx + SQLite" } }
                        dt { "Brand" }
                        dd { "Infiproxy" }
                    }
                }

                section {
                    h2 { "GitHub stars" }
                    div class="notice" {
                        "Live stars are intentionally not fetched by the panel yet: keeping the control plane offline-capable avoids an extra HTTPS client dependency and background network calls."
                    }
                    dl class="details" {
                        dt { "Recommended API" }
                        dd { code { "GET https://api.github.com/repos/infinitrator/stealthhub-panel" } }
                        dt { "Field" }
                        dd { code { "stargazers_count" } }
                        dt { "Production approach" }
                        dd { "Fetch with ETag, cache for 6-24 hours in SQLite, render the cached value in this tab." }
                    }
                    a class="button" href="https://github.com/infinitrator/stealthhub-panel" rel="noreferrer" { "Open GitHub" }
                }

                section {
                    h2 { "Acknowledgements" }
                    div class="table-wrap" {
                        table {
                            thead {
                                tr {
                                    th { "Area" }
                                    th { "Technology" }
                                    th { "Role" }
                                }
                            }
                            tbody {
                                tr { td { "Web" } td { "Axum / Maud" } td { "Server-rendered admin interface" } }
                                tr { td { "Storage" } td { "SQLite / SQLx" } td { "Single-node durable state" } }
                                tr { td { "Subscriptions" } td { "Mihomo YAML" } td { "Client import format" } }
                                tr { td { "Deployment" } td { "systemd" } td { "Bare-metal VPS runtime" } }
                            }
                        }
                    }
                }
            },
        )
        .into_string(),
    )
    .into_response()
}

async fn protocols_page(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let auth = match require_admin(&state, &headers).await {
        Ok(value) => value,
        Err(response) => return response,
    };

    let settings = match load_panel_settings(&state.pool).await {
        Ok(value) => value,
        Err(err) => {
            return html_error_response_with_back(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Protocols unavailable",
                format!("Failed to load panel settings: {err}"),
                "/admin",
                "Back to Dashboard",
            );
        }
    };

    let profiles = match list_protocol_profiles_decoded(&state.pool).await {
        Ok(value) => value,
        Err(err) => {
            return html_error_response_with_back(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Protocols unavailable",
                format!("Failed to load protocol profiles: {err}"),
                "/admin",
                "Back to Dashboard",
            );
        }
    };

    let secret_names = match list_secret_names(&state.pool).await {
        Ok(value) => value,
        Err(err) => {
            return html_error_response_with_back(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Protocols unavailable",
                format!("Failed to load secret names: {err}"),
                "/admin",
                "Back to Dashboard",
            );
        }
    };

    Html(
        layout(
            "Protocols",
            html! {
                (admin_bar(&auth))
                h1 { "Protocols" }

                div class="status-strip" {
                    div class="metric" {
                        span { "Profiles" }
                        strong { (profiles.len()) }
                    }
                    div class="metric" {
                        span { "Enabled" }
                        strong { (profiles.iter().filter(|profile| profile.enabled).count()) }
                    }
                    div class="metric" {
                        span { "Secrets" }
                        strong { (secret_names.len()) }
                    }
                    div class="metric" {
                        span { "Subscription host" }
                        strong { (&settings.subscription_domain) }
                    }
                }

                section {
                    h2 { "Mihomo subscription endpoint" }
                    dl class="details" {
                        dt { "Subscription domain" }
                        dd { code { (&settings.subscription_domain) } }
                        dt { "Node domain" }
                        dd { code { (&settings.node_domain) } }
                    }
                }

                section {
                    h2 { "Transport matrix" }
                    div class="table-wrap" {
                        table {
                            thead {
                                tr {
                                    th { "Profile" }
                                    th { "Purpose" }
                                    th { "Masking knobs" }
                                    th { "Client impact" }
                                }
                            }
                            tbody {
                                tr {
                                    td { code { "vless-reality-xhttp" } }
                                    td { "Primary TLS-like profile for modern Mihomo clients." }
                                    td { code { "server_name" } " + " code { "path" } " + REALITY public key/short ID." }
                                    td { "Best default when client supports XHTTP." }
                                }
                                tr {
                                    td { code { "vless-reality-tcp" } }
                                    td { "Lean fallback with fewer moving parts." }
                                    td { code { "server_name" } " + REALITY public key/short ID." }
                                    td { "Useful for conservative client profiles." }
                                }
                                tr {
                                    td { code { "ss2022-shadowtls" } }
                                    td { "Compatibility transport with ShadowTLS front." }
                                    td { code { "server_name" } " + independent SS/ShadowTLS secrets." }
                                    td { "Good fallback when VLESS is undesirable." }
                                }
                                tr {
                                    td { code { "hysteria2" } " / " code { "tuic" } }
                                    td { "QUIC speed fallback for high-latency routes." }
                                    td { code { "sni" } " + password/obfs secrets." }
                                    td { "Enable only when UDP path is healthy." }
                                }
                            }
                        }
                    }
                }

                section {
                    h2 { "Protocol profiles" }
                    @if profiles.is_empty() {
                        p { "No protocol profiles configured yet." }
                    } @else {
                        div class="table-wrap" {
                            table {
                                thead {
                                    tr {
                                        th { "Name" }
                                        th { "Kind" }
                                        th { "Role" }
                                        th { "Enabled" }
                                        th { "Endpoint" }
                                        th { "Secrets" }
                                    }
                                }
                                tbody {
                                    @for profile in &profiles {
                                        tr {
                                            td { code { (&profile.name) } }
                                            td { (proxy_kind_label(&profile.kind)) }
                                            td { (proxy_role_label(&profile.role)) }
                                            td {
                                                @if profile.enabled {
                                                    span class="badge ok" { "on" }
                                                } @else {
                                                    span class="badge off" { "off" }
                                                }
                                            }
                                            td { code { (format!("{}:{}", profile.server, profile.port)) } }
                                            td {
                                                @let missing = missing_secret_names(profile, &secret_names);
                                                @if profile.required_secret_names().is_empty() {
                                                    span class="badge ok" { "none" }
                                                } @else if missing.is_empty() {
                                                    span class="badge ok" { "ready" }
                                                    br;
                                                    @for secret in profile.required_secret_names() {
                                                        code { (secret) }
                                                        " "
                                                    }
                                                } @else {
                                                    span class="badge off" { "missing" }
                                                    br;
                                                    @for secret in missing {
                                                        code { (secret) }
                                                        " "
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

                section {
                    h2 { "Profile parameters" }
                    datalist id="secret-names" {
                        @for secret in &secret_names {
                            option value=(secret) {}
                        }
                    }
                    div class="config-list" {
                        @for profile in &profiles {
                            (protocol_profile_editor(profile, &auth, &secret_names))
                        }
                    }
                }
            },
        )
        .into_string(),
    )
    .into_response()
}

async fn update_protocol_action(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(name): Path<String>,
    Form(form): Form<ProtocolProfileForm>,
) -> Response {
    let auth = match require_admin(&state, &headers).await {
        Ok(value) => value,
        Err(response) => return response,
    };

    if let Some(response) = csrf_error_response(&auth, &form.csrf_token) {
        return response;
    }

    let profiles = match list_protocol_profiles_decoded(&state.pool).await {
        Ok(value) => value,
        Err(err) => {
            return html_error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Protocol update failed",
                format!("Failed to load protocol profiles: {err}"),
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

    let config = match protocol_config_from_form(&existing, &form) {
        Ok(value) => value,
        Err(err) => {
            return html_error_response(
                StatusCode::BAD_REQUEST,
                "Protocol update failed",
                err.to_string(),
            )
        }
    };

    let input = UpdateProtocolProfile {
        name: existing.name,
        enabled: checkbox_enabled(&form.enabled),
        server: form.server.trim().to_string(),
        port: form.port,
        config,
    };

    match update_protocol_profile(&state.pool, input).await {
        Ok(_) => Redirect::to("/admin/protocols").into_response(),
        Err(err) => html_error_response(
            StatusCode::BAD_REQUEST,
            "Protocol update failed",
            format!("Failed to update profile: {err}"),
        ),
    }
}

fn protocol_config_from_form(
    existing: &ProtocolProfile,
    form: &ProtocolProfileForm,
) -> anyhow::Result<ProtocolConfig> {
    if form.server.trim().is_empty() {
        return Err(anyhow::anyhow!("Server address is required"));
    }

    match &existing.config {
        ProtocolConfig::VlessRealityXhttp { uuid_source, .. } => {
            Ok(ProtocolConfig::VlessRealityXhttp {
                uuid_source: uuid_source.clone(),
                server_name: required_field(&form.server_name, "TLS server name")?,
                path: required_field(&form.path, "XHTTP path")?,
                public_key_secret: required_field(
                    &form.public_key_secret,
                    "REALITY public key secret",
                )?,
                short_id_secret: required_field(&form.short_id_secret, "REALITY short ID secret")?,
            })
        }
        ProtocolConfig::VlessRealityTcp { uuid_source, .. } => {
            Ok(ProtocolConfig::VlessRealityTcp {
                uuid_source: uuid_source.clone(),
                server_name: required_field(&form.server_name, "TLS server name")?,
                public_key_secret: required_field(
                    &form.public_key_secret,
                    "REALITY public key secret",
                )?,
                short_id_secret: required_field(&form.short_id_secret, "REALITY short ID secret")?,
            })
        }
        ProtocolConfig::Shadowsocks2022ShadowTls { .. } => {
            Ok(ProtocolConfig::Shadowsocks2022ShadowTls {
                server_name: required_field(&form.server_name, "ShadowTLS server name")?,
                password_secret: required_field(
                    &form.password_secret,
                    "Shadowsocks password secret",
                )?,
                shadow_tls_password_secret: required_field(
                    &form.shadow_tls_password_secret,
                    "ShadowTLS password secret",
                )?,
            })
        }
        ProtocolConfig::Hysteria2 { .. } => Ok(ProtocolConfig::Hysteria2 {
            password_secret: required_field(&form.password_secret, "Hysteria2 password secret")?,
            sni: required_field(&form.sni, "TLS SNI")?,
            obfs_password_secret: optional_field(&form.obfs_password_secret),
        }),
        ProtocolConfig::AnyTls { .. } => Ok(ProtocolConfig::AnyTls {
            password_secret: required_field(&form.password_secret, "AnyTLS password secret")?,
            sni: required_field(&form.sni, "TLS SNI")?,
        }),
        ProtocolConfig::Tuic { uuid_source, .. } => Ok(ProtocolConfig::Tuic {
            uuid_source: uuid_source.clone(),
            password_secret: required_field(&form.password_secret, "TUIC password secret")?,
            sni: required_field(&form.sni, "TLS SNI")?,
        }),
    }
}

fn required_field(value: &str, label: &str) -> anyhow::Result<String> {
    let value = value.trim();
    if value.is_empty() {
        return Err(anyhow::anyhow!("{label} is required"));
    }
    Ok(value.to_string())
}

fn optional_field(value: &str) -> Option<String> {
    let value = value.trim();
    (!value.is_empty()).then(|| value.to_string())
}

fn normalize_public_host(value: &str) -> Result<String, &'static str> {
    let value = value.trim().trim_end_matches('.');
    if value.is_empty() {
        return Err("Host must not be empty.");
    }

    if value.contains("://") || value.contains('/') || value.contains('\\') {
        return Err("Use host only, without scheme, path, or trailing slash.");
    }

    if value.len() > 253 {
        return Err("Host is too long.");
    }

    let valid = value
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '-' | '_' | ':'));
    if !valid || value.split('.').any(|part| part.is_empty()) {
        return Err("Host contains unsupported characters.");
    }

    Ok(value.to_ascii_lowercase())
}

fn checkbox_enabled(value: &str) -> bool {
    matches!(value, "1" | "true" | "yes" | "on")
}

fn protocol_profile_editor(
    profile: &ProtocolProfile,
    auth: &AuthenticatedAdmin,
    secret_names: &[String],
) -> Markup {
    html! {
        section class="config-row" {
            div class="config-row-head" {
                h3 { (&profile.name) }
                div class="config-row-meta" {
                    span class=(format!("badge {}", if profile.enabled { "ok" } else { "off" })) {
                        @if profile.enabled { "enabled" } @else { "disabled" }
                    }
                    span class="badge neutral" { (proxy_kind_label(&profile.kind)) }
                    span class="badge neutral" { (proxy_role_label(&profile.role)) }
                }
            }
            form method="post" action=(format!("/admin/protocols/{}/update", profile.name)) class="config-form" {
                (csrf_field(&auth.csrf_token))
                label class="switch-field" {
                    input type="checkbox" name="enabled" checked[profile.enabled];
                    span class="switch-ui" {}
                    span {
                        strong { "Enabled" }
                        small { "Include this proxy in generated Mihomo subscriptions." }
                    }
                }
                label {
                    span { "Server address" }
                    input type="text" name="server" value=(&profile.server) required;
                    small { "Hostname or IP used by the Mihomo proxy object." }
                }
                label {
                    span { "Server port" }
                    input type="number" name="port" min="1" max="65535" value=(profile.port) required;
                    small { "Remote port used by the client." }
                }
                (protocol_specific_fields(profile, secret_names))
                button type="submit" { "Save profile" }
            }
        }
    }
}

fn protocol_specific_fields(profile: &ProtocolProfile, secret_names: &[String]) -> Markup {
    match &profile.config {
        ProtocolConfig::VlessRealityXhttp {
            server_name,
            path,
            public_key_secret,
            short_id_secret,
            ..
        } => html! {
            (text_input("server_name", "TLS server name", server_name, "SNI and XHTTP Host value used by Mihomo."))
            (text_input("path", "XHTTP path", path, "HTTP path sent by the xhttp transport."))
            (secret_input("public_key_secret", "REALITY public key secret", public_key_secret, secret_names))
            (secret_input("short_id_secret", "REALITY short ID secret", short_id_secret, secret_names))
        },
        ProtocolConfig::VlessRealityTcp {
            server_name,
            public_key_secret,
            short_id_secret,
            ..
        } => html! {
            (text_input("server_name", "TLS server name", server_name, "SNI value for REALITY verification."))
            (secret_input("public_key_secret", "REALITY public key secret", public_key_secret, secret_names))
            (secret_input("short_id_secret", "REALITY short ID secret", short_id_secret, secret_names))
        },
        ProtocolConfig::Shadowsocks2022ShadowTls {
            server_name,
            password_secret,
            shadow_tls_password_secret,
        } => html! {
            (text_input("server_name", "ShadowTLS server name", server_name, "TLS host presented by ShadowTLS v3."))
            (secret_input("password_secret", "Shadowsocks password secret", password_secret, secret_names))
            (secret_input(
                "shadow_tls_password_secret",
                "ShadowTLS password secret",
                shadow_tls_password_secret,
                secret_names
            ))
        },
        ProtocolConfig::Hysteria2 {
            password_secret,
            sni,
            obfs_password_secret,
        } => html! {
            (text_input("sni", "TLS SNI", sni, "Server name used by the TLS handshake."))
            (secret_input("password_secret", "Hysteria2 password secret", password_secret, secret_names))
            (optional_secret_input(
                "obfs_password_secret",
                "Salamander obfs secret",
                obfs_password_secret.as_deref().unwrap_or(""),
                secret_names
            ))
        },
        ProtocolConfig::AnyTls {
            password_secret,
            sni,
        } => html! {
            (text_input("sni", "TLS SNI", sni, "Server name used by AnyTLS."))
            (secret_input("password_secret", "AnyTLS password secret", password_secret, secret_names))
        },
        ProtocolConfig::Tuic {
            password_secret,
            sni,
            ..
        } => html! {
            (text_input("sni", "TLS SNI", sni, "Server name used by TUIC."))
            (secret_input("password_secret", "TUIC password secret", password_secret, secret_names))
        },
    }
}

fn text_input(name: &str, label: &str, value: &str, help: &str) -> Markup {
    html! {
        label {
            span { (label) }
            input type="text" name=(name) value=(value) required;
            small { (help) }
        }
    }
}

fn secret_input(name: &str, label: &str, value: &str, secret_names: &[String]) -> Markup {
    html! {
        label {
            span { (label) }
            input type="text" name=(name) value=(value) list="secret-names" required;
            small {
                "SQLite secret name. "
                @if secret_names.iter().any(|secret| secret == value) {
                    span class="inline-ok" { "present" }
                } @else {
                    span class="inline-warn" { "missing" }
                }
            }
        }
    }
}

fn optional_secret_input(name: &str, label: &str, value: &str, secret_names: &[String]) -> Markup {
    html! {
        label {
            span { (label) }
            input type="text" name=(name) value=(value) list="secret-names";
            small {
                "Optional SQLite secret name."
                @if !value.is_empty() && secret_names.iter().any(|secret| secret == value) {
                    " "
                    span class="inline-ok" { "present" }
                } @else if !value.is_empty() {
                    " "
                    span class="inline-warn" { "missing" }
                }
            }
        }
    }
}

async fn users_page(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let auth = match require_admin(&state, &headers).await {
        Ok(value) => value,
        Err(response) => return response,
    };

    let users = match list_users(&state.pool).await {
        Ok(value) => value,
        Err(err) => {
            return Html(
                layout(
                    "Users error",
                    html! {
                        h1 { "Users" }
                        div class="notice error" {
                            "Failed to load users: " (err.to_string())
                        }
                    },
                )
                .into_string(),
            )
            .into_response();
        }
    };

    Html(
        layout(
            "Users",
            html! {
                (admin_bar(&auth))
                h1 { "Users" }

                section {
                    h2 { "Create user" }
                    form method="post" action="/admin/users/create" class="form" {
                        (csrf_field(&auth.csrf_token))
                        label {
                            span { "Username" }
                            input type="text" name="username" placeholder="fedor-phone" required;
                        }

                        label {
                            span { "Traffic limit, GB" }
                            input type="number" name="traffic_limit_gb" min="0" placeholder="empty = unlimited";
                        }

                        label {
                            span { "Expires in days" }
                            input type="number" name="expires_in_days" min="0" max="3650" placeholder="empty = never";
                        }

                        button type="submit" { "Create" }
                    }
                }

                section {
                    h2 { "Existing users" }

                    @if users.is_empty() {
                        p { "No users yet." }
                    } @else {
                        div class="table-wrap" {
                            table {
                                thead {
                                    tr {
                                        th { "ID" }
                                        th { "Username" }
                                        th { "Enabled" }
                                        th { "UUID" }
                                        th { "Subscription" }
                                        th { "Traffic" }
                                        th { "Expires" }
                                        th { "Actions" }
                                    }
                                }
                                tbody {
                                    @for user in users {
                                        tr {
                                            td { (user.id) }
                                            td { (user.username) }
                                            td {
                                                @if user.enabled {
                                                    span class="badge ok" { "on" }
                                                } @else {
                                                    span class="badge off" { "off" }
                                                }
                                            }
                                            td {
                                                code { (user.uuid) }
                                            }
                                            td {
                                                code { (format!("/sub/{}", user.subscription_token)) }
                                                br;
                                                a href=(format!("/sub/{}", user.subscription_token)) { "open" }
                                                " "
                                                a href=(format!("/sub/{}/mihomo.yaml", user.subscription_token)) { "download" }
                                            }
                                            td {
                                                (format_user_traffic(&user))
                                            }
                                            td {
                                                (format_user_expiry(&user))
                                            }
                                            td {
                                                @if user.enabled {
                                                    form method="post" action=(format!("/admin/users/{}/toggle", user.id)) class="inline-form" {
                                                        (csrf_field(&auth.csrf_token))
                                                        button type="submit" { "Disable" }
                                                    }
                                                } @else {
                                                    form method="post" action=(format!("/admin/users/{}/toggle", user.id)) class="inline-form" {
                                                        (csrf_field(&auth.csrf_token))
                                                        button type="submit" { "Enable" }
                                                    }
                                                }

                                                a class="button compact" href=(format!("/admin/users/{}/reset-token", user.id)) { "Reset token" }
                                                a class="button compact danger" href=(format!("/admin/users/{}/delete", user.id)) { "Delete" }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            },
        )
        .into_string(),
    )
    .into_response()
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

    if username.is_empty() {
        return html_error_response(StatusCode::BAD_REQUEST, "Bad request", "Username is empty");
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

    match create_user(&state.pool, input).await {
        Ok(_) => Redirect::to("/admin/users").into_response(),
        Err(err) => html_error_response(
            StatusCode::BAD_REQUEST,
            "Create user failed",
            format!("Failed to create user: {err}"),
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
        Err(err) => {
            return html_error_response(
                StatusCode::NOT_FOUND,
                "User not found",
                format!("Failed to find user: {err}"),
            );
        }
    };

    match set_user_enabled(&state.pool, id, !user.enabled).await {
        Ok(_) => Redirect::to("/admin/users").into_response(),
        Err(err) => html_error_response(
            StatusCode::BAD_REQUEST,
            "Toggle user failed",
            format!("Failed to toggle user: {err}"),
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
        Err(err) => {
            return html_error_response(
                StatusCode::NOT_FOUND,
                "User not found",
                format!("Failed to find user: {err}"),
            );
        }
    };

    Html(
        layout(
            "Reset token",
            html! {
                (admin_bar(&auth))
                h1 { "Reset token" }

                section class="confirm-panel" {
                    h2 { "Confirm subscription token reset" }
                    p {
                        "Old subscription URL for "
                        strong { (user.username) }
                        " will stop working immediately. The user will need the new URL."
                    }
                    dl class="details" {
                        dt { "Current subscription" }
                        dd { code { (format!("/sub/{}/mihomo.yaml", user.subscription_token)) } }
                        dt { "Status" }
                        dd {
                            @if user.enabled {
                                span class="badge ok" { "on" }
                            } @else {
                                span class="badge off" { "off" }
                            }
                        }
                    }
                    div class="actions" {
                        form method="post" action=(format!("/admin/users/{}/reset-token", user.id)) class="inline-form" {
                            (csrf_field(&auth.csrf_token))
                            button type="submit" class="danger" { "Reset token" }
                        }
                        a class="button secondary" href="/admin/users" { "Cancel" }
                    }
                }
            },
        )
        .into_string(),
    )
    .into_response()
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

    match reset_user_subscription_token(&state.pool, id).await {
        Ok(_) => Redirect::to("/admin/users").into_response(),
        Err(err) => html_error_response(
            StatusCode::BAD_REQUEST,
            "Reset token failed",
            format!("Failed to reset token: {err}"),
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
        Err(err) => {
            return html_error_response(
                StatusCode::NOT_FOUND,
                "User not found",
                format!("Failed to find user: {err}"),
            );
        }
    };

    Html(
        layout(
            "Delete user",
            html! {
                (admin_bar(&auth))
                h1 { "Delete user" }

                section class="confirm-panel danger-zone" {
                    h2 { "Confirm user deletion" }
                    p {
                        "This removes "
                        strong { (user.username) }
                        " from the users table and invalidates the subscription token."
                    }
                    dl class="details" {
                        dt { "UUID" }
                        dd { code { (user.uuid) } }
                        dt { "Subscription" }
                        dd { code { (format!("/sub/{}/mihomo.yaml", user.subscription_token)) } }
                        dt { "Traffic" }
                        dd {
                            (format_bytes(user.traffic_used_bytes))
                            " / "
                            @match user.traffic_limit_bytes {
                                Some(limit) => {
                                    (format_bytes(limit))
                                },
                                None => {
                                    "unlimited"
                                },
                            }
                        }
                    }
                    div class="actions" {
                        form method="post" action=(format!("/admin/users/{}/delete", user.id)) class="inline-form" {
                            (csrf_field(&auth.csrf_token))
                            button type="submit" class="danger" { "Delete user" }
                        }
                        a class="button secondary" href="/admin/users" { "Cancel" }
                    }
                }
            },
        )
        .into_string(),
    )
    .into_response()
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

    match delete_user(&state.pool, id).await {
        Ok(_) => Redirect::to("/admin/users").into_response(),
        Err(err) => html_error_response(
            StatusCode::BAD_REQUEST,
            "Delete user failed",
            format!("Failed to delete user: {err}"),
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
            Err(err) => Err(html_error_response_with_back(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Auth failed",
                format!("Failed to inspect admin setup state: {err}"),
                "/",
                "Back to Home",
            )),
        },
        Err(err) => Err(html_error_response_with_back(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Auth failed",
            format!("Failed to validate admin session: {err}"),
            "/admin/login",
            "Back to Login",
        )),
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
    if admin.is_some() {
        touch_admin_session(&state.pool, &token_hash).await?;
    } else {
        delete_admin_session(&state.pool, &token_hash).await?;
    }

    Ok(admin.map(|admin| AuthenticatedAdmin {
        admin,
        csrf_token: csrf_token_for_session_token(&token),
    }))
}

async fn create_session_redirect(state: &AppState, admin_id: i64, location: &str) -> Response {
    let token = generate_session_token();
    let token_hash = hash_session_token(&token);
    let expires_at = Utc::now() + Duration::days(ADMIN_SESSION_TTL_DAYS);

    match create_admin_session(&state.pool, admin_id, &token_hash, expires_at).await {
        Ok(()) => {
            let mut response = Redirect::to(location).into_response();
            append_session_cookie(&mut response, active_session_cookie(state, token));
            response
        }
        Err(err) => html_error_response_with_back(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Session failed",
            format!("Failed to create admin session: {err}"),
            "/admin/login",
            "Back to Login",
        ),
    }
}

fn hash_password(password: &str) -> anyhow::Result<String> {
    let salt = SaltString::generate(&mut OsRng);
    let password_hash = Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map_err(|err| anyhow::anyhow!("argon2 password hash failed: {err}"))?;

    Ok(password_hash.to_string())
}

fn verify_password(password: &str, password_hash: &str) -> anyhow::Result<bool> {
    let parsed_hash = PasswordHash::new(password_hash)
        .map_err(|err| anyhow::anyhow!("stored password hash is invalid: {err}"))?;

    match Argon2::default().verify_password(password.as_bytes(), &parsed_hash) {
        Ok(()) => Ok(true),
        Err(argon2::password_hash::Error::Password) => Ok(false),
        Err(err) => Err(anyhow::anyhow!(
            "argon2 password verification failed: {err}"
        )),
    }
}

fn generate_session_token() -> String {
    let mut token = [0_u8; 32];
    OsRng.fill_bytes(&mut token);
    URL_SAFE_NO_PAD.encode(token)
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

fn session_token_from_headers(headers: &HeaderMap) -> Option<String> {
    let cookie_header = headers.get(header::COOKIE)?.to_str().ok()?;

    cookie_header.split(';').find_map(|value| {
        let cookie = Cookie::parse(value.trim().to_string()).ok()?;
        (cookie.name() == ADMIN_SESSION_COOKIE).then(|| cookie.value().to_string())
    })
}

fn active_session_cookie(state: &AppState, token: String) -> Cookie<'static> {
    Cookie::build((ADMIN_SESSION_COOKIE, token))
        .path("/")
        .http_only(true)
        .secure(state.cookie_secure)
        .same_site(SameSite::Lax)
        .max_age(CookieDuration::days(ADMIN_SESSION_TTL_DAYS))
        .build()
}

fn expired_session_cookie(state: &AppState) -> Cookie<'static> {
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

    vec![
        format!("username:{username}"),
        format!("source:{}", login_source_hint(headers, peer_addr)),
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
        .or_else(|| headers.get("x-forwarded-for"))
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(',').next())
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
            .unwrap_or_else(|poisoned| poisoned.into_inner());
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
            .unwrap_or_else(|poisoned| poisoned.into_inner());
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
            .unwrap_or_else(|poisoned| poisoned.into_inner());

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

fn csrf_field(token: &str) -> Markup {
    html! {
        input type="hidden" name="csrf_token" value=(token);
    }
}

async fn load_secret_values_map(
    pool: &SqlitePool,
    profiles: &[ProtocolProfile],
) -> anyhow::Result<HashMap<String, String>> {
    let mut secrets = HashMap::new();

    for secret_name in profiles
        .iter()
        .flat_map(ProtocolProfile::required_secret_names)
    {
        if secrets.contains_key(secret_name) {
            continue;
        }

        if let Some(secret) = get_secret(pool, secret_name).await? {
            secrets.insert(secret_name.to_string(), secret.value);
        }
    }

    Ok(secrets)
}

fn missing_secret_names(profile: &ProtocolProfile, present_secret_names: &[String]) -> Vec<String> {
    profile
        .required_secret_names()
        .into_iter()
        .filter(|name| !present_secret_names.iter().any(|present| present == name))
        .map(str::to_string)
        .collect()
}

fn proxy_kind_label(kind: &ProxyKind) -> &'static str {
    match kind {
        ProxyKind::VlessRealityXhttp => "VLESS + REALITY + XHTTP",
        ProxyKind::VlessRealityTcp => "VLESS + REALITY + TCP",
        ProxyKind::Shadowsocks2022ShadowTls => "SS2022 + ShadowTLS",
        ProxyKind::Hysteria2 => "Hysteria2",
        ProxyKind::AnyTls => "AnyTLS",
        ProxyKind::Tuic => "TUIC",
    }
}

fn proxy_role_label(role: &ProxyRole) -> &'static str {
    match role {
        ProxyRole::AutoSafe => "AUTO-SAFE",
        ProxyRole::Speed => "SPEED",
        ProxyRole::Compatibility => "COMPAT",
        ProxyRole::RuAccess => "RU-ACCESS",
        ProxyRole::Manual => "MANUAL",
    }
}

fn core_priority_class(priority: &str) -> &'static str {
    match priority {
        "primary" | "compat" => "ok",
        "telegram" => "warn",
        _ => "off",
    }
}

pub(crate) fn admin_bar(auth: &AuthenticatedAdmin) -> Markup {
    html! {
        div class="admin-bar" {
            span {
                "Signed in as " strong { (auth.admin.username) }
                @if is_owner_admin(auth) {
                    " "
                    span class="badge ok" { "owner" }
                }
            }
            form method="post" action="/admin/logout" class="inline-form" {
                (csrf_field(&auth.csrf_token))
                button type="submit" { "Logout" }
            }
        }
    }
}

fn is_owner_admin(auth: &AuthenticatedAdmin) -> bool {
    auth.admin.id == 1
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
    let is_admin_path = request.uri().path().starts_with("/admin");
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
            "default-src 'none'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; form-action 'self'; base-uri 'none'; frame-ancestors 'none'",
        ),
    );
    headers.insert(
        "Permissions-Policy",
        HeaderValue::from_static("camera=(), microphone=(), geolocation=(), payment=()"),
    );

    if is_admin_path {
        headers.insert(
            header::CACHE_CONTROL,
            HeaderValue::from_static("no-store, max-age=0"),
        );
    }

    response
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
    let message = message.into();

    (
        status,
        Html(
            layout(
                title,
                html! {
                    h1 { (title) }
                    div class="notice error" {
                        (message)
                    }
                    a class="button" href=(back_href) { (back_label) }
                },
            )
            .into_string(),
        ),
    )
        .into_response()
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
    let expire = user
        .expires_at
        .map(|value| value.timestamp().max(0))
        .unwrap_or(0);
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
    match user.traffic_limit_bytes {
        Some(limit) => format!(
            "{} / {}",
            format_bytes(user.traffic_used_bytes),
            format_bytes(limit)
        ),
        None => format!("{} / unlimited", format_bytes(user.traffic_used_bytes)),
    }
}

fn format_user_expiry(user: &UserRecord) -> String {
    user.expires_at
        .map(|value| value.format("%Y-%m-%d %H:%M UTC").to_string())
        .unwrap_or_else(|| "never".to_string())
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
