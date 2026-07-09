use argon2::{
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use axum::{
    body::Body,
    extract::connect_info::ConnectInfo,
    extract::{Form, Path, State},
    http::{header, HeaderMap, Request, StatusCode},
    middleware::{self, Next},
    response::{Html, IntoResponse, Redirect, Response},
    routing::{get, post},
    Router,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chrono::{Duration, Utc};
use cookie::{time::Duration as CookieDuration, Cookie, SameSite};
use maud::{html, Markup, PreEscaped, DOCTYPE};
use rand_core::{OsRng, RngCore};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use sqlx::SqlitePool;
use std::{
    collections::HashMap,
    net::SocketAddr,
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
        update_protocol_profile, update_routing_rule_set, AdminRecord, NewUser,
        UpdateProtocolProfile, UpdateRoutingRuleSet,
    },
};
use subtle::ConstantTimeEq;
use tower_http::trace::TraceLayer;

const ADMIN_SESSION_COOKIE: &str = "stealthhub_admin_session";
const ADMIN_SESSION_TTL_DAYS: i64 = 7;
const MIN_ADMIN_PASSWORD_LEN: usize = 12;
const LOGIN_FAILURE_DELAY_MS: u64 = 500;
const DUMMY_PASSWORD_HASH: &str = "$argon2id$v=19$m=19456,t=2,p=1$gTSHLOLVD71RNAjjkqaKvQ$cCpCPgJOl06K2/RHtedp/MTm/4u+0n4JeNlYF00eQj4";
const DEPLOYMENT_MODE: &str = "bare-metal systemd";
const LOGIN_RATE_LIMIT_WINDOW: StdDuration = StdDuration::from_secs(15 * 60);
const LOGIN_RATE_LIMIT_MAX_FAILURES: u32 = 5;
const CORE_RUNTIMES: &[CoreRuntime] = &[
    CoreRuntime {
        name: "Xray",
        role: "VLESS REALITY XHTTP/TCP",
        service: "stealthhub-xray.service",
        binary_path: "/opt/stealthhub/cores/xray/current/xray",
        local_binary_path: ".runtime/cores/xray/current/xray",
        config_path: "/etc/stealthhub-cores/xray/config.json",
        update_channel: "XTLS/Xray-core GitHub releases",
        priority: "primary",
    },
    CoreRuntime {
        name: "sing-box",
        role: "SS2022 ShadowTLS, AnyTLS, compatibility",
        service: "stealthhub-sing-box.service",
        binary_path: "/opt/stealthhub/cores/sing-box/current/sing-box",
        local_binary_path: ".runtime/cores/sing-box/current/sing-box",
        config_path: "/etc/stealthhub-cores/sing-box/config.json",
        update_channel: "SagerNet/sing-box GitHub releases",
        priority: "compat",
    },
    CoreRuntime {
        name: "Hysteria",
        role: "Hysteria2 speed fallback",
        service: "stealthhub-hysteria.service",
        binary_path: "/opt/stealthhub/cores/hysteria/current/hysteria",
        local_binary_path: ".runtime/cores/hysteria/current/hysteria",
        config_path: "/etc/stealthhub-cores/hysteria/config.yaml",
        update_channel: "apernet/hysteria GitHub releases",
        priority: "speed",
    },
    CoreRuntime {
        name: "TUIC",
        role: "TUIC QUIC speed fallback",
        service: "stealthhub-tuic.service",
        binary_path: "/opt/stealthhub/cores/tuic/current/tuic-server",
        local_binary_path: ".runtime/cores/tuic/current/tuic-server",
        config_path: "/etc/stealthhub-cores/tuic/config.json",
        update_channel: "tuic-protocol/tuic GitHub releases",
        priority: "optional",
    },
];

#[derive(Debug, Clone, Copy)]
struct CoreRuntime {
    name: &'static str,
    role: &'static str,
    service: &'static str,
    binary_path: &'static str,
    local_binary_path: &'static str,
    config_path: &'static str,
    update_channel: &'static str,
    priority: &'static str,
}

#[derive(Clone)]
struct AppState {
    pool: SqlitePool,
    cookie_secure: bool,
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
struct AuthenticatedAdmin {
    admin: AdminRecord,
    csrf_token: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter("stealthhub_panel=debug,tower_http=debug,info")
        .init();

    let bind = std::env::var("STEALTHHUB_BIND").unwrap_or_else(|_| "127.0.0.1:8080".to_string());
    let db_url = std::env::var("STEALTHHUB_DB")
        .unwrap_or_else(|_| "sqlite://./stealthhub.sqlite?mode=rwc".to_string());
    let cookie_secure = std::env::var("STEALTHHUB_COOKIE_SECURE")
        .map(|value| matches!(value.as_str(), "1" | "true" | "yes" | "on"))
        .unwrap_or(false);
    let enable_demo_user = std::env::var("STEALTHHUB_ENABLE_DEMO_USER")
        .map(|value| matches!(value.as_str(), "1" | "true" | "yes" | "on"))
        .unwrap_or(false);

    if !cookie_secure && !bind.starts_with("127.0.0.1:") && !bind.starts_with("localhost:") {
        tracing::warn!(
            "admin session cookie Secure flag is disabled; set STEALTHHUB_COOKIE_SECURE=true behind HTTPS"
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
        .route("/admin/protocols", get(protocols_page))
        .route(
            "/admin/protocols/:name/update",
            post(update_protocol_action),
        )
        .route(
            "/admin/routing",
            get(routing_page).post(update_routing_rule_action),
        )
        .route("/admin/system", get(system_page))
        .route("/admin/cores", get(cores_page))
        .route("/admin/users/create", post(create_user_action))
        .route("/admin/users/:id/toggle", post(toggle_user_action))
        .route(
            "/admin/users/:id/reset-token",
            get(reset_user_token_page).post(reset_user_token_action),
        )
        .route(
            "/admin/users/:id/delete",
            get(delete_user_page).post(delete_user_action),
        )
        .route("/health", get(health))
        .route("/ready", get(readiness))
        .route("/sub/:token/mihomo.yaml", get(mihomo_subscription))
        .route("/rules/:name", get(rule_provider))
        .with_state(state)
        .layer(middleware::from_fn(security_headers))
        .layer(TraceLayer::new_for_http());

    tracing::info!("StealthHub Panel listening on http://{}", bind);

    let listener = tokio::net::TcpListener::bind(&bind).await?;
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await?;

    Ok(())
}

async fn health() -> impl IntoResponse {
    "ok\n"
}

async fn readiness(State(state): State<AppState>) -> Response {
    match sqlx::query_scalar::<_, i64>("SELECT 1")
        .fetch_one(&state.pool)
        .await
    {
        Ok(1) => (StatusCode::OK, "ready\n").into_response(),
        Ok(_) => (
            StatusCode::SERVICE_UNAVAILABLE,
            "database readiness probe returned an unexpected value\n",
        )
            .into_response(),
        Err(err) => (
            StatusCode::SERVICE_UNAVAILABLE,
            format!("database is not ready: {err}\n"),
        )
            .into_response(),
    }
}

async fn mihomo_subscription(State(state): State<AppState>, Path(token): Path<String>) -> Response {
    let user = match get_user_by_token(&state.pool, &token).await {
        Ok(value) => value,
        Err(_) => {
            return (StatusCode::UNAUTHORIZED, "invalid subscription token\n").into_response()
        }
    };

    if !user.enabled {
        return (StatusCode::FORBIDDEN, "subscription disabled\n").into_response();
    }

    let subscription_user: SubscriptionUser = user.into();
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
        "application/yaml; charset=utf-8".parse().unwrap(),
    );
    headers.insert(
        header::CACHE_CONTROL,
        "no-cache, no-store, must-revalidate".parse().unwrap(),
    );
    headers.insert(
        "Subscription-Userinfo",
        "upload=0; download=0; total=0; expire=0".parse().unwrap(),
    );

    (headers, yaml).into_response()
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
        "application/yaml; charset=utf-8".parse().unwrap(),
    );
    headers.insert(
        header::CACHE_CONTROL,
        "public, max-age=300".parse().unwrap(),
    );

    (headers, body).into_response()
}

async fn index() -> impl IntoResponse {
    Html(
        layout(
            "StealthHub Panel",
            html! {
                h1 { "StealthHub Panel" }
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
                        dd { code { "/opt/stealthhub/cores/{core}/{version}" } }
                        dt { "Active binary" }
                        dd { code { "/opt/stealthhub/cores/{core}/current" } }
                        dt { "Configs" }
                        dd { code { "/etc/stealthhub-cores/{core}" } }
                        dt { "Service templates" }
                        dd { code { "deploy/cores/systemd/*.service" } }
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
                    h2 { "Runtime contract" }
                    dl class="details" {
                        dt { "Binary" }
                        dd { code { "/usr/local/bin/stealthhub-panel" } }
                        dt { "Environment" }
                        dd { code { "/etc/stealthhub-panel/stealthhub-panel.env" } }
                        dt { "Database" }
                        dd { code { "/var/lib/stealthhub-panel/stealthhub.sqlite" } }
                        dt { "Service" }
                        dd { code { "stealthhub-panel.service" } }
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
                                                code { (format!("/sub/{}/mihomo.yaml", user.subscription_token)) }
                                                br;
                                                a href=(format!("/sub/{}/mihomo.yaml", user.subscription_token)) { "download" }
                                            }
                                            td {
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

    let input = NewUser {
        username,
        traffic_limit_bytes,
        expires_at: None,
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

async fn require_admin(
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
    hasher.update(b"stealthhub-admin-csrf-v1:");
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
    response.headers_mut().append(
        header::SET_COOKIE,
        cookie
            .to_string()
            .parse()
            .expect("session cookie header must be valid"),
    );
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

    response.headers_mut().insert(
        header::RETRY_AFTER,
        retry_after_secs
            .parse()
            .expect("retry-after seconds must be a valid header"),
    );

    response
}

fn login_rate_limit_keys(
    headers: &HeaderMap,
    peer_addr: SocketAddr,
    username: &str,
) -> Vec<String> {
    let username = username.trim().to_ascii_lowercase();
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
        .filter(|value| !value.is_empty())
        .map(str::to_string)
}

impl LoginRateLimiter {
    fn retry_after(&self, keys: &[String]) -> Option<StdDuration> {
        let now = Instant::now();
        let mut attempts = self
            .attempts
            .lock()
            .expect("login limiter mutex should not be poisoned");

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
            .expect("login limiter mutex should not be poisoned");

        for key in keys {
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
            .expect("login limiter mutex should not be poisoned");

        for key in keys {
            attempts.remove(key);
        }
    }
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
        _ => "off",
    }
}

fn admin_bar(auth: &AuthenticatedAdmin) -> Markup {
    html! {
        div class="admin-bar" {
            span { "Signed in as " strong { (auth.admin.username) } }
            form method="post" action="/admin/logout" class="inline-form" {
                (csrf_field(&auth.csrf_token))
                button type="submit" { "Logout" }
            }
        }
    }
}

async fn security_headers(request: Request<Body>, next: Next) -> Response {
    let is_admin_path = request.uri().path().starts_with("/admin");
    let mut response = next.run(request).await;
    let headers = response.headers_mut();

    headers.insert(header::X_FRAME_OPTIONS, "DENY".parse().unwrap());
    headers.insert(header::X_CONTENT_TYPE_OPTIONS, "nosniff".parse().unwrap());
    headers.insert(header::REFERRER_POLICY, "no-referrer".parse().unwrap());
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        "default-src 'none'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; form-action 'self'; base-uri 'none'; frame-ancestors 'none'"
            .parse()
            .unwrap(),
    );
    headers.insert(
        "Permissions-Policy",
        "camera=(), microphone=(), geolocation=(), payment=()"
            .parse()
            .unwrap(),
    );

    if is_admin_path {
        headers.insert(
            header::CACHE_CONTROL,
            "no-store, max-age=0".parse().unwrap(),
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

fn format_bytes(value: i64) -> String {
    const GB: f64 = 1024.0 * 1024.0 * 1024.0;
    if value <= 0 {
        return "0 GB".to_string();
    }

    format!("{:.2} GB", value as f64 / GB)
}

fn layout(title: &str, body: Markup) -> Markup {
    html! {
        (DOCTYPE)
        html lang="ru" {
            head {
                meta charset="utf-8";
                meta name="viewport" content="width=device-width, initial-scale=1";
                title { (title) }
                style {
                    (PreEscaped(r#"
                    :root {
                        color-scheme: light;
                        font-family: "Aptos", "Segoe UI", "Helvetica Neue", Arial, sans-serif;
                        background: #e7edf2;
                        color: #202a33;
                        --bg: #e7edf2;
                        --chrome: #0a4964;
                        --chrome-dark: #07344a;
                        --chrome-soft: #d9e8ef;
                        --panel: #ffffff;
                        --panel-soft: #f5f8fa;
                        --panel-strong: #eef4f7;
                        --border: #c6d2db;
                        --border-strong: #88a4b5;
                        --text: #202a33;
                        --muted: #627483;
                        --accent: #087da1;
                        --accent-dark: #075f7b;
                        --ok-bg: #e2f4e8;
                        --ok-text: #17653a;
                        --warn-bg: #fff3d5;
                        --warn-text: #875600;
                        --danger-bg: #fbe4e4;
                        --danger-text: #9f1c1c;
                    }
                    * { box-sizing: border-box; }
                    body {
                        margin: 0;
                        min-height: 100vh;
                        background: var(--bg);
                        color: var(--text);
                    }
                    .app-chrome {
                        min-height: 100vh;
                        display: grid;
                        grid-template-rows: auto 1fr;
                    }
                    .masthead {
                        min-height: 46px;
                        display: flex;
                        align-items: center;
                        justify-content: space-between;
                        gap: 18px;
                        padding: 8px 22px;
                        background: linear-gradient(180deg, var(--chrome) 0%, var(--chrome-dark) 100%);
                        border-bottom: 1px solid #062f42;
                        color: #f6fbfd;
                        box-shadow: 0 1px 0 rgba(255,255,255,0.18) inset;
                    }
                    .masthead-title {
                        display: flex;
                        align-items: center;
                        gap: 10px;
                        font-weight: 750;
                        letter-spacing: 0.01em;
                    }
                    .brand-mark {
                        width: 22px;
                        height: 22px;
                        border-radius: 4px;
                        background:
                            linear-gradient(90deg, transparent 0 18%, rgba(255,255,255,0.9) 18% 24%, transparent 24% 38%, rgba(255,255,255,0.9) 38% 44%, transparent 44% 58%, rgba(255,255,255,0.9) 58% 64%, transparent 64%),
                            #16a0c3;
                        border: 1px solid rgba(255,255,255,0.55);
                    }
                    .masthead-meta {
                        color: #cde7f1;
                        font-size: 12px;
                        text-transform: uppercase;
                        letter-spacing: 0.08em;
                    }
                    .layout-shell {
                        display: grid;
                        grid-template-columns: 232px minmax(0, 1fr);
                        min-height: 0;
                    }
                    .content {
                        width: 100%;
                        max-width: 1280px;
                        padding: 22px 26px 42px;
                    }
                    a {
                        color: inherit;
                        text-underline-offset: 3px;
                    }
                    h1 {
                        font-size: 26px;
                        line-height: 1.2;
                        margin: 0 0 12px;
                        color: #152633;
                    }
                    h2 {
                        margin: 0 0 12px;
                        font-size: 16px;
                        color: #1b3342;
                    }
                    p { color: var(--muted); line-height: 1.55; }
                    code {
                        display: inline-block;
                        padding: 3px 6px;
                        border-radius: 3px;
                        background: #edf3f6;
                        border: 1px solid #c9d7df;
                        color: #17495e;
                        word-break: break-all;
                    }
                    .top-nav {
                        min-height: 100%;
                        padding: 16px 10px;
                        border-right: 1px solid var(--border);
                        background: linear-gradient(180deg, #f8fbfc 0%, #edf3f6 100%);
                    }
                    .top-nav a {
                        display: block;
                        margin-bottom: 4px;
                        padding: 9px 10px;
                        border: 1px solid transparent;
                        border-radius: 3px;
                        color: #273a46;
                        text-decoration: none;
                        font-size: 14px;
                        font-weight: 650;
                    }
                    .top-nav a:hover {
                        color: var(--text);
                        border-color: #b5c8d3;
                        background: #ffffff;
                    }
                    .nav-section {
                        margin: 10px 8px 8px;
                        color: #6b7d89;
                        font-size: 11px;
                        font-weight: 800;
                        text-transform: uppercase;
                        letter-spacing: 0.08em;
                    }
                    .cards, .grid {
                        display: flex;
                        flex-direction: column;
                        gap: 7px;
                        margin-top: 16px;
                    }
                    .card, section, .notice {
                        background: var(--panel);
                        border: 1px solid var(--border);
                        border-radius: 4px;
                        padding: 13px 14px;
                        text-decoration: none;
                        box-shadow: 0 1px 2px rgba(31, 55, 70, 0.06);
                    }
                    section {
                        margin-top: 12px;
                    }
                    .cards .card, .grid section {
                        min-height: 52px;
                        display: grid;
                        grid-template-columns: 220px minmax(0, 1fr) auto;
                        align-items: center;
                        gap: 12px;
                        margin-top: 0;
                        padding: 10px 12px;
                    }
                    .cards .card h2, .grid section h2 {
                        margin: 0;
                    }
                    .cards .card p, .grid section p {
                        margin: 0;
                    }
                    .grid section ul {
                        grid-column: 2 / -1;
                        columns: 2;
                        margin: 0;
                        padding-left: 18px;
                    }
                    .grid section .button {
                        justify-self: end;
                    }
                    .card:hover, .button:hover, button:hover {
                        border-color: var(--accent);
                    }
                    .notice {
                        margin: 14px 0;
                        background: var(--panel-soft);
                        color: var(--muted);
                        border-left: 4px solid var(--accent);
                    }
                    .error {
                        border-color: #c64d4d;
                        color: var(--danger-text);
                        background: #fff6f6;
                    }
                    li { margin: 6px 0; }
                    .button, button {
                        display: inline-block;
                        min-height: 34px;
                        padding: 7px 12px;
                        border-radius: 3px;
                        border: 1px solid var(--border-strong);
                        background: linear-gradient(180deg, #ffffff 0%, #e7eef2 100%);
                        color: #173244;
                        text-decoration: none;
                        cursor: pointer;
                        font-weight: 650;
                        box-shadow: 0 1px 0 rgba(255,255,255,0.9) inset;
                    }
                    .button.compact {
                        min-height: 30px;
                        padding: 6px 10px;
                        margin: 0 6px 6px 0;
                    }
                    .button.secondary {
                        border-color: var(--border);
                        background: #f7fafb;
                        color: var(--muted);
                    }
                    .form {
                        display: grid;
                        gap: 12px;
                        max-width: 520px;
                    }
                    label {
                        display: grid;
                        gap: 6px;
                    }
                    label span {
                        color: var(--muted);
                        font-size: 14px;
                    }
                    input, select, textarea {
                        width: 100%;
                        min-height: 38px;
                        padding: 9px 10px;
                        border-radius: 3px;
                        border: 1px solid var(--border);
                        background: #ffffff;
                        color: var(--text);
                        font-size: 15px;
                    }
                    textarea {
                        min-height: 180px;
                        resize: vertical;
                        font-family: "SFMono-Regular", Consolas, "Liberation Mono", monospace;
                        line-height: 1.45;
                    }
                    input:focus, select:focus, textarea:focus {
                        outline: 2px solid rgba(8, 125, 161, 0.22);
                        border-color: var(--accent);
                    }
                    small {
                        color: var(--muted);
                        font-size: 12px;
                        line-height: 1.35;
                    }
                    .table-wrap {
                        overflow-x: auto;
                        border: 1px solid var(--border);
                        border-radius: 4px;
                        background: #ffffff;
                    }
                    table {
                        width: 100%;
                        border-collapse: collapse;
                        min-width: 860px;
                    }
                    th, td {
                        text-align: left;
                        border-bottom: 1px solid var(--border);
                        padding: 9px 10px;
                        vertical-align: top;
                        font-size: 14px;
                    }
                    tbody tr:hover {
                        background: #f3f8fa;
                    }
                    th {
                        color: #425563;
                        font-size: 12px;
                        text-transform: uppercase;
                        letter-spacing: 0.05em;
                        background: linear-gradient(180deg, #f5f8fa 0%, #e7eef2 100%);
                    }
                    .badge {
                        display: inline-block;
                        padding: 3px 8px;
                        border-radius: 3px;
                        font-weight: 700;
                        font-size: 12px;
                        border: 1px solid transparent;
                    }
                    .badge.ok {
                        background: var(--ok-bg);
                        color: var(--ok-text);
                        border-color: #a8d9bb;
                    }
                    .badge.off {
                        background: var(--danger-bg);
                        color: var(--danger-text);
                        border-color: #e4b0b0;
                    }
                    .badge.neutral {
                        background: #edf3f6;
                        color: #315063;
                        border-color: #c9d7df;
                    }
                    .inline-ok {
                        color: var(--ok-text);
                        font-weight: 700;
                    }
                    .inline-warn {
                        color: var(--danger-text);
                        font-weight: 700;
                    }
                    .inline-form {
                        display: inline-block;
                        margin: 0 6px 6px 0;
                    }
                    .admin-bar {
                        display: flex;
                        align-items: center;
                        justify-content: space-between;
                        gap: 12px;
                        margin-bottom: 16px;
                        padding: 10px 12px;
                        border: 1px solid var(--border);
                        border-radius: 4px;
                        background: var(--panel-strong);
                    }
                    .status-strip {
                        display: flex;
                        flex-direction: column;
                        gap: 6px;
                        margin: 16px 0;
                    }
                    .metric {
                        min-height: 42px;
                        display: grid;
                        grid-template-columns: 180px minmax(0, 1fr);
                        align-items: center;
                        gap: 12px;
                        padding: 8px 12px;
                        border: 1px solid var(--border);
                        border-radius: 4px;
                        background: linear-gradient(180deg, #ffffff 0%, #f5f8fa 100%);
                    }
                    .metric span {
                        display: block;
                        color: var(--muted);
                        font-size: 12px;
                        text-transform: uppercase;
                        letter-spacing: 0.04em;
                    }
                    .metric strong {
                        display: block;
                        margin-top: 0;
                    }
                    .actions {
                        display: flex;
                        flex-wrap: wrap;
                        align-items: center;
                        gap: 8px;
                        margin-top: 16px;
                    }
                    .config-list {
                        display: flex;
                        flex-direction: column;
                        gap: 10px;
                    }
                    .config-row {
                        padding: 0;
                    }
                    .config-row-head {
                        display: flex;
                        align-items: center;
                        justify-content: space-between;
                        gap: 12px;
                        padding: 10px 12px;
                        border-bottom: 1px solid var(--border);
                        background: var(--panel-strong);
                    }
                    .config-row h3 {
                        margin: 0;
                        font-size: 15px;
                    }
                    .config-row-meta {
                        display: flex;
                        flex-wrap: wrap;
                        align-items: center;
                        justify-content: flex-end;
                        gap: 6px;
                    }
                    .config-form {
                        display: grid;
                        grid-template-columns: repeat(2, minmax(0, 1fr));
                        gap: 12px;
                        padding: 12px;
                    }
                    .config-form.wide {
                        grid-template-columns: minmax(220px, 0.35fr) minmax(0, 0.65fr);
                    }
                    .config-form button {
                        justify-self: start;
                    }
                    .full-span {
                        grid-column: 1 / -1;
                    }
                    .switch-field {
                        display: grid;
                        grid-template-columns: 42px minmax(0, 1fr);
                        align-items: center;
                        gap: 10px;
                    }
                    .switch-field input {
                        position: absolute;
                        opacity: 0;
                        width: 1px;
                        height: 1px;
                    }
                    .switch-ui {
                        width: 38px;
                        height: 20px;
                        position: relative;
                        border-radius: 999px;
                        border: 1px solid #9fb2bf;
                        background: #d5dde3;
                    }
                    .switch-ui::after {
                        content: "";
                        position: absolute;
                        top: 2px;
                        left: 2px;
                        width: 14px;
                        height: 14px;
                        border-radius: 50%;
                        background: #ffffff;
                        border: 1px solid #9fb2bf;
                        transition: transform 120ms ease;
                    }
                    .switch-field input:checked + .switch-ui {
                        background: #0d8faf;
                        border-color: #087da1;
                    }
                    .switch-field input:checked + .switch-ui::after {
                        transform: translateX(18px);
                    }
                    .details {
                        display: grid;
                        grid-template-columns: max-content minmax(0, 1fr);
                        gap: 8px 14px;
                        margin: 16px 0 0;
                    }
                    .details dt {
                        color: var(--muted);
                        font-size: 13px;
                    }
                    .details dd {
                        min-width: 0;
                        margin: 0;
                    }
                    .danger-zone {
                        border-color: #d88f8f;
                    }

                    .button.danger, button.danger {
                        border-color: #c64d4d;
                        background: var(--danger-bg);
                        color: var(--danger-text);
                    }
                    @media (max-width: 760px) {
                        .masthead {
                            align-items: flex-start;
                            flex-direction: column;
                            gap: 4px;
                            padding: 10px 14px;
                        }
                        .layout-shell {
                            display: block;
                        }
                        .top-nav {
                            min-height: auto;
                            display: flex;
                            flex-wrap: wrap;
                            gap: 6px;
                            padding: 10px;
                            border-right: 0;
                            border-bottom: 1px solid var(--border);
                        }
                        .top-nav a {
                            margin-bottom: 0;
                            padding: 7px 9px;
                        }
                        .nav-section {
                            width: 100%;
                            margin: 6px 4px 0;
                        }
                        .content {
                            padding: 16px 12px 32px;
                        }
                        .cards .card, .grid section, .metric {
                            grid-template-columns: 1fr;
                            align-items: start;
                            gap: 6px;
                        }
                        .config-row-head {
                            align-items: flex-start;
                            flex-direction: column;
                        }
                        .config-row-meta {
                            justify-content: flex-start;
                        }
                        .config-form, .config-form.wide {
                            grid-template-columns: 1fr;
                        }
                        .full-span {
                            grid-column: auto;
                        }
                        .grid section ul {
                            grid-column: auto;
                            columns: 1;
                        }
                        .grid section .button {
                            justify-self: start;
                        }
                        h1 { font-size: 24px; }
                        .admin-bar {
                            align-items: flex-start;
                            flex-direction: column;
                        }
                        .details {
                            grid-template-columns: 1fr;
                        }
                    }
                    "#))
                }
            }
            body {
                div class="app-chrome" {
                    header class="masthead" {
                        div class="masthead-title" {
                            span class="brand-mark" aria-hidden="true" {}
                            span { "StealthHub Panel" }
                        }
                        div class="masthead-meta" { "admin console" }
                    }
                    div class="layout-shell" {
                        nav class="top-nav" aria-label="Main navigation" {
                            div class="nav-section" { "Operate" }
                            a href="/" { "Home" }
                            a href="/admin" { "Dashboard" }
                            a href="/admin/users" { "Users" }
                            a href="/admin/protocols" { "Protocols" }
                            a href="/admin/routing" { "Routing" }
                            a href="/admin/cores" { "Cores" }
                            div class="nav-section" { "Maintenance" }
                            a href="/admin/system" { "System" }
                            a href="/health" { "Health" }
                        }
                        main class="content" {
                            (body)
                        }
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
