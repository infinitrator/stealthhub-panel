//! Axum web control plane for Infiproxy.
//!
//! The binary wires routes, authentication, CSRF protection, settings, users,
//! protocol editors, routing editors and owner-only danger operations. Heavy
//! host helpers and UI layout live in sibling modules to keep this file focused
//! on request/response flow.

mod health;
mod ip;
mod modules;
mod ops;
mod ui;
mod update;
mod views;

pub(crate) use crate::views::components::{admin_bar, csrf_field};
use crate::{
    health::{health, readiness},
    ip::ip_check_page,
    ops::*,
    ui::APP_NAME,
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
    response::{IntoResponse, Redirect, Response},
    routing::{get, post},
    Router,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chrono::{Duration, Utc};
use cookie::{time::Duration as CookieDuration, Cookie, SameSite};
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
    models::{ProtocolConfig, ProtocolProfile, SubscriptionUser},
    rules::routing_rule_payload_yaml,
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
    update_notice: Option<update::Notice>,
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
    if !cookie_secure && !bind.starts_with("127.0.0.1:") && !bind.starts_with("localhost:") {
        tracing::warn!(
            "admin session cookie Secure flag is disabled; set INFIPROXY_COOKIE_SECURE=true behind HTTPS"
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
    update::spawn_checker(pool.clone());
    modules::spawn_checker(pool.clone());

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
        .route("/admin/configs", get(configs_page).post(config_save_action))
        .route(
            "/admin/system/uninstall-preview",
            post(uninstall_preview_action),
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
        Err(_) => return views::subscription::render_invalid(),
    };

    let settings = match load_panel_settings(&state.pool).await {
        Ok(value) => value,
        Err(err) => return (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()).into_response(),
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
    views::public::render_home()
}

async fn setup_admin_page(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if let Ok(Some(_)) = current_admin(&state, &headers).await {
        return Redirect::to("/admin").into_response();
    }

    match admin_count(&state.pool).await {
        Ok(0) => views::public::render_setup(),
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

    views::public::render_login()
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

    views::dashboard::render(&auth)
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
    let update_status = match update::load_status(&state.pool).await {
        Ok(value) => value,
        Err(err) => {
            return html_error_response_with_back(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Update state unavailable",
                format!("Failed to load panel update settings: {err}"),
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
    let mut settings_to_save = vec![
        ("panel_name", panel_name.to_string()),
        ("subscription_domain", subscription_domain),
        ("node_domain", node_domain),
    ];

    if is_owner_admin(&auth) {
        let update_enabled = form.panel_update_enabled.trim().is_empty()
            || update::parse_bool_setting(&form.panel_update_enabled);
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

    for (key, value) in settings_to_save {
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

    if let Err(err) = upsert_setting(&state.pool, "panel_update_status", "requested").await {
        return html_error_response_with_back(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Update not requested",
            format!("Failed to persist update request: {err}"),
            "/admin/settings",
            "Back to Settings",
        );
    }

    if let Err(err) = update::request_now() {
        return html_error_response_with_back(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Update not requested",
            format!("Failed to notify root updater: {err}"),
            "/admin/settings",
            "Back to Settings",
        );
    }

    Redirect::to("/admin/settings").into_response()
}

async fn cores_page(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let auth = match require_admin(&state, &headers).await {
        Ok(value) => value,
        Err(response) => return response,
    };
    let statuses = match modules::load_all(&state.pool).await {
        Ok(value) => value,
        Err(err) => {
            return html_error_response_with_back(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Module state unavailable",
                format!("Failed to load module state: {err}"),
                "/admin",
                "Back to Dashboard",
            );
        }
    };
    let available = match modules::available() {
        Ok(value) => value,
        Err(err) => {
            return html_error_response_with_back(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Module catalog unavailable",
                err.to_string(),
                "/admin",
                "Back to Dashboard",
            );
        }
    };

    views::modules::render(&auth, &statuses, &available)
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
    if let Err(err) = modules::refresh_all(&state.pool).await {
        return html_error_response_with_back(
            StatusCode::BAD_GATEWAY,
            "Module check failed",
            format!("Could not refresh upstream versions: {err}"),
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
        Err(err) => {
            return html_error_response_with_back(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Module registry unavailable",
                err.to_string(),
                "/admin/cores",
                "Back to Modules",
            );
        }
    }
    if let Err(err) = modules::refresh_one(&state.pool, &module_id).await {
        return html_error_response_with_back(
            StatusCode::BAD_GATEWAY,
            "Module check failed",
            format!("Could not refresh {module_id}: {err}"),
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
        Err(err) => {
            return html_error_response_with_back(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Module registry unavailable",
                err.to_string(),
                "/admin/cores",
                "Back to Modules",
            );
        }
    };
    if let Err(err) = modules::request_update(&spec.id) {
        return html_error_response_with_back(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Module update not requested",
            format!("Could not notify the root updater: {err}"),
            "/admin/cores",
            "Back to Modules",
        );
    }
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
    if let Err(err) = modules::set_auto_update(&state.pool, &module_id, enabled).await {
        return html_error_response_with_back(
            StatusCode::BAD_REQUEST,
            "Module policy not saved",
            format!("Could not update module policy: {err}"),
            "/admin/cores",
            "Back to Modules",
        );
    }
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

    if let Err(err) = modules::request_register(&module_id) {
        return html_error_response_with_back(
            StatusCode::BAD_REQUEST,
            "Module registration rejected",
            err.to_string(),
            "/admin/cores",
            "Back to Modules",
        );
    }
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
    if let Err(err) = modules::request_remove(&module_id) {
        return html_error_response_with_back(
            StatusCode::BAD_REQUEST,
            "Module removal rejected",
            err.to_string(),
            "/admin/cores",
            "Back to Modules",
        );
    }
    Redirect::to("/admin/cores").into_response()
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

    views::routing::render(&auth, &rule_sets)
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

    views::system::render(&auth, db_ready, state.cookie_secure, &host)
}

async fn configs_page(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let auth = match require_admin(&state, &headers).await {
        Ok(value) => value,
        Err(response) => return response,
    };

    let snapshots = config_files()
        .into_iter()
        .map(read_config_spec)
        .collect::<Vec<_>>();

    views::configs::render_index(&auth, &snapshots)
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

    views::configs::render_save(&auth, &report, status)
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
    views::system::render_action(&auth, target, &report)
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

    views::system::render_uninstall(&auth, &plan)
}

async fn credits_page(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let auth = match require_admin(&state, &headers).await {
        Ok(value) => value,
        Err(response) => return response,
    };

    views::credits::render(&auth)
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

    views::protocols::render(&auth, &settings, &profiles, &secret_names)
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

async fn users_page(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let auth = match require_admin(&state, &headers).await {
        Ok(value) => value,
        Err(response) => return response,
    };

    let users = match list_users(&state.pool).await {
        Ok(value) => value,
        Err(err) => {
            return html_error_response_with_back(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Users unavailable",
                format!("Failed to load users: {err}"),
                "/admin",
                "Back to Dashboard",
            );
        }
    };

    views::users::render_index(&auth, &users)
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

    let update_notice = update::load_notice(&state.pool).await?;

    Ok(admin.map(|admin| AuthenticatedAdmin {
        admin,
        csrf_token: csrf_token_for_session_token(&token),
        update_notice,
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
