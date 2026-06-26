use argon2::{
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use axum::{
    body::Body,
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
use std::collections::HashMap;
use stealthhub_core::{
    mihomo::generate_mihomo_yaml,
    models::{ProtocolProfile, ProxyKind, ProxyRole, SubscriptionUser},
    rules::{banking_direct_yaml, direct_local_yaml, proxy_ai_yaml, streaming_yaml},
    storage::{
        admin_count, create_admin, create_admin_session, create_user, delete_admin_session,
        delete_expired_admin_sessions, delete_user, ensure_default_protocol_profiles,
        ensure_default_settings, ensure_demo_user, get_admin_by_id, get_admin_by_username,
        get_secret, get_user_by_id, get_user_by_token, get_valid_admin_session, init_db,
        list_protocol_profiles_decoded, list_secret_names, list_users, load_panel_settings,
        open_pool, reset_user_subscription_token, set_user_enabled, touch_admin_session,
        AdminRecord, NewUser,
    },
};
use tower_http::trace::TraceLayer;

const ADMIN_SESSION_COOKIE: &str = "stealthhub_admin_session";
const ADMIN_SESSION_TTL_DAYS: i64 = 7;
const MIN_ADMIN_PASSWORD_LEN: usize = 12;
const LOGIN_FAILURE_DELAY_MS: u64 = 500;
const DUMMY_PASSWORD_HASH: &str = "$argon2id$v=19$m=19456,t=2,p=1$gTSHLOLVD71RNAjjkqaKvQ$cCpCPgJOl06K2/RHtedp/MTm/4u+0n4JeNlYF00eQj4";

#[derive(Clone)]
struct AppState {
    pool: SqlitePool,
    cookie_secure: bool,
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

    if !cookie_secure && !bind.starts_with("127.0.0.1:") && !bind.starts_with("localhost:") {
        tracing::warn!(
            "admin session cookie Secure flag is disabled; set STEALTHHUB_COOKIE_SECURE=true behind HTTPS"
        );
    }

    let pool = open_pool(&db_url).await?;
    init_db(&pool).await?;
    ensure_default_settings(&pool).await?;
    ensure_demo_user(&pool).await?;
    ensure_default_protocol_profiles(&pool).await?;
    delete_expired_admin_sessions(&pool).await?;

    let state = AppState {
        pool,
        cookie_secure,
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
        .route("/sub/:token/mihomo.yaml", get(mihomo_subscription))
        .route("/rules/:name", get(rule_provider))
        .with_state(state)
        .layer(middleware::from_fn(security_headers))
        .layer(TraceLayer::new_for_http());

    tracing::info!("StealthHub Panel listening on http://{}", bind);

    let listener = tokio::net::TcpListener::bind(&bind).await?;
    axum::serve(listener, app).await?;

    Ok(())
}

async fn health() -> impl IntoResponse {
    "ok\n"
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

    let yaml = match generate_mihomo_yaml(&settings, &subscription_user, &profiles, &secrets) {
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

async fn rule_provider(Path(name): Path<String>) -> Response {
    let body = match name.as_str() {
        "banking-direct.yaml" => banking_direct_yaml(),
        "direct-local.yaml" => direct_local_yaml(),
        "proxy-ai.yaml" => proxy_ai_yaml(),
        "streaming.yaml" => streaming_yaml(),
        _ => return (StatusCode::NOT_FOUND, "rule not found\n").into_response(),
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
                p { "Fast single-node Rust control panel for Clash Mi / mihomo.yaml." }
                div class="cards" {
                    a class="card" href="/admin" {
                        h2 { "Admin GUI" }
                        p { "Dashboard, users, protocols, system settings." }
                    }
                    a class="card" href="/admin/users" {
                        h2 { "Users" }
                        p { "Создание пользователей и подписок." }
                    }
                    a class="card" href="/sub/demo/mihomo.yaml" {
                        h2 { "Demo mihomo.yaml" }
                        p { "Проверить отдачу подписки для Clash Mi." }
                    }
                    a class="card" href="/health" {
                        h2 { "Health" }
                        p { "Проверка живости панели." }
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

async fn login_action(State(state): State<AppState>, Form(form): Form<LoginForm>) -> Response {
    if let Ok(0) = admin_count(&state.pool).await {
        return Redirect::to("/admin/setup").into_response();
    }

    let admin = match get_admin_by_username(&state.pool, &form.username).await {
        Ok(Some(value)) => value,
        Ok(None) => {
            let _ = verify_password(&form.password, DUMMY_PASSWORD_HASH);
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
        Ok(true) => create_session_redirect(&state, admin.id, "/admin").await,
        Ok(false) => login_failed_response().await,
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

                div class="notice" {
                    strong { "v0.1:" }
                    " SQLite users + protected admin GUI. Следующий этап — real protocol configs, systemd и safe apply."
                }

                div class="grid" {
                    section {
                        h2 { "Users" }
                        p { "Создание пользователей и token-based подписок." }
                        a class="button" href="/admin/users" { "Open Users" }
                    }

                    section {
                        h2 { "Protocols" }
                        p { "Профили, secrets и сборка реального Mihomo YAML из SQLite." }
                        a class="button" href="/admin/protocols" { "Open Protocols" }
                    }

                    section {
                        h2 { "Routing" }
                        ul {
                            li { "BANKING / RU / LOCAL → DIRECT" }
                            li { "AI / GitHub → AUTO-SAFE" }
                            li { "Streaming → SPEED" }
                            li { "Final → MANUAL" }
                        }
                    }

                    section {
                        h2 { "Protocol plan" }
                        ul {
                            li { "VLESS + REALITY + XHTTP" }
                            li { "SS2022 + ShadowTLS v3" }
                            li { "AnyTLS" }
                            li { "Hysteria2 speed fallback" }
                            li { "TUIC speed fallback" }
                        }
                    }

                    section {
                        h2 { "System control roadmap" }
                        ul {
                            li { "systemd status/restart" }
                            li { "journal logs" }
                            li { "firewall ports" }
                            li { "backup/restore" }
                            li { "git pull + build + restart" }
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

                div class="notice" {
                    "Эта страница уже показывает, из каких профилей и secret names будет собираться подписка `mihomo.yaml`. Следующий шаг после нее — формы редактирования и safe apply на сервер."
                }

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
                    h2 { "Panel settings" }
                    dl class="details" {
                        dt { "Panel name" }
                        dd { code { (&settings.panel_name) } }
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
                                    @for profile in profiles {
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
                                                @let missing = missing_secret_names(&profile, &secret_names);
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
                    h2 { "Current public outputs" }
                    ul {
                        li { code { "/sub/{token}/mihomo.yaml" } " now uses DB-backed settings and profiles." }
                        li { code { "/rules/banking-direct.yaml" } ", " code { "/rules/direct-local.yaml" } ", " code { "/rules/proxy-ai.yaml" } ", " code { "/rules/streaming.yaml" } " remain static built-ins for now." }
                    }
                }
            },
        )
        .into_string(),
    )
    .into_response()
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

                div class="notice" {
                    "Пока это базовый users MVP: создание пользователя, токен подписки, enable/disable, reset token и delete."
                }

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
                        " from the panel and invalidates the subscription token. Proxy server config cleanup will be handled by the future safe-apply flow."
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

fn csrf_error_response(auth: &AuthenticatedAdmin, csrf_token: &str) -> Option<Response> {
    if csrf_token == auth.csrf_token {
        return None;
    }

    Some(html_error_response_with_back(
        StatusCode::FORBIDDEN,
        "Request blocked",
        "Security token is missing or invalid. Please reload the page and try again.",
        "/admin/users",
        "Back to Users",
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
                        color-scheme: dark;
                        font-family: ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
                        background: #090d12;
                        color: #e5edf5;
                        --bg: #090d12;
                        --panel: #111821;
                        --panel-soft: #0f151d;
                        --border: #253244;
                        --border-strong: #3a5270;
                        --text: #e5edf5;
                        --muted: #9fb0c3;
                        --accent: #5aa7ff;
                        --ok-bg: #0d3125;
                        --ok-text: #9be7bf;
                        --danger-bg: #351515;
                        --danger-text: #ffb3b3;
                    }
                    * { box-sizing: border-box; }
                    body {
                        max-width: 1200px;
                        margin: 0 auto;
                        padding: 24px 18px 40px;
                        background: var(--bg);
                        color: var(--text);
                    }
                    a {
                        color: inherit;
                        text-underline-offset: 3px;
                    }
                    h1 {
                        font-size: 30px;
                        line-height: 1.15;
                        margin: 0 0 10px;
                    }
                    h2 {
                        margin: 0 0 12px;
                        font-size: 18px;
                    }
                    p { color: var(--muted); }
                    code {
                        display: inline-block;
                        padding: 4px 7px;
                        border-radius: 6px;
                        background: #0c121a;
                        border: 1px solid #1e2a39;
                        color: #b8d7ff;
                        word-break: break-all;
                    }
                    .top-nav {
                        display: flex;
                        flex-wrap: wrap;
                        align-items: center;
                        gap: 8px;
                        margin-bottom: 22px;
                        padding: 10px 12px;
                        border: 1px solid var(--border);
                        border-radius: 8px;
                        background: #0d141d;
                    }
                    .top-nav a {
                        padding: 6px 8px;
                        border-radius: 6px;
                        color: var(--muted);
                        text-decoration: none;
                    }
                    .top-nav a:hover {
                        color: var(--text);
                        background: #172235;
                    }
                    .cards, .grid {
                        display: grid;
                        grid-template-columns: repeat(auto-fit, minmax(260px, 1fr));
                        gap: 12px;
                        margin-top: 18px;
                    }
                    .card, section, .notice {
                        background: var(--panel);
                        border: 1px solid var(--border);
                        border-radius: 8px;
                        padding: 16px;
                        text-decoration: none;
                    }
                    .card:hover, .button:hover, button:hover {
                        border-color: var(--accent);
                    }
                    .notice {
                        margin: 16px 0;
                        background: var(--panel-soft);
                        color: var(--muted);
                    }
                    .error {
                        border-color: #ef4444;
                        color: var(--danger-text);
                    }
                    li { margin: 6px 0; }
                    .button, button {
                        display: inline-block;
                        min-height: 36px;
                        padding: 8px 12px;
                        border-radius: 6px;
                        border: 1px solid var(--border-strong);
                        background: #172235;
                        color: var(--text);
                        text-decoration: none;
                        cursor: pointer;
                        font-weight: 650;
                    }
                    .button.compact {
                        min-height: 32px;
                        padding: 6px 10px;
                        margin: 0 6px 6px 0;
                    }
                    .button.secondary {
                        border-color: var(--border);
                        background: #0d141d;
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
                    input {
                        width: 100%;
                        min-height: 40px;
                        padding: 10px 11px;
                        border-radius: 6px;
                        border: 1px solid var(--border);
                        background: #0c121a;
                        color: var(--text);
                        font-size: 16px;
                    }
                    input:focus {
                        outline: 2px solid rgba(90, 167, 255, 0.35);
                        border-color: var(--accent);
                    }
                    .table-wrap {
                        overflow-x: auto;
                        border: 1px solid var(--border);
                        border-radius: 8px;
                    }
                    table {
                        width: 100%;
                        border-collapse: collapse;
                        min-width: 860px;
                    }
                    th, td {
                        text-align: left;
                        border-bottom: 1px solid var(--border);
                        padding: 11px 10px;
                        vertical-align: top;
                    }
                    tbody tr:hover {
                        background: rgba(90, 167, 255, 0.04);
                    }
                    th {
                        color: var(--muted);
                        font-size: 13px;
                        text-transform: uppercase;
                        letter-spacing: 0.04em;
                        background: #0f151d;
                    }
                    .badge {
                        display: inline-block;
                        padding: 4px 8px;
                        border-radius: 999px;
                        font-weight: 700;
                        font-size: 12px;
                    }
                    .badge.ok {
                        background: var(--ok-bg);
                        color: var(--ok-text);
                    }
                    .badge.off {
                        background: var(--danger-bg);
                        color: var(--danger-text);
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
                        margin-bottom: 20px;
                        padding: 12px 14px;
                        border: 1px solid var(--border);
                        border-radius: 8px;
                        background: #101820;
                    }
                    .status-strip {
                        display: grid;
                        grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
                        gap: 10px;
                        margin: 18px 0;
                    }
                    .metric {
                        padding: 12px;
                        border: 1px solid var(--border);
                        border-radius: 8px;
                        background: #0d141d;
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
                        margin-top: 4px;
                    }
                    .actions {
                        display: flex;
                        flex-wrap: wrap;
                        align-items: center;
                        gap: 8px;
                        margin-top: 16px;
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
                        border-color: #7f1d1d;
                    }

                    .button.danger, button.danger {
                        border-color: #7f1d1d;
                        background: var(--danger-bg);
                        color: var(--danger-text);
                    }
                    @media (max-width: 640px) {
                        body { padding: 16px 12px 32px; }
                        h1 { font-size: 26px; }
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
                nav class="top-nav" {
                    a href="/" { "Home" }
                    a href="/admin" { "Dashboard" }
                    a href="/admin/users" { "Users" }
                    a href="/admin/protocols" { "Protocols" }
                    a href="/health" { "Health" }
                }
                (body)
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
}
