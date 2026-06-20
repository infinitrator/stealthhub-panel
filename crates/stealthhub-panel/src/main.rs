use argon2::{
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use axum::{
    extract::{Form, Path, State},
    http::{header, HeaderMap, StatusCode},
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
use stealthhub_core::{
    mihomo::generate_demo_mihomo_yaml,
    models::{demo_settings, SubscriptionUser},
    rules::{banking_direct_yaml, direct_local_yaml, proxy_ai_yaml, streaming_yaml},
    storage::{
        admin_count, create_admin, create_admin_session, create_user, delete_admin_session,
        delete_expired_admin_sessions, delete_user, ensure_demo_user, get_admin_by_id,
        get_admin_by_username, get_user_by_id, get_user_by_token, get_valid_admin_session, init_db,
        list_users, open_pool, reset_user_subscription_token, set_user_enabled,
        touch_admin_session, AdminRecord, NewUser,
    },
};
use tower_http::trace::TraceLayer;

const ADMIN_SESSION_COOKIE: &str = "stealthhub_admin_session";
const ADMIN_SESSION_TTL_DAYS: i64 = 7;
const MIN_ADMIN_PASSWORD_LEN: usize = 12;

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

    let pool = open_pool(&db_url).await?;
    init_db(&pool).await?;
    ensure_demo_user(&pool).await?;
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
        .route("/admin/users/create", post(create_user_action))
        .route("/admin/users/:id/toggle", post(toggle_user_action))
        .route(
            "/admin/users/:id/reset-token",
            post(reset_user_token_action),
        )
        .route("/admin/users/:id/delete", post(delete_user_action))
        .route("/health", get(health))
        .route("/sub/:token/mihomo.yaml", get(mihomo_subscription))
        .route("/rules/:name", get(rule_provider))
        .with_state(state)
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

    let yaml = match generate_demo_mihomo_yaml(&demo_settings(), &subscription_user) {
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
            return login_failed_response();
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
        Ok(false) => login_failed_response(),
        Err(err) => html_error_response_with_back(
            StatusCode::BAD_REQUEST,
            "Login failed",
            format!("Stored password hash is invalid: {err}"),
            "/admin/login",
            "Back to Login",
        ),
    }
}

async fn logout_action(State(state): State<AppState>, headers: HeaderMap) -> Response {
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
    let admin = match require_admin(&state, &headers).await {
        Ok(value) => value,
        Err(response) => return response,
    };

    Html(
        layout(
            "Dashboard",
            html! {
                (admin_bar(&admin))
                h1 { "Dashboard" }

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

async fn users_page(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let admin = match require_admin(&state, &headers).await {
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
                (admin_bar(&admin))
                h1 { "Users" }

                div class="notice" {
                    "Пока это базовый users MVP: создание пользователя, токен подписки, enable/disable, reset token и delete."
                }

                section {
                    h2 { "Create user" }
                    form method="post" action="/admin/users/create" class="form" {
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
                                                    button type="submit" { "Disable" }
                                                }
                                            } @else {
                                                form method="post" action=(format!("/admin/users/{}/toggle", user.id)) class="inline-form" {
                                                    button type="submit" { "Enable" }
                                                }
                                            }

                                            form method="post" action=(format!("/admin/users/{}/reset-token", user.id)) class="inline-form" {
                                                button type="submit" { "Reset token" }
                                            }

                                            form method="post" action=(format!("/admin/users/{}/delete", user.id)) class="inline-form" onsubmit="return confirm('Delete this user?');" {
                                                button type="submit" class="danger" { "Delete" }
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
    if let Err(response) = require_admin(&state, &headers).await {
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
) -> Response {
    if let Err(response) = require_admin(&state, &headers).await {
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

async fn reset_user_token_action(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<i64>,
) -> Response {
    if let Err(response) = require_admin(&state, &headers).await {
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

async fn delete_user_action(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<i64>,
) -> Response {
    if let Err(response) = require_admin(&state, &headers).await {
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

async fn require_admin(state: &AppState, headers: &HeaderMap) -> Result<AdminRecord, Response> {
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
) -> anyhow::Result<Option<AdminRecord>> {
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

    Ok(admin)
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

fn login_failed_response() -> Response {
    html_error_response_with_back(
        StatusCode::UNAUTHORIZED,
        "Login failed",
        "Username or password is incorrect",
        "/admin/login",
        "Back to Login",
    )
}

fn admin_bar(admin: &AdminRecord) -> Markup {
    html! {
        div class="admin-bar" {
            span { "Signed in as " strong { (admin.username) } }
            form method="post" action="/admin/logout" class="inline-form" {
                button type="submit" { "Logout" }
            }
        }
    }
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
                        background: #0b0f14;
                        color: #e5edf5;
                    }
                    body {
                        max-width: 1200px;
                        margin: 0 auto;
                        padding: 32px 18px;
                    }
                    a { color: inherit; }
                    h1 { font-size: 32px; margin-bottom: 8px; }
                    h2 { margin-top: 0; }
                    code {
                        display: inline-block;
                        padding: 6px 8px;
                        border-radius: 8px;
                        background: #101820;
                        color: #b8d7ff;
                        word-break: break-all;
                    }
                    .cards, .grid {
                        display: grid;
                        grid-template-columns: repeat(auto-fit, minmax(260px, 1fr));
                        gap: 14px;
                        margin-top: 24px;
                    }
                    .card, section, .notice {
                        background: #111821;
                        border: 1px solid #223042;
                        border-radius: 14px;
                        padding: 18px;
                        text-decoration: none;
                    }
                    .card:hover, .button:hover, button:hover {
                        border-color: #4c85ff;
                    }
                    .notice {
                        margin: 20px 0;
                        background: #161c24;
                    }
                    .error {
                        border-color: #ef4444;
                    }
                    li { margin: 6px 0; }
                    .button, button {
                        display: inline-block;
                        padding: 10px 14px;
                        border-radius: 10px;
                        border: 1px solid #31507a;
                        background: #172235;
                        color: #e5edf5;
                        text-decoration: none;
                        cursor: pointer;
                        font-weight: 700;
                    }
                    .form {
                        display: grid;
                        gap: 14px;
                        max-width: 520px;
                    }
                    label {
                        display: grid;
                        gap: 6px;
                    }
                    label span {
                        color: #b7c3d2;
                        font-size: 14px;
                    }
                    input {
                        padding: 12px;
                        border-radius: 10px;
                        border: 1px solid #26374c;
                        background: #0c121a;
                        color: #e5edf5;
                        font-size: 16px;
                    }
                    table {
                        width: 100%;
                        border-collapse: collapse;
                        overflow: hidden;
                    }
                    th, td {
                        text-align: left;
                        border-bottom: 1px solid #223042;
                        padding: 12px 8px;
                        vertical-align: top;
                    }
                    th {
                        color: #b7c3d2;
                        font-size: 13px;
                        text-transform: uppercase;
                        letter-spacing: 0.06em;
                    }
                    .badge {
                        display: inline-block;
                        padding: 4px 8px;
                        border-radius: 999px;
                        font-weight: 700;
                        font-size: 12px;
                    }
                    .badge.ok {
                        background: #0f3a2a;
                        color: #9ff0c0;
                    }
                    .badge.off {
                        background: #3a1414;
                        color: #ffb0b0;
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
                        border: 1px solid #223042;
                        border-radius: 10px;
                        background: #101820;
                    }

                    button.danger {
                        border-color: #7f1d1d;
                        background: #3a1414;
                        color: #ffb0b0;
                    }
                    "#))
                }
            }
            body {
                nav style="margin-bottom: 20px;" {
                    a href="/" { "Home" }
                    " · "
                    a href="/admin" { "Dashboard" }
                    " · "
                    a href="/admin/users" { "Users" }
                    " · "
                    a href="/health" { "Health" }
                }
                (body)
            }
        }
    }
}
