use axum::{
    extract::{Form, Path, State},
    http::{header, HeaderMap, StatusCode},
    response::{Html, IntoResponse, Redirect, Response},
    routing::{get, post},
    Router,
};
use maud::{html, Markup, PreEscaped, DOCTYPE};
use serde::Deserialize;
use sqlx::SqlitePool;
use stealthhub_core::{
    mihomo::generate_demo_mihomo_yaml,
    models::{demo_settings, SubscriptionUser},
    rules::{banking_direct_yaml, direct_local_yaml, proxy_ai_yaml, streaming_yaml},
    storage::{
        create_user, ensure_demo_user, get_user_by_token, init_db, list_users, open_pool, NewUser,
    },
};
use tower_http::trace::TraceLayer;

#[derive(Clone)]
struct AppState {
    pool: SqlitePool,
}

#[derive(Debug, Deserialize)]
struct CreateUserForm {
    username: String,
    traffic_limit_gb: Option<i64>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter("stealthhub_panel=debug,tower_http=debug,info")
        .init();

    let bind = std::env::var("STEALTHHUB_BIND").unwrap_or_else(|_| "127.0.0.1:8080".to_string());
    let db_url = std::env::var("STEALTHHUB_DB")
        .unwrap_or_else(|_| "sqlite://./stealthhub.sqlite?mode=rwc".to_string());

    let pool = open_pool(&db_url).await?;
    init_db(&pool).await?;
    ensure_demo_user(&pool).await?;

    let state = AppState { pool };

    let app = Router::new()
        .route("/", get(index))
        .route("/admin", get(admin_dashboard))
        .route("/admin/users", get(users_page))
        .route("/admin/users/create", post(create_user_action))
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

async fn admin_dashboard() -> impl IntoResponse {
    Html(
        layout(
            "Dashboard",
            html! {
                h1 { "Dashboard" }

                div class="notice" {
                    strong { "v0.1:" }
                    " SQLite users + real subscription tokens. Следующий этап — auth, edit/delete users, systemd и real protocol configs."
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
}

async fn users_page(State(state): State<AppState>) -> impl IntoResponse {
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
            );
        }
    };

    Html(
        layout(
            "Users",
            html! {
                h1 { "Users" }

                div class="notice" {
                    "Пока это базовый users MVP: создание пользователя, токен подписки и UUID. Edit/delete добавим следующим шагом."
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
}

async fn create_user_action(
    State(state): State<AppState>,
    Form(form): Form<CreateUserForm>,
) -> impl IntoResponse {
    let username = form.username.trim().to_string();

    if username.is_empty() {
        return (StatusCode::BAD_REQUEST, "username is empty").into_response();
    }

    let traffic_limit_bytes = form
        .traffic_limit_gb
        .filter(|value| *value > 0)
        .map(|gb| gb * 1024 * 1024 * 1024);

    let input = NewUser {
        username,
        traffic_limit_bytes,
        expires_at: None,
    };

    match create_user(&state.pool, input).await {
        Ok(_) => Redirect::to("/admin/users").into_response(),
        Err(err) => (
            StatusCode::BAD_REQUEST,
            format!("failed to create user: {err}"),
        )
            .into_response(),
    }
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
