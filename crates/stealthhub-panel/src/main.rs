use axum::{
    extract::Path,
    http::{header, HeaderMap, StatusCode},
    response::{Html, IntoResponse, Response},
    routing::get,
    Router,
};
use maud::{html, Markup, DOCTYPE};
use stealthhub_core::{
    mihomo::generate_demo_mihomo_yaml,
    models::{demo_settings, demo_user},
    rules::{banking_direct_yaml, direct_local_yaml, proxy_ai_yaml, streaming_yaml},
};
use tower_http::trace::TraceLayer;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter("stealthhub_panel=debug,tower_http=debug,info")
        .init();

    let app = Router::new()
        .route("/", get(index))
        .route("/admin", get(admin_dashboard))
        .route("/health", get(health))
        .route("/sub/:token/mihomo.yaml", get(mihomo_subscription))
        .route("/rules/:name", get(rule_provider))
        .layer(TraceLayer::new_for_http());

    let bind = std::env::var("STEALTHHUB_BIND").unwrap_or_else(|_| "127.0.0.1:8080".to_string());
    tracing::info!("StealthHub Panel listening on http://{}", bind);

    let listener = tokio::net::TcpListener::bind(&bind).await?;
    axum::serve(listener, app).await?;

    Ok(())
}

async fn health() -> impl IntoResponse {
    "ok\n"
}

async fn mihomo_subscription(Path(token): Path<String>) -> Response {
    if token != "demo" {
        return (StatusCode::UNAUTHORIZED, "invalid subscription token\n").into_response();
    }

    let yaml = match generate_demo_mihomo_yaml(&demo_settings(), &demo_user()) {
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
    Html(layout("Dashboard", html! {
        h1 { "Dashboard" }

        div class="notice" {
            strong { "MVP-0:" }
            " сейчас это скелет панели. Следующий этап — SQLite, пользователи, авторизация, реальные протоколы и systemd."
        }

        div class="grid" {
            section {
                h2 { "Subscriptions" }
                p { "Primary target: Clash Mi / mihomo.yaml" }
                code { "/sub/demo/mihomo.yaml" }
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
    }).into_string())
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
                    r#"
                    :root {
                        color-scheme: dark;
                        font-family: ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
                        background: #0b0f14;
                        color: #e5edf5;
                    }
                    body {
                        max-width: 1100px;
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
                    .card:hover {
                        border-color: #4c85ff;
                    }
                    .notice {
                        margin: 20px 0;
                        background: #161c24;
                    }
                    li { margin: 6px 0; }
                    "#
                }
            }
            body {
                (body)
            }
        }
    }
}
