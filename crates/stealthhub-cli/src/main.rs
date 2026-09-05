//! Command-line maintenance utilities for local Infiproxy development.
//!
//! The CLI intentionally stays small: it initializes `SQLite` state and performs
//! explicit user maintenance without starting the web control plane.

use chrono::Utc;
use clap::{Parser, Subcommand};
use stealthhub_core::adapters::{core_registry, protocol_registry};
use stealthhub_core::storage::{
    create_user, ensure_default_protocol_profiles, ensure_default_routing_rule_sets,
    ensure_default_settings, init_db, list_users, migrate_available_adapter_states,
    migrate_protocol_adapter_configs, open_pool, DbPool, NewUser,
};

#[derive(Parser)]
#[command(name = "infiproxy")]
#[command(about = "Infiproxy CLI")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    CreateUser {
        #[arg(long, default_value = "sqlite://./infiproxy.local.sqlite?mode=rwc")]
        db: String,
        #[arg(long)]
        username: String,
        #[arg(long)]
        traffic_limit_gb: Option<i64>,
    },
    ListUsers {
        #[arg(long, default_value = "sqlite://./infiproxy.local.sqlite?mode=rwc")]
        db: String,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Command::CreateUser {
            db,
            username,
            traffic_limit_gb,
        } => {
            let pool = open_initialized_pool(&db).await?;
            let traffic_limit_bytes = traffic_limit_gb
                .map(|gib| {
                    anyhow::ensure!(gib > 0, "traffic limit must be positive");
                    gib.checked_mul(1024 * 1024 * 1024)
                        .ok_or_else(|| anyhow::anyhow!("traffic limit is too large"))
                })
                .transpose()?;
            let user = create_user(
                &pool,
                NewUser {
                    username,
                    traffic_limit_bytes,
                    expires_at: None,
                },
            )
            .await?;

            println!("created user: {}", user.username);
            println!("uuid: {}", user.uuid);
            println!("subscription token: {}", user.subscription_token);
            println!("mihomo path: /sub/{}/mihomo.yaml", user.subscription_token);
        }
        Command::ListUsers { db } => {
            let pool = open_initialized_pool(&db).await?;
            let users = list_users(&pool).await?;
            let now = Utc::now();

            if users.is_empty() {
                println!("no users");
            } else {
                for user in users {
                    let limit = user
                        .traffic_limit_bytes
                        .map_or_else(|| "unlimited".to_string(), format_bytes);
                    let access = user.access_state_at(now);
                    let status = if access.allowed() {
                        "active".to_string()
                    } else {
                        [
                            access.disabled.then_some("disabled"),
                            access.expired.then_some("expired"),
                            access.quota_exceeded.then_some("quota-blocked"),
                        ]
                        .into_iter()
                        .flatten()
                        .collect::<Vec<_>>()
                        .join(",")
                    };
                    println!(
                        "{}\t{}\t{}\t/sub/{}/mihomo.yaml",
                        user.id, user.username, status, user.subscription_token
                    );
                    println!("  uuid: {}", user.uuid);
                    println!(
                        "  traffic: {} used / {} limit",
                        format_bytes(user.traffic_used_bytes),
                        limit
                    );
                }
            }
        }
    }

    Ok(())
}

async fn open_initialized_pool(database_url: &str) -> anyhow::Result<DbPool> {
    let pool = open_pool(database_url).await?;
    init_db(&pool).await?;
    ensure_default_settings(&pool).await?;
    ensure_default_protocol_profiles(&pool).await?;
    let protocols = protocol_registry()?;
    let cores = core_registry()?;
    migrate_protocol_adapter_configs(&pool, &protocols).await?;
    migrate_available_adapter_states(&pool, &protocols, &cores).await?;
    ensure_default_routing_rule_sets(&pool).await?;
    Ok(pool)
}

fn format_bytes(bytes: i64) -> String {
    const GIB: f64 = 1024.0 * 1024.0 * 1024.0;
    const MIB: f64 = 1024.0 * 1024.0;

    if bytes.abs() >= 1024 * 1024 * 1024 {
        format!("{:.2} GiB", bytes as f64 / GIB)
    } else if bytes.abs() >= 1024 * 1024 {
        format!("{:.2} MiB", bytes as f64 / MIB)
    } else {
        format!("{bytes} B")
    }
}
