use clap::{Parser, Subcommand};
use stealthhub_core::{
    mihomo::generate_demo_mihomo_yaml,
    models::{demo_settings, demo_user},
    storage::{
        create_user, ensure_default_protocol_profiles, ensure_default_routing_rule_sets,
        ensure_default_settings, init_db, list_users, open_pool, DbPool, NewUser,
    },
};

#[derive(Parser)]
#[command(name = "stealthhub")]
#[command(about = "StealthHub Panel CLI")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    GenerateMihomo,
    CreateUser {
        #[arg(long, default_value = "sqlite://./stealthhub.local.sqlite?mode=rwc")]
        db: String,
        #[arg(long)]
        username: String,
        #[arg(long)]
        traffic_limit_gb: Option<i64>,
    },
    ListUsers {
        #[arg(long, default_value = "sqlite://./stealthhub.local.sqlite?mode=rwc")]
        db: String,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Command::GenerateMihomo => {
            let yaml = generate_demo_mihomo_yaml(&demo_settings(), &demo_user())?;
            println!("{yaml}");
        }
        Command::CreateUser {
            db,
            username,
            traffic_limit_gb,
        } => {
            let pool = open_initialized_pool(&db).await?;
            let user = create_user(
                &pool,
                NewUser {
                    username,
                    traffic_limit_bytes: traffic_limit_gb
                        .map(|gb| gb.saturating_mul(1024 * 1024 * 1024)),
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

            if users.is_empty() {
                println!("no users");
            } else {
                for user in users {
                    let limit = user
                        .traffic_limit_bytes
                        .map(format_bytes)
                        .unwrap_or_else(|| "unlimited".to_string());
                    let status = if user.enabled { "enabled" } else { "disabled" };
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
