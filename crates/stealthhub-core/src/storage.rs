use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{sqlite::SqlitePoolOptions, FromRow, SqlitePool};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct UserRecord {
    pub id: i64,
    pub username: String,
    pub uuid: String,
    pub subscription_token: String,
    pub enabled: bool,
    pub traffic_limit_bytes: Option<i64>,
    pub traffic_used_bytes: i64,
    pub expires_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct NewUser {
    pub username: String,
    pub traffic_limit_bytes: Option<i64>,
    pub expires_at: Option<DateTime<Utc>>,
}

pub async fn open_pool(database_url: &str) -> Result<SqlitePool> {
    let pool = SqlitePoolOptions::new()
        .max_connections(5)
        .connect(database_url)
        .await?;

    Ok(pool)
}

pub async fn init_db(pool: &SqlitePool) -> Result<()> {
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            uuid TEXT NOT NULL UNIQUE,
            subscription_token TEXT NOT NULL UNIQUE,
            enabled INTEGER NOT NULL DEFAULT 1,
            traffic_limit_bytes INTEGER NULL,
            traffic_used_bytes INTEGER NOT NULL DEFAULT 0,
            expires_at TEXT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
        "#,
    )
    .execute(pool)
    .await?;

    sqlx::query(
        r#"
        CREATE INDEX IF NOT EXISTS idx_users_subscription_token
        ON users(subscription_token);
        "#,
    )
    .execute(pool)
    .await?;

    sqlx::query(
        r#"
        CREATE INDEX IF NOT EXISTS idx_users_enabled
        ON users(enabled);
        "#,
    )
    .execute(pool)
    .await?;

    Ok(())
}

pub async fn ensure_demo_user(pool: &SqlitePool) -> Result<()> {
    let exists: Option<(i64,)> =
        sqlx::query_as("SELECT id FROM users WHERE subscription_token = ?")
            .bind("demo")
            .fetch_optional(pool)
            .await?;

    if exists.is_some() {
        return Ok(());
    }

    let now = Utc::now();

    sqlx::query(
        r#"
        INSERT INTO users (
            username,
            uuid,
            subscription_token,
            enabled,
            traffic_limit_bytes,
            traffic_used_bytes,
            expires_at,
            created_at,
            updated_at
        )
        VALUES (?, ?, ?, 1, NULL, 0, NULL, ?, ?)
        "#,
    )
    .bind("demo")
    .bind("11111111-1111-4111-8111-111111111111")
    .bind("demo")
    .bind(now)
    .bind(now)
    .execute(pool)
    .await?;

    Ok(())
}

pub async fn create_user(pool: &SqlitePool, input: NewUser) -> Result<UserRecord> {
    let now = Utc::now();
    let uuid = Uuid::new_v4().to_string();
    let subscription_token = Uuid::new_v4().simple().to_string();

    sqlx::query(
        r#"
        INSERT INTO users (
            username,
            uuid,
            subscription_token,
            enabled,
            traffic_limit_bytes,
            traffic_used_bytes,
            expires_at,
            created_at,
            updated_at
        )
        VALUES (?, ?, ?, 1, ?, 0, ?, ?, ?)
        "#,
    )
    .bind(input.username.trim())
    .bind(uuid)
    .bind(subscription_token.clone())
    .bind(input.traffic_limit_bytes)
    .bind(input.expires_at)
    .bind(now)
    .bind(now)
    .execute(pool)
    .await?;

    get_user_by_token(pool, &subscription_token).await
}

pub async fn list_users(pool: &SqlitePool) -> Result<Vec<UserRecord>> {
    let users = sqlx::query_as::<_, UserRecord>(
        r#"
        SELECT
            id,
            username,
            uuid,
            subscription_token,
            enabled,
            traffic_limit_bytes,
            traffic_used_bytes,
            expires_at,
            created_at,
            updated_at
        FROM users
        ORDER BY id DESC
        "#,
    )
    .fetch_all(pool)
    .await?;

    Ok(users)
}

pub async fn get_user_by_token(pool: &SqlitePool, token: &str) -> Result<UserRecord> {
    let user = sqlx::query_as::<_, UserRecord>(
        r#"
        SELECT
            id,
            username,
            uuid,
            subscription_token,
            enabled,
            traffic_limit_bytes,
            traffic_used_bytes,
            expires_at,
            created_at,
            updated_at
        FROM users
        WHERE subscription_token = ?
        "#,
    )
    .bind(token)
    .fetch_one(pool)
    .await?;

    Ok(user)
}
