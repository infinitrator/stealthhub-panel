use anyhow::{bail, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{
    sqlite::{SqliteConnectOptions, SqlitePoolOptions, SqliteRow},
    Row, SqlitePool,
};
use std::{str::FromStr, time::Duration as StdDuration};
use uuid::Uuid;

use crate::{
    models::{PanelSettings, ProtocolConfig, ProtocolProfile, ProxyKind, ProxyRole},
    rules::{
        default_routing_rule_set, default_routing_rule_sets, is_valid_routing_target,
        validate_classical_rule_payload, RoutingRuleSet,
    },
};

pub type DbPool = SqlitePool;

#[derive(Debug, Clone, Serialize, Deserialize)]
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminRecord {
    pub id: i64,
    pub username: String,
    pub password_hash: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminSessionRecord {
    pub id: i64,
    pub admin_id: i64,
    pub token_hash: String,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    pub last_seen_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SettingRecord {
    pub key: String,
    pub value: String,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretRecord {
    pub name: String,
    pub value: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtocolProfileRecord {
    pub id: i64,
    pub name: String,
    pub kind: String,
    pub role: String,
    pub enabled: bool,
    pub server: String,
    pub port: i64,
    pub config_json: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct NewProtocolProfile {
    pub name: String,
    pub kind: ProxyKind,
    pub role: ProxyRole,
    pub enabled: bool,
    pub server: String,
    pub port: u16,
    pub config: ProtocolConfig,
}

#[derive(Debug, Clone)]
pub struct UpdateProtocolProfile {
    pub name: String,
    pub enabled: bool,
    pub server: String,
    pub port: u16,
    pub config: ProtocolConfig,
}

#[derive(Debug, Clone)]
pub struct UpdateRoutingRuleSet {
    pub slug: String,
    pub enabled: bool,
    pub target: String,
    pub payload: String,
}

impl<'r> sqlx::FromRow<'r, SqliteRow> for UserRecord {
    fn from_row(row: &'r SqliteRow) -> std::result::Result<Self, sqlx::Error> {
        Ok(Self {
            id: row.try_get("id")?,
            username: row.try_get("username")?,
            uuid: row.try_get("uuid")?,
            subscription_token: row.try_get("subscription_token")?,
            enabled: row.try_get("enabled")?,
            traffic_limit_bytes: row.try_get("traffic_limit_bytes")?,
            traffic_used_bytes: row.try_get("traffic_used_bytes")?,
            expires_at: row.try_get("expires_at")?,
            created_at: row.try_get("created_at")?,
            updated_at: row.try_get("updated_at")?,
        })
    }
}

impl<'r> sqlx::FromRow<'r, SqliteRow> for AdminRecord {
    fn from_row(row: &'r SqliteRow) -> std::result::Result<Self, sqlx::Error> {
        Ok(Self {
            id: row.try_get("id")?,
            username: row.try_get("username")?,
            password_hash: row.try_get("password_hash")?,
            created_at: row.try_get("created_at")?,
            updated_at: row.try_get("updated_at")?,
        })
    }
}

impl<'r> sqlx::FromRow<'r, SqliteRow> for AdminSessionRecord {
    fn from_row(row: &'r SqliteRow) -> std::result::Result<Self, sqlx::Error> {
        Ok(Self {
            id: row.try_get("id")?,
            admin_id: row.try_get("admin_id")?,
            token_hash: row.try_get("token_hash")?,
            expires_at: row.try_get("expires_at")?,
            created_at: row.try_get("created_at")?,
            last_seen_at: row.try_get("last_seen_at")?,
        })
    }
}

impl<'r> sqlx::FromRow<'r, SqliteRow> for SettingRecord {
    fn from_row(row: &'r SqliteRow) -> std::result::Result<Self, sqlx::Error> {
        Ok(Self {
            key: row.try_get("key")?,
            value: row.try_get("value")?,
            updated_at: row.try_get("updated_at")?,
        })
    }
}

impl<'r> sqlx::FromRow<'r, SqliteRow> for SecretRecord {
    fn from_row(row: &'r SqliteRow) -> std::result::Result<Self, sqlx::Error> {
        Ok(Self {
            name: row.try_get("name")?,
            value: row.try_get("value")?,
            created_at: row.try_get("created_at")?,
            updated_at: row.try_get("updated_at")?,
        })
    }
}

impl<'r> sqlx::FromRow<'r, SqliteRow> for ProtocolProfileRecord {
    fn from_row(row: &'r SqliteRow) -> std::result::Result<Self, sqlx::Error> {
        Ok(Self {
            id: row.try_get("id")?,
            name: row.try_get("name")?,
            kind: row.try_get("kind")?,
            role: row.try_get("role")?,
            enabled: row.try_get("enabled")?,
            server: row.try_get("server")?,
            port: row.try_get("port")?,
            config_json: row.try_get("config_json")?,
            created_at: row.try_get("created_at")?,
            updated_at: row.try_get("updated_at")?,
        })
    }
}

pub async fn open_pool(database_url: &str) -> Result<SqlitePool> {
    let options = SqliteConnectOptions::from_str(database_url)?
        .foreign_keys(true)
        .busy_timeout(StdDuration::from_secs(10));

    let pool = SqlitePoolOptions::new()
        .max_connections(5)
        .connect_with(options)
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

    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS admins (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
        "#,
    )
    .execute(pool)
    .await?;

    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS admin_sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            admin_id INTEGER NOT NULL,
            token_hash TEXT NOT NULL UNIQUE,
            expires_at TEXT NOT NULL,
            created_at TEXT NOT NULL,
            last_seen_at TEXT NOT NULL,
            FOREIGN KEY(admin_id) REFERENCES admins(id) ON DELETE CASCADE
        );
        "#,
    )
    .execute(pool)
    .await?;

    sqlx::query(
        r#"
        CREATE INDEX IF NOT EXISTS idx_admin_sessions_token_hash
        ON admin_sessions(token_hash);
        "#,
    )
    .execute(pool)
    .await?;

    sqlx::query(
        r#"
        CREATE INDEX IF NOT EXISTS idx_admin_sessions_expires_at
        ON admin_sessions(expires_at);
        "#,
    )
    .execute(pool)
    .await?;

    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
        "#,
    )
    .execute(pool)
    .await?;

    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS secret_values (
            name TEXT PRIMARY KEY,
            value TEXT NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
        "#,
    )
    .execute(pool)
    .await?;

    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS protocol_profiles (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE,
            kind TEXT NOT NULL,
            role TEXT NOT NULL,
            enabled INTEGER NOT NULL DEFAULT 1,
            server TEXT NOT NULL,
            port INTEGER NOT NULL CHECK(port > 0 AND port <= 65535),
            config_json TEXT NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
        "#,
    )
    .execute(pool)
    .await?;

    sqlx::query(
        r#"
        CREATE INDEX IF NOT EXISTS idx_protocol_profiles_role
        ON protocol_profiles(role);
        "#,
    )
    .execute(pool)
    .await?;

    sqlx::query(
        r#"
        CREATE INDEX IF NOT EXISTS idx_protocol_profiles_enabled
        ON protocol_profiles(enabled);
        "#,
    )
    .execute(pool)
    .await?;

    Ok(())
}

pub async fn ensure_default_settings(pool: &SqlitePool) -> Result<()> {
    upsert_setting_if_missing(pool, "panel_name", "Infiproxy").await?;
    upsert_setting_if_missing(pool, "subscription_domain", "sub.infiproxy.local").await?;
    upsert_setting_if_missing(pool, "node_domain", "node.infiproxy.local").await?;

    Ok(())
}

pub async fn ensure_default_routing_rule_sets(pool: &SqlitePool) -> Result<()> {
    for rule_set in default_routing_rule_sets() {
        upsert_setting_if_missing(
            pool,
            &routing_setting_key(&rule_set.slug, "enabled"),
            bool_setting(rule_set.enabled),
        )
        .await?;
        upsert_setting_if_missing(
            pool,
            &routing_setting_key(&rule_set.slug, "target"),
            &rule_set.target,
        )
        .await?;
        upsert_setting_if_missing(
            pool,
            &routing_setting_key(&rule_set.slug, "payload"),
            &rule_set.payload,
        )
        .await?;
    }

    Ok(())
}

pub async fn ensure_demo_user(pool: &SqlitePool) -> Result<()> {
    let exists: Option<(i64,)> = sqlx::query_as(
        r#"
        SELECT id
        FROM users
        WHERE username = ? OR uuid = ?
        LIMIT 1
        "#,
    )
    .bind("demo")
    .bind("11111111-1111-4111-8111-111111111111")
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

pub async fn ensure_default_protocol_profiles(pool: &SqlitePool) -> Result<()> {
    let (count,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM protocol_profiles")
        .fetch_one(pool)
        .await?;

    if count > 0 {
        return Ok(());
    }

    let defaults = vec![
        NewProtocolProfile {
            name: "VLESS-XHTTP-SAFE".to_string(),
            kind: ProxyKind::VlessRealityXhttp,
            role: ProxyRole::AutoSafe,
            enabled: true,
            server: "node.infiproxy.local".to_string(),
            port: 8443,
            config: ProtocolConfig::VlessRealityXhttp {
                uuid_source: crate::models::UserUuidSource::SubscriptionUser,
                server_name: "www.microsoft.com".to_string(),
                path: "/api/v1".to_string(),
                public_key_secret: "xray.reality.public_key".to_string(),
                short_id_secret: "xray.reality.short_id".to_string(),
            },
        },
        NewProtocolProfile {
            name: "SS2022-SHADOWTLS-FALLBACK".to_string(),
            kind: ProxyKind::Shadowsocks2022ShadowTls,
            role: ProxyRole::Compatibility,
            enabled: true,
            server: "node.infiproxy.local".to_string(),
            port: 9443,
            config: ProtocolConfig::Shadowsocks2022ShadowTls {
                server_name: "www.apple.com".to_string(),
                password_secret: "shadowsocks.2022.password".to_string(),
                shadow_tls_password_secret: "shadowtls.password".to_string(),
            },
        },
        NewProtocolProfile {
            name: "ANYTLS-EXPERIMENTAL".to_string(),
            kind: ProxyKind::AnyTls,
            role: ProxyRole::Compatibility,
            enabled: false,
            server: "node.infiproxy.local".to_string(),
            port: 10443,
            config: ProtocolConfig::AnyTls {
                password_secret: "anytls.password".to_string(),
                sni: "www.apple.com".to_string(),
            },
        },
        NewProtocolProfile {
            name: "HYSTERIA2-SPEED".to_string(),
            kind: ProxyKind::Hysteria2,
            role: ProxyRole::Speed,
            enabled: false,
            server: "node.infiproxy.local".to_string(),
            port: 443,
            config: ProtocolConfig::Hysteria2 {
                password_secret: "hysteria2.password".to_string(),
                sni: "www.bing.com".to_string(),
                obfs_password_secret: Some("hysteria2.obfs_password".to_string()),
            },
        },
        NewProtocolProfile {
            name: "TUIC-SPEED".to_string(),
            kind: ProxyKind::Tuic,
            role: ProxyRole::Speed,
            enabled: false,
            server: "node.infiproxy.local".to_string(),
            port: 11443,
            config: ProtocolConfig::Tuic {
                uuid_source: crate::models::UserUuidSource::SubscriptionUser,
                password_secret: "tuic.password".to_string(),
                sni: "www.github.com".to_string(),
            },
        },
    ];

    for profile in defaults {
        create_protocol_profile(pool, profile).await?;
    }

    Ok(())
}

pub async fn admin_count(pool: &SqlitePool) -> Result<i64> {
    let (count,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM admins")
        .fetch_one(pool)
        .await?;

    Ok(count)
}

pub async fn create_admin(
    pool: &SqlitePool,
    username: &str,
    password_hash: &str,
) -> Result<AdminRecord> {
    let now = Utc::now();
    let username = username.trim();

    sqlx::query(
        r#"
        INSERT INTO admins (
            username,
            password_hash,
            created_at,
            updated_at
        )
        VALUES (?, ?, ?, ?)
        "#,
    )
    .bind(username)
    .bind(password_hash)
    .bind(now)
    .bind(now)
    .execute(pool)
    .await?;

    get_admin_by_username(pool, username)
        .await?
        .ok_or_else(|| anyhow::anyhow!("admin was not created"))
}

pub async fn get_admin_by_username(
    pool: &SqlitePool,
    username: &str,
) -> Result<Option<AdminRecord>> {
    let admin = sqlx::query_as::<_, AdminRecord>(
        r#"
        SELECT
            id,
            username,
            password_hash,
            created_at,
            updated_at
        FROM admins
        WHERE username = ?
        "#,
    )
    .bind(username.trim())
    .fetch_optional(pool)
    .await?;

    Ok(admin)
}

pub async fn get_admin_by_id(pool: &SqlitePool, id: i64) -> Result<Option<AdminRecord>> {
    let admin = sqlx::query_as::<_, AdminRecord>(
        r#"
        SELECT
            id,
            username,
            password_hash,
            created_at,
            updated_at
        FROM admins
        WHERE id = ?
        "#,
    )
    .bind(id)
    .fetch_optional(pool)
    .await?;

    Ok(admin)
}

pub async fn create_admin_session(
    pool: &SqlitePool,
    admin_id: i64,
    token_hash: &str,
    expires_at: DateTime<Utc>,
) -> Result<()> {
    let now = Utc::now();

    sqlx::query(
        r#"
        INSERT INTO admin_sessions (
            admin_id,
            token_hash,
            expires_at,
            created_at,
            last_seen_at
        )
        VALUES (?, ?, ?, ?, ?)
        "#,
    )
    .bind(admin_id)
    .bind(token_hash)
    .bind(expires_at)
    .bind(now)
    .bind(now)
    .execute(pool)
    .await?;

    Ok(())
}

pub async fn get_valid_admin_session(
    pool: &SqlitePool,
    token_hash: &str,
) -> Result<Option<AdminSessionRecord>> {
    let now = Utc::now();
    let session = sqlx::query_as::<_, AdminSessionRecord>(
        r#"
        SELECT
            id,
            admin_id,
            token_hash,
            expires_at,
            created_at,
            last_seen_at
        FROM admin_sessions
        WHERE token_hash = ? AND expires_at > ?
        "#,
    )
    .bind(token_hash)
    .bind(now)
    .fetch_optional(pool)
    .await?;

    Ok(session)
}

pub async fn touch_admin_session(pool: &SqlitePool, token_hash: &str) -> Result<()> {
    let now = Utc::now();

    sqlx::query(
        r#"
        UPDATE admin_sessions
        SET last_seen_at = ?
        WHERE token_hash = ?
        "#,
    )
    .bind(now)
    .bind(token_hash)
    .execute(pool)
    .await?;

    Ok(())
}

pub async fn delete_admin_session(pool: &SqlitePool, token_hash: &str) -> Result<()> {
    sqlx::query(
        r#"
        DELETE FROM admin_sessions
        WHERE token_hash = ?
        "#,
    )
    .bind(token_hash)
    .execute(pool)
    .await?;

    Ok(())
}

pub async fn delete_expired_admin_sessions(pool: &SqlitePool) -> Result<()> {
    let now = Utc::now();

    sqlx::query(
        r#"
        DELETE FROM admin_sessions
        WHERE expires_at <= ?
        "#,
    )
    .bind(now)
    .execute(pool)
    .await?;

    Ok(())
}

pub async fn upsert_setting(pool: &SqlitePool, key: &str, value: &str) -> Result<()> {
    let now = Utc::now();

    sqlx::query(
        r#"
        INSERT INTO settings (key, value, updated_at)
        VALUES (?, ?, ?)
        ON CONFLICT(key) DO UPDATE SET
            value = excluded.value,
            updated_at = excluded.updated_at
        "#,
    )
    .bind(key.trim())
    .bind(value)
    .bind(now)
    .execute(pool)
    .await?;

    Ok(())
}

async fn upsert_setting_if_missing(pool: &SqlitePool, key: &str, value: &str) -> Result<()> {
    let now = Utc::now();

    sqlx::query(
        r#"
        INSERT INTO settings (key, value, updated_at)
        VALUES (?, ?, ?)
        ON CONFLICT(key) DO NOTHING
        "#,
    )
    .bind(key.trim())
    .bind(value)
    .bind(now)
    .execute(pool)
    .await?;

    Ok(())
}

pub async fn get_setting(pool: &SqlitePool, key: &str) -> Result<Option<SettingRecord>> {
    let setting = sqlx::query_as::<_, SettingRecord>(
        r#"
        SELECT key, value, updated_at
        FROM settings
        WHERE key = ?
        "#,
    )
    .bind(key.trim())
    .fetch_optional(pool)
    .await?;

    Ok(setting)
}

pub async fn list_settings(pool: &SqlitePool) -> Result<Vec<SettingRecord>> {
    let settings = sqlx::query_as::<_, SettingRecord>(
        r#"
        SELECT key, value, updated_at
        FROM settings
        ORDER BY key ASC
        "#,
    )
    .fetch_all(pool)
    .await?;

    Ok(settings)
}

pub async fn upsert_secret(pool: &SqlitePool, name: &str, value: &str) -> Result<()> {
    let now = Utc::now();

    sqlx::query(
        r#"
        INSERT INTO secret_values (name, value, created_at, updated_at)
        VALUES (?, ?, ?, ?)
        ON CONFLICT(name) DO UPDATE SET
            value = excluded.value,
            updated_at = excluded.updated_at
        "#,
    )
    .bind(name.trim())
    .bind(value)
    .bind(now)
    .bind(now)
    .execute(pool)
    .await?;

    Ok(())
}

pub async fn get_secret(pool: &SqlitePool, name: &str) -> Result<Option<SecretRecord>> {
    let secret = sqlx::query_as::<_, SecretRecord>(
        r#"
        SELECT name, value, created_at, updated_at
        FROM secret_values
        WHERE name = ?
        "#,
    )
    .bind(name.trim())
    .fetch_optional(pool)
    .await?;

    Ok(secret)
}

pub async fn list_secret_names(pool: &SqlitePool) -> Result<Vec<String>> {
    let rows = sqlx::query_as::<_, (String,)>(
        r#"
        SELECT name
        FROM secret_values
        ORDER BY name ASC
        "#,
    )
    .fetch_all(pool)
    .await?;

    Ok(rows.into_iter().map(|(name,)| name).collect())
}

pub async fn create_protocol_profile(
    pool: &SqlitePool,
    input: NewProtocolProfile,
) -> Result<ProtocolProfileRecord> {
    let now = Utc::now();
    let kind = storage_string(&input.kind)?;
    let role = storage_string(&input.role)?;
    let config_json = serde_json::to_string(&input.config)?;

    sqlx::query(
        r#"
        INSERT INTO protocol_profiles (
            name,
            kind,
            role,
            enabled,
            server,
            port,
            config_json,
            created_at,
            updated_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        "#,
    )
    .bind(input.name.trim())
    .bind(kind)
    .bind(role)
    .bind(input.enabled)
    .bind(input.server.trim())
    .bind(i64::from(input.port))
    .bind(config_json)
    .bind(now)
    .bind(now)
    .execute(pool)
    .await?;

    get_protocol_profile_by_name(pool, &input.name)
        .await?
        .ok_or_else(|| anyhow::anyhow!("protocol profile was not created"))
}

pub async fn get_protocol_profile_by_name(
    pool: &SqlitePool,
    name: &str,
) -> Result<Option<ProtocolProfileRecord>> {
    let profile = sqlx::query_as::<_, ProtocolProfileRecord>(
        r#"
        SELECT
            id,
            name,
            kind,
            role,
            enabled,
            server,
            port,
            config_json,
            created_at,
            updated_at
        FROM protocol_profiles
        WHERE name = ?
        "#,
    )
    .bind(name.trim())
    .fetch_optional(pool)
    .await?;

    Ok(profile)
}

pub async fn list_protocol_profiles(pool: &SqlitePool) -> Result<Vec<ProtocolProfileRecord>> {
    let profiles = sqlx::query_as::<_, ProtocolProfileRecord>(
        r#"
        SELECT
            id,
            name,
            kind,
            role,
            enabled,
            server,
            port,
            config_json,
            created_at,
            updated_at
        FROM protocol_profiles
        ORDER BY role ASC, name ASC
        "#,
    )
    .fetch_all(pool)
    .await?;

    Ok(profiles)
}

pub fn decode_protocol_profile(record: ProtocolProfileRecord) -> Result<ProtocolProfile> {
    let kind: ProxyKind = serde_json::from_value(serde_json::Value::String(record.kind))?;
    let role: ProxyRole = serde_json::from_value(serde_json::Value::String(record.role))?;
    let config: ProtocolConfig = serde_json::from_str(&record.config_json)?;
    let port = u16::try_from(record.port).map_err(|_| anyhow::anyhow!("invalid protocol port"))?;

    Ok(ProtocolProfile {
        name: record.name,
        kind,
        role,
        server: record.server,
        port,
        enabled: record.enabled,
        config,
    })
}

pub async fn list_protocol_profiles_decoded(pool: &SqlitePool) -> Result<Vec<ProtocolProfile>> {
    list_protocol_profiles(pool)
        .await?
        .into_iter()
        .map(decode_protocol_profile)
        .collect()
}

pub async fn update_protocol_profile(
    pool: &SqlitePool,
    input: UpdateProtocolProfile,
) -> Result<ProtocolProfileRecord> {
    let existing = get_protocol_profile_by_name(pool, &input.name)
        .await?
        .ok_or_else(|| anyhow::anyhow!("protocol profile not found"))?;
    let now = Utc::now();
    let config_json = serde_json::to_string(&input.config)?;

    sqlx::query(
        r#"
        UPDATE protocol_profiles
        SET enabled = ?, server = ?, port = ?, config_json = ?, updated_at = ?
        WHERE name = ?
        "#,
    )
    .bind(input.enabled)
    .bind(input.server.trim())
    .bind(i64::from(input.port))
    .bind(config_json)
    .bind(now)
    .bind(existing.name.as_str())
    .execute(pool)
    .await?;

    get_protocol_profile_by_name(pool, &existing.name)
        .await?
        .ok_or_else(|| anyhow::anyhow!("protocol profile was not updated"))
}

pub async fn load_routing_rule_sets(pool: &SqlitePool) -> Result<Vec<RoutingRuleSet>> {
    let mut result = Vec::new();

    for mut rule_set in default_routing_rule_sets() {
        if let Some(enabled) =
            get_setting(pool, &routing_setting_key(&rule_set.slug, "enabled")).await?
        {
            rule_set.enabled = parse_bool_setting(&enabled.value);
        }
        if let Some(target) =
            get_setting(pool, &routing_setting_key(&rule_set.slug, "target")).await?
        {
            rule_set.target = target.value;
        }
        if let Some(payload) =
            get_setting(pool, &routing_setting_key(&rule_set.slug, "payload")).await?
        {
            rule_set.payload = payload.value;
        }

        result.push(rule_set);
    }

    Ok(result)
}

pub async fn update_routing_rule_set(pool: &SqlitePool, input: UpdateRoutingRuleSet) -> Result<()> {
    let slug = input.slug.trim();
    if default_routing_rule_set(slug).is_none() {
        return Err(anyhow::anyhow!("unknown rule set"));
    }

    let target = input.target.trim();
    if !is_valid_routing_target(target) {
        return Err(anyhow::anyhow!("unsupported routing target"));
    }

    let rules = validate_classical_rule_payload(&input.payload)?;
    let payload = rules.join("\n");

    upsert_setting(
        pool,
        &routing_setting_key(slug, "enabled"),
        bool_setting(input.enabled),
    )
    .await?;
    upsert_setting(pool, &routing_setting_key(slug, "target"), target).await?;
    upsert_setting(pool, &routing_setting_key(slug, "payload"), &payload).await?;

    Ok(())
}

pub async fn load_panel_settings(pool: &SqlitePool) -> Result<PanelSettings> {
    let mut settings = PanelSettings::default();

    if let Some(value) = get_setting(pool, "panel_name").await? {
        settings.panel_name = value.value;
    }

    if let Some(value) = get_setting(pool, "subscription_domain").await? {
        settings.subscription_domain = value.value;
    }

    if let Some(value) = get_setting(pool, "node_domain").await? {
        settings.node_domain = value.value;
    }

    Ok(settings)
}

fn routing_setting_key(slug: &str, field: &str) -> String {
    format!("routing.ruleset.{}.{}", slug.trim(), field)
}

fn bool_setting(value: bool) -> &'static str {
    if value {
        "true"
    } else {
        "false"
    }
}

fn parse_bool_setting(value: &str) -> bool {
    matches!(value.trim(), "1" | "true" | "yes" | "on")
}

fn storage_string<T>(value: &T) -> Result<String>
where
    T: Serialize,
{
    let value = serde_json::to_value(value)?;
    value
        .as_str()
        .map(str::to_string)
        .ok_or_else(|| anyhow::anyhow!("expected enum to serialize as string"))
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
pub async fn get_user_by_id(pool: &SqlitePool, id: i64) -> Result<UserRecord> {
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
        WHERE id = ?
        "#,
    )
    .bind(id)
    .fetch_one(pool)
    .await?;

    Ok(user)
}

pub async fn set_user_enabled(pool: &SqlitePool, id: i64, enabled: bool) -> Result<()> {
    let now = Utc::now();

    let result = sqlx::query(
        r#"
        UPDATE users
        SET enabled = ?, updated_at = ?
        WHERE id = ?
        "#,
    )
    .bind(enabled)
    .bind(now)
    .bind(id)
    .execute(pool)
    .await?;

    if result.rows_affected() == 0 {
        bail!("user not found");
    }

    Ok(())
}

pub async fn reset_user_subscription_token(pool: &SqlitePool, id: i64) -> Result<String> {
    let now = Utc::now();
    let new_token = Uuid::new_v4().simple().to_string();

    let result = sqlx::query(
        r#"
        UPDATE users
        SET subscription_token = ?, updated_at = ?
        WHERE id = ?
        "#,
    )
    .bind(&new_token)
    .bind(now)
    .bind(id)
    .execute(pool)
    .await?;

    if result.rows_affected() == 0 {
        bail!("user not found");
    }

    Ok(new_token)
}

pub async fn delete_user(pool: &SqlitePool, id: i64) -> Result<()> {
    let result = sqlx::query(
        r#"
        DELETE FROM users
        WHERE id = ?
        "#,
    )
    .bind(id)
    .execute(pool)
    .await?;

    if result.rows_affected() == 0 {
        bail!("user not found");
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::{Path, PathBuf};

    async fn test_pool() -> Result<(SqlitePool, PathBuf)> {
        let path =
            std::env::temp_dir().join(format!("infiproxy-test-{}.sqlite", Uuid::new_v4().simple()));
        let database_url = format!("sqlite://{}?mode=rwc", path.display());
        let pool = open_pool(&database_url).await?;

        init_db(&pool).await?;

        Ok((pool, path))
    }

    async fn close_and_remove(pool: SqlitePool, path: &Path) {
        pool.close().await;

        let _ = std::fs::remove_file(path);
        let _ = std::fs::remove_file(format!("{}-shm", path.display()));
        let _ = std::fs::remove_file(format!("{}-wal", path.display()));
    }

    #[tokio::test]
    async fn demo_user_is_idempotent_after_token_reset() -> Result<()> {
        let (pool, path) = test_pool().await?;

        ensure_demo_user(&pool).await?;
        let demo = get_user_by_token(&pool, "demo").await?;

        let new_token = reset_user_subscription_token(&pool, demo.id).await?;
        ensure_demo_user(&pool).await?;

        assert!(get_user_by_token(&pool, "demo").await.is_err());

        let users = list_users(&pool).await?;
        let demo_users: Vec<_> = users
            .iter()
            .filter(|user| {
                user.username == "demo" || user.uuid == "11111111-1111-4111-8111-111111111111"
            })
            .collect();

        assert_eq!(demo_users.len(), 1);
        assert_eq!(demo_users[0].subscription_token.as_str(), new_token);

        close_and_remove(pool, &path).await;

        Ok(())
    }

    #[tokio::test]
    async fn demo_user_is_recreated_after_delete() -> Result<()> {
        let (pool, path) = test_pool().await?;

        ensure_demo_user(&pool).await?;
        let demo = get_user_by_token(&pool, "demo").await?;

        delete_user(&pool, demo.id).await?;
        assert!(get_user_by_token(&pool, "demo").await.is_err());

        ensure_demo_user(&pool).await?;
        let recreated = get_user_by_token(&pool, "demo").await?;

        assert_eq!(recreated.username, "demo");
        assert_eq!(recreated.uuid, "11111111-1111-4111-8111-111111111111");
        assert!(recreated.enabled);

        close_and_remove(pool, &path).await;

        Ok(())
    }

    #[tokio::test]
    async fn user_mutations_error_when_user_is_missing() -> Result<()> {
        let (pool, path) = test_pool().await?;

        let err = set_user_enabled(&pool, 404, false).await.unwrap_err();
        assert!(err.to_string().contains("user not found"));

        let err = reset_user_subscription_token(&pool, 404).await.unwrap_err();
        assert!(err.to_string().contains("user not found"));

        let err = delete_user(&pool, 404).await.unwrap_err();
        assert!(err.to_string().contains("user not found"));

        close_and_remove(pool, &path).await;

        Ok(())
    }

    #[tokio::test]
    async fn admin_sessions_round_trip_and_delete() -> Result<()> {
        let (pool, path) = test_pool().await?;

        assert_eq!(admin_count(&pool).await?, 0);

        let admin = create_admin(&pool, "admin", "argon2-hash-placeholder").await?;
        assert_eq!(admin.username, "admin");
        assert_eq!(admin_count(&pool).await?, 1);

        let token_hash = "session-token-hash";
        let expires_at = Utc::now() + chrono::Duration::days(1);

        create_admin_session(&pool, admin.id, token_hash, expires_at).await?;
        let session = get_valid_admin_session(&pool, token_hash).await?;
        assert!(session.is_some());

        touch_admin_session(&pool, token_hash).await?;
        delete_admin_session(&pool, token_hash).await?;

        let session = get_valid_admin_session(&pool, token_hash).await?;
        assert!(session.is_none());

        close_and_remove(pool, &path).await;

        Ok(())
    }

    #[tokio::test]
    async fn admin_sessions_are_removed_with_admin() -> Result<()> {
        let (pool, path) = test_pool().await?;

        let admin = create_admin(&pool, "admin", "argon2-hash-placeholder").await?;
        create_admin_session(
            &pool,
            admin.id,
            "session-token-hash",
            Utc::now() + chrono::Duration::days(1),
        )
        .await?;

        sqlx::query("DELETE FROM admins WHERE id = ?")
            .bind(admin.id)
            .execute(&pool)
            .await?;

        let (session_count,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM admin_sessions")
            .fetch_one(&pool)
            .await?;

        assert_eq!(session_count, 0);

        close_and_remove(pool, &path).await;

        Ok(())
    }

    #[tokio::test]
    async fn settings_and_secrets_round_trip() -> Result<()> {
        let (pool, path) = test_pool().await?;

        upsert_setting(&pool, "subscription_domain", "atlas.example.test").await?;
        upsert_setting(&pool, "subscription_domain", "edge.example.test").await?;

        let setting = get_setting(&pool, "subscription_domain")
            .await?
            .expect("setting should exist");
        assert_eq!(setting.value, "edge.example.test");

        let settings = list_settings(&pool).await?;
        assert_eq!(settings.len(), 1);

        upsert_secret(&pool, "xray.reality.public_key", "public-key").await?;
        upsert_secret(&pool, "xray.reality.short_id", "short-id").await?;

        let secret = get_secret(&pool, "xray.reality.public_key")
            .await?
            .expect("secret should exist");
        assert_eq!(secret.value, "public-key");

        let secret_names = list_secret_names(&pool).await?;
        assert_eq!(
            secret_names,
            vec![
                "xray.reality.public_key".to_string(),
                "xray.reality.short_id".to_string()
            ]
        );

        close_and_remove(pool, &path).await;

        Ok(())
    }

    #[tokio::test]
    async fn protocol_profiles_store_structured_config() -> Result<()> {
        let (pool, path) = test_pool().await?;

        let profile = create_protocol_profile(
            &pool,
            NewProtocolProfile {
                name: "VLESS-XHTTP-SAFE".to_string(),
                kind: ProxyKind::VlessRealityXhttp,
                role: ProxyRole::AutoSafe,
                enabled: true,
                server: "iberia.example.test".to_string(),
                port: 8443,
                config: ProtocolConfig::VlessRealityXhttp {
                    uuid_source: crate::models::UserUuidSource::SubscriptionUser,
                    server_name: "www.microsoft.com".to_string(),
                    path: "/api/v1".to_string(),
                    public_key_secret: "xray.reality.public_key".to_string(),
                    short_id_secret: "xray.reality.short_id".to_string(),
                },
            },
        )
        .await?;

        assert_eq!(profile.kind, "vless-reality-xhttp");
        assert_eq!(profile.role, "auto-safe");
        assert_eq!(profile.port, 8443);

        let config: ProtocolConfig = serde_json::from_str(&profile.config_json)?;
        assert_eq!(
            config,
            ProtocolConfig::VlessRealityXhttp {
                uuid_source: crate::models::UserUuidSource::SubscriptionUser,
                server_name: "www.microsoft.com".to_string(),
                path: "/api/v1".to_string(),
                public_key_secret: "xray.reality.public_key".to_string(),
                short_id_secret: "xray.reality.short_id".to_string(),
            }
        );

        let profiles = list_protocol_profiles(&pool).await?;
        assert_eq!(profiles.len(), 1);

        close_and_remove(pool, &path).await;

        Ok(())
    }

    #[tokio::test]
    async fn protocol_profiles_update_config_and_enabled_state() -> Result<()> {
        let (pool, path) = test_pool().await?;

        create_protocol_profile(
            &pool,
            NewProtocolProfile {
                name: "VLESS-XHTTP-SAFE".to_string(),
                kind: ProxyKind::VlessRealityXhttp,
                role: ProxyRole::AutoSafe,
                enabled: true,
                server: "old.example.test".to_string(),
                port: 8443,
                config: ProtocolConfig::VlessRealityXhttp {
                    uuid_source: crate::models::UserUuidSource::SubscriptionUser,
                    server_name: "www.microsoft.com".to_string(),
                    path: "/api/v1".to_string(),
                    public_key_secret: "xray.reality.public_key".to_string(),
                    short_id_secret: "xray.reality.short_id".to_string(),
                },
            },
        )
        .await?;

        let updated = update_protocol_profile(
            &pool,
            UpdateProtocolProfile {
                name: "VLESS-XHTTP-SAFE".to_string(),
                enabled: false,
                server: "new.example.test".to_string(),
                port: 9443,
                config: ProtocolConfig::VlessRealityXhttp {
                    uuid_source: crate::models::UserUuidSource::SubscriptionUser,
                    server_name: "www.apple.com".to_string(),
                    path: "/edge".to_string(),
                    public_key_secret: "xray.reality.public_key".to_string(),
                    short_id_secret: "xray.reality.short_id".to_string(),
                },
            },
        )
        .await?;

        assert!(!updated.enabled);
        assert_eq!(updated.server, "new.example.test");
        assert_eq!(updated.port, 9443);
        assert!(updated.config_json.contains("/edge"));

        close_and_remove(pool, &path).await;

        Ok(())
    }

    #[tokio::test]
    async fn routing_rule_sets_round_trip_and_validate_input() -> Result<()> {
        let (pool, path) = test_pool().await?;

        ensure_default_routing_rule_sets(&pool).await?;
        let rule_sets = load_routing_rule_sets(&pool).await?;
        assert_eq!(rule_sets.len(), 4);
        assert!(rule_sets.iter().all(|rule_set| rule_set.enabled));

        update_routing_rule_set(
            &pool,
            UpdateRoutingRuleSet {
                slug: "proxy-ai".to_string(),
                enabled: true,
                target: "AUTO-SAFE".to_string(),
                payload: "DOMAIN-SUFFIX,openai.com\nDOMAIN-SUFFIX,perplexity.ai".to_string(),
            },
        )
        .await?;

        let rule_sets = load_routing_rule_sets(&pool).await?;
        let proxy_ai = rule_sets
            .iter()
            .find(|rule_set| rule_set.slug == "proxy-ai")
            .expect("proxy-ai rule set should exist");
        assert!(proxy_ai.payload.contains("perplexity.ai"));

        let err = update_routing_rule_set(
            &pool,
            UpdateRoutingRuleSet {
                slug: "proxy-ai".to_string(),
                enabled: true,
                target: "AUTO-SAFE".to_string(),
                payload: "RULE-SET,other,DIRECT".to_string(),
            },
        )
        .await
        .unwrap_err();
        assert!(err
            .to_string()
            .contains("cannot reference another rule set"));

        let err = update_routing_rule_set(
            &pool,
            UpdateRoutingRuleSet {
                slug: "proxy-ai".to_string(),
                enabled: true,
                target: "INVALID".to_string(),
                payload: "DOMAIN-SUFFIX,openai.com".to_string(),
            },
        )
        .await
        .unwrap_err();
        assert!(err.to_string().contains("unsupported routing target"));

        close_and_remove(pool, &path).await;

        Ok(())
    }
}
