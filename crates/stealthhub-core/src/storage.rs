//! `SQLite` persistence layer for Infiproxy.
//!
//! This module owns schema creation, migrations-by-idempotent-DDL and CRUD
//! helpers for users, admins, sessions, settings, secrets, protocol profiles and
//! routing rule sets. Callers receive typed records instead of raw SQL rows.

use anyhow::{bail, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{
    sqlite::{
        SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions, SqliteRow, SqliteSynchronous,
    },
    Row, Sqlite, SqlitePool, Transaction,
};
use std::{fmt, str::FromStr, time::Duration as StdDuration};
use uuid::Uuid;

use crate::{
    adapter::{valid_adapter_id, CoreRegistry, ProtocolRegistry},
    desired::DesiredState,
    inventory::{adapter_kind, PersistedAdapterState},
    models::{PanelSettings, ProtocolProfile, ProxyRole},
    rules::{
        default_routing_rule_set, default_routing_rule_sets, is_valid_routing_target,
        validate_classical_rule_payload, RoutingRuleSet,
    },
};

pub type DbPool = SqlitePool;

#[derive(Clone, Serialize, Deserialize)]
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

impl fmt::Debug for UserRecord {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("UserRecord")
            .field("id", &self.id)
            .field("username", &self.username)
            .field("uuid", &"[REDACTED]")
            .field("subscription_token", &"[REDACTED]")
            .field("enabled", &self.enabled)
            .field("traffic_limit_bytes", &self.traffic_limit_bytes)
            .field("traffic_used_bytes", &self.traffic_used_bytes)
            .field("expires_at", &self.expires_at)
            .field("created_at", &self.created_at)
            .field("updated_at", &self.updated_at)
            .finish()
    }
}

#[derive(Debug, Clone)]
pub struct NewUser {
    pub username: String,
    pub traffic_limit_bytes: Option<i64>,
    pub expires_at: Option<DateTime<Utc>>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct AdminRecord {
    pub id: i64,
    pub username: String,
    pub password_hash: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl fmt::Debug for AdminRecord {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AdminRecord")
            .field("id", &self.id)
            .field("username", &self.username)
            .field("password_hash", &"[REDACTED]")
            .field("created_at", &self.created_at)
            .field("updated_at", &self.updated_at)
            .finish()
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct AdminSessionRecord {
    pub id: i64,
    pub admin_id: i64,
    pub token_hash: String,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    pub last_seen_at: DateTime<Utc>,
}

impl fmt::Debug for AdminSessionRecord {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AdminSessionRecord")
            .field("id", &self.id)
            .field("admin_id", &self.admin_id)
            .field("token_hash", &"[REDACTED]")
            .field("expires_at", &self.expires_at)
            .field("created_at", &self.created_at)
            .field("last_seen_at", &self.last_seen_at)
            .finish()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SettingRecord {
    pub key: String,
    pub value: String,
    pub updated_at: DateTime<Utc>,
}

/// Sanitized desired/applied controller status exposed to the panel.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReconcileStateRecord {
    pub desired_generation: i64,
    pub applied_generation: i64,
    pub status: String,
    pub last_operation_id: Option<String>,
    pub last_error: Option<String>,
    pub affected_resources_json: String,
    pub started_at: Option<DateTime<Utc>>,
    pub completed_at: Option<DateTime<Utc>>,
    pub updated_at: DateTime<Utc>,
}

/// Opaque durable state retained even while its adapter package is absent.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AdapterStateRecord {
    pub adapter_id: String,
    pub adapter_kind: String,
    pub resource_id: String,
    pub schema_version: i64,
    pub config_json: String,
    pub enabled: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Sanitized result copied from the root-owned transaction journal.
pub struct ReconcileResultUpdate<'a> {
    pub desired_generation: u64,
    pub applied_generation: u64,
    pub status: &'a str,
    pub operation_id: &'a str,
    pub affected_resources: &'a [String],
    pub error: Option<&'a str>,
    pub started_at: Option<&'a str>,
    pub completed_at: Option<&'a str>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct SecretRecord {
    pub name: String,
    pub value: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl fmt::Debug for SecretRecord {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretRecord")
            .field("name", &self.name)
            .field("value", &"[REDACTED]")
            .field("created_at", &self.created_at)
            .field("updated_at", &self.updated_at)
            .finish()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProtocolProfileRecord {
    pub id: i64,
    pub name: String,
    pub kind: String,
    pub role: String,
    pub enabled: bool,
    pub server: String,
    pub port: i64,
    pub config_json: String,
    pub schema_version: i64,
    pub preferred_core_id: Option<String>,
    pub managed_resource_id: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct NewProtocolProfile {
    pub name: String,
    pub protocol_id: String,
    pub schema_version: u32,
    pub role: ProxyRole,
    pub enabled: bool,
    pub server: String,
    pub port: u16,
    pub preferred_core_id: Option<String>,
    pub managed_resource_id: Option<String>,
    pub config: serde_json::Value,
}

#[derive(Debug, Clone)]
pub struct UpdateProtocolProfile {
    pub name: String,
    pub enabled: bool,
    pub server: String,
    pub port: u16,
    pub preferred_core_id: Option<String>,
    pub managed_resource_id: Option<String>,
    pub config: serde_json::Value,
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

impl<'r> sqlx::FromRow<'r, SqliteRow> for ReconcileStateRecord {
    fn from_row(row: &'r SqliteRow) -> std::result::Result<Self, sqlx::Error> {
        Ok(Self {
            desired_generation: row.try_get("desired_generation")?,
            applied_generation: row.try_get("applied_generation")?,
            status: row.try_get("status")?,
            last_operation_id: row.try_get("last_operation_id")?,
            last_error: row.try_get("last_error")?,
            affected_resources_json: row.try_get("affected_resources_json")?,
            started_at: row.try_get("started_at")?,
            completed_at: row.try_get("completed_at")?,
            updated_at: row.try_get("updated_at")?,
        })
    }
}

impl<'r> sqlx::FromRow<'r, SqliteRow> for AdapterStateRecord {
    fn from_row(row: &'r SqliteRow) -> std::result::Result<Self, sqlx::Error> {
        Ok(Self {
            adapter_id: row.try_get("adapter_id")?,
            adapter_kind: row.try_get("adapter_kind")?,
            resource_id: row.try_get("resource_id")?,
            schema_version: row.try_get("schema_version")?,
            config_json: row.try_get("config_json")?,
            enabled: row.try_get("enabled")?,
            created_at: row.try_get("created_at")?,
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
            schema_version: row.try_get("schema_version")?,
            preferred_core_id: row.try_get("preferred_core_id")?,
            managed_resource_id: row.try_get("managed_resource_id")?,
            created_at: row.try_get("created_at")?,
            updated_at: row.try_get("updated_at")?,
        })
    }
}

pub async fn open_pool(database_url: &str) -> Result<SqlitePool> {
    let mut options = SqliteConnectOptions::from_str(database_url)?
        .create_if_missing(true)
        .foreign_keys(true)
        .busy_timeout(StdDuration::from_secs(10));
    if !database_url.contains(":memory:") {
        options = options
            .journal_mode(SqliteJournalMode::Wal)
            .synchronous(SqliteSynchronous::Normal);
    }
    let max_connections = std::env::var("INFIPROXY_DB_MAX_CONNECTIONS")
        .ok()
        .or_else(|| std::env::var("STEALTHHUB_DB_MAX_CONNECTIONS").ok())
        .and_then(|value| value.parse::<u32>().ok())
        .filter(|value| (1..=16).contains(value))
        .unwrap_or(2);

    let pool = SqlitePoolOptions::new()
        .max_connections(max_connections)
        .connect_with(options)
        .await?;

    Ok(pool)
}

pub async fn init_db(pool: &SqlitePool) -> Result<()> {
    sqlx::query(
        r"
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
        ",
    )
    .execute(pool)
    .await?;

    sqlx::query(
        r"
        CREATE TABLE IF NOT EXISTS reconcile_state (
            singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
            desired_generation INTEGER NOT NULL DEFAULT 0 CHECK(desired_generation >= 0),
            applied_generation INTEGER NOT NULL DEFAULT 0 CHECK(applied_generation >= 0),
            status TEXT NOT NULL DEFAULT 'applied',
            last_operation_id TEXT NULL,
            last_error TEXT NULL,
            affected_resources_json TEXT NOT NULL DEFAULT '[]',
            started_at TEXT NULL,
            completed_at TEXT NULL,
            updated_at TEXT NOT NULL
        );
        ",
    )
    .execute(pool)
    .await?;
    sqlx::query(
        r"
        INSERT INTO reconcile_state (singleton, updated_at)
        VALUES (1, ?)
        ON CONFLICT(singleton) DO NOTHING
        ",
    )
    .bind(Utc::now())
    .execute(pool)
    .await?;

    sqlx::query(
        r"
        CREATE INDEX IF NOT EXISTS idx_users_subscription_token
        ON users(subscription_token);
        ",
    )
    .execute(pool)
    .await?;

    sqlx::query(
        r"
        CREATE INDEX IF NOT EXISTS idx_users_enabled
        ON users(enabled);
        ",
    )
    .execute(pool)
    .await?;

    sqlx::query(
        r"
        CREATE TABLE IF NOT EXISTS admins (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
        ",
    )
    .execute(pool)
    .await?;

    sqlx::query(
        r"
        CREATE TABLE IF NOT EXISTS admin_sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            admin_id INTEGER NOT NULL,
            token_hash TEXT NOT NULL UNIQUE,
            expires_at TEXT NOT NULL,
            created_at TEXT NOT NULL,
            last_seen_at TEXT NOT NULL,
            FOREIGN KEY(admin_id) REFERENCES admins(id) ON DELETE CASCADE
        );
        ",
    )
    .execute(pool)
    .await?;

    sqlx::query(
        r"
        CREATE INDEX IF NOT EXISTS idx_admin_sessions_token_hash
        ON admin_sessions(token_hash);
        ",
    )
    .execute(pool)
    .await?;

    sqlx::query(
        r"
        CREATE INDEX IF NOT EXISTS idx_admin_sessions_expires_at
        ON admin_sessions(expires_at);
        ",
    )
    .execute(pool)
    .await?;

    sqlx::query(
        r"
        CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
        ",
    )
    .execute(pool)
    .await?;

    sqlx::query(
        r"
        CREATE TABLE IF NOT EXISTS secret_values (
            name TEXT PRIMARY KEY,
            value TEXT NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
        ",
    )
    .execute(pool)
    .await?;

    sqlx::query(
        r"
        CREATE TABLE IF NOT EXISTS protocol_profiles (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE,
            kind TEXT NOT NULL,
            role TEXT NOT NULL,
            enabled INTEGER NOT NULL DEFAULT 1,
            server TEXT NOT NULL,
            port INTEGER NOT NULL CHECK(port > 0 AND port <= 65535),
            config_json TEXT NOT NULL,
            schema_version INTEGER NOT NULL DEFAULT 1 CHECK(schema_version > 0),
            preferred_core_id TEXT NULL,
            managed_resource_id TEXT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
        ",
    )
    .execute(pool)
    .await?;

    ensure_protocol_profile_columns(pool).await?;

    sqlx::query(
        r"
        CREATE INDEX IF NOT EXISTS idx_protocol_profiles_role
        ON protocol_profiles(role);
        ",
    )
    .execute(pool)
    .await?;

    sqlx::query(
        r"
        CREATE INDEX IF NOT EXISTS idx_protocol_profiles_enabled
        ON protocol_profiles(enabled);
        ",
    )
    .execute(pool)
    .await?;

    run_versioned_migrations(pool).await?;

    Ok(())
}

const ADAPTER_STATE_MIGRATION: i64 = 1;

async fn run_versioned_migrations(pool: &SqlitePool) -> Result<()> {
    let mut transaction = pool.begin().await?;
    sqlx::query(
        r"
        CREATE TABLE IF NOT EXISTS schema_migrations (
            version INTEGER PRIMARY KEY CHECK(version > 0),
            name TEXT NOT NULL UNIQUE,
            applied_at TEXT NOT NULL
        )
        ",
    )
    .execute(&mut *transaction)
    .await?;
    let applied =
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM schema_migrations WHERE version = ?")
            .bind(ADAPTER_STATE_MIGRATION)
            .fetch_one(&mut *transaction)
            .await?;
    if applied == 0 {
        sqlx::query(
            r"
            CREATE TABLE adapter_state (
                adapter_id TEXT NOT NULL,
                adapter_kind TEXT NOT NULL,
                resource_id TEXT NOT NULL,
                schema_version INTEGER NOT NULL CHECK(schema_version > 0),
                config_json TEXT NOT NULL,
                enabled INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                PRIMARY KEY(adapter_kind, adapter_id, resource_id)
            )
            ",
        )
        .execute(&mut *transaction)
        .await?;
        sqlx::query("INSERT INTO schema_migrations (version, name, applied_at) VALUES (?, ?, ?)")
            .bind(ADAPTER_STATE_MIGRATION)
            .bind("add opaque durable adapter state")
            .bind(Utc::now())
            .execute(&mut *transaction)
            .await?;
    }
    transaction.commit().await?;
    Ok(())
}

async fn bump_desired_generation(transaction: &mut Transaction<'_, Sqlite>) -> Result<u64> {
    let operation_id = Uuid::new_v4().to_string();
    let now = Utc::now();
    sqlx::query(
        r"
        UPDATE reconcile_state
        SET desired_generation = desired_generation + 1,
            status = 'pending',
            last_operation_id = ?,
            last_error = NULL,
            affected_resources_json = '[]',
            started_at = NULL,
            completed_at = NULL,
            updated_at = ?
        WHERE singleton = 1
        ",
    )
    .bind(operation_id)
    .bind(now)
    .execute(&mut **transaction)
    .await?;
    let (generation,): (i64,) =
        sqlx::query_as("SELECT desired_generation FROM reconcile_state WHERE singleton = 1")
            .fetch_one(&mut **transaction)
            .await?;
    u64::try_from(generation).map_err(|_| anyhow::anyhow!("invalid desired generation"))
}

/// Returns the sanitized controller state used by UI and root worker.
pub async fn get_reconcile_state(pool: &SqlitePool) -> Result<ReconcileStateRecord> {
    Ok(sqlx::query_as::<_, ReconcileStateRecord>(
        r"
        SELECT desired_generation, applied_generation, status, last_operation_id,
               last_error, affected_resources_json, started_at, completed_at, updated_at
        FROM reconcile_state
        WHERE singleton = 1
        ",
    )
    .fetch_one(pool)
    .await?)
}

/// Persists a sanitized privileged-worker result without generated configs.
pub async fn mark_reconcile_result(
    pool: &SqlitePool,
    update: ReconcileResultUpdate<'_>,
) -> Result<()> {
    let desired_generation = i64::try_from(update.desired_generation)?;
    let applied_generation = i64::try_from(update.applied_generation)?;
    let resources = serde_json::to_string(update.affected_resources)?;
    let safe_error = update
        .error
        .map(|value| value.chars().take(512).collect::<String>());
    sqlx::query(
        r"
        UPDATE reconcile_state
        SET applied_generation = ?, status = ?, last_operation_id = ?,
            last_error = ?, affected_resources_json = ?, started_at = ?,
            completed_at = ?, updated_at = ?
        WHERE singleton = 1 AND desired_generation = ?
        ",
    )
    .bind(applied_generation)
    .bind(update.status)
    .bind(update.operation_id)
    .bind(safe_error)
    .bind(resources)
    .bind(update.started_at)
    .bind(update.completed_at)
    .bind(Utc::now())
    .bind(desired_generation)
    .execute(pool)
    .await?;
    Ok(())
}

async fn ensure_protocol_profile_columns(pool: &SqlitePool) -> Result<()> {
    let columns = sqlx::query("PRAGMA table_info(protocol_profiles)")
        .fetch_all(pool)
        .await?
        .into_iter()
        .map(|row| row.get::<String, _>("name"))
        .collect::<std::collections::BTreeSet<_>>();

    for (name, statement) in [
        (
            "schema_version",
            "ALTER TABLE protocol_profiles ADD COLUMN schema_version INTEGER NOT NULL DEFAULT 1 CHECK(schema_version > 0)",
        ),
        (
            "preferred_core_id",
            "ALTER TABLE protocol_profiles ADD COLUMN preferred_core_id TEXT NULL",
        ),
        (
            "managed_resource_id",
            "ALTER TABLE protocol_profiles ADD COLUMN managed_resource_id TEXT NULL",
        ),
    ] {
        if !columns.contains(name) {
            sqlx::query(statement).execute(pool).await?;
        }
    }
    Ok(())
}

pub async fn ensure_default_settings(pool: &SqlitePool) -> Result<()> {
    upsert_setting_if_missing(pool, "panel_name", "Infiproxy").await?;
    upsert_setting_if_missing(pool, "subscription_domain", "sub.infiproxy.local").await?;
    upsert_setting_if_missing(pool, "node_domain", "node.infiproxy.local").await?;
    upsert_setting_if_missing(pool, "panel_update_enabled", "true").await?;
    upsert_setting_if_missing(pool, "panel_update_hour", "5").await?;
    upsert_setting_if_missing(pool, "panel_update_time", "05:00").await?;
    upsert_setting_if_missing(pool, "panel_update_repo", "infinitrator/stealthhub-panel").await?;
    upsert_setting_if_missing(pool, "panel_update_ref", "main").await?;
    upsert_setting_if_missing(pool, "panel_update_available", "false").await?;
    upsert_setting_if_missing(pool, "panel_update_checked_at", "never").await?;
    upsert_setting_if_missing(pool, "panel_update_current_sha", "unknown").await?;
    upsert_setting_if_missing(pool, "panel_update_latest_sha", "unknown").await?;
    upsert_setting_if_missing(pool, "panel_update_planned_for", "not scheduled").await?;
    upsert_setting_if_missing(pool, "panel_update_status", "idle").await?;

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

pub async fn ensure_default_protocol_profiles(pool: &SqlitePool) -> Result<()> {
    for profile in crate::adapters::default_profiles() {
        ensure_protocol_profile(pool, &NewProtocolProfile::from(profile)).await?;
    }

    Ok(())
}

async fn ensure_protocol_profile(pool: &SqlitePool, input: &NewProtocolProfile) -> Result<()> {
    let now = Utc::now();
    let role = storage_string(&input.role)?;
    let config_json = serde_json::to_string(&input.config)?;

    sqlx::query(
        r"
        INSERT INTO protocol_profiles (
            name, kind, role, enabled, server, port, config_json, schema_version,
            preferred_core_id, managed_resource_id, created_at, updated_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(name) DO NOTHING
        ",
    )
    .bind(input.name.trim())
    .bind(input.protocol_id.trim())
    .bind(role)
    .bind(input.enabled)
    .bind(input.server.trim())
    .bind(i64::from(input.port))
    .bind(config_json)
    .bind(i64::from(input.schema_version))
    .bind(input.preferred_core_id.as_deref())
    .bind(input.managed_resource_id.as_deref())
    .bind(now)
    .bind(now)
    .execute(pool)
    .await?;
    Ok(())
}

impl From<ProtocolProfile> for NewProtocolProfile {
    fn from(profile: ProtocolProfile) -> Self {
        Self {
            name: profile.name,
            protocol_id: profile.protocol_id,
            schema_version: profile.schema_version,
            role: profile.role,
            enabled: profile.enabled,
            server: profile.server,
            port: profile.port,
            preferred_core_id: profile.preferred_core_id,
            managed_resource_id: profile.managed_resource_id,
            config: profile.config,
        }
    }
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
        r"
        INSERT INTO admins (
            username,
            password_hash,
            created_at,
            updated_at
        )
        VALUES (?, ?, ?, ?)
        ",
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

/// Creates the first administrator with one atomic conditional insert.
///
/// This closes the initial-setup race where two concurrent requests could both
/// observe an empty table before inserting separate privileged accounts.
pub async fn create_first_admin(
    pool: &SqlitePool,
    username: &str,
    password_hash: &str,
) -> Result<AdminRecord> {
    let now = Utc::now();
    let username = username.trim();
    let result = sqlx::query(
        r"
        INSERT INTO admins (username, password_hash, created_at, updated_at)
        SELECT ?, ?, ?, ?
        WHERE NOT EXISTS (SELECT 1 FROM admins)
        ",
    )
    .bind(username)
    .bind(password_hash)
    .bind(now)
    .bind(now)
    .execute(pool)
    .await?;

    if result.rows_affected() != 1 {
        bail!("initial administrator already exists");
    }

    get_admin_by_username(pool, username)
        .await?
        .ok_or_else(|| anyhow::anyhow!("initial administrator was not created"))
}

pub async fn is_owner_admin_id(pool: &SqlitePool, admin_id: i64) -> Result<bool> {
    let owner_id = sqlx::query_scalar::<_, Option<i64>>("SELECT MIN(id) FROM admins")
        .fetch_one(pool)
        .await?;

    Ok(owner_id == Some(admin_id))
}

pub async fn get_admin_by_username(
    pool: &SqlitePool,
    username: &str,
) -> Result<Option<AdminRecord>> {
    let admin = sqlx::query_as::<_, AdminRecord>(
        r"
        SELECT
            id,
            username,
            password_hash,
            created_at,
            updated_at
        FROM admins
        WHERE username = ?
        ",
    )
    .bind(username.trim())
    .fetch_optional(pool)
    .await?;

    Ok(admin)
}

pub async fn get_admin_by_id(pool: &SqlitePool, id: i64) -> Result<Option<AdminRecord>> {
    let admin = sqlx::query_as::<_, AdminRecord>(
        r"
        SELECT
            id,
            username,
            password_hash,
            created_at,
            updated_at
        FROM admins
        WHERE id = ?
        ",
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
        r"
        INSERT INTO admin_sessions (
            admin_id,
            token_hash,
            expires_at,
            created_at,
            last_seen_at
        )
        VALUES (?, ?, ?, ?, ?)
        ",
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
        r"
        SELECT
            id,
            admin_id,
            token_hash,
            expires_at,
            created_at,
            last_seen_at
        FROM admin_sessions
        WHERE token_hash = ? AND expires_at > ?
        ",
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
        r"
        UPDATE admin_sessions
        SET last_seen_at = ?
        WHERE token_hash = ?
        ",
    )
    .bind(now)
    .bind(token_hash)
    .execute(pool)
    .await?;

    Ok(())
}

pub async fn delete_admin_session(pool: &SqlitePool, token_hash: &str) -> Result<()> {
    sqlx::query(
        r"
        DELETE FROM admin_sessions
        WHERE token_hash = ?
        ",
    )
    .bind(token_hash)
    .execute(pool)
    .await?;

    Ok(())
}

/// Replaces one administrator password and revokes every existing session in a
/// single transaction so no old session survives a successful credential
/// rotation.
pub async fn update_admin_password_and_revoke_sessions(
    pool: &SqlitePool,
    admin_id: i64,
    password_hash: &str,
) -> Result<()> {
    let now = Utc::now();
    let mut transaction = pool.begin().await?;
    let result = sqlx::query(
        r"
        UPDATE admins
        SET password_hash = ?, updated_at = ?
        WHERE id = ?
        ",
    )
    .bind(password_hash)
    .bind(now)
    .bind(admin_id)
    .execute(&mut *transaction)
    .await?;

    if result.rows_affected() != 1 {
        bail!("administrator not found");
    }

    sqlx::query("DELETE FROM admin_sessions WHERE admin_id = ?")
        .bind(admin_id)
        .execute(&mut *transaction)
        .await?;
    transaction.commit().await?;
    Ok(())
}

pub async fn delete_expired_admin_sessions(pool: &SqlitePool) -> Result<()> {
    let now = Utc::now();

    sqlx::query(
        r"
        DELETE FROM admin_sessions
        WHERE expires_at <= ?
        ",
    )
    .bind(now)
    .execute(pool)
    .await?;

    Ok(())
}

pub async fn upsert_setting(pool: &SqlitePool, key: &str, value: &str) -> Result<()> {
    let now = Utc::now();

    sqlx::query(
        r"
        INSERT INTO settings (key, value, updated_at)
        VALUES (?, ?, ?)
        ON CONFLICT(key) DO UPDATE SET
            value = excluded.value,
            updated_at = excluded.updated_at
        ",
    )
    .bind(key.trim())
    .bind(value)
    .bind(now)
    .execute(pool)
    .await?;

    Ok(())
}

/// Atomically writes a related group of settings with one timestamp.
pub async fn upsert_settings(pool: &SqlitePool, values: &[(String, String)]) -> Result<()> {
    let now = Utc::now();
    let mut transaction = pool.begin().await?;

    for (key, value) in values {
        sqlx::query(
            r"
            INSERT INTO settings (key, value, updated_at)
            VALUES (?, ?, ?)
            ON CONFLICT(key) DO UPDATE SET
                value = excluded.value,
                updated_at = excluded.updated_at
            ",
        )
        .bind(key.trim())
        .bind(value)
        .bind(now)
        .execute(&mut *transaction)
        .await?;
    }

    transaction.commit().await?;
    Ok(())
}

/// Atomically writes runtime-affecting settings and advances desired state.
pub async fn upsert_desired_settings(
    pool: &SqlitePool,
    values: &[(String, String)],
) -> Result<u64> {
    let now = Utc::now();
    let mut transaction = pool.begin().await?;
    for (key, value) in values {
        sqlx::query(
            r"
            INSERT INTO settings (key, value, updated_at)
            VALUES (?, ?, ?)
            ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at
            ",
        )
        .bind(key.trim())
        .bind(value)
        .bind(now)
        .execute(&mut *transaction)
        .await?;
    }
    let generation = bump_desired_generation(&mut transaction).await?;
    transaction.commit().await?;
    Ok(generation)
}

/// Atomically writes settings and advances desired state only when one of the
/// selected runtime keys actually changes.
pub async fn upsert_settings_with_runtime_keys(
    pool: &SqlitePool,
    values: &[(String, String)],
    runtime_keys: &[&str],
) -> Result<Option<u64>> {
    let now = Utc::now();
    let mut transaction = pool.begin().await?;
    let mut runtime_changed = false;
    for (key, value) in values {
        if runtime_keys.contains(&key.as_str()) {
            let previous =
                sqlx::query_as::<_, (String,)>("SELECT value FROM settings WHERE key = ?")
                    .bind(key.trim())
                    .fetch_optional(&mut *transaction)
                    .await?
                    .map(|(value,)| value);
            runtime_changed |= previous.as_deref() != Some(value.as_str());
        }
        sqlx::query(
            r"
            INSERT INTO settings (key, value, updated_at)
            VALUES (?, ?, ?)
            ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at
            ",
        )
        .bind(key.trim())
        .bind(value)
        .bind(now)
        .execute(&mut *transaction)
        .await?;
    }
    let generation = if runtime_changed {
        Some(bump_desired_generation(&mut transaction).await?)
    } else {
        None
    };
    transaction.commit().await?;
    Ok(generation)
}

async fn upsert_setting_if_missing(pool: &SqlitePool, key: &str, value: &str) -> Result<()> {
    let now = Utc::now();

    sqlx::query(
        r"
        INSERT INTO settings (key, value, updated_at)
        VALUES (?, ?, ?)
        ON CONFLICT(key) DO NOTHING
        ",
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
        r"
        SELECT key, value, updated_at
        FROM settings
        WHERE key = ?
        ",
    )
    .bind(key.trim())
    .fetch_optional(pool)
    .await?;

    Ok(setting)
}

pub async fn list_settings(pool: &SqlitePool) -> Result<Vec<SettingRecord>> {
    let settings = sqlx::query_as::<_, SettingRecord>(
        r"
        SELECT key, value, updated_at
        FROM settings
        ORDER BY key ASC
        ",
    )
    .fetch_all(pool)
    .await?;

    Ok(settings)
}

fn valid_adapter_namespace(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

fn valid_adapter_resource_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

/// Inserts or updates opaque adapter-owned state without interpreting payload fields.
pub async fn upsert_adapter_state(pool: &SqlitePool, state: &PersistedAdapterState) -> Result<()> {
    if !valid_adapter_id(&state.adapter_id)
        || !valid_adapter_namespace(&state.adapter_kind)
        || !valid_adapter_resource_id(&state.resource_id)
        || state.schema_version == 0
    {
        bail!("invalid durable adapter state identity");
    }
    let config_json = serde_json::to_string(&state.config)?;
    let now = Utc::now();
    sqlx::query(
        r"
        INSERT INTO adapter_state (
            adapter_id, adapter_kind, resource_id, schema_version, config_json,
            enabled, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(adapter_kind, adapter_id, resource_id) DO UPDATE SET
            schema_version = excluded.schema_version,
            config_json = excluded.config_json,
            enabled = excluded.enabled,
            updated_at = excluded.updated_at
        ",
    )
    .bind(&state.adapter_id)
    .bind(&state.adapter_kind)
    .bind(&state.resource_id)
    .bind(i64::from(state.schema_version))
    .bind(config_json)
    .bind(state.enabled)
    .bind(now)
    .bind(now)
    .execute(pool)
    .await?;
    Ok(())
}

/// Returns every adapter row, including unavailable and unknown adapter kinds.
pub async fn list_adapter_state_records(pool: &SqlitePool) -> Result<Vec<AdapterStateRecord>> {
    Ok(sqlx::query_as::<_, AdapterStateRecord>(
        r"
        SELECT adapter_id, adapter_kind, resource_id, schema_version,
               config_json, enabled, created_at, updated_at
        FROM adapter_state
        ORDER BY adapter_kind, adapter_id, resource_id
        ",
    )
    .fetch_all(pool)
    .await?)
}

/// Decodes only the generic envelope; adapter configuration remains opaque JSON.
pub fn decode_adapter_state(record: &AdapterStateRecord) -> Result<PersistedAdapterState> {
    Ok(PersistedAdapterState {
        adapter_id: record.adapter_id.clone(),
        adapter_kind: record.adapter_kind.clone(),
        resource_id: record.resource_id.clone(),
        schema_version: u32::try_from(record.schema_version)
            .map_err(|_| anyhow::anyhow!("invalid adapter state schema version"))?,
        config: serde_json::from_str(&record.config_json)?,
        enabled: record.enabled,
    })
}

pub async fn list_adapter_states(pool: &SqlitePool) -> Result<Vec<PersistedAdapterState>> {
    list_adapter_state_records(pool)
        .await?
        .iter()
        .map(decode_adapter_state)
        .collect()
}

/// Reattaches state for adapters currently present. Unknown/future rows remain untouched.
pub async fn migrate_available_adapter_states(
    pool: &SqlitePool,
    protocols: &ProtocolRegistry,
    cores: &CoreRegistry,
) -> Result<Vec<String>> {
    let records = list_adapter_state_records(pool).await?;
    let mut migrated = Vec::new();
    let mut transaction = pool.begin().await?;
    for record in records {
        let Ok(from_version) = u32::try_from(record.schema_version) else {
            continue;
        };
        let Ok(config) = serde_json::from_str::<serde_json::Value>(&record.config_json) else {
            continue;
        };
        let migration = match record.adapter_kind.as_str() {
            adapter_kind::PROTOCOL => protocols
                .get(&record.adapter_id)
                .and_then(|adapter| adapter.migrate_state(from_version, config).ok()),
            adapter_kind::CORE | adapter_kind::INFRASTRUCTURE => cores
                .get(&record.adapter_id)
                .and_then(|adapter| adapter.migrate_state(from_version, config).ok()),
            _ => None,
        };
        let Some((schema_version, config)) = migration else {
            continue;
        };
        let config_json = serde_json::to_string(&config)?;
        if schema_version != from_version || config_json != record.config_json {
            sqlx::query(
                r"
                UPDATE adapter_state
                SET schema_version = ?, config_json = ?, updated_at = ?
                WHERE adapter_kind = ? AND adapter_id = ? AND resource_id = ?
                ",
            )
            .bind(i64::from(schema_version))
            .bind(config_json)
            .bind(Utc::now())
            .bind(&record.adapter_kind)
            .bind(&record.adapter_id)
            .bind(&record.resource_id)
            .execute(&mut *transaction)
            .await?;
            migrated.push(format!(
                "{}:{}:{}",
                record.adapter_kind, record.adapter_id, record.resource_id
            ));
        }
    }
    transaction.commit().await?;
    Ok(migrated)
}

pub async fn upsert_secret(pool: &SqlitePool, name: &str, value: &str) -> Result<()> {
    let now = Utc::now();
    let mut transaction = pool.begin().await?;

    sqlx::query(
        r"
        INSERT INTO secret_values (name, value, created_at, updated_at)
        VALUES (?, ?, ?, ?)
        ON CONFLICT(name) DO UPDATE SET
            value = excluded.value,
            updated_at = excluded.updated_at
        ",
    )
    .bind(name.trim())
    .bind(value)
    .bind(now)
    .bind(now)
    .execute(&mut *transaction)
    .await?;
    bump_desired_generation(&mut transaction).await?;
    transaction.commit().await?;
    Ok(())
}

pub async fn get_secret(pool: &SqlitePool, name: &str) -> Result<Option<SecretRecord>> {
    let secret = sqlx::query_as::<_, SecretRecord>(
        r"
        SELECT name, value, created_at, updated_at
        FROM secret_values
        WHERE name = ?
        ",
    )
    .bind(name.trim())
    .fetch_optional(pool)
    .await?;

    Ok(secret)
}

pub async fn list_secret_names(pool: &SqlitePool) -> Result<Vec<String>> {
    let rows = sqlx::query_as::<_, (String,)>(
        r"
        SELECT name
        FROM secret_values
        ORDER BY name ASC
        ",
    )
    .fetch_all(pool)
    .await?;

    Ok(rows.into_iter().map(|(name,)| name).collect())
}

pub async fn delete_secret(pool: &SqlitePool, name: &str) -> Result<()> {
    let mut transaction = pool.begin().await?;
    let result = sqlx::query("DELETE FROM secret_values WHERE name = ?")
        .bind(name.trim())
        .execute(&mut *transaction)
        .await?;

    if result.rows_affected() == 0 {
        bail!("secret not found");
    }
    bump_desired_generation(&mut transaction).await?;
    transaction.commit().await?;
    Ok(())
}

pub async fn create_protocol_profile(
    pool: &SqlitePool,
    input: NewProtocolProfile,
) -> Result<ProtocolProfileRecord> {
    let now = Utc::now();
    let role = storage_string(&input.role)?;
    let config_json = serde_json::to_string(&input.config)?;

    let mut transaction = pool.begin().await?;
    sqlx::query(
        r"
        INSERT INTO protocol_profiles (
            name,
            kind,
            role,
            enabled,
            server,
            port,
            config_json,
            schema_version,
            preferred_core_id,
            managed_resource_id,
            created_at,
            updated_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ",
    )
    .bind(input.name.trim())
    .bind(input.protocol_id.trim())
    .bind(role)
    .bind(input.enabled)
    .bind(input.server.trim())
    .bind(i64::from(input.port))
    .bind(config_json)
    .bind(i64::from(input.schema_version))
    .bind(input.preferred_core_id.as_deref())
    .bind(input.managed_resource_id.as_deref())
    .bind(now)
    .bind(now)
    .execute(&mut *transaction)
    .await?;
    bump_desired_generation(&mut transaction).await?;
    transaction.commit().await?;

    get_protocol_profile_by_name(pool, &input.name)
        .await?
        .ok_or_else(|| anyhow::anyhow!("protocol profile was not created"))
}

pub async fn get_protocol_profile_by_name(
    pool: &SqlitePool,
    name: &str,
) -> Result<Option<ProtocolProfileRecord>> {
    let profile = sqlx::query_as::<_, ProtocolProfileRecord>(
        r"
        SELECT
            id,
            name,
            kind,
            role,
            enabled,
            server,
            port,
            config_json,
            schema_version,
            preferred_core_id,
            managed_resource_id,
            created_at,
            updated_at
        FROM protocol_profiles
        WHERE name = ?
        ",
    )
    .bind(name.trim())
    .fetch_optional(pool)
    .await?;

    Ok(profile)
}

pub async fn list_protocol_profiles(pool: &SqlitePool) -> Result<Vec<ProtocolProfileRecord>> {
    let profiles = sqlx::query_as::<_, ProtocolProfileRecord>(
        r"
        SELECT
            id,
            name,
            kind,
            role,
            enabled,
            server,
            port,
            config_json,
            schema_version,
            preferred_core_id,
            managed_resource_id,
            created_at,
            updated_at
        FROM protocol_profiles
        ORDER BY role ASC, name ASC
        ",
    )
    .fetch_all(pool)
    .await?;

    Ok(profiles)
}

pub fn decode_protocol_profile(record: ProtocolProfileRecord) -> Result<ProtocolProfile> {
    let role: ProxyRole = serde_json::from_value(serde_json::Value::String(record.role))?;
    let config: serde_json::Value = serde_json::from_str(&record.config_json)?;
    let port = u16::try_from(record.port).map_err(|_| anyhow::anyhow!("invalid protocol port"))?;
    let schema_version = u32::try_from(record.schema_version)
        .map_err(|_| anyhow::anyhow!("invalid protocol schema version"))?;

    Ok(ProtocolProfile {
        name: record.name,
        protocol_id: record.kind,
        schema_version,
        role,
        server: record.server,
        port,
        enabled: record.enabled,
        preferred_core_id: record.preferred_core_id,
        managed_resource_id: record.managed_resource_id,
        config,
    })
}

/// Idempotently upgrades known adapter payloads while preserving unknown rows.
pub async fn migrate_protocol_adapter_configs(
    pool: &SqlitePool,
    registry: &crate::adapter::ProtocolRegistry,
) -> Result<()> {
    let mut transaction = pool.begin().await?;
    let records = sqlx::query_as::<_, ProtocolProfileRecord>(
        r"
        SELECT id, name, kind, role, enabled, server, port, config_json,
               schema_version, preferred_core_id, managed_resource_id,
               created_at, updated_at
        FROM protocol_profiles
        ORDER BY id ASC
        ",
    )
    .fetch_all(&mut *transaction)
    .await?;
    for record in records {
        let Some(adapter) = registry.get(&record.kind) else {
            continue;
        };
        let config = serde_json::from_str(&record.config_json)?;
        let from_version = u32::try_from(record.schema_version)
            .map_err(|_| anyhow::anyhow!("invalid adapter schema version"))?;
        let (schema_version, migrated) = adapter.migrate_config(from_version, config)?;
        let migrated_json = serde_json::to_string(&migrated)?;
        let preferred_core_id = record.preferred_core_id.clone().or_else(|| {
            crate::adapters::legacy_runtime_preference(&record.kind).map(str::to_string)
        });
        let managed_resource_id = record
            .managed_resource_id
            .clone()
            .or_else(|| Some(format!("legacy-profile-{}", record.id)));
        if schema_version != from_version
            || migrated_json != record.config_json
            || preferred_core_id != record.preferred_core_id
            || managed_resource_id != record.managed_resource_id
        {
            sqlx::query(
                r"
                UPDATE protocol_profiles
                SET schema_version = ?, config_json = ?, preferred_core_id = ?,
                    managed_resource_id = ?, updated_at = ?
                WHERE id = ?
                ",
            )
            .bind(i64::from(schema_version))
            .bind(migrated_json)
            .bind(preferred_core_id)
            .bind(managed_resource_id)
            .bind(Utc::now())
            .bind(record.id)
            .execute(&mut *transaction)
            .await?;
        }
    }
    transaction.commit().await?;
    Ok(())
}

pub async fn list_protocol_profiles_decoded(pool: &SqlitePool) -> Result<Vec<ProtocolProfile>> {
    list_protocol_profiles(pool)
        .await?
        .into_iter()
        .map(decode_protocol_profile)
        .collect()
}

/// Loads one coherent desired-state snapshot for the privileged worker.
pub async fn load_desired_state(pool: &SqlitePool) -> Result<DesiredState> {
    let mut transaction = pool.begin().await?;
    let (generation,): (i64,) =
        sqlx::query_as("SELECT desired_generation FROM reconcile_state WHERE singleton = 1")
            .fetch_one(&mut *transaction)
            .await?;
    let records = sqlx::query_as::<_, ProtocolProfileRecord>(
        r"
        SELECT id, name, kind, role, enabled, server, port, config_json,
               schema_version, preferred_core_id, managed_resource_id,
               created_at, updated_at
        FROM protocol_profiles
        ORDER BY role ASC, name ASC
        ",
    )
    .fetch_all(&mut *transaction)
    .await?;
    let now = Utc::now();
    let users = sqlx::query_as::<_, UserRecord>(
        r"
        SELECT id, username, uuid, subscription_token, enabled, traffic_limit_bytes,
               traffic_used_bytes, expires_at, created_at, updated_at
        FROM users
        WHERE enabled = 1
          AND (expires_at IS NULL OR expires_at > ?)
          AND (traffic_limit_bytes IS NULL OR traffic_used_bytes < traffic_limit_bytes)
        ORDER BY id ASC
        ",
    )
    .bind(now)
    .fetch_all(&mut *transaction)
    .await?;
    let settings =
        sqlx::query_as::<_, (String, String)>("SELECT key, value FROM settings ORDER BY key ASC")
            .fetch_all(&mut *transaction)
            .await?
            .into_iter()
            .collect();
    transaction.commit().await?;
    Ok(DesiredState {
        generation: u64::try_from(generation)
            .map_err(|_| anyhow::anyhow!("invalid desired generation"))?,
        profiles: records
            .into_iter()
            .map(decode_protocol_profile)
            .collect::<Result<Vec<_>>>()?,
        users: users.into_iter().map(Into::into).collect(),
        settings,
        infrastructure: Vec::new(),
    })
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

    let mut transaction = pool.begin().await?;
    sqlx::query(
        r"
        UPDATE protocol_profiles
        SET enabled = ?, server = ?, port = ?, config_json = ?, preferred_core_id = ?,
            managed_resource_id = ?, updated_at = ?
        WHERE name = ?
        ",
    )
    .bind(input.enabled)
    .bind(input.server.trim())
    .bind(i64::from(input.port))
    .bind(config_json)
    .bind(input.preferred_core_id.as_deref())
    .bind(input.managed_resource_id.as_deref())
    .bind(now)
    .bind(existing.name.as_str())
    .execute(&mut *transaction)
    .await?;
    bump_desired_generation(&mut transaction).await?;
    transaction.commit().await?;

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

const fn bool_setting(value: bool) -> &'static str {
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

    let mut transaction = pool.begin().await?;
    sqlx::query(
        r"
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
        ",
    )
    .bind(input.username.trim())
    .bind(uuid)
    .bind(subscription_token.clone())
    .bind(input.traffic_limit_bytes)
    .bind(input.expires_at)
    .bind(now)
    .bind(now)
    .execute(&mut *transaction)
    .await?;
    bump_desired_generation(&mut transaction).await?;
    transaction.commit().await?;

    get_user_by_token(pool, &subscription_token).await
}

pub async fn list_users(pool: &SqlitePool) -> Result<Vec<UserRecord>> {
    let users = sqlx::query_as::<_, UserRecord>(
        r"
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
        ",
    )
    .fetch_all(pool)
    .await?;

    Ok(users)
}

pub async fn get_user_by_token(pool: &SqlitePool, token: &str) -> Result<UserRecord> {
    let user = sqlx::query_as::<_, UserRecord>(
        r"
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
        ",
    )
    .bind(token)
    .fetch_one(pool)
    .await?;

    Ok(user)
}
pub async fn get_user_by_id(pool: &SqlitePool, id: i64) -> Result<UserRecord> {
    let user = sqlx::query_as::<_, UserRecord>(
        r"
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
        ",
    )
    .bind(id)
    .fetch_one(pool)
    .await?;

    Ok(user)
}

pub async fn set_user_enabled(pool: &SqlitePool, id: i64, enabled: bool) -> Result<()> {
    let now = Utc::now();
    let mut transaction = pool.begin().await?;

    let result = sqlx::query(
        r"
        UPDATE users
        SET enabled = ?, updated_at = ?
        WHERE id = ?
        ",
    )
    .bind(enabled)
    .bind(now)
    .bind(id)
    .execute(&mut *transaction)
    .await?;

    if result.rows_affected() == 0 {
        bail!("user not found");
    }
    bump_desired_generation(&mut transaction).await?;
    transaction.commit().await?;
    Ok(())
}

pub async fn reset_user_subscription_token(pool: &SqlitePool, id: i64) -> Result<String> {
    let now = Utc::now();
    let new_token = Uuid::new_v4().simple().to_string();

    let result = sqlx::query(
        r"
        UPDATE users
        SET subscription_token = ?, updated_at = ?
        WHERE id = ?
        ",
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
    let mut transaction = pool.begin().await?;
    let result = sqlx::query(
        r"
        DELETE FROM users
        WHERE id = ?
        ",
    )
    .bind(id)
    .execute(&mut *transaction)
    .await?;

    if result.rows_affected() == 0 {
        bail!("user not found");
    }
    bump_desired_generation(&mut transaction).await?;
    transaction.commit().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adapter::{
        ClientRenderContext, ConfigField, ProtocolAdapter, ProtocolAdapterManifest, ServerFragment,
        ServerRenderContext, ADAPTER_API_VERSION,
    };
    use std::{
        collections::BTreeSet,
        path::{Path, PathBuf},
        sync::Arc,
    };

    struct StateMigrationAdapter {
        manifest: ProtocolAdapterManifest,
    }

    impl StateMigrationAdapter {
        fn new() -> Self {
            Self {
                manifest: ProtocolAdapterManifest {
                    api_version: ADAPTER_API_VERSION,
                    id: "returning-adapter".to_string(),
                    display_name: "Returning adapter".to_string(),
                    schema_version: 1,
                    required_core_capabilities: BTreeSet::from(["test-capability".to_string()]),
                    user_participates: false,
                },
            }
        }
    }

    impl ProtocolAdapter for StateMigrationAdapter {
        fn manifest(&self) -> &ProtocolAdapterManifest {
            &self.manifest
        }

        fn fields(&self) -> &[ConfigField] {
            &[]
        }

        fn validate_config(&self, _schema_version: u32, _config: &serde_json::Value) -> Result<()> {
            Ok(())
        }

        fn migrate_config(
            &self,
            from_version: u32,
            config: serde_json::Value,
        ) -> Result<(u32, serde_json::Value)> {
            Ok((from_version, config))
        }

        fn state_schema_version(&self) -> u32 {
            2
        }

        fn migrate_state(
            &self,
            from_version: u32,
            mut config: serde_json::Value,
        ) -> Result<(u32, serde_json::Value)> {
            if from_version > self.state_schema_version() {
                bail!("adapter state schema is newer than this adapter");
            }
            config["migrated"] = serde_json::json!(true);
            Ok((self.state_schema_version(), config))
        }

        fn client_secret_references(
            &self,
            _config: &serde_json::Value,
        ) -> Result<Vec<crate::adapter::SecretRef>> {
            Ok(Vec::new())
        }

        fn server_secret_references(
            &self,
            _config: &serde_json::Value,
        ) -> Result<Vec<crate::adapter::SecretRef>> {
            Ok(Vec::new())
        }

        fn render_client(&self, _context: &ClientRenderContext<'_>) -> Result<serde_json::Value> {
            bail!("not used by storage migration tests")
        }

        fn render_server(&self, _context: &ServerRenderContext<'_>) -> Result<ServerFragment> {
            bail!("not used by storage migration tests")
        }
    }

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
    async fn adapter_state_migration_is_idempotent() -> Result<()> {
        let (pool, path) = test_pool().await?;

        init_db(&pool).await?;
        let migrations: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM schema_migrations")
            .fetch_one(&pool)
            .await?;
        assert_eq!(migrations, 1);

        let integrity: String = sqlx::query_scalar("PRAGMA integrity_check")
            .fetch_one(&pool)
            .await?;
        assert_eq!(integrity, "ok");

        close_and_remove(pool, &path).await;
        Ok(())
    }

    #[tokio::test]
    async fn unavailable_adapter_state_survives_restart_unchanged() -> Result<()> {
        let (pool, path) = test_pool().await?;
        let state = PersistedAdapterState {
            adapter_id: "detached-adapter".to_string(),
            adapter_kind: adapter_kind::PROTOCOL.to_string(),
            resource_id: "primary".to_string(),
            schema_version: 7,
            config: serde_json::json!({
                "opaque": {"future": [1, 2, 3]},
                "unknown_secret_reference": "preserve-only"
            }),
            enabled: false,
        };
        upsert_adapter_state(&pool, &state).await?;
        let before = list_adapter_state_records(&pool).await?;

        init_db(&pool).await?;
        let empty_protocols = ProtocolRegistry::default();
        let empty_cores = CoreRegistry::default();
        assert!(
            migrate_available_adapter_states(&pool, &empty_protocols, &empty_cores)
                .await?
                .is_empty()
        );
        let after = list_adapter_state_records(&pool).await?;

        assert_eq!(before.len(), 1);
        assert_eq!(before[0].adapter_id, after[0].adapter_id);
        assert_eq!(before[0].schema_version, after[0].schema_version);
        assert_eq!(before[0].config_json, after[0].config_json);
        assert_eq!(before[0].enabled, after[0].enabled);
        assert_eq!(before[0].updated_at, after[0].updated_at);

        close_and_remove(pool, &path).await;
        Ok(())
    }

    #[tokio::test]
    async fn returning_adapter_migrates_preserved_state_without_losing_unknown_fields() -> Result<()>
    {
        let (pool, path) = test_pool().await?;
        upsert_adapter_state(
            &pool,
            &PersistedAdapterState {
                adapter_id: "returning-adapter".to_string(),
                adapter_kind: adapter_kind::PROTOCOL.to_string(),
                resource_id: "primary".to_string(),
                schema_version: 1,
                config: serde_json::json!({"known": true, "future": {"keep": 42}}),
                enabled: true,
            },
        )
        .await?;
        let mut protocols = ProtocolRegistry::default();
        protocols.register(Arc::new(StateMigrationAdapter::new()))?;

        let migrated =
            migrate_available_adapter_states(&pool, &protocols, &CoreRegistry::default()).await?;
        assert_eq!(migrated, vec!["protocol:returning-adapter:primary"]);
        let state = list_adapter_states(&pool).await?.remove(0);
        assert_eq!(state.schema_version, 2);
        assert_eq!(state.config["migrated"], true);
        assert_eq!(state.config["future"]["keep"], 42);
        assert!(
            migrate_available_adapter_states(&pool, &protocols, &CoreRegistry::default(),)
                .await?
                .is_empty()
        );

        close_and_remove(pool, &path).await;
        Ok(())
    }

    #[tokio::test]
    async fn first_admin_creation_is_atomic() -> Result<()> {
        let (pool, path) = test_pool().await?;
        let first_pool = pool.clone();
        let second_pool = pool.clone();

        let (first, second) = tokio::join!(
            create_first_admin(&first_pool, "owner-a", "hash-a"),
            create_first_admin(&second_pool, "owner-b", "hash-b")
        );

        assert_ne!(first.is_ok(), second.is_ok());
        assert_eq!(admin_count(&pool).await?, 1);
        let owner = first
            .ok()
            .or_else(|| second.ok())
            .expect("one owner exists");
        assert!(is_owner_admin_id(&pool, owner.id).await?);

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
    async fn password_rotation_revokes_all_admin_sessions() -> Result<()> {
        let (pool, path) = test_pool().await?;
        let admin = create_admin(&pool, "admin", "old-hash").await?;
        create_admin_session(
            &pool,
            admin.id,
            "session-token-hash",
            Utc::now() + chrono::Duration::days(1),
        )
        .await?;

        update_admin_password_and_revoke_sessions(&pool, admin.id, "new-hash").await?;

        let updated = get_admin_by_id(&pool, admin.id)
            .await?
            .expect("administrator should still exist");
        assert_eq!(updated.password_hash, "new-hash");
        assert!(get_valid_admin_session(&pool, "session-token-hash")
            .await?
            .is_none());

        close_and_remove(pool, &path).await;
        Ok(())
    }

    #[tokio::test]
    async fn settings_and_secrets_round_trip() -> Result<()> {
        let (pool, path) = test_pool().await?;

        upsert_setting(&pool, "subscription_domain", "atlas.example.test").await?;
        upsert_setting(&pool, "subscription_domain", "edge.example.test").await?;
        upsert_settings(
            &pool,
            &[
                ("panel_update_time".to_string(), "05:00".to_string()),
                ("panel_update_enabled".to_string(), "true".to_string()),
            ],
        )
        .await?;

        let setting = get_setting(&pool, "subscription_domain")
            .await?
            .expect("setting should exist");
        assert_eq!(setting.value, "edge.example.test");

        let settings = list_settings(&pool).await?;
        assert_eq!(settings.len(), 3);
        let update_time = get_setting(&pool, "panel_update_time")
            .await?
            .expect("batched setting should exist");
        let update_enabled = get_setting(&pool, "panel_update_enabled")
            .await?
            .expect("batched setting should exist");
        assert_eq!(update_time.updated_at, update_enabled.updated_at);

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
    async fn only_runtime_setting_changes_advance_desired_generation() -> Result<()> {
        let (pool, path) = test_pool().await?;
        let runtime_keys = ["subscription_domain", "node_domain"];

        let generation = upsert_settings_with_runtime_keys(
            &pool,
            &[("panel_name".to_string(), "Operations".to_string())],
            &runtime_keys,
        )
        .await?;
        assert_eq!(generation, None);
        assert_eq!(get_reconcile_state(&pool).await?.desired_generation, 0);

        let generation = upsert_settings_with_runtime_keys(
            &pool,
            &[(
                "subscription_domain".to_string(),
                "sub.example.test".to_string(),
            )],
            &runtime_keys,
        )
        .await?;
        assert_eq!(generation, Some(1));

        let generation = upsert_settings_with_runtime_keys(
            &pool,
            &[(
                "subscription_domain".to_string(),
                "sub.example.test".to_string(),
            )],
            &runtime_keys,
        )
        .await?;
        assert_eq!(generation, None);
        assert_eq!(get_reconcile_state(&pool).await?.desired_generation, 1);

        close_and_remove(pool, &path).await;
        Ok(())
    }

    #[test]
    fn sensitive_database_records_are_redacted_in_debug_output() {
        let now = Utc::now();
        let secret = SecretRecord {
            name: "runtime.secret".to_string(),
            value: "plaintext-canary".to_string(),
            created_at: now,
            updated_at: now,
        };
        let user = UserRecord {
            id: 1,
            username: "operator".to_string(),
            uuid: "uuid-canary".to_string(),
            subscription_token: "subscription-canary".to_string(),
            enabled: true,
            traffic_limit_bytes: None,
            traffic_used_bytes: 0,
            expires_at: None,
            created_at: now,
            updated_at: now,
        };
        let subscription_user = crate::models::SubscriptionUser {
            username: "operator".to_string(),
            uuid: "subscription-uuid-canary".to_string(),
            subscription_token: "subscription-model-canary".to_string(),
        };
        let debug = format!("{secret:?} {user:?} {subscription_user:?}");
        assert!(!debug.contains("plaintext-canary"));
        assert!(!debug.contains("uuid-canary"));
        assert!(!debug.contains("subscription-canary"));
        assert!(!debug.contains("subscription-uuid-canary"));
        assert!(!debug.contains("subscription-model-canary"));
        assert!(debug.contains("[REDACTED]"));
    }

    #[tokio::test]
    async fn protocol_profiles_store_structured_config() -> Result<()> {
        let (pool, path) = test_pool().await?;

        let profile = create_protocol_profile(
            &pool,
            NewProtocolProfile {
                name: "VLESS-XHTTP-SAFE".to_string(),
                protocol_id: "vless-reality-xhttp".to_string(),
                schema_version: 1,
                role: ProxyRole::AutoSafe,
                enabled: true,
                server: "iberia.example.test".to_string(),
                port: 8443,
                preferred_core_id: None,
                managed_resource_id: None,
                config: serde_json::json!({
                    "server_name": "www.microsoft.com",
                    "path": "/api/v1",
                    "public_key_secret": "xray.reality.public_key",
                    "short_id_secret": "xray.reality.short_id"
                }),
            },
        )
        .await?;

        assert_eq!(profile.kind, "vless-reality-xhttp");
        assert_eq!(profile.role, "auto-safe");
        assert_eq!(profile.port, 8443);

        let config: serde_json::Value = serde_json::from_str(&profile.config_json)?;
        assert_eq!(config["path"], "/api/v1");

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
                protocol_id: "vless-reality-xhttp".to_string(),
                schema_version: 1,
                role: ProxyRole::AutoSafe,
                enabled: true,
                server: "old.example.test".to_string(),
                port: 8443,
                preferred_core_id: None,
                managed_resource_id: None,
                config: serde_json::json!({"server_name":"www.microsoft.com","path":"/api/v1","public_key_secret":"xray.reality.public_key","short_id_secret":"xray.reality.short_id"}),
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
                preferred_core_id: None,
                managed_resource_id: None,
                config: serde_json::json!({"server_name":"www.apple.com","path":"/edge","public_key_secret":"xray.reality.public_key","short_id_secret":"xray.reality.short_id"}),
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
    async fn default_protocol_profiles_are_added_without_overwriting_existing_profiles(
    ) -> Result<()> {
        let (pool, path) = test_pool().await?;

        ensure_default_protocol_profiles(&pool).await?;
        let profiles = list_protocol_profiles_decoded(&pool).await?;
        assert_eq!(profiles.len(), 6);
        assert!(profiles
            .iter()
            .any(|profile| profile.protocol_id == "vless-reality-tcp"));

        update_protocol_profile(
            &pool,
            UpdateProtocolProfile {
                name: "VLESS-XHTTP-SAFE".to_string(),
                enabled: true,
                server: "custom.example.test".to_string(),
                port: 9443,
                preferred_core_id: None,
                managed_resource_id: None,
                config: serde_json::json!({"server_name":"www.apple.com","path":"/custom","public_key_secret":"xray.reality.public_key","short_id_secret":"xray.reality.short_id"}),
            },
        )
        .await?;

        ensure_default_protocol_profiles(&pool).await?;
        let profiles = list_protocol_profiles_decoded(&pool).await?;
        assert_eq!(profiles.len(), 6);
        let customized = profiles
            .iter()
            .find(|profile| profile.name == "VLESS-XHTTP-SAFE")
            .expect("built-in profile should remain available");
        assert!(customized.enabled);
        assert_eq!(customized.server, "custom.example.test");
        assert_eq!(customized.port, 9443);

        close_and_remove(pool, &path).await;
        Ok(())
    }

    #[tokio::test]
    async fn adapter_migration_is_idempotent_and_preserves_profiles_and_unknown_data() -> Result<()>
    {
        let (pool, path) = test_pool().await?;
        ensure_default_protocol_profiles(&pool).await?;
        let original = list_protocol_profiles(&pool).await?;
        assert_eq!(original.len(), 6);
        let mut expected_enabled = std::collections::BTreeMap::new();

        for (index, record) in original.iter().enumerate() {
            expected_enabled.insert(record.id, index % 2 == 0);
            let mut config: serde_json::Value = serde_json::from_str(&record.config_json)?;
            config["future_option"] = serde_json::json!({"preserve": index});
            if let Some(object) = config.as_object_mut() {
                object.remove("private_key_secret");
            }
            sqlx::query(
                r"
                UPDATE protocol_profiles
                SET enabled = ?, config_json = ?, preferred_core_id = NULL,
                    managed_resource_id = NULL
                WHERE id = ?
                ",
            )
            .bind(index % 2 == 0)
            .bind(serde_json::to_string(&config)?)
            .bind(record.id)
            .execute(&pool)
            .await?;
        }
        create_protocol_profile(
            &pool,
            NewProtocolProfile {
                name: "EXTERNAL-PRESERVED".to_string(),
                protocol_id: "external-future-adapter".to_string(),
                schema_version: 7,
                role: ProxyRole::Manual,
                enabled: false,
                server: "future.example.test".to_string(),
                port: 18443,
                preferred_core_id: Some("external-future-core".to_string()),
                managed_resource_id: Some("external-future-resource".to_string()),
                config: serde_json::json!({
                    "opaque": [1, 2, 3],
                    "secret_ref": "future.secret.reference"
                }),
            },
        )
        .await?;

        let registry = crate::adapters::protocol_registry()?;
        migrate_protocol_adapter_configs(&pool, &registry).await?;
        let first = list_protocol_profiles(&pool).await?;
        migrate_protocol_adapter_configs(&pool, &registry).await?;
        let second = list_protocol_profiles(&pool).await?;

        assert_eq!(first.len(), 7);
        assert_eq!(first, second);
        for record in first
            .iter()
            .filter(|record| record.kind != "external-future-adapter")
        {
            assert_eq!(Some(&record.enabled), expected_enabled.get(&record.id));
            let config: serde_json::Value = serde_json::from_str(&record.config_json)?;
            assert!(config["future_option"]["preserve"].is_number());
            assert!(record.managed_resource_id.is_some());
        }
        let external = first
            .iter()
            .find(|record| record.kind == "external-future-adapter")
            .expect("unknown adapter row must survive migration");
        assert!(!external.enabled);
        assert_eq!(external.schema_version, 7);
        assert_eq!(external.role, "manual");
        assert!(external.config_json.contains("future.secret.reference"));

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
