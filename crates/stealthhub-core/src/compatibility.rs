//! Offline compatibility verification for explicit SQLite database copies.
//!
//! Reports contain only row counts, column names, hashes and boolean checks.
//! Durable values, identities, addresses and secrets are never serialized.

use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
};

use anyhow::{bail, Context, Result};
use serde::Serialize;
use sha2::{Digest, Sha256};
use sqlx::{AssertSqlSafe, Row, SqlitePool, TypeInfo, ValueRef};
use uuid::Uuid;

use crate::storage::{init_db, open_pool};

const PRODUCTION_DATABASE: &str = "/var/lib/infiproxy/infiproxy.sqlite";
const DURABLE_TABLES: &[&str] = &[
    "admins",
    "admin_sessions",
    "users",
    "settings",
    "secret_values",
    "protocol_profiles",
    "reconcile_state",
    "adapter_state",
    "schema_migrations",
    "client_transport_pools",
    "client_transport_pool_members",
    "client_routing_rules",
    "routing_rule_sets",
    "routing_rule_entries",
    "routing_rule_sources",
    "runtime_user_sync",
    "client_dns_policy",
];

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct TableFingerprint {
    pub row_count: u64,
    pub columns: Vec<String>,
    pub sha256: String,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct DatabaseSnapshot {
    pub tables: BTreeMap<String, TableFingerprint>,
    pub integrity_ok: bool,
    pub foreign_key_violations: u64,
    pub generation_relationship_valid: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct CompatibilityReport {
    pub source: PathBuf,
    pub working_copy: PathBuf,
    pub legacy_data_preserved: bool,
    pub migration_idempotent: bool,
    pub integrity_ok: bool,
    pub foreign_key_violations: u64,
    pub routing_schema_present: bool,
    pub before: DatabaseSnapshot,
    pub after_first_migration: DatabaseSnapshot,
    pub after_second_migration: DatabaseSnapshot,
}

impl CompatibilityReport {
    #[must_use]
    pub fn passed(&self) -> bool {
        self.legacy_data_preserved
            && self.migration_idempotent
            && self.integrity_ok
            && self.foreign_key_violations == 0
            && self.routing_schema_present
            && self.after_second_migration.generation_relationship_valid
    }
}

/// Copies and migrates an explicitly supplied offline database copy.
pub async fn run(source: &Path) -> Result<CompatibilityReport> {
    validate_source_path(source)?;
    let source = source
        .canonicalize()
        .context("canonicalize compatibility source")?;
    reject_live_wal(&source)?;
    let working_copy = working_copy_path(&source)?;
    fs::copy(&source, &working_copy).context("create compatibility working copy")?;
    set_private_permissions(&working_copy)?;

    let database_url = format!("sqlite://{}?mode=rwc", working_copy.display());
    let pool = open_pool(&database_url).await?;
    let before = snapshot(&pool, None).await?;
    init_db(&pool).await?;
    let after_baseline = snapshot(&pool, Some(&before)).await?;
    let after_first_migration = snapshot(&pool, None).await?;
    init_db(&pool).await?;
    let after_second_migration = snapshot(&pool, None).await?;
    pool.close().await;

    let legacy_data_preserved = preserves_baseline(&before, &after_baseline);
    let migration_idempotent = after_first_migration == after_second_migration;
    let integrity_ok = after_second_migration.integrity_ok;
    let foreign_key_violations = after_second_migration.foreign_key_violations;
    let routing_schema_present = [
        "client_transport_pools",
        "client_transport_pool_members",
        "client_routing_rules",
        "routing_rule_sets",
        "routing_rule_entries",
        "routing_rule_sources",
        "runtime_user_sync",
        "client_dns_policy",
    ]
    .iter()
    .all(|table| after_second_migration.tables.contains_key(*table));
    Ok(CompatibilityReport {
        source,
        working_copy,
        legacy_data_preserved,
        migration_idempotent,
        integrity_ok,
        foreign_key_violations,
        routing_schema_present,
        before,
        after_first_migration,
        after_second_migration,
    })
}

fn validate_source_path(source: &Path) -> Result<()> {
    if source.as_os_str().is_empty() || source == Path::new(PRODUCTION_DATABASE) {
        bail!("refusing canonical production database path");
    }
    if !source.is_file() {
        bail!("compatibility source must be an explicit existing file");
    }
    if let (Ok(source), Ok(production)) = (
        source.canonicalize(),
        Path::new(PRODUCTION_DATABASE).canonicalize(),
    ) {
        if source == production {
            bail!("refusing canonical production database path");
        }
    }
    Ok(())
}

fn reject_live_wal(source: &Path) -> Result<()> {
    let wal = PathBuf::from(format!("{}-wal", source.display()));
    if wal.metadata().is_ok_and(|metadata| metadata.len() > 0) {
        bail!("source has a non-empty WAL; create an offline SQLite backup first");
    }
    Ok(())
}

fn working_copy_path(source: &Path) -> Result<PathBuf> {
    let parent = source
        .parent()
        .context("compatibility source has no parent")?;
    let stem = source
        .file_stem()
        .and_then(|value| value.to_str())
        .unwrap_or("database");
    Ok(parent.join(format!(
        "{stem}.compat-working-{}.sqlite",
        Uuid::new_v4().simple()
    )))
}

#[cfg(unix)]
fn set_private_permissions(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(())
}

#[cfg(not(unix))]
fn set_private_permissions(_path: &Path) -> Result<()> {
    Ok(())
}

async fn snapshot(
    pool: &SqlitePool,
    baseline: Option<&DatabaseSnapshot>,
) -> Result<DatabaseSnapshot> {
    let mut tables = BTreeMap::new();
    for table in DURABLE_TABLES {
        if !table_exists(pool, table).await? {
            continue;
        }
        let columns = if let Some(baseline) = baseline {
            baseline.tables.get(*table).map(|fact| fact.columns.clone())
        } else {
            None
        }
        .unwrap_or(column_names(pool, table).await?);
        tables.insert(
            (*table).to_string(),
            fingerprint_table(pool, table, columns).await?,
        );
    }
    let integrity: String = sqlx::query_scalar("PRAGMA integrity_check")
        .fetch_one(pool)
        .await?;
    let foreign_key_violations = sqlx::query("PRAGMA foreign_key_check")
        .fetch_all(pool)
        .await?
        .len() as u64;
    let generation_relationship_valid = if table_exists(pool, "reconcile_state").await? {
        sqlx::query_as::<_, (i64, i64)>(
            "SELECT desired_generation, applied_generation FROM reconcile_state WHERE singleton = 1",
        )
        .fetch_optional(pool)
        .await?
        .is_none_or(|(desired, applied)| desired >= 0 && applied >= 0 && applied <= desired)
    } else {
        true
    };
    Ok(DatabaseSnapshot {
        tables,
        integrity_ok: integrity == "ok",
        foreign_key_violations,
        generation_relationship_valid,
    })
}

async fn table_exists(pool: &SqlitePool, table: &str) -> Result<bool> {
    Ok(sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = ?",
    )
    .bind(table)
    .fetch_one(pool)
    .await?
        == 1)
}

async fn column_names(pool: &SqlitePool, table: &str) -> Result<Vec<String>> {
    validate_identifier(table)?;
    let query = format!("PRAGMA table_info(\"{table}\")");
    let columns = sqlx::query(AssertSqlSafe(query))
        .fetch_all(pool)
        .await?
        .into_iter()
        .map(|row| row.try_get::<String, _>("name"))
        .collect::<std::result::Result<Vec<_>, _>>()?;
    for column in &columns {
        validate_identifier(column)?;
    }
    Ok(columns)
}

async fn fingerprint_table(
    pool: &SqlitePool,
    table: &str,
    columns: Vec<String>,
) -> Result<TableFingerprint> {
    validate_identifier(table)?;
    if columns.is_empty() {
        bail!("durable table has no columns");
    }
    for column in &columns {
        validate_identifier(column)?;
    }
    let projection = columns
        .iter()
        .map(|column| format!("\"{column}\""))
        .collect::<Vec<_>>()
        .join(", ");
    let query = format!("SELECT {projection} FROM \"{table}\" ORDER BY rowid");
    let rows = sqlx::query(AssertSqlSafe(query)).fetch_all(pool).await?;
    let mut hash = Sha256::new();
    for column in &columns {
        hash.update(column.as_bytes());
        hash.update([0]);
    }
    for row in &rows {
        for index in 0..row.columns().len() {
            let value = row.try_get_raw(index)?;
            hash.update(value.type_info().name().as_bytes());
            hash.update([0]);
            if value.is_null() {
                hash.update([0xff]);
            } else {
                match value.type_info().name() {
                    "INTEGER" => hash.update(row.try_get::<i64, _>(index)?.to_le_bytes()),
                    "REAL" => hash.update(row.try_get::<f64, _>(index)?.to_bits().to_le_bytes()),
                    "TEXT" => hash.update(row.try_get::<String, _>(index)?.as_bytes()),
                    "BLOB" => hash.update(row.try_get::<Vec<u8>, _>(index)?),
                    other => bail!("unsupported SQLite storage class: {other}"),
                }
            }
            hash.update([0]);
        }
    }
    Ok(TableFingerprint {
        row_count: rows.len() as u64,
        columns,
        sha256: hex_digest(&hash.finalize()),
    })
}

fn hex_digest(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

fn validate_identifier(value: &str) -> Result<()> {
    if value.is_empty()
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
    {
        bail!("invalid SQLite identifier in compatibility snapshot");
    }
    Ok(())
}

fn preserves_baseline(before: &DatabaseSnapshot, after: &DatabaseSnapshot) -> bool {
    before.tables.iter().all(|(name, expected)| {
        after.tables.get(name).is_some_and(|actual| {
            actual.row_count == expected.row_count
                && actual.columns.starts_with(&expected.columns)
                && actual.sha256 == expected.sha256
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use sqlx::sqlite::SqliteConnectOptions;
    use std::str::FromStr;

    #[test]
    fn production_path_is_always_refused() {
        let error = validate_source_path(Path::new(PRODUCTION_DATABASE)).unwrap_err();
        assert!(error.to_string().contains("refusing canonical production"));
    }

    #[tokio::test]
    async fn legacy_copy_is_preserved_and_migration_is_idempotent() -> Result<()> {
        let source = std::env::temp_dir().join(format!(
            "infiproxy-legacy-{}.sqlite",
            Uuid::new_v4().simple()
        ));
        let options = SqliteConnectOptions::from_str(&format!("sqlite://{}", source.display()))?
            .create_if_missing(true);
        let pool = SqlitePool::connect_with(options).await?;
        sqlx::query(
            "CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, subscription_token TEXT, enabled INTEGER, future_json TEXT)",
        )
        .execute(&pool)
        .await?;
        sqlx::query(
            "INSERT INTO users VALUES (1, 'operator', 'secret-token', 0, '{\"future\":42}')",
        )
        .execute(&pool)
        .await?;
        pool.close().await;

        let report = run(&source).await?;
        assert!(report.passed());
        assert_eq!(report.before.tables["users"].row_count, 1);
        let json = serde_json::to_string(&report)?;
        assert!(!json.contains("operator"));
        assert!(!json.contains("secret-token"));
        assert!(!json.contains("future\":42"));

        let _ = fs::remove_file(&source);
        let _ = fs::remove_file(&report.working_copy);
        Ok(())
    }
}
