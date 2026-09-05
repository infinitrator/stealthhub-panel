//! Read-only, bounded node observations. No migrations or credential queries.

use crate::command;
use anyhow::{bail, Result};
use chrono::Utc;
use serde::Serialize;
use sqlx::{sqlite::SqliteConnectOptions, Connection, Row, SqliteConnection};
use std::{collections::BTreeMap, fs, io::Read, path::Path, str::FromStr, time::Duration};
use stealthhub_core::{
    access::UserAccessState,
    module_manifest::{load_registry, ReadOptions},
};

#[derive(Clone, Debug, Default, Serialize)]
pub struct Snapshot {
    pub hostname: String,
    pub revision: String,
    pub panel: String,
    pub reconcile: String,
    pub sections: BTreeMap<String, String>,
    pub modules: Vec<String>,
    pub services: Vec<String>,
    pub active_runtimes: usize,
    pub panel_url: String,
}

/// Bounds both allocation and input size; files are data and never sourced.
pub fn read_small(path: &Path) -> Result<String> {
    let mut content = String::new();
    fs::File::open(path)?
        .take(65537)
        .read_to_string(&mut content)?;
    if content.len() > 65536 {
        bail!("status file exceeds 64 KiB");
    }
    Ok(content)
}

fn filtered_env(path: &str, keys: &[&str]) -> BTreeMap<String, String> {
    read_small(Path::new(path))
        .unwrap_or_default()
        .lines()
        .filter_map(|line| {
            let (key, value) = line.split_once('=')?;
            keys.contains(&key)
                .then(|| (key.to_string(), command::safe_output(value)))
        })
        .collect()
}

async fn probe(program: &str, args: &[&str]) -> String {
    command::run(
        program,
        &args.iter().map(|v| (*v).to_string()).collect::<Vec<_>>(),
        None,
        Duration::from_secs(3),
        false,
    )
    .await
    .unwrap_or_else(|e| format!("Unavailable: {e}"))
}

async fn database(snapshot: &mut Snapshot) -> Result<()> {
    let config = filtered_env(
        "/etc/infiproxy/infiproxy.env",
        &["INFIPROXY_DB", "STEALTHHUB_DB"],
    );
    let url = config
        .get("INFIPROXY_DB")
        .or_else(|| config.get("STEALTHHUB_DB"))
        .map_or(
            "sqlite:///var/lib/infiproxy/infiproxy.sqlite",
            String::as_str,
        );
    let options = SqliteConnectOptions::from_str(url)?
        .read_only(true)
        .create_if_missing(false)
        .busy_timeout(Duration::from_secs(2));
    let mut db = SqliteConnection::connect_with(&options).await?;
    let row = sqlx::query("SELECT desired_generation,applied_generation,status,last_error FROM reconcile_state WHERE singleton=1").fetch_one(&mut db).await?;
    snapshot.reconcile = row.try_get("status")?;
    snapshot.sections.insert(
        "Reconcile".into(),
        format!(
            "Desired: {}\nApplied: {}\nState: {}\nDetail: {}",
            row.try_get::<i64, _>("desired_generation")?,
            row.try_get::<i64, _>("applied_generation")?,
            snapshot.reconcile,
            command::safe_output(
                &row.try_get::<Option<String>, _>("last_error")?
                    .unwrap_or_default()
            )
        ),
    );
    let users = sqlx::query("SELECT id,username,enabled,expires_at,traffic_limit_bytes,traffic_used_bytes FROM users ORDER BY id DESC LIMIT 500").fetch_all(&mut db).await?;
    let now = Utc::now();
    let mut lines = vec![
        "ID / USER / EFFECTIVE ACCESS / EXPIRY (UTC)".into(),
        "Stored quota only; live traffic accounting unavailable.".into(),
    ];
    for user in users {
        let expiry = user.try_get::<Option<chrono::DateTime<Utc>>, _>("expires_at")?;
        let access = UserAccessState::evaluate(
            user.try_get("enabled")?,
            expiry,
            user.try_get("traffic_limit_bytes")?,
            user.try_get("traffic_used_bytes")?,
            now,
        );
        let status = if access.allowed() {
            "Active".into()
        } else {
            [
                access.disabled.then_some("Disabled"),
                access.expired.then_some("Expired"),
                access.quota_exceeded.then_some("Quota blocked"),
            ]
            .into_iter()
            .flatten()
            .collect::<Vec<_>>()
            .join(" / ")
        };
        lines.push(format!(
            "{}  {}  {}  {}",
            user.try_get::<i64, _>("id")?,
            user.try_get::<String, _>("username")?,
            status,
            expiry.map_or("Never".into(), |v| v.to_rfc3339())
        ));
    }
    snapshot
        .sections
        .insert("Users".into(), command::safe_output(&lines.join("\n")));
    let profiles = sqlx::query("SELECT name,kind,enabled,server,port,preferred_core_id FROM protocol_profiles ORDER BY name LIMIT 500").fetch_all(&mut db).await?;
    let lines = profiles
        .iter()
        .map(|p| {
            Ok(format!(
                "{} / {} / {} / {}:{} / runtime {}",
                p.try_get::<String, _>("name")?,
                p.try_get::<String, _>("kind")?,
                if p.try_get::<bool, _>("enabled")? {
                    "Enabled"
                } else {
                    "Disabled"
                },
                p.try_get::<String, _>("server")?,
                p.try_get::<i64, _>("port")?,
                p.try_get::<Option<String>, _>("preferred_core_id")?
                    .unwrap_or("automatic".into())
            ))
        })
        .collect::<Result<Vec<_>>>()?;
    snapshot
        .sections
        .insert("Profiles".into(), command::safe_output(&lines.join("\n")));
    let policy = sqlx::query(
        "SELECT key,value FROM settings WHERE key IN ('panel_update_enabled','panel_update_time')",
    )
    .fetch_all(&mut db)
    .await?;
    for row in policy {
        snapshot
            .sections
            .entry("Updates".into())
            .or_default()
            .push_str(&format!(
                "\n{} = {}",
                row.try_get::<String, _>("key")?,
                row.try_get::<String, _>("value")?
            ));
    }
    db.close().await?;
    Ok(())
}

pub async fn collect() -> Snapshot {
    let mut s = Snapshot {
        hostname: probe("hostname", &[]).await.trim().to_string(),
        revision: read_small(Path::new(
            "/var/lib/infiproxy-maintenance/panel-last-applied.sha",
        ))
        .unwrap_or("Unavailable".into())
        .trim()
        .chars()
        .take(12)
        .collect(),
        ..Snapshot::default()
    };
    let state = probe(
        "systemctl",
        &[
            "show",
            "infiproxy.service",
            "--property=ActiveState",
            "--value",
        ],
    )
    .await;
    s.panel = state.trim().to_string();
    let mut updates = filtered_env("/etc/infiproxy-update.conf", &["REPO", "REF"]);
    updates.extend(filtered_env(
        "/var/lib/infiproxy-maintenance/panel-update-status.env",
        &["CURRENT_SHA", "LATEST_SHA", "CHECKED_AT", "STATUS"],
    ));
    s.sections.insert(
        "Updates".into(),
        updates
            .iter()
            .map(|(k, v)| format!("{k}: {v}"))
            .collect::<Vec<_>>()
            .join("\n"),
    );
    if let Err(e) = database(&mut s).await {
        s.sections
            .insert("Database".into(), format!("Unavailable: {e}"));
    } else {
        s.sections.insert(
            "Database".into(),
            "Read-only database access succeeded".into(),
        );
    }
    s.services = vec![
        "infiproxy.service".into(),
        "infiproxy-reconcile.service".into(),
        "infiproxy-panel-update.service".into(),
        "infiproxy-module-update.service".into(),
        "nginx.service".into(),
        "ssh.service".into(),
    ];
    let mut runtime_lines = Vec::new();
    match load_registry(
        Path::new("/etc/infiproxy-modules.d"),
        ReadOptions {
            root_owned: true,
            registration: false,
        },
    ) {
        Ok(specs) => {
            for spec in specs.into_iter().take(64) {
                let status = probe(
                    "systemctl",
                    &[
                        "show",
                        &spec.service,
                        "--property=ActiveState,UnitFileState,Result,ExecMainStatus",
                        "--no-pager",
                    ],
                )
                .await;
                if status.lines().any(|line| line == "ActiveState=active") {
                    s.active_runtimes += 1;
                }
                let version = read_small(
                    &Path::new("/var/lib/infiproxy-maintenance/module-versions")
                        .join(format!("{}.version", spec.id)),
                )
                .unwrap_or("Unknown".into());
                let capabilities = stealthhub_core::adapters::core_registry()
                    .ok()
                    .and_then(|registry| {
                        registry.get(&spec.id).map(|a| {
                            a.manifest()
                                .capabilities
                                .iter()
                                .map(|c| c.as_str())
                                .collect::<Vec<_>>()
                                .join(", ")
                        })
                    })
                    .unwrap_or("Missing adapter".into());
                runtime_lines.push(format!(
                    "{} / {}\nInstalled: {} / version {}\n{}\nCapabilities: {}\nConfig: {}\n",
                    spec.id,
                    spec.service,
                    Path::new(&spec.binary_path).exists(),
                    version.trim(),
                    status.trim(),
                    capabilities,
                    spec.config_path
                ));
                s.modules.push(spec.id);
                s.services.push(spec.service);
            }
        }
        Err(e) => runtime_lines.push(format!("Manifest registry unavailable: {e}")),
    }
    s.sections.insert(
        "Runtimes".into(),
        if runtime_lines.is_empty() {
            "No registered runtime modules".into()
        } else {
            command::safe_output(&runtime_lines.join("\n"))
        },
    );
    let (uptime, health, ready, listeners) = tokio::join!(
        probe("uptime", &[]),
        probe(
            "curl",
            &[
                "--noproxy",
                "*",
                "--silent",
                "--show-error",
                "--fail",
                "--max-time",
                "3",
                "http://127.0.0.1:8080/health"
            ]
        ),
        probe(
            "curl",
            &[
                "--noproxy",
                "*",
                "--silent",
                "--show-error",
                "--fail",
                "--max-time",
                "3",
                "http://127.0.0.1:8080/ready"
            ]
        ),
        probe("ss", &["-lntu"])
    );
    s.sections.insert("Dashboard".into(), format!("NODE: {}\nPANEL PROCESS: {}\nDEPLOYED REV: {}\n{}\nUPTIME: {}\nRegistered runtimes: {}\nHEALTH: {}\nREADY: {}\n\n{}",s.hostname,s.panel,s.revision,s.sections.get("Reconcile").unwrap_or(&"Reconcile unavailable".into()),uptime.trim(),s.modules.len(),health.trim(),ready.trim(),s.sections.get("Database").unwrap_or(&String::new())));
    s.sections.insert(
        "Diagnostics".into(),
        format!(
            "LISTENERS (process/listener checks, no handshake proof)\n{listeners}\n\nDB: {}",
            s.sections.get("Database").unwrap_or(&String::new())
        ),
    );
    let refs = fs::read_dir("/etc/infiproxy/secrets.d")
        .map(|entries| {
            entries
                .filter_map(Result::ok)
                .filter(|e| e.file_type().is_ok_and(|f| f.is_file()))
                .filter_map(|e| e.file_name().into_string().ok())
                .take(500)
                .collect::<Vec<_>>()
                .join("\n")
        })
        .unwrap_or("Root-only references unavailable".into());
    s.sections.insert("Secrets".into(), refs);
    s.sections.insert("System".into(), "Panel: infiproxy.service\nRuntime identity: infiproxy-runtime\n\nUse the web panel for user/profile edits.\nEnvironment is edited only at its fixed path through legacy recovery.\n\nHTTPS panel: inspect the HTTPS workspace.\nBefore HTTPS: ssh -L 8080:127.0.0.1:8080 root@SERVER\nOpen http://127.0.0.1:8080/admin".into());
    let site =
        read_small(Path::new("/etc/nginx/sites-available/infiproxy.conf")).unwrap_or_default();
    let domain = site
        .lines()
        .filter_map(|line| line.trim().strip_prefix("server_name "))
        .map(|line| line.trim_end_matches(';').trim())
        .find(|value| {
            *value != "_"
                && value
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || b".-".contains(&c))
        });
    s.panel_url = domain.map_or(
        "http://127.0.0.1:8080/admin (SSH tunnel)".into(),
        |domain| format!("https://{domain}/admin"),
    );
    for name in ["Dashboard", "System"] {
        s.sections
            .entry(name.into())
            .or_default()
            .push_str(&format!(
                "\nPanel URL: {}\nActive runtimes: {} / {} registered",
                s.panel_url,
                s.active_runtimes,
                s.modules.len()
            ));
    }
    s
}
