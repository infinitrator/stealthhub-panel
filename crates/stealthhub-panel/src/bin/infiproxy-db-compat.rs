//! Offline migration compatibility runner for an explicit SQLite backup copy.

use std::path::Path;

use anyhow::{bail, Context, Result};

#[tokio::main]
async fn main() -> Result<()> {
    let mut arguments = std::env::args_os().skip(1);
    let source = arguments
        .next()
        .context("usage: infiproxy-db-compat target/compat/production-copy.sqlite")?;
    if arguments.next().is_some() {
        bail!("exactly one explicit offline database path is required");
    }
    let report = stealthhub_core::compatibility::run(Path::new(&source)).await?;
    println!("{}", serde_json::to_string_pretty(&report)?);
    if !report.passed() {
        bail!("database compatibility invariants failed; working copy was preserved");
    }
    Ok(())
}
