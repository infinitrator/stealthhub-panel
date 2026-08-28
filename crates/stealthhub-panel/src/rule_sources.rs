//! Bounded data-only refresh for remote routing rule sources.

use anyhow::{bail, Context, Result};
use chrono::Utc;
use reqwest::{
    header::{ETAG, IF_MODIFIED_SINCE, IF_NONE_MATCH, LAST_MODIFIED, LOCATION},
    redirect::Policy,
    Client, StatusCode, Url,
};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use sqlx::SqlitePool;
use std::{
    net::{IpAddr, SocketAddr},
    time::Duration,
};
use stealthhub_core::{
    rules::{validate_classical_rule_payload, RuleSetSource, RuleSourceFormat},
    storage::{
        get_rule_source, list_rule_sources, update_rule_source_error, update_rule_source_success,
    },
};

const MAX_REDIRECTS: usize = 3;
const MAX_BODY_BYTES: usize = 4 * 1024 * 1024;
const MAX_LINES: usize = 100_000;
const MAX_LINE_BYTES: usize = 4_096;

/// Starts the low-frequency scheduler for enabled, due sources.
pub(crate) fn spawn_checker(pool: SqlitePool) {
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_secs(60)).await;
        loop {
            match list_rule_sources(&pool).await {
                Ok(sources) => {
                    for source in sources.into_iter().filter(source_is_due) {
                        if let Err(error) = refresh(&pool, &source.id).await {
                            tracing::warn!(
                                source = source.id,
                                "rule source refresh failed: {error}"
                            );
                        }
                    }
                }
                Err(error) => tracing::warn!("could not load scheduled rule sources: {error}"),
            }
            tokio::time::sleep(Duration::from_secs(300)).await;
        }
    });
}

fn source_is_due(source: &RuleSetSource) -> bool {
    if !source.enabled {
        return false;
    }
    source
        .last_successful_fetch
        .as_deref()
        .and_then(|value| chrono::DateTime::parse_from_rfc3339(value).ok())
        .is_none_or(|last| {
            Utc::now().signed_duration_since(last.with_timezone(&Utc))
                >= chrono::Duration::seconds(i64::from(source.refresh_interval_seconds))
        })
}

#[derive(Deserialize)]
struct YamlPayload {
    payload: Vec<String>,
}

/// Refreshes one source while retaining its previous cache on every failure.
pub(crate) async fn refresh(pool: &SqlitePool, id: &str) -> Result<RuleSetSource> {
    let source = get_rule_source(pool, id)
        .await?
        .ok_or_else(|| anyhow::anyhow!("unknown rule source"))?;
    let result = fetch(&source).await;
    match result {
        Ok(Some(mut updated)) => {
            updated.last_successful_fetch = Some(Utc::now().to_rfc3339());
            update_rule_source_success(pool, &updated).await?;
        }
        Ok(None) => {
            let mut current = source.clone();
            current.last_successful_fetch = Some(Utc::now().to_rfc3339());
            update_rule_source_success(pool, &current).await?;
        }
        Err(error) => {
            update_rule_source_error(pool, id, &error.to_string()).await?;
            return Err(error);
        }
    }
    get_rule_source(pool, id)
        .await?
        .ok_or_else(|| anyhow::anyhow!("refreshed rule source disappeared"))
}

async fn fetch(source: &RuleSetSource) -> Result<Option<RuleSetSource>> {
    let mut url = Url::parse(&source.url).context("invalid source URL")?;
    for redirect_count in 0..=MAX_REDIRECTS {
        let addresses = validate_remote_url(&url).await?;
        let host = url
            .host_str()
            .ok_or_else(|| anyhow::anyhow!("remote rule source has no host"))?;
        // Pin the connection to the addresses that passed the SSRF check. A
        // second resolver lookup here would leave a DNS-rebinding race.
        let client = Client::builder()
            .redirect(Policy::none())
            .connect_timeout(Duration::from_secs(8))
            .timeout(Duration::from_secs(25))
            .user_agent(concat!("Infiproxy/", env!("CARGO_PKG_VERSION")))
            .resolve_to_addrs(host, &addresses)
            .build()?;
        let mut request = client.get(url.clone());
        if let Some(etag) = source.etag.as_deref() {
            request = request.header(IF_NONE_MATCH, etag);
        }
        if let Some(modified) = source.last_modified.as_deref() {
            request = request.header(IF_MODIFIED_SINCE, modified);
        }
        let mut response = request.send().await?;
        if response.status() == StatusCode::NOT_MODIFIED {
            return Ok(None);
        }
        if response.status().is_redirection() {
            if redirect_count == MAX_REDIRECTS {
                bail!("remote rule source exceeded redirect limit");
            }
            let location = response
                .headers()
                .get(LOCATION)
                .and_then(|value| value.to_str().ok())
                .ok_or_else(|| anyhow::anyhow!("redirect has no valid location"))?;
            url = url.join(location).context("invalid redirect target")?;
            continue;
        }
        response.error_for_status_ref()?;
        if response
            .content_length()
            .is_some_and(|length| length > MAX_BODY_BYTES as u64)
        {
            bail!("remote rule source exceeds body limit");
        }
        let etag = bounded_header(response.headers().get(ETAG));
        let last_modified = bounded_header(response.headers().get(LAST_MODIFIED));
        let mut body = Vec::new();
        while let Some(chunk) = response.chunk().await? {
            if body.len().saturating_add(chunk.len()) > MAX_BODY_BYTES {
                bail!("remote rule source exceeds body limit");
            }
            body.extend_from_slice(&chunk);
        }
        let text = std::str::from_utf8(&body).context("remote rule source is not UTF-8")?;
        let rules = parse_source(source.format, text)?;
        let mut updated = source.clone();
        updated.etag = etag;
        updated.last_modified = last_modified;
        updated.checksum = Some(
            Sha256::digest(&body)
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect(),
        );
        updated.entry_count = u32::try_from(rules.len())?;
        updated.cached_payload = rules.join("\n");
        updated.last_error = None;
        return Ok(Some(updated));
    }
    bail!("remote rule source redirect loop")
}

fn parse_source(format: RuleSourceFormat, text: &str) -> Result<Vec<String>> {
    if text.lines().count() > MAX_LINES || text.lines().any(|line| line.len() > MAX_LINE_BYTES) {
        bail!("remote rule source exceeds line bounds");
    }
    let payload = match format {
        RuleSourceFormat::Yaml | RuleSourceFormat::MihomoClassical => {
            serde_norway::from_str::<YamlPayload>(text)?
                .payload
                .join("\n")
        }
        RuleSourceFormat::Text => text
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty() && !line.starts_with('#'))
            .map(|line| {
                if line.contains(',') {
                    line.to_string()
                } else {
                    format!("DOMAIN-SUFFIX,{}", line.trim_start_matches("+."))
                }
            })
            .collect::<Vec<_>>()
            .join("\n"),
    };
    validate_classical_rule_payload(&payload)
}

async fn validate_remote_url(url: &Url) -> Result<Vec<SocketAddr>> {
    if url.scheme() != "https" || !url.username().is_empty() || url.password().is_some() {
        bail!("remote rule source must use HTTPS without URL credentials");
    }
    let host = url
        .host_str()
        .ok_or_else(|| anyhow::anyhow!("remote rule source has no host"))?;
    if host.eq_ignore_ascii_case("localhost") || host.ends_with(".localhost") {
        bail!("local remote-rule host is forbidden");
    }
    let addresses = tokio::net::lookup_host((host, url.port_or_known_default().unwrap_or(443)))
        .await
        .context("resolve remote rule source")?
        .collect::<Vec<_>>();
    if addresses.is_empty()
        || addresses
            .iter()
            .any(|address| forbidden_address(address.ip()))
    {
        bail!("remote rule source resolves to a forbidden address");
    }
    Ok(addresses)
}

fn forbidden_address(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => {
            address.is_private()
                || address.is_loopback()
                || address.is_link_local()
                || address.is_broadcast()
                || address.is_documentation()
                || address.is_unspecified()
                || address.is_multicast()
        }
        IpAddr::V6(address) => {
            address.is_loopback()
                || address.is_unspecified()
                || address.is_multicast()
                || address.is_unique_local()
                || address.is_unicast_link_local()
        }
    }
}

fn bounded_header(value: Option<&reqwest::header::HeaderValue>) -> Option<String> {
    value
        .and_then(|value| value.to_str().ok())
        .filter(|value| value.len() <= 512 && !value.chars().any(char::is_control))
        .map(str::to_string)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn text_and_yaml_sources_are_bounded_data_only() {
        assert_eq!(
            parse_source(RuleSourceFormat::Text, "example.com\nDOMAIN,exact.test\n").unwrap(),
            vec![
                "DOMAIN-SUFFIX,example.com".to_string(),
                "DOMAIN,exact.test".to_string()
            ]
        );
        assert!(parse_source(RuleSourceFormat::Text, &"x".repeat(MAX_LINE_BYTES + 1)).is_err());
        assert!(parse_source(RuleSourceFormat::Yaml, "payload: [RULE-SET,other]").is_err());
    }

    #[test]
    fn private_and_local_addresses_are_forbidden() {
        assert!(forbidden_address("127.0.0.1".parse().unwrap()));
        assert!(forbidden_address("10.0.0.1".parse().unwrap()));
        assert!(!forbidden_address("1.1.1.1".parse().unwrap()));
    }
}
