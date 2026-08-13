//! Native manifest and GitHub metadata validator for the root module updater.

use serde::Deserialize;
use std::{env, io::Read, path::PathBuf, process::ExitCode};
use stealthhub_core::module_manifest::{load_registry, pipe_record, read_manifest, ReadOptions};

const MAX_GITHUB_RESPONSE_BYTES: u64 = 4 * 1024 * 1024;

#[derive(Debug, Deserialize)]
struct Release {
    tag_name: String,
    #[serde(default)]
    assets: Vec<ReleaseAsset>,
    #[serde(default)]
    draft: bool,
    #[serde(default)]
    prerelease: bool,
}

#[derive(Debug, Deserialize)]
struct ReleaseAsset {
    name: String,
    browser_download_url: String,
    #[serde(default)]
    digest: Option<String>,
}

#[derive(Debug, PartialEq, Eq)]
struct ReleaseMetadata {
    tag: String,
    asset_name: String,
    asset_url: String,
    digest: String,
    checksum_url: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct StableVersion {
    major: u64,
    minor: u64,
    patch: u64,
}

#[derive(Deserialize)]
struct Commit {
    sha: String,
}

#[derive(Deserialize)]
struct CloudflareEnvelope {
    #[serde(default)]
    success: bool,
    #[serde(default)]
    result: Vec<CloudflareObject>,
}

#[derive(Deserialize)]
struct CloudflareObject {
    id: String,
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("helper error: {error:#}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> anyhow::Result<()> {
    let mut args = env::args().skip(1);
    let command = args.next().ok_or_else(|| anyhow::anyhow!(usage()))?;
    if command == "release-metadata" {
        let pattern = args.next().ok_or_else(|| anyhow::anyhow!(usage()))?;
        ensure_no_extra_args(args)?;
        return print_release_metadata(&pattern);
    }
    if command == "headscale-step-metadata" {
        let pattern = args.next().ok_or_else(|| anyhow::anyhow!(usage()))?;
        let current = args.next().ok_or_else(|| anyhow::anyhow!(usage()))?;
        ensure_no_extra_args(args)?;
        return print_headscale_step_metadata(&pattern, &current);
    }
    if command == "commit-sha" {
        ensure_no_extra_args(args)?;
        return print_commit_sha();
    }
    if command == "release-tag" {
        ensure_no_extra_args(args)?;
        let release: Release = read_json_stdin()?;
        println!("{}", safe_single_line(&release.tag_name)?);
        return Ok(());
    }
    if command == "cloudflare-first-id" {
        ensure_no_extra_args(args)?;
        let response: CloudflareEnvelope = read_json_stdin()?;
        anyhow::ensure!(response.success, "Cloudflare API reported failure");
        if let Some(item) = response.result.first() {
            println!("{}", safe_single_line(&item.id)?);
        }
        return Ok(());
    }
    if command == "cloudflare-success" {
        ensure_no_extra_args(args)?;
        let response: serde_json::Value = read_json_stdin()?;
        anyhow::ensure!(
            response.get("success").and_then(serde_json::Value::as_bool) == Some(true),
            "Cloudflare API reported failure"
        );
        return Ok(());
    }
    if command == "headscale-user-id" {
        ensure_no_extra_args(args)?;
        let value: serde_json::Value = read_json_stdin()?;
        let id = value
            .get("id")
            .and_then(|value| {
                value
                    .as_u64()
                    .or_else(|| value.as_str().and_then(|text| text.parse().ok()))
            })
            .filter(|id| *id > 0)
            .ok_or_else(|| anyhow::anyhow!("Headscale response has no valid user ID"))?;
        println!("{id}");
        return Ok(());
    }

    let path = PathBuf::from(args.next().ok_or_else(|| anyhow::anyhow!(usage()))?);
    let mut options = ReadOptions::default();
    for flag in args {
        match flag.as_str() {
            "--root-owned" => options.root_owned = true,
            "--registration" => options.registration = true,
            _ => anyhow::bail!("unknown option: {flag}"),
        }
    }

    match command.as_str() {
        "list" => {
            for spec in load_registry(&path, options)? {
                println!("{}", spec.id);
            }
        }
        "read" => println!("{}", pipe_record(&read_manifest(&path, options)?)),
        "validate" => {
            read_manifest(&path, options)?;
        }
        _ => anyhow::bail!(usage()),
    }
    Ok(())
}

fn print_release_metadata(pattern: &str) -> anyhow::Result<()> {
    let release: Release = read_json_stdin()?;
    let metadata = select_release_metadata(pattern, &release)?;
    print_metadata(&metadata);
    Ok(())
}

fn print_headscale_step_metadata(pattern: &str, current: &str) -> anyhow::Result<()> {
    let releases: Vec<Release> = read_json_stdin()?;
    let metadata = select_headscale_step_metadata(pattern, current, &releases)?;
    print_metadata(&metadata);
    Ok(())
}

fn print_metadata(metadata: &ReleaseMetadata) {
    println!(
        "{}|{}|{}|{}|{}",
        metadata.tag,
        metadata.asset_name,
        metadata.asset_url,
        metadata.digest,
        metadata.checksum_url
    );
}

fn select_headscale_step_metadata(
    pattern: &str,
    current: &str,
    releases: &[Release],
) -> anyhow::Result<ReleaseMetadata> {
    let current = parse_stable_version(current)
        .ok_or_else(|| anyhow::anyhow!("installed Headscale version is not stable semver"))?;
    let stable = releases
        .iter()
        .filter(|release| !release.draft && !release.prerelease)
        .filter_map(|release| {
            parse_stable_version(&release.tag_name).map(|version| (version, release))
        })
        .collect::<Vec<_>>();
    let (latest, _) = stable
        .iter()
        .max_by_key(|(version, _)| *version)
        .copied()
        .ok_or_else(|| anyhow::anyhow!("GitHub returned no stable Headscale releases"))?;
    anyhow::ensure!(
        current <= latest,
        "installed Headscale version is newer than upstream"
    );
    anyhow::ensure!(
        current.major == latest.major,
        "Headscale major-version upgrades require an explicit migration"
    );

    let target_minor = if current.minor < latest.minor {
        current.minor + 1
    } else {
        current.minor
    };
    let (_, release) = stable
        .into_iter()
        .filter(|(version, _)| {
            version.major == current.major && version.minor == target_minor && *version >= current
        })
        .max_by_key(|(version, _)| *version)
        .ok_or_else(|| {
            anyhow::anyhow!(
                "no stable Headscale release found for required minor {}.{}",
                current.major,
                target_minor
            )
        })?;
    select_release_metadata(pattern, release)
}

fn parse_stable_version(value: &str) -> Option<StableVersion> {
    let value = value.strip_prefix('v').unwrap_or(value);
    let mut parts = value.split('.');
    let version = StableVersion {
        major: parts.next()?.parse().ok()?,
        minor: parts.next()?.parse().ok()?,
        patch: parts.next()?.parse().ok()?,
    };
    parts.next().is_none().then_some(version)
}

fn select_release_metadata(pattern: &str, release: &Release) -> anyhow::Result<ReleaseMetadata> {
    if pattern.is_empty()
        || pattern.len() > 180
        || !pattern
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '+' | '-' | '{' | '}'))
    {
        anyhow::bail!("invalid asset pattern");
    }
    let version = release
        .tag_name
        .strip_prefix("app/v")
        .or_else(|| release.tag_name.strip_prefix("tuic-server-"))
        .or_else(|| release.tag_name.strip_prefix('v'))
        .unwrap_or(&release.tag_name);
    let expected = pattern
        .replace("{version}", version)
        .replace("{tag}", &release.tag_name);
    let asset = release
        .assets
        .iter()
        .find(|asset| asset.name == expected)
        .ok_or_else(|| anyhow::anyhow!("release asset not found: {expected}"))?;
    let sidecars = [
        format!("{expected}.dgst"),
        format!("{expected}.sha256sum"),
        "hashes.txt".to_string(),
        "checksums.txt".to_string(),
    ];
    let checksum_url = sidecars
        .iter()
        .find_map(|name| {
            release
                .assets
                .iter()
                .find(|candidate| candidate.name == *name)
                .map(|candidate| candidate.browser_download_url.as_str())
        })
        .unwrap_or_default();
    let raw_digest = asset.digest.as_deref().unwrap_or_default();
    let digest = raw_digest.strip_prefix("sha256:").unwrap_or(raw_digest);
    for url in [asset.browser_download_url.as_str(), checksum_url] {
        if !url.is_empty() && !url.starts_with("https://github.com/") {
            anyhow::bail!("release asset URL is outside GitHub");
        }
    }
    if !digest.is_empty() && !is_sha256(digest) {
        anyhow::bail!("invalid SHA-256 digest in GitHub response");
    }
    for value in [
        release.tag_name.as_str(),
        expected.as_str(),
        asset.browser_download_url.as_str(),
        digest,
        checksum_url,
    ] {
        if value.contains('|') || value.chars().any(char::is_control) {
            anyhow::bail!("unsafe value in GitHub response");
        }
    }
    Ok(ReleaseMetadata {
        tag: release.tag_name.clone(),
        asset_name: expected,
        asset_url: asset.browser_download_url.clone(),
        digest: digest.to_ascii_lowercase(),
        checksum_url: checksum_url.to_string(),
    })
}

fn print_commit_sha() -> anyhow::Result<()> {
    let commit: Commit = read_json_stdin()?;
    if commit.sha.len() != 40 || !commit.sha.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        anyhow::bail!("invalid commit SHA in GitHub response");
    }
    println!("{}", commit.sha);
    Ok(())
}

fn read_json_stdin<T: for<'de> Deserialize<'de>>() -> anyhow::Result<T> {
    let mut body = Vec::new();
    std::io::stdin()
        .take(MAX_GITHUB_RESPONSE_BYTES + 1)
        .read_to_end(&mut body)?;
    if body.len() as u64 > MAX_GITHUB_RESPONSE_BYTES {
        anyhow::bail!("GitHub response is too large");
    }
    Ok(serde_json::from_slice(&body)?)
}

fn ensure_no_extra_args(mut args: impl Iterator<Item = String>) -> anyhow::Result<()> {
    if let Some(extra) = args.next() {
        anyhow::bail!("unexpected argument: {extra}");
    }
    Ok(())
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn safe_single_line(value: &str) -> anyhow::Result<&str> {
    if value.is_empty()
        || value.len() > 256
        || value.contains('|')
        || value.chars().any(char::is_control)
    {
        anyhow::bail!("invalid scalar in JSON response");
    }
    Ok(value)
}

fn usage() -> String {
    concat!(
        "usage: infiproxy-module-manifest <read|validate|list> <path> ",
        "[--root-owned] [--registration]\n       ",
        "infiproxy-module-manifest <release-metadata PATTERN|headscale-step-metadata PATTERN CURRENT|commit-sha|release-tag|cloudflare-first-id|cloudflare-success|headscale-user-id> ",
        "< GitHub-response.json"
    )
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    const PATTERN: &str = "tuic-server-{version}-x86_64-unknown-linux-gnu";
    const ASSET: &str = "tuic-server-1.0.0-x86_64-unknown-linux-gnu";
    const ASSET_URL: &str = "https://github.com/tuic-protocol/tuic/releases/download/tuic-server-1.0.0/tuic-server-1.0.0-x86_64-unknown-linux-gnu";
    const CHECKSUM_URL: &str =
        "https://github.com/tuic-protocol/tuic/releases/download/tuic-server-1.0.0/checksums.txt";
    const SHA256: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    fn release_with(asset_digest: Option<serde_json::Value>, checksum: bool) -> Release {
        let mut asset = serde_json::json!({
            "name": ASSET,
            "browser_download_url": ASSET_URL,
        });
        if let Some(digest) = asset_digest {
            asset["digest"] = digest;
        }
        let mut assets = vec![asset];
        if checksum {
            assets.push(serde_json::json!({
                "name": "checksums.txt",
                "browser_download_url": CHECKSUM_URL,
                "digest": null,
            }));
        }
        serde_json::from_value(serde_json::json!({
            "tag_name": "tuic-server-1.0.0",
            "assets": assets,
        }))
        .expect("release fixture should deserialize")
    }

    fn headscale_release(version: &str, prerelease: bool) -> Release {
        let tag = format!("v{version}");
        serde_json::from_value(serde_json::json!({
            "tag_name": tag,
            "draft": false,
            "prerelease": prerelease,
            "assets": [{
                "name": format!("headscale_{version}_linux_amd64"),
                "browser_download_url": format!(
                    "https://github.com/juanfont/headscale/releases/download/v{version}/headscale_{version}_linux_amd64"
                ),
                "digest": format!("sha256:{SHA256}")
            }]
        }))
        .expect("Headscale release fixture should deserialize")
    }

    #[test]
    fn headscale_updates_one_minor_at_a_time() {
        let releases = vec![
            headscale_release("0.29.3", false),
            headscale_release("0.29.0-beta.1", true),
            headscale_release("0.28.1", false),
            headscale_release("0.27.1", false),
            headscale_release("0.27.0", false),
            headscale_release("0.26.1", false),
        ];
        let pattern = "headscale_{version}_linux_amd64";

        let first = select_headscale_step_metadata(pattern, "v0.26.1", &releases)
            .expect("first safe step should resolve");
        assert_eq!(first.tag, "v0.27.1");
        let second = select_headscale_step_metadata(pattern, "0.27.1", &releases)
            .expect("second safe step should resolve");
        assert_eq!(second.tag, "v0.28.1");
        let latest = select_headscale_step_metadata(pattern, "v0.29.0", &releases)
            .expect("same-minor patch should resolve");
        assert_eq!(latest.tag, "v0.29.3");
    }

    #[test]
    fn nullable_missing_and_empty_digests_use_checksum_sidecar() {
        let null_fixture: Release = serde_json::from_str(include_str!(
            "../../../../deploy/tests/fixtures/tuic-release-null-digest.json"
        ))
        .expect("TUIC release fixture should deserialize");
        let metadata = select_release_metadata(PATTERN, &null_fixture)
            .expect("null digest should use sidecar metadata");
        assert_eq!(metadata.asset_name, ASSET);
        assert_eq!(metadata.asset_url, ASSET_URL);
        assert_eq!(metadata.digest, "");
        assert_eq!(metadata.checksum_url, CHECKSUM_URL);

        for digest in [None, Some(serde_json::json!(""))] {
            let metadata = select_release_metadata(PATTERN, &release_with(digest, true))
                .expect("empty digest should use sidecar metadata");
            assert_eq!(metadata.asset_name, ASSET);
            assert_eq!(metadata.asset_url, ASSET_URL);
            assert_eq!(metadata.digest, "");
            assert_eq!(metadata.checksum_url, CHECKSUM_URL);
        }
    }

    #[test]
    fn prefixed_and_plain_sha256_digests_are_normalized() {
        for digest in [format!("sha256:{SHA256}"), SHA256.to_uppercase()] {
            let metadata = select_release_metadata(
                PATTERN,
                &release_with(Some(serde_json::json!(digest)), false),
            )
            .expect("valid digest should be accepted");
            assert_eq!(metadata.digest, SHA256);
            assert_eq!(metadata.checksum_url, "");
        }
    }

    #[test]
    fn invalid_digest_asset_and_external_urls_are_rejected() {
        let invalid_digest = release_with(Some(serde_json::json!("sha256:not-a-digest")), true);
        assert!(select_release_metadata(PATTERN, &invalid_digest).is_err());

        let missing_asset: Release = serde_json::from_value(serde_json::json!({
            "tag_name": "tuic-server-1.0.0",
            "assets": [],
        }))
        .unwrap();
        assert!(select_release_metadata(PATTERN, &missing_asset).is_err());

        let mut external = release_with(Some(serde_json::json!(SHA256)), false);
        external.assets[0].browser_download_url = "https://example.com/tuic-server".to_string();
        assert!(select_release_metadata(PATTERN, &external).is_err());
    }

    #[test]
    fn missing_checksum_is_returned_empty_for_fail_closed_updater_resolution() {
        let metadata = select_release_metadata(PATTERN, &release_with(None, false))
            .expect("parser should leave checksum enforcement to updater");
        assert_eq!(metadata.digest, "");
        assert_eq!(metadata.checksum_url, "");
    }
}
