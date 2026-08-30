//! Persistable client routing and transport-pool policy.
//!
//! The policy references stable profile and pool identities. Mihomo-specific
//! serialization stays in the subscription assembler; storage and UI can edit
//! this model without embedding YAML fragments.

use std::collections::BTreeSet;

use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};

use crate::models::{ProtocolProfile, ProxyRole};

/// Mihomo proxy-group behavior represented independently of YAML.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum PoolKind {
    Select,
    UrlTest,
    Fallback,
    LoadBalance,
}

impl PoolKind {
    #[must_use]
    pub const fn mihomo_name(self) -> &'static str {
        match self {
            Self::Select => "select",
            Self::UrlTest => "url-test",
            Self::Fallback => "fallback",
            Self::LoadBalance => "load-balance",
        }
    }
}

/// One ordered transport-pool member selector.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case", tag = "kind", content = "value")]
pub enum PoolMember {
    Profile(String),
    Capability(String),
    Role(ProxyRole),
    Pool(String),
    AllProfiles,
    Direct,
    Reject,
}

/// Persisted proxy-group definition.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TransportPool {
    pub id: String,
    pub display_name: String,
    pub kind: PoolKind,
    pub enabled: bool,
    pub members: Vec<PoolMember>,
    pub test_url: Option<String>,
    pub interval_seconds: Option<u32>,
    pub timeout_ms: Option<u32>,
    pub tolerance_ms: Option<u32>,
    pub max_failures: Option<u32>,
    pub lazy: bool,
    pub minimum_healthy_count: Option<u32>,
    pub fallback_pool: Option<String>,
    pub priority: i32,
    pub strategy: Option<String>,
}

/// One ordered inline Mihomo rule. Rule-set providers remain typed separately.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RoutingPolicyRule {
    pub id: String,
    pub display_name: String,
    pub enabled: bool,
    pub priority: i32,
    pub condition: String,
    pub target: String,
}

/// Complete persistent policy used to assemble one client subscription.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ClientPolicy {
    pub pools: Vec<TransportPool>,
    pub rules: Vec<RoutingPolicyRule>,
}

/// DNS behavior kept independent from transport selection.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DnsPolicy {
    pub enabled: bool,
    pub ipv6: bool,
    pub enhanced_mode: String,
    pub respect_rules: bool,
    pub bootstrap_resolvers: Vec<String>,
    pub remote_resolvers: Vec<String>,
    pub direct_resolvers: Vec<String>,
}

impl DnsPolicy {
    pub fn validate(&self) -> Result<()> {
        if !matches!(self.enhanced_mode.as_str(), "redir-host" | "fake-ip") {
            bail!("unsupported DNS enhanced mode");
        }
        for resolver in self
            .bootstrap_resolvers
            .iter()
            .chain(&self.remote_resolvers)
            .chain(&self.direct_resolvers)
        {
            if resolver.is_empty()
                || resolver.len() > 256
                || resolver.chars().any(char::is_control)
                || !(resolver == "system"
                    || resolver.parse::<std::net::IpAddr>().is_ok()
                    || ["https://", "tls://", "quic://", "udp://", "tcp://"]
                        .iter()
                        .any(|prefix| resolver.starts_with(prefix)))
            {
                bail!("invalid DNS resolver");
            }
        }
        if self.enabled
            && (self.bootstrap_resolvers.is_empty()
                || self.remote_resolvers.is_empty()
                || self.direct_resolvers.is_empty())
        {
            bail!("enabled DNS policy requires bootstrap, remote, and direct resolvers");
        }
        Ok(())
    }
}

#[must_use]
pub fn default_dns_policy() -> DnsPolicy {
    DnsPolicy {
        enabled: true,
        ipv6: false,
        enhanced_mode: "redir-host".to_string(),
        respect_rules: true,
        bootstrap_resolvers: vec!["1.1.1.1".to_string(), "9.9.9.9".to_string()],
        remote_resolvers: vec![
            "https://cloudflare-dns.com/dns-query".to_string(),
            "https://dns.quad9.net/dns-query".to_string(),
        ],
        direct_resolvers: vec!["system".to_string()],
    }
}

impl ClientPolicy {
    /// Validates references and rejects pool cycles before subscription output.
    pub fn validate(&self, profiles: &[ProtocolProfile]) -> Result<()> {
        let profile_ids = profiles
            .iter()
            .filter(|profile| profile.enabled)
            .map(|profile| profile.name.as_str())
            .collect::<BTreeSet<_>>();
        let all_pool_ids = self
            .pools
            .iter()
            .map(|pool| pool.id.as_str())
            .collect::<BTreeSet<_>>();
        if all_pool_ids.len() != self.pools.len() {
            bail!("transport pool IDs must be unique");
        }
        for pool in &self.pools {
            validate_policy_id(&pool.id)?;
            if pool.display_name.trim().is_empty() || pool.display_name.len() > 80 {
                bail!("transport pool display name is invalid");
            }
        }
        let pool_ids = self
            .pools
            .iter()
            .filter(|pool| pool.enabled)
            .map(|pool| pool.id.as_str())
            .collect::<BTreeSet<_>>();
        for pool in self.pools.iter().filter(|pool| pool.enabled) {
            if pool.members.is_empty() {
                bail!("transport pool must contain at least one member");
            }
            for member in &pool.members {
                match member {
                    PoolMember::Profile(id) if !profile_ids.contains(id.as_str()) => {
                        bail!("transport pool references an unavailable profile")
                    }
                    PoolMember::Capability(id)
                        if !profiles.iter().any(|profile| {
                            profile.enabled && profile.protocol_id == id.as_str()
                        }) =>
                    {
                        bail!("transport pool capability selector resolves to no profile")
                    }
                    PoolMember::Pool(id) if !pool_ids.contains(id.as_str()) => {
                        bail!("transport pool references an unavailable pool")
                    }
                    _ => {}
                }
            }
            if let Some(fallback) = pool.fallback_pool.as_deref() {
                if fallback == pool.id || !pool_ids.contains(fallback) {
                    bail!("transport pool fallback reference is invalid");
                }
            }
            if pool.timeout_ms == Some(0)
                || pool.interval_seconds == Some(0)
                || pool.max_failures == Some(0)
                || pool.minimum_healthy_count == Some(0)
            {
                bail!("transport pool numeric limits must be positive");
            }
            if let Some(url) = pool.test_url.as_deref() {
                if !url.starts_with("https://")
                    || url.len() > 512
                    || url.chars().any(char::is_control)
                {
                    bail!("transport pool health URL must be bounded HTTPS");
                }
            }
            if let Some(strategy) = pool.strategy.as_deref() {
                if !matches!(
                    strategy,
                    "round-robin" | "consistent-hashing" | "sticky-sessions"
                ) {
                    bail!("unsupported load-balance strategy");
                }
            }
            detect_cycle(&pool.id, &pool.id, &self.pools, &mut BTreeSet::new())?;
        }
        let rule_ids = self
            .rules
            .iter()
            .map(|rule| rule.id.as_str())
            .collect::<BTreeSet<_>>();
        if rule_ids.len() != self.rules.len() {
            bail!("routing policy IDs must be unique");
        }
        for rule in &self.rules {
            validate_policy_id(&rule.id)?;
            if rule.display_name.trim().is_empty() || rule.display_name.len() > 80 {
                bail!("routing policy display name is invalid");
            }
            if !rule.enabled {
                continue;
            }
            if rule.condition.trim().is_empty() || rule.condition.contains('\n') {
                bail!("routing policy condition is invalid");
            }
            let target_valid = matches!(rule.target.as_str(), "DIRECT" | "REJECT")
                || pool_ids.contains(rule.target.as_str())
                || profile_ids.contains(rule.target.as_str())
                || rule
                    .target
                    .strip_prefix("capability:")
                    .is_some_and(|capability| {
                        profiles
                            .iter()
                            .any(|profile| profile.enabled && profile.protocol_id == capability)
                    });
            if !target_valid {
                bail!("routing policy references an unavailable target");
            }
        }
        Ok(())
    }

    /// Resolves selectors to ordered, deduplicated Mihomo member names.
    pub fn resolved_pools(
        &self,
        profiles: &[ProtocolProfile],
    ) -> Result<Vec<(TransportPool, Vec<String>)>> {
        self.validate(profiles)?;
        let enabled = profiles
            .iter()
            .filter(|profile| profile.enabled)
            .collect::<Vec<_>>();
        self.pools
            .iter()
            .filter(|pool| pool.enabled)
            .map(|pool| {
                let mut members = Vec::new();
                for member in &pool.members {
                    match member {
                        PoolMember::Profile(id) | PoolMember::Pool(id) => members.push(id.clone()),
                        PoolMember::Capability(capability) => members.extend(
                            enabled
                                .iter()
                                .filter(|profile| profile.protocol_id == *capability)
                                .map(|profile| profile.name.clone()),
                        ),
                        PoolMember::Role(role) => members.extend(
                            enabled
                                .iter()
                                .filter(|profile| profile.role == *role)
                                .map(|profile| profile.name.clone()),
                        ),
                        PoolMember::AllProfiles => {
                            members.extend(enabled.iter().map(|profile| profile.name.clone()))
                        }
                        PoolMember::Direct => members.push("DIRECT".to_string()),
                        PoolMember::Reject => members.push("REJECT".to_string()),
                    }
                }
                let mut seen = BTreeSet::new();
                members.retain(|member| seen.insert(member.clone()));
                if members.is_empty() {
                    bail!("transport pool resolves to no members");
                }
                Ok((pool.clone(), members))
            })
            .collect()
    }

    /// Resolves routing selectors to concrete Mihomo targets.
    pub fn resolved_rules(&self, profiles: &[ProtocolProfile]) -> Result<Vec<(String, String)>> {
        self.validate(profiles)?;
        let mut rules = self
            .rules
            .iter()
            .filter(|rule| rule.enabled)
            .collect::<Vec<_>>();
        rules.sort_by_key(|rule| rule.priority);
        rules
            .into_iter()
            .map(|rule| {
                let target = if let Some(capability) = rule.target.strip_prefix("capability:") {
                    profiles
                        .iter()
                        .find(|profile| profile.enabled && profile.protocol_id == capability)
                        .map(|profile| profile.name.clone())
                        .ok_or_else(|| anyhow::anyhow!("routing capability has no profile"))?
                } else {
                    rule.target.clone()
                };
                Ok((rule.condition.clone(), target))
            })
            .collect()
    }
}

fn validate_policy_id(value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        bail!("invalid policy identity");
    }
    Ok(())
}

fn detect_cycle<'a>(
    root: &str,
    current: &str,
    pools: &'a [TransportPool],
    visiting: &mut BTreeSet<&'a str>,
) -> Result<()> {
    let Some(pool) = pools.iter().find(|pool| pool.enabled && pool.id == current) else {
        return Ok(());
    };
    if !visiting.insert(pool.id.as_str()) {
        bail!("transport pool references contain a cycle");
    }
    let children = pool
        .members
        .iter()
        .filter_map(|member| match member {
            PoolMember::Pool(id) => Some(id.as_str()),
            _ => None,
        })
        .chain(pool.fallback_pool.as_deref());
    for child in children {
        if child == root {
            bail!("transport pool references contain a cycle");
        }
        detect_cycle(root, child, pools, visiting)?;
    }
    visiting.remove(pool.id.as_str());
    Ok(())
}

/// Compatibility bootstrap inserted once by the storage migration.
#[must_use]
pub fn default_client_policy() -> ClientPolicy {
    use PoolMember::{AllProfiles, Capability, Direct, Pool, Role};
    let pool = |id: &str,
                kind: PoolKind,
                members: Vec<PoolMember>,
                interval: Option<u32>,
                tolerance: Option<u32>,
                strategy: Option<&str>| TransportPool {
        id: id.to_string(),
        display_name: id.to_string(),
        kind,
        enabled: true,
        members,
        test_url: interval.map(|_| "https://www.gstatic.com/generate_204".to_string()),
        interval_seconds: interval,
        timeout_ms: interval.map(|_| 5_000),
        tolerance_ms: tolerance,
        max_failures: interval.map(|_| 5),
        lazy: true,
        minimum_healthy_count: None,
        fallback_pool: None,
        priority: 100,
        strategy: strategy.map(str::to_string),
    };
    let disabled = |mut pool: TransportPool| {
        pool.enabled = false;
        pool
    };
    ClientPolicy {
        pools: vec![
            disabled(pool(
                "STEALTH-TCP",
                PoolKind::Select,
                [
                    "vless-reality-tcp",
                    "vless-shadowtls-v3",
                    "vless-restls",
                    "vless-jls",
                    "anytls-shadowtls-v3",
                    "anytls-restls",
                    "anytls-jls",
                    "trojan-shadowtls-v3",
                    "trojan-restls",
                    "trojan-jls",
                    "trojan-reality",
                    "snell-v5-shadowtls-v3",
                    "snell-v5-restls",
                    "snell-v5-jls",
                ]
                .into_iter()
                .map(|id| Capability(id.to_string()))
                .collect(),
                None,
                None,
                None,
            )),
            disabled(pool(
                "HTTPS-LIKE",
                PoolKind::Select,
                [
                    "trusttunnel-h2",
                    "vless-jls",
                    "anytls-jls",
                    "trojan-jls",
                    "snell-v5-jls",
                    "sudoku-httpmask",
                ]
                .into_iter()
                .map(|id| Capability(id.to_string()))
                .collect(),
                None,
                None,
                None,
            )),
            disabled(pool(
                "FAST-UDP",
                PoolKind::Select,
                ["hysteria2", "tuic", "shadowquic"]
                    .into_iter()
                    .map(|id| Capability(id.to_string()))
                    .collect(),
                None,
                None,
                None,
            )),
            pool(
                "AUTO-SAFE",
                PoolKind::UrlTest,
                vec![
                    Role(ProxyRole::AutoSafe),
                    Role(ProxyRole::Compatibility),
                    AllProfiles,
                ],
                Some(300),
                Some(50),
                None,
            ),
            pool(
                "FAILOVER",
                PoolKind::Fallback,
                vec![Pool("AUTO-SAFE".to_string())],
                Some(120),
                None,
                None,
            ),
            pool(
                "BALANCE",
                PoolKind::LoadBalance,
                vec![Pool("AUTO-SAFE".to_string())],
                Some(180),
                None,
                Some("round-robin"),
            ),
            pool(
                "SPEED",
                PoolKind::Select,
                vec![
                    Role(ProxyRole::Speed),
                    Pool("AUTO-SAFE".to_string()),
                    Direct,
                ],
                None,
                None,
                None,
            ),
            pool(
                "RU-ACCESS",
                PoolKind::Select,
                vec![
                    Role(ProxyRole::RuAccess),
                    Pool("AUTO-SAFE".to_string()),
                    Direct,
                ],
                None,
                None,
                None,
            ),
            pool(
                "MANUAL",
                PoolKind::Select,
                vec![
                    Pool("AUTO-SAFE".to_string()),
                    Pool("FAILOVER".to_string()),
                    Pool("BALANCE".to_string()),
                    Pool("SPEED".to_string()),
                    Pool("RU-ACCESS".to_string()),
                    AllProfiles,
                    Direct,
                ],
                None,
                None,
                None,
            ),
        ],
        rules: vec![
            RoutingPolicyRule {
                id: "geoip-ru".to_string(),
                display_name: "Russian IP ranges".to_string(),
                enabled: true,
                priority: 100,
                condition: "GEOIP,RU".to_string(),
                target: "DIRECT".to_string(),
            },
            RoutingPolicyRule {
                id: "private-10".to_string(),
                display_name: "Private 10/8".to_string(),
                enabled: true,
                priority: 110,
                condition: "IP-CIDR,10.0.0.0/8,no-resolve".to_string(),
                target: "DIRECT".to_string(),
            },
            RoutingPolicyRule {
                id: "private-172".to_string(),
                display_name: "Private 172.16/12".to_string(),
                enabled: true,
                priority: 120,
                condition: "IP-CIDR,172.16.0.0/12,no-resolve".to_string(),
                target: "DIRECT".to_string(),
            },
            RoutingPolicyRule {
                id: "private-192".to_string(),
                display_name: "Private 192.168/16".to_string(),
                enabled: true,
                priority: 130,
                condition: "IP-CIDR,192.168.0.0/16,no-resolve".to_string(),
                target: "DIRECT".to_string(),
            },
            RoutingPolicyRule {
                id: "catch-all".to_string(),
                display_name: "Default route".to_string(),
                enabled: true,
                priority: 1000,
                condition: "MATCH".to_string(),
                target: "MANUAL".to_string(),
            },
        ],
    }
}

/// Stable role encoding used by normalized storage rows.
#[must_use]
pub fn role_name(role: ProxyRole) -> &'static str {
    match role {
        ProxyRole::AutoSafe => "auto-safe",
        ProxyRole::Speed => "speed",
        ProxyRole::Compatibility => "compatibility",
        ProxyRole::RuAccess => "ru-access",
        ProxyRole::Manual => "manual",
    }
}

pub fn parse_role(value: &str) -> Result<ProxyRole> {
    match value {
        "auto-safe" => Ok(ProxyRole::AutoSafe),
        "speed" => Ok(ProxyRole::Speed),
        "compatibility" => Ok(ProxyRole::Compatibility),
        "ru-access" => Ok(ProxyRole::RuAccess),
        "manual" => Ok(ProxyRole::Manual),
        _ => bail!("invalid proxy role"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn profile(name: &str, role: ProxyRole) -> ProtocolProfile {
        ProtocolProfile {
            name: name.to_string(),
            protocol_id: "test".to_string(),
            schema_version: 1,
            role,
            server: "node.example.test".to_string(),
            port: 443,
            enabled: true,
            preferred_core_id: None,
            managed_resource_id: None,
            config: json!({}),
        }
    }

    #[test]
    fn default_policy_resolves_dynamic_profiles_without_duplicate_members() {
        let profiles = [
            profile("SAFE", ProxyRole::AutoSafe),
            profile("FAST", ProxyRole::Speed),
        ];
        let pools = default_client_policy().resolved_pools(&profiles).unwrap();
        let auto_safe = pools
            .iter()
            .find(|(pool, _)| pool.id == "AUTO-SAFE")
            .unwrap();
        assert_eq!(auto_safe.1, vec!["SAFE", "FAST"]);
        let manual = pools.iter().find(|(pool, _)| pool.id == "MANUAL").unwrap();
        assert_eq!(
            manual.1.iter().filter(|member| *member == "SAFE").count(),
            1
        );
    }

    #[test]
    fn missing_references_and_cycles_fail_closed() {
        let mut policy = default_client_policy();
        policy
            .pools
            .iter_mut()
            .find(|pool| pool.id == "AUTO-SAFE")
            .unwrap()
            .members = vec![PoolMember::Pool("MISSING".to_string())];
        assert!(policy
            .validate(&[profile("SAFE", ProxyRole::AutoSafe)])
            .is_err());

        let mut policy = default_client_policy();
        policy
            .pools
            .iter_mut()
            .find(|pool| pool.id == "AUTO-SAFE")
            .unwrap()
            .members = vec![PoolMember::Pool("FAILOVER".to_string())];
        assert!(policy
            .validate(&[profile("SAFE", ProxyRole::AutoSafe)])
            .is_err());
    }
}
