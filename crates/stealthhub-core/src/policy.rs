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
    pub kind: PoolKind,
    pub enabled: bool,
    pub members: Vec<PoolMember>,
    pub test_url: Option<String>,
    pub interval_seconds: Option<u32>,
    pub tolerance_ms: Option<u32>,
    pub strategy: Option<String>,
}

/// One ordered inline Mihomo rule. Rule-set providers remain typed separately.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RoutingPolicyRule {
    pub id: String,
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

impl ClientPolicy {
    /// Validates references and rejects pool cycles before subscription output.
    pub fn validate(&self, profiles: &[ProtocolProfile]) -> Result<()> {
        let profile_ids = profiles
            .iter()
            .filter(|profile| profile.enabled)
            .map(|profile| profile.name.as_str())
            .collect::<BTreeSet<_>>();
        let pool_ids = self
            .pools
            .iter()
            .filter(|pool| pool.enabled)
            .map(|pool| pool.id.as_str())
            .collect::<BTreeSet<_>>();
        if pool_ids.len() != self.pools.iter().filter(|pool| pool.enabled).count() {
            bail!("transport pool IDs must be unique");
        }
        for pool in self.pools.iter().filter(|pool| pool.enabled) {
            validate_policy_id(&pool.id)?;
            if pool.members.is_empty() {
                bail!("transport pool must contain at least one member");
            }
            for member in &pool.members {
                match member {
                    PoolMember::Profile(id) if !profile_ids.contains(id.as_str()) => {
                        bail!("transport pool references an unavailable profile")
                    }
                    PoolMember::Pool(id) if !pool_ids.contains(id.as_str()) => {
                        bail!("transport pool references an unavailable pool")
                    }
                    _ => {}
                }
            }
            detect_cycle(&pool.id, &pool.id, &self.pools, &mut BTreeSet::new())?;
        }
        for rule in self.rules.iter().filter(|rule| rule.enabled) {
            validate_policy_id(&rule.id)?;
            if rule.condition.trim().is_empty() || rule.condition.contains('\n') {
                bail!("routing policy condition is invalid");
            }
            if !matches!(rule.target.as_str(), "DIRECT" | "REJECT")
                && !pool_ids.contains(rule.target.as_str())
            {
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
    for child in pool.members.iter().filter_map(|member| match member {
        PoolMember::Pool(id) => Some(id.as_str()),
        _ => None,
    }) {
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
    use PoolMember::{AllProfiles, Direct, Pool, Role};
    let pool = |id: &str,
                kind: PoolKind,
                members: Vec<PoolMember>,
                interval: Option<u32>,
                tolerance: Option<u32>,
                strategy: Option<&str>| TransportPool {
        id: id.to_string(),
        kind,
        enabled: true,
        members,
        test_url: interval.map(|_| "https://www.gstatic.com/generate_204".to_string()),
        interval_seconds: interval,
        tolerance_ms: tolerance,
        strategy: strategy.map(str::to_string),
    };
    ClientPolicy {
        pools: vec![
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
                enabled: true,
                priority: 100,
                condition: "GEOIP,RU".to_string(),
                target: "DIRECT".to_string(),
            },
            RoutingPolicyRule {
                id: "private-10".to_string(),
                enabled: true,
                priority: 110,
                condition: "IP-CIDR,10.0.0.0/8,no-resolve".to_string(),
                target: "DIRECT".to_string(),
            },
            RoutingPolicyRule {
                id: "private-172".to_string(),
                enabled: true,
                priority: 120,
                condition: "IP-CIDR,172.16.0.0/12,no-resolve".to_string(),
                target: "DIRECT".to_string(),
            },
            RoutingPolicyRule {
                id: "private-192".to_string(),
                enabled: true,
                priority: 130,
                condition: "IP-CIDR,192.168.0.0/16,no-resolve".to_string(),
                target: "DIRECT".to_string(),
            },
            RoutingPolicyRule {
                id: "catch-all".to_string(),
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
        policy.pools[0].members = vec![PoolMember::Pool("MISSING".to_string())];
        assert!(policy
            .validate(&[profile("SAFE", ProxyRole::AutoSafe)])
            .is_err());

        let mut policy = default_client_policy();
        policy.pools[0].members = vec![PoolMember::Pool("FAILOVER".to_string())];
        assert!(policy
            .validate(&[profile("SAFE", ProxyRole::AutoSafe)])
            .is_err());
    }
}
