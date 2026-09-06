//! Canonical, read-only explanation of the generated Mihomo routing order.
//!
//! The model intentionally separates configuration explanation from rendering.
//! Web SVG, accessible tables, domain inspection and the SSH TUI consume the
//! same ordered paths. Unsupported match classes remain explicit uncertainty.

use std::collections::{BTreeMap, BTreeSet};

use crate::{
    models::ProtocolProfile,
    policy::{ClientPolicy, PoolMember},
    rules::{compile_rule_set_payload, RoutingRuleSet, RuleEntry, RuleSetSource},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TopologyState {
    Ready,
    Dynamic,
    Unresolved,
    Unsupported,
}

impl TopologyState {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Ready => "ready",
            Self::Dynamic => "dynamic",
            Self::Unresolved => "unresolved",
            Self::Unsupported => "unsupported simulation",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TargetKind {
    Direct,
    Reject,
    Pool,
    Profile,
    Fallback,
    Unavailable,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeResolution {
    pub id: String,
    pub available: bool,
    pub adapter_present: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TopologyAvailability {
    pub protocol_adapters: BTreeSet<String>,
    pub profile_runtimes: BTreeMap<String, RuntimeResolution>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TopologyPath {
    pub order: usize,
    pub source: String,
    pub matcher: String,
    pub entry_count: usize,
    pub target: String,
    pub target_kind: TargetKind,
    pub profile: Option<String>,
    pub runtime: Option<String>,
    pub state: TopologyState,
    pub detail: String,
    matchers: Vec<DomainMatcher>,
    has_unsupported_matcher: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TopologyPool {
    pub id: String,
    pub kind: String,
    pub members: Vec<String>,
    pub state: TopologyState,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TopologyIssue {
    pub subject: String,
    pub detail: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RoutingTopology {
    pub paths: Vec<TopologyPath>,
    pub pools: Vec<TopologyPool>,
    pub issues: Vec<TopologyIssue>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InspectionOutcome {
    Matched,
    Default,
    Uncertain,
    Invalid,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteInspection {
    pub domain: String,
    pub outcome: InspectionOutcome,
    pub path: Option<TopologyPath>,
    pub explanation: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum DomainMatcher {
    Exact(String),
    Suffix(String),
    Keyword(String),
    Wildcard(String),
    Match,
}

impl RoutingTopology {
    #[must_use]
    pub fn build(
        rule_sets: &[RoutingRuleSet],
        policy: &ClientPolicy,
        profiles: &[ProtocolProfile],
        entries: &BTreeMap<String, Vec<RuleEntry>>,
        sources: &BTreeMap<String, Vec<RuleSetSource>>,
        availability: &TopologyAvailability,
    ) -> Self {
        let mut topology = Self::default();
        let pools = policy
            .pools
            .iter()
            .filter(|pool| pool.enabled)
            .map(|pool| (pool.id.as_str(), pool))
            .collect::<BTreeMap<_, _>>();

        for pool in pools.values() {
            let members = pool.members.iter().map(member_label).collect::<Vec<_>>();
            let unresolved = pool.members.iter().any(|member| match member {
                PoolMember::Profile(id) => !profiles.iter().any(|p| p.enabled && p.name == *id),
                PoolMember::Pool(id) => !pools.contains_key(id.as_str()),
                PoolMember::Capability(id) => {
                    !profiles.iter().any(|p| p.enabled && p.protocol_id == *id)
                }
                _ => false,
            });
            let state = if unresolved || members.is_empty() {
                topology.issues.push(TopologyIssue {
                    subject: format!("pool:{}", pool.id),
                    detail: "Pool contains an unavailable member or resolves empty".into(),
                });
                TopologyState::Unresolved
            } else {
                TopologyState::Dynamic
            };
            topology.pools.push(TopologyPool {
                id: pool.id.clone(),
                kind: pool.kind.mihomo_name().into(),
                members,
                state,
            });
        }

        for rule_set in rule_sets.iter().filter(|set| set.enabled) {
            let set_entries = entries.get(&rule_set.slug).map_or(&[][..], Vec::as_slice);
            let set_sources = sources.get(&rule_set.slug).map_or(&[][..], Vec::as_slice);
            let (compiled, compile_error) =
                match compile_rule_set_payload(set_entries, &rule_set.payload, set_sources) {
                    Ok(value) => (value, None),
                    Err(error) => (String::new(), Some(error.to_string())),
                };
            let rules = compiled.lines().collect::<Vec<_>>();
            let (matchers, unsupported) = domain_matchers(&rules);
            let mut path = resolve_target(
                PathInput {
                    order: topology.paths.len() + 1,
                    source: format!("provider:{}", rule_set.slug),
                    matcher: format!("RULE-SET {}", rule_set.slug),
                    entry_count: rules.len(),
                    target: &rule_set.target,
                },
                profiles,
                &pools,
                availability,
            );
            path.matchers = matchers;
            path.has_unsupported_matcher = unsupported;
            apply_pool_state(&mut path, &topology.pools);
            if let Some(error) = compile_error {
                path.state = TopologyState::Unresolved;
                path.detail = format!("Provider payload is invalid: {error}");
                topology.issues.push(TopologyIssue {
                    subject: format!("provider:{}", rule_set.slug),
                    detail: path.detail.clone(),
                });
            }
            record_path_issue(&mut topology.issues, &path);
            topology.paths.push(path);
        }

        let mut inline = policy
            .rules
            .iter()
            .filter(|rule| rule.enabled)
            .collect::<Vec<_>>();
        inline.sort_by_key(|rule| (rule.priority, rule.id.as_str()));
        for rule in inline {
            let resolved_target = rule
                .target
                .strip_prefix("capability:")
                .and_then(|capability| {
                    profiles
                        .iter()
                        .find(|profile| profile.enabled && profile.protocol_id == capability)
                })
                .map_or(rule.target.as_str(), |profile| profile.name.as_str());
            let rule_lines = [rule.condition.as_str()];
            let (matchers, unsupported) = domain_matchers(&rule_lines);
            let mut path = resolve_target(
                PathInput {
                    order: topology.paths.len() + 1,
                    source: format!("rule:{}", rule.id),
                    matcher: rule.condition.clone(),
                    entry_count: 1,
                    target: resolved_target,
                },
                profiles,
                &pools,
                availability,
            );
            path.matchers = matchers;
            path.has_unsupported_matcher = unsupported;
            apply_pool_state(&mut path, &topology.pools);
            if rule.target.starts_with("capability:") && resolved_target == rule.target {
                path.state = TopologyState::Unresolved;
                path.detail = "Capability selector resolves to no enabled profile".into();
                topology.issues.push(TopologyIssue {
                    subject: format!("rule:{}", rule.id),
                    detail: path.detail.clone(),
                });
            }
            if unsupported {
                topology.issues.push(TopologyIssue {
                    subject: path.source.clone(),
                    detail:
                        "Matcher requires runtime data or is not supported by domain inspection"
                            .into(),
                });
            }
            record_path_issue(&mut topology.issues, &path);
            topology.paths.push(path);
        }

        if !topology
            .paths
            .iter()
            .any(|path| path.matchers.contains(&DomainMatcher::Match))
        {
            let order = topology.paths.len() + 1;
            topology.paths.push(TopologyPath {
                order,
                source: "implicit-fallback".into(),
                matcher: "No explicit MATCH rule".into(),
                entry_count: 0,
                target: "runtime-dependent".into(),
                target_kind: TargetKind::Fallback,
                profile: None,
                runtime: None,
                state: TopologyState::Unresolved,
                detail: "Generated policy has no explicit catch-all; no-match behavior is not asserted by Infiproxy".into(),
                matchers: Vec::new(),
                has_unsupported_matcher: false,
            });
            topology.issues.push(TopologyIssue {
                subject: "fallback".into(),
                detail: "No explicit MATCH rule is configured".into(),
            });
        }
        topology
    }

    #[must_use]
    pub fn inspect_domain(&self, domain: &str) -> RouteInspection {
        let domain = domain.trim().trim_end_matches('.').to_ascii_lowercase();
        if !valid_domain(&domain) {
            return RouteInspection {
                domain,
                outcome: InspectionOutcome::Invalid,
                path: None,
                explanation: "Enter a host name containing only DNS labels".into(),
            };
        }
        for path in &self.paths {
            if path.matchers.iter().any(|matcher| matcher.matches(&domain)) {
                return RouteInspection {
                    domain,
                    outcome: InspectionOutcome::Matched,
                    path: Some(path.clone()),
                    explanation: format!("First definite match is route #{}", path.order),
                };
            }
            if path.has_unsupported_matcher {
                return RouteInspection {
                    domain,
                    outcome: InspectionOutcome::Uncertain,
                    path: Some(path.clone()),
                    explanation: format!(
                        "Route #{} contains IP, process, regex or other runtime-dependent matching before any later definite match",
                        path.order
                    ),
                };
            }
        }
        RouteInspection {
            domain,
            outcome: InspectionOutcome::Default,
            path: self
                .paths
                .iter()
                .find(|path| path.target_kind == TargetKind::Fallback)
                .cloned(),
            explanation:
                "No configured domain rule definitely matches; no explicit catch-all is available"
                    .into(),
        }
    }

    #[must_use]
    pub fn text_tree(&self) -> String {
        let mut lines = vec!["ROUTING / first match wins".to_string()];
        for path in &self.paths {
            lines.push(format!(
                "{:02}. {} [{}]",
                path.order,
                path.source,
                path.state.label()
            ));
            lines.push(format!("    {} -> {}", path.matcher, path.target));
            if let Some(profile) = &path.profile {
                lines.push(format!("       profile: {profile}"));
            }
            if let Some(runtime) = &path.runtime {
                lines.push(format!("       runtime: {runtime}"));
            }
        }
        if !self.pools.is_empty() {
            lines.push("POOLS / client-side member selection".into());
            for pool in &self.pools {
                lines.push(format!(
                    "- {} ({}) [{}]",
                    pool.id,
                    pool.kind,
                    pool.state.label()
                ));
                lines.push(format!("    {}", pool.members.join(" -> ")));
            }
        }
        if !self.issues.is_empty() {
            lines.push(format!(
                "ATTENTION: {} topology issue(s)",
                self.issues.len()
            ));
        }
        lines.join("\n")
    }
}

fn record_path_issue(issues: &mut Vec<TopologyIssue>, path: &TopologyPath) {
    if path.state == TopologyState::Unresolved
        && !issues.iter().any(|issue| issue.subject == path.source)
    {
        issues.push(TopologyIssue {
            subject: path.source.clone(),
            detail: path.detail.clone(),
        });
    }
}

fn apply_pool_state(path: &mut TopologyPath, pools: &[TopologyPool]) {
    if path.target_kind != TargetKind::Pool {
        return;
    }
    if let Some(pool) = pools.iter().find(|pool| pool.id == path.target) {
        path.detail = format!(
            "Client selects a member at runtime: {}",
            pool.members.join(", ")
        );
        if pool.state == TopologyState::Unresolved {
            path.state = TopologyState::Unresolved;
            path.detail = format!(
                "Pool cannot resolve all members: {}",
                pool.members.join(", ")
            );
        }
    }
}

impl DomainMatcher {
    fn matches(&self, domain: &str) -> bool {
        match self {
            Self::Exact(value) => domain == value,
            Self::Suffix(value) => domain == value || domain.ends_with(&format!(".{value}")),
            Self::Keyword(value) => domain.contains(value),
            Self::Wildcard(value) => wildcard_matches(value.as_bytes(), domain.as_bytes()),
            Self::Match => true,
        }
    }
}

struct PathInput<'a> {
    order: usize,
    source: String,
    matcher: String,
    entry_count: usize,
    target: &'a str,
}

fn resolve_target(
    input: PathInput<'_>,
    profiles: &[ProtocolProfile],
    pools: &BTreeMap<&str, &crate::policy::TransportPool>,
    availability: &TopologyAvailability,
) -> TopologyPath {
    let mut path = TopologyPath {
        order: input.order,
        source: input.source,
        matcher: input.matcher,
        entry_count: input.entry_count,
        target: input.target.to_string(),
        target_kind: TargetKind::Unavailable,
        profile: None,
        runtime: None,
        state: TopologyState::Unresolved,
        detail: "Target is unavailable".into(),
        matchers: Vec::new(),
        has_unsupported_matcher: false,
    };
    match input.target {
        "DIRECT" => {
            path.target_kind = TargetKind::Direct;
            path.state = TopologyState::Ready;
            path.detail = "Connection bypasses proxy groups".into();
        }
        "REJECT" => {
            path.target_kind = TargetKind::Reject;
            path.state = TopologyState::Ready;
            path.detail = "Connection is rejected by the client policy".into();
        }
        _ if pools.contains_key(input.target) => {
            path.target_kind = TargetKind::Pool;
            path.state = TopologyState::Dynamic;
            path.detail = "Pool member selection occurs in the Mihomo client".into();
        }
        _ => {
            if let Some(profile) = profiles
                .iter()
                .find(|profile| profile.enabled && profile.name == input.target)
            {
                path.target_kind = TargetKind::Profile;
                path.profile = Some(profile.name.clone());
                if !availability
                    .protocol_adapters
                    .contains(&profile.protocol_id)
                {
                    path.state = TopologyState::Unresolved;
                    path.detail = "Protocol adapter is missing".into();
                } else if let Some(runtime) = availability.profile_runtimes.get(&profile.name) {
                    path.runtime = Some(runtime.id.clone());
                    if !runtime.adapter_present {
                        path.state = TopologyState::Unresolved;
                        path.detail = "Runtime adapter is missing".into();
                    } else if !runtime.available {
                        path.state = TopologyState::Unresolved;
                        path.detail = "Compatible runtime is unavailable".into();
                    } else {
                        path.state = TopologyState::Ready;
                        path.detail = "Profile and runtime are available".into();
                    }
                } else {
                    path.state = TopologyState::Dynamic;
                    path.detail =
                        "Runtime is selected by adapter capabilities during generation".into();
                }
            }
        }
    }
    path
}

fn member_label(member: &PoolMember) -> String {
    match member {
        PoolMember::Profile(value) => format!("profile:{value}"),
        PoolMember::Capability(value) => format!("capability:{value}"),
        PoolMember::Role(value) => format!("role:{value:?}"),
        PoolMember::Pool(value) => format!("pool:{value}"),
        PoolMember::AllProfiles => "all-enabled-profiles".into(),
        PoolMember::Direct => "DIRECT".into(),
        PoolMember::Reject => "REJECT".into(),
    }
}

fn domain_matchers(lines: &[&str]) -> (Vec<DomainMatcher>, bool) {
    let mut result = Vec::new();
    let mut unsupported = false;
    for line in lines {
        let mut parts = line.split(',').map(str::trim);
        let kind = parts.next().unwrap_or_default();
        let value = parts.next().unwrap_or_default().to_ascii_lowercase();
        let matcher = match kind {
            "DOMAIN" if !value.is_empty() => Some(DomainMatcher::Exact(value)),
            "DOMAIN-SUFFIX" if !value.is_empty() => Some(DomainMatcher::Suffix(value)),
            "DOMAIN-KEYWORD" if !value.is_empty() => Some(DomainMatcher::Keyword(value)),
            "DOMAIN-WILDCARD" if !value.is_empty() => Some(DomainMatcher::Wildcard(value)),
            "MATCH" => Some(DomainMatcher::Match),
            _ => {
                unsupported = true;
                None
            }
        };
        result.extend(matcher);
    }
    (result, unsupported)
}

fn valid_domain(domain: &str) -> bool {
    !domain.is_empty()
        && domain.len() <= 253
        && domain.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
}

fn wildcard_matches(pattern: &[u8], value: &[u8]) -> bool {
    let (mut p, mut v, mut star, mut retry) = (0, 0, None, 0);
    while v < value.len() {
        if p < pattern.len() && (pattern[p] == b'?' || pattern[p] == value[v]) {
            p += 1;
            v += 1;
        } else if p < pattern.len() && pattern[p] == b'*' {
            star = Some(p);
            p += 1;
            retry = v;
        } else if let Some(star_index) = star {
            p = star_index + 1;
            retry += 1;
            v = retry;
        } else {
            return false;
        }
    }
    while p < pattern.len() && pattern[p] == b'*' {
        p += 1;
    }
    p == pattern.len()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        models::ProxyRole,
        policy::{PoolKind, RoutingPolicyRule, TransportPool},
        rules::{RuleKind, RuleSourceFormat},
    };
    use serde_json::json;

    fn profile(name: &str, adapter: &str) -> ProtocolProfile {
        ProtocolProfile {
            name: name.into(),
            protocol_id: adapter.into(),
            schema_version: 1,
            role: ProxyRole::AutoSafe,
            server: "node.example".into(),
            port: 443,
            enabled: true,
            preferred_core_id: None,
            managed_resource_id: None,
            config: json!({"password":"SECRET_CANARY"}),
        }
    }

    fn availability() -> TopologyAvailability {
        TopologyAvailability {
            protocol_adapters: BTreeSet::from(["vless".into()]),
            profile_runtimes: BTreeMap::from([(
                "proxy-main".into(),
                RuntimeResolution {
                    id: "xray".into(),
                    available: true,
                    adapter_present: true,
                },
            )]),
        }
    }

    #[test]
    fn empty_policy_is_explicit_unresolved_fallback() {
        let topology = RoutingTopology::build(
            &[],
            &ClientPolicy {
                pools: vec![],
                rules: vec![],
            },
            &[],
            &BTreeMap::new(),
            &BTreeMap::new(),
            &TopologyAvailability::default(),
        );
        assert_eq!(topology.paths.len(), 1);
        assert_eq!(topology.paths[0].target_kind, TargetKind::Fallback);
        assert_eq!(
            topology.inspect_domain("example.com").outcome,
            InspectionOutcome::Default
        );
    }

    #[test]
    fn providers_are_grouped_and_first_match_wins() {
        let sets = vec![
            RoutingRuleSet {
                slug: "a-direct".into(),
                title: "Direct".into(),
                effect: String::new(),
                target: "DIRECT".into(),
                enabled: true,
                payload: "DOMAIN-SUFFIX,example.com".into(),
            },
            RoutingRuleSet {
                slug: "b-reject".into(),
                title: "Reject".into(),
                effect: String::new(),
                target: "REJECT".into(),
                enabled: true,
                payload: "DOMAIN,api.example.com".into(),
            },
        ];
        let topology = RoutingTopology::build(
            &sets,
            &ClientPolicy {
                pools: vec![],
                rules: vec![],
            },
            &[],
            &BTreeMap::new(),
            &BTreeMap::new(),
            &TopologyAvailability::default(),
        );
        let result = topology.inspect_domain("api.example.com");
        assert_eq!(result.path.unwrap().target_kind, TargetKind::Direct);
        assert_eq!(topology.paths[0].entry_count, 1);
    }

    #[test]
    fn normalized_sources_and_large_sets_stay_one_path() {
        let set = RoutingRuleSet {
            slug: "grouped".into(),
            title: "Grouped".into(),
            effect: String::new(),
            target: "DIRECT".into(),
            enabled: true,
            payload: String::new(),
        };
        let entries = BTreeMap::from([(
            "grouped".into(),
            (0..600)
                .map(|index| RuleEntry {
                    id: format!("r{index}"),
                    rule_set_id: "grouped".into(),
                    enabled: true,
                    kind: RuleKind::Domain,
                    value: format!("d{index}.example"),
                    comment: None,
                    source_tag: None,
                    priority: index,
                })
                .collect(),
        )]);
        let sources = BTreeMap::from([(
            "grouped".into(),
            vec![RuleSetSource {
                id: "remote".into(),
                rule_set_id: "grouped".into(),
                url: "https://rules.example/list".into(),
                format: RuleSourceFormat::Text,
                enabled: true,
                refresh_interval_seconds: 3600,
                etag: None,
                last_modified: None,
                last_successful_fetch: None,
                checksum: None,
                entry_count: 1,
                last_error: None,
                cached_payload: "DOMAIN-SUFFIX,remote.example".into(),
            }],
        )]);
        let topology = RoutingTopology::build(
            &[set],
            &ClientPolicy {
                pools: vec![],
                rules: vec![],
            },
            &[],
            &entries,
            &sources,
            &TopologyAvailability::default(),
        );
        assert_eq!(topology.paths.len(), 2);
        assert_eq!(topology.paths[0].entry_count, 601);
        assert_eq!(
            topology.inspect_domain("x.remote.example").outcome,
            InspectionOutcome::Matched
        );
    }

    #[test]
    fn profile_pool_missing_adapter_and_runtime_states_are_truthful() {
        let profiles = vec![profile("proxy-main", "vless")];
        let policy = ClientPolicy {
            pools: vec![TransportPool {
                id: "AUTO".into(),
                display_name: "Auto".into(),
                kind: PoolKind::Select,
                enabled: true,
                members: vec![PoolMember::Profile("proxy-main".into())],
                test_url: None,
                interval_seconds: None,
                timeout_ms: None,
                tolerance_ms: None,
                max_failures: None,
                lazy: false,
                minimum_healthy_count: None,
                fallback_pool: None,
                priority: 1,
                strategy: None,
            }],
            rules: vec![
                RoutingPolicyRule {
                    id: "profile".into(),
                    display_name: "Profile".into(),
                    enabled: true,
                    priority: 1,
                    condition: "DOMAIN,profile.example".into(),
                    target: "proxy-main".into(),
                },
                RoutingPolicyRule {
                    id: "pool".into(),
                    display_name: "Pool".into(),
                    enabled: true,
                    priority: 2,
                    condition: "DOMAIN-SUFFIX,pool.example".into(),
                    target: "AUTO".into(),
                },
            ],
        };
        let topology = RoutingTopology::build(
            &[],
            &policy,
            &profiles,
            &BTreeMap::new(),
            &BTreeMap::new(),
            &availability(),
        );
        assert_eq!(topology.paths[0].runtime.as_deref(), Some("xray"));
        assert_eq!(topology.paths[1].state, TopologyState::Dynamic);
        assert!(!format!("{topology:?}").contains("SECRET_CANARY"));
        let missing = RoutingTopology::build(
            &[],
            &policy,
            &profiles,
            &BTreeMap::new(),
            &BTreeMap::new(),
            &TopologyAvailability::default(),
        );
        assert_eq!(missing.paths[0].state, TopologyState::Unresolved);

        let mut broken_pool_policy = policy;
        broken_pool_policy.pools[0].members = vec![PoolMember::Profile("absent".into())];
        let broken_pool = RoutingTopology::build(
            &[],
            &broken_pool_policy,
            &profiles,
            &BTreeMap::new(),
            &BTreeMap::new(),
            &availability(),
        );
        assert_eq!(broken_pool.paths[1].state, TopologyState::Unresolved);
    }

    #[test]
    fn unsupported_rule_before_domain_match_returns_uncertain() {
        let policy = ClientPolicy {
            pools: vec![],
            rules: vec![
                RoutingPolicyRule {
                    id: "ip".into(),
                    display_name: "IP".into(),
                    enabled: true,
                    priority: 1,
                    condition: "IP-CIDR,10.0.0.0/8".into(),
                    target: "DIRECT".into(),
                },
                RoutingPolicyRule {
                    id: "domain".into(),
                    display_name: "Domain".into(),
                    enabled: true,
                    priority: 2,
                    condition: "DOMAIN,example.com".into(),
                    target: "REJECT".into(),
                },
                RoutingPolicyRule {
                    id: "fallback".into(),
                    display_name: "Fallback".into(),
                    enabled: true,
                    priority: 3,
                    condition: "MATCH".into(),
                    target: "DIRECT".into(),
                },
            ],
        };
        let topology = RoutingTopology::build(
            &[],
            &policy,
            &[],
            &BTreeMap::new(),
            &BTreeMap::new(),
            &TopologyAvailability::default(),
        );
        assert_eq!(
            topology.inspect_domain("example.com").outcome,
            InspectionOutcome::Uncertain
        );
        assert_eq!(
            topology.paths.last().unwrap().target_kind,
            TargetKind::Direct
        );
    }

    #[test]
    fn unresolved_target_is_reported_and_topology_is_deterministic() {
        let policy = ClientPolicy {
            pools: vec![],
            rules: vec![RoutingPolicyRule {
                id: "missing".into(),
                display_name: "Missing".into(),
                enabled: true,
                priority: 1,
                condition: "DOMAIN,example.com".into(),
                target: "missing-profile".into(),
            }],
        };
        let first = RoutingTopology::build(
            &[],
            &policy,
            &[],
            &BTreeMap::new(),
            &BTreeMap::new(),
            &TopologyAvailability::default(),
        );
        let second = RoutingTopology::build(
            &[],
            &policy,
            &[],
            &BTreeMap::new(),
            &BTreeMap::new(),
            &TopologyAvailability::default(),
        );
        assert_eq!(first, second);
        assert_eq!(first.paths[0].state, TopologyState::Unresolved);
        assert!(first
            .issues
            .iter()
            .any(|issue| issue.subject == "rule:missing"));
    }

    #[test]
    fn classical_domain_entry_uses_the_shared_first_match_inspector() {
        let set = RoutingRuleSet {
            slug: "classical".into(),
            title: "Classical".into(),
            effect: String::new(),
            target: "REJECT".into(),
            enabled: true,
            payload: String::new(),
        };
        let entries = BTreeMap::from([(
            "classical".into(),
            vec![RuleEntry {
                id: "entry".into(),
                rule_set_id: "classical".into(),
                enabled: true,
                kind: RuleKind::Classical,
                value: "DOMAIN,classical.example".into(),
                comment: None,
                source_tag: None,
                priority: 1,
            }],
        )]);
        let topology = RoutingTopology::build(
            &[set],
            &ClientPolicy {
                pools: vec![],
                rules: vec![],
            },
            &[],
            &entries,
            &BTreeMap::new(),
            &TopologyAvailability::default(),
        );
        let inspected = topology.inspect_domain("classical.example");
        assert_eq!(inspected.outcome, InspectionOutcome::Matched);
        assert_eq!(inspected.path.unwrap().target_kind, TargetKind::Reject);
    }
}
