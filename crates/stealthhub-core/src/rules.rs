//! Routing rule-set definitions and validation.
//!
//! Rule payloads are stored in classical Mihomo provider format. This module
//! keeps defaults and validation close together so invalid routing payloads are
//! rejected before they reach generated subscriptions.

use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

const CLASSICAL_CONDITION_TYPES: &[&str] = &[
    "DOMAIN",
    "DOMAIN-SUFFIX",
    "DOMAIN-KEYWORD",
    "DOMAIN-WILDCARD",
    "DOMAIN-REGEX",
    "GEOSITE",
    "IP-CIDR",
    "IP-CIDR6",
    "IP-SUFFIX",
    "IP-ASN",
    "GEOIP",
    "SRC-GEOIP",
    "SRC-IP-ASN",
    "SRC-IP-CIDR",
    "SRC-IP-SUFFIX",
    "DST-PORT",
    "SRC-PORT",
    "IN-PORT",
    "IN-TYPE",
    "IN-USER",
    "IN-NAME",
    "PROCESS-PATH",
    "PROCESS-PATH-WILDCARD",
    "PROCESS-PATH-REGEX",
    "PROCESS-NAME",
    "PROCESS-NAME-WILDCARD",
    "PROCESS-NAME-REGEX",
    "UID",
    "NETWORK",
    "DSCP",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoutingRuleSet {
    pub slug: String,
    pub title: String,
    pub effect: String,
    pub target: String,
    pub enabled: bool,
    pub payload: String,
}

/// Normalized rule kind supported by the operator UI.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING-KEBAB-CASE")]
pub enum RuleKind {
    Domain,
    DomainSuffix,
    DomainKeyword,
    IpCidr,
    IpCidr6,
    Geoip,
    Geosite,
    Asn,
    ProcessName,
    DstPort,
    SrcPort,
    Network,
    Classical,
}

impl RuleKind {
    #[must_use]
    pub const fn mihomo_name(self) -> &'static str {
        match self {
            Self::Domain => "DOMAIN",
            Self::DomainSuffix => "DOMAIN-SUFFIX",
            Self::DomainKeyword => "DOMAIN-KEYWORD",
            Self::IpCidr => "IP-CIDR",
            Self::IpCidr6 => "IP-CIDR6",
            Self::Geoip => "GEOIP",
            Self::Geosite => "GEOSITE",
            Self::Asn => "IP-ASN",
            Self::ProcessName => "PROCESS-NAME",
            Self::DstPort => "DST-PORT",
            Self::SrcPort => "SRC-PORT",
            Self::Network => "NETWORK",
            Self::Classical => "CLASSICAL",
        }
    }

    pub fn parse(value: &str) -> Result<Self> {
        match value.trim().to_ascii_uppercase().as_str() {
            "DOMAIN" => Ok(Self::Domain),
            "DOMAIN-SUFFIX" => Ok(Self::DomainSuffix),
            "DOMAIN-KEYWORD" => Ok(Self::DomainKeyword),
            "IP-CIDR" => Ok(Self::IpCidr),
            "IP-CIDR6" => Ok(Self::IpCidr6),
            "GEOIP" => Ok(Self::Geoip),
            "GEOSITE" => Ok(Self::Geosite),
            "ASN" | "IP-ASN" => Ok(Self::Asn),
            "PROCESS-NAME" => Ok(Self::ProcessName),
            "DST-PORT" => Ok(Self::DstPort),
            "SRC-PORT" => Ok(Self::SrcPort),
            "NETWORK" => Ok(Self::Network),
            "CLASSICAL" => Ok(Self::Classical),
            _ => bail!("unsupported normalized rule kind"),
        }
    }
}

/// One countable, editable routing rule independent of provider syntax.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RuleEntry {
    pub id: String,
    pub rule_set_id: String,
    pub enabled: bool,
    pub kind: RuleKind,
    pub value: String,
    pub comment: Option<String>,
    pub source_tag: Option<String>,
    pub priority: i32,
}

impl RuleEntry {
    pub fn validate(&self) -> Result<()> {
        if self.id.is_empty()
            || self.id.len() > 64
            || !self
                .id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        {
            bail!("invalid rule entry ID");
        }
        if self.rule_set_id.is_empty() || self.rule_set_id.len() > 64 {
            bail!("invalid rule-set reference");
        }
        if self.value.trim().is_empty()
            || self.value.len() > 1024
            || self.value.chars().any(char::is_control)
        {
            bail!("invalid normalized rule value");
        }
        if self.comment.as_ref().is_some_and(|value| {
            value.len() > 256 || value.chars().any(|character| character.is_control())
        }) || self.source_tag.as_ref().is_some_and(|value| {
            value.len() > 64 || value.chars().any(|character| character.is_control())
        }) {
            bail!("invalid rule entry metadata");
        }
        self.compiled()?;
        Ok(())
    }

    pub fn compiled(&self) -> Result<String> {
        let value = self.value.trim();
        if self.kind == RuleKind::Classical {
            return validate_classical_rule_payload(value)?
                .into_iter()
                .next()
                .ok_or_else(|| anyhow::anyhow!("empty classical rule"));
        }
        validate_classical_rule_payload(&format!("{},{value}", self.kind.mihomo_name()))?
            .into_iter()
            .next()
            .ok_or_else(|| anyhow::anyhow!("empty normalized rule"))
    }
}

/// Supported remote rule source representation.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum RuleSourceFormat {
    Text,
    Yaml,
    MihomoClassical,
}

impl RuleSourceFormat {
    pub fn parse(value: &str) -> Result<Self> {
        match value {
            "text" => Ok(Self::Text),
            "yaml" => Ok(Self::Yaml),
            "mihomo-classical" => Ok(Self::MihomoClassical),
            _ => bail!("unsupported rule source format"),
        }
    }
}

/// Persisted source metadata and last-known-good data cache.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RuleSetSource {
    pub id: String,
    pub rule_set_id: String,
    pub url: String,
    pub format: RuleSourceFormat,
    pub enabled: bool,
    pub refresh_interval_seconds: u32,
    pub etag: Option<String>,
    pub last_modified: Option<String>,
    pub last_successful_fetch: Option<String>,
    pub checksum: Option<String>,
    pub entry_count: u32,
    pub last_error: Option<String>,
    pub cached_payload: String,
}

/// Compiles all layers into one deterministic provider payload.
pub fn compile_rule_set_payload(
    entries: &[RuleEntry],
    local_payload: &str,
    sources: &[RuleSetSource],
) -> Result<String> {
    let mut compiled = entries
        .iter()
        .filter(|entry| entry.enabled)
        .map(|entry| entry.compiled())
        .collect::<Result<Vec<_>>>()?;
    if !local_payload.trim().is_empty() {
        compiled.extend(validate_classical_rule_payload(local_payload)?);
    }
    for source in sources.iter().filter(|source| source.enabled) {
        if source.cached_payload.trim().is_empty() {
            continue;
        }
        compiled.extend(validate_classical_rule_payload(&source.cached_payload)?);
    }
    let mut seen = BTreeSet::new();
    compiled.retain(|rule| seen.insert(rule.to_ascii_lowercase()));
    if compiled.is_empty() {
        bail!("compiled rule set is empty");
    }
    Ok(compiled.join("\n"))
}

#[derive(Serialize)]
struct ProviderPayload {
    payload: Vec<String>,
}

#[derive(Debug, Clone, Copy)]
pub struct DefaultRoutingRuleSet {
    pub slug: &'static str,
    pub title: &'static str,
    pub effect: &'static str,
    pub target: &'static str,
    pub payload: &'static [&'static str],
}

pub const ROUTING_TARGETS: &[&str] = &[
    "DIRECT",
    "AUTO-SAFE",
    "SPEED",
    "RU-ACCESS",
    "MANUAL",
    "REJECT",
];

const DEFAULT_RULE_SETS: &[DefaultRoutingRuleSet] = &[
    DefaultRoutingRuleSet {
        slug: "banking-direct",
        title: "Banking and government",
        effect: "Send matching domains directly without proxy.",
        target: "DIRECT",
        payload: &[
            "DOMAIN-SUFFIX,sberbank.ru",
            "DOMAIN-SUFFIX,online.sberbank.ru",
            "DOMAIN-SUFFIX,sberbank.com",
            "DOMAIN-SUFFIX,gazprombank.ru",
            "DOMAIN-SUFFIX,tbank.ru",
            "DOMAIN-SUFFIX,tinkoff.ru",
            "DOMAIN-SUFFIX,vtb.ru",
            "DOMAIN-SUFFIX,alfabank.ru",
            "DOMAIN-SUFFIX,gosuslugi.ru",
            "DOMAIN-SUFFIX,nalog.gov.ru",
        ],
    },
    DefaultRoutingRuleSet {
        slug: "direct-local",
        title: "Local and RU",
        effect: "Keep private networks and RU domains on direct routing.",
        target: "DIRECT",
        payload: &[
            "DOMAIN-SUFFIX,local",
            "DOMAIN-SUFFIX,lan",
            "DOMAIN-SUFFIX,ru",
            "DOMAIN-SUFFIX,рф",
            "IP-CIDR,10.0.0.0/8,no-resolve",
            "IP-CIDR,172.16.0.0/12,no-resolve",
            "IP-CIDR,192.168.0.0/16,no-resolve",
        ],
    },
    DefaultRoutingRuleSet {
        slug: "proxy-ai",
        title: "AI and development",
        effect: "Route selected AI/development domains through AUTO-SAFE.",
        target: "AUTO-SAFE",
        payload: &[
            "DOMAIN-SUFFIX,openai.com",
            "DOMAIN-SUFFIX,chatgpt.com",
            "DOMAIN-SUFFIX,anthropic.com",
            "DOMAIN-SUFFIX,claude.ai",
            "DOMAIN-SUFFIX,github.com",
            "DOMAIN-SUFFIX,githubusercontent.com",
        ],
    },
    DefaultRoutingRuleSet {
        slug: "streaming",
        title: "Streaming",
        effect: "Route high-bandwidth media domains through SPEED.",
        target: "SPEED",
        payload: &[
            "DOMAIN-SUFFIX,youtube.com",
            "DOMAIN-SUFFIX,googlevideo.com",
            "DOMAIN-SUFFIX,ytimg.com",
            "DOMAIN-SUFFIX,netflix.com",
            "DOMAIN-SUFFIX,spotify.com",
        ],
    },
];

#[must_use]
pub fn default_routing_rule_sets() -> Vec<RoutingRuleSet> {
    DEFAULT_RULE_SETS
        .iter()
        .map(|rule_set| RoutingRuleSet {
            slug: rule_set.slug.to_string(),
            title: rule_set.title.to_string(),
            effect: rule_set.effect.to_string(),
            target: rule_set.target.to_string(),
            enabled: true,
            payload: rule_set.payload.join("\n"),
        })
        .collect()
}

#[must_use]
pub fn default_routing_rule_set(slug: &str) -> Option<DefaultRoutingRuleSet> {
    DEFAULT_RULE_SETS
        .iter()
        .copied()
        .find(|rule_set| rule_set.slug == slug)
}

#[must_use]
pub fn is_valid_routing_target(target: &str) -> bool {
    ROUTING_TARGETS.contains(&target)
}

pub fn validate_classical_rule_payload(payload: &str) -> Result<Vec<String>> {
    let mut rules = Vec::new();

    for (index, raw_line) in payload.lines().enumerate() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        let Some((kind, rest)) = line.split_once(',') else {
            bail!("line {} must use TYPE,value syntax", index + 1);
        };

        let kind = kind.trim();
        if kind.is_empty() || rest.trim().is_empty() {
            bail!("line {} has an empty rule type or value", index + 1);
        }

        if matches!(kind, "RULE-SET" | "SUB-RULE") {
            bail!("line {} cannot reference another rule set", index + 1);
        }
        if matches!(kind, "AND" | "OR" | "NOT" | "MATCH") {
            bail!(
                "line {} cannot contain a logical or catch-all rule",
                index + 1
            );
        }
        if !CLASSICAL_CONDITION_TYPES.contains(&kind) {
            bail!("line {} uses an unsupported rule type", index + 1);
        }
        if line.len() > 1024 || line.chars().any(char::is_control) {
            bail!(
                "line {} is too long or contains control characters",
                index + 1
            );
        }
        if rest
            .split(',')
            .skip(1)
            .map(str::trim)
            .any(|value| ROUTING_TARGETS.contains(&value))
        {
            bail!(
                "line {} must not override the rule-set routing target",
                index + 1
            );
        }

        rules.push(line.to_string());
    }

    if rules.is_empty() {
        bail!("rule payload must contain at least one rule");
    }

    Ok(rules)
}

pub fn routing_rule_payload_yaml(payload: &str) -> Result<String> {
    let rules = validate_classical_rule_payload(payload)?;
    Ok(serde_norway::to_string(&ProviderPayload {
        payload: rules,
    })?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classical_payload_validation_trims_comments_and_rejects_nested_sets() {
        let rules = validate_classical_rule_payload(
            r"
            # comment
            DOMAIN-SUFFIX,example.com
            IP-CIDR,10.0.0.0/8,no-resolve
            ",
        )
        .expect("payload should be valid");

        assert_eq!(
            rules,
            vec![
                "DOMAIN-SUFFIX,example.com".to_string(),
                "IP-CIDR,10.0.0.0/8,no-resolve".to_string()
            ]
        );

        let err = validate_classical_rule_payload("RULE-SET,other,DIRECT").unwrap_err();
        assert!(err
            .to_string()
            .contains("cannot reference another rule set"));
        assert!(validate_classical_rule_payload("UNKNOWN,value").is_err());
        assert!(validate_classical_rule_payload("DOMAIN,example.com,REJECT").is_err());
        assert!(validate_classical_rule_payload("AND,((DOMAIN,a),(DOMAIN,b))").is_err());
    }

    #[test]
    fn routing_rule_payload_yaml_outputs_mihomo_payload_document() {
        let yaml = routing_rule_payload_yaml("DOMAIN-SUFFIX,example.com").unwrap();

        assert_eq!(yaml, "payload:\n- DOMAIN-SUFFIX,example.com\n");
    }

    #[test]
    fn normalized_local_and_imported_layers_compile_in_precedence_order() {
        let entries = vec![RuleEntry {
            id: "manual-one".to_string(),
            rule_set_id: "set-one".to_string(),
            enabled: true,
            kind: RuleKind::DomainSuffix,
            value: "example.com".to_string(),
            comment: None,
            source_tag: Some("manual".to_string()),
            priority: 10,
        }];
        let sources = vec![RuleSetSource {
            id: "source-one".to_string(),
            rule_set_id: "set-one".to_string(),
            url: "https://example.test/rules.txt".to_string(),
            format: RuleSourceFormat::Text,
            enabled: true,
            refresh_interval_seconds: 3600,
            etag: None,
            last_modified: None,
            last_successful_fetch: None,
            checksum: None,
            entry_count: 2,
            last_error: None,
            cached_payload: "DOMAIN-SUFFIX,example.com\nDOMAIN,imported.test".to_string(),
        }];
        let compiled = compile_rule_set_payload(
            &entries,
            "DOMAIN,local.test\nDOMAIN-SUFFIX,example.com",
            &sources,
        )
        .unwrap();
        assert_eq!(
            compiled,
            "DOMAIN-SUFFIX,example.com\nDOMAIN,local.test\nDOMAIN,imported.test"
        );
    }
}
