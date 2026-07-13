//! Routing rule-set definitions and validation.
//!
//! Rule payloads are stored in classical Mihomo provider format. This module
//! keeps defaults and validation close together so invalid routing payloads are
//! rejected before they reach generated subscriptions.

use anyhow::{bail, Result};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoutingRuleSet {
    pub slug: String,
    pub title: String,
    pub effect: String,
    pub target: String,
    pub enabled: bool,
    pub payload: String,
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

pub fn default_routing_rule_set(slug: &str) -> Option<DefaultRoutingRuleSet> {
    DEFAULT_RULE_SETS
        .iter()
        .copied()
        .find(|rule_set| rule_set.slug == slug)
}

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

        rules.push(line.to_string());
    }

    if rules.is_empty() {
        bail!("rule payload must contain at least one rule");
    }

    Ok(rules)
}

pub fn routing_rule_payload_yaml(payload: &str) -> Result<String> {
    let rules = validate_classical_rule_payload(payload)?;
    let mut yaml = String::from("payload:\n");

    for rule in rules {
        yaml.push_str("  - ");
        yaml.push_str(&rule);
        yaml.push('\n');
    }

    Ok(yaml)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classical_payload_validation_trims_comments_and_rejects_nested_sets() {
        let rules = validate_classical_rule_payload(
            r#"
            # comment
            DOMAIN-SUFFIX,example.com
            IP-CIDR,10.0.0.0/8,no-resolve
            "#,
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
    }

    #[test]
    fn routing_rule_payload_yaml_outputs_mihomo_payload_document() {
        let yaml = routing_rule_payload_yaml("DOMAIN-SUFFIX,example.com").unwrap();

        assert_eq!(yaml, "payload:\n  - DOMAIN-SUFFIX,example.com\n");
    }
}
