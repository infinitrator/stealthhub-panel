//! Mihomo subscription YAML generation.
//!
//! The functions in this module convert persisted panel settings, protocol
//! profiles, secrets and routing rule sets into client-importable Mihomo config.
//! Inputs are explicit so generation can be tested without a database.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use anyhow::{bail, Result};
use serde_json::json;

use crate::{
    adapter::{ClientRenderContext, MapSecretResolver, ProtocolRegistry},
    models::{PanelSettings, ProtocolProfile, SubscriptionUser},
    policy::{default_client_policy, default_dns_policy, ClientPolicy, DnsPolicy},
    rules::RoutingRuleSet,
};

/// Generates a Mihomo document with the trusted built-in adapter registry.
pub fn generate_mihomo_yaml(
    settings: &PanelSettings,
    user: &SubscriptionUser,
    profiles: &[ProtocolProfile],
    secrets: &HashMap<String, String>,
    routing_rule_sets: &[RoutingRuleSet],
) -> Result<String> {
    let registry = crate::adapters::protocol_registry()?;
    generate_mihomo_yaml_with_registry(
        MihomoGenerationInput {
            settings,
            user,
            profiles,
            secrets,
            routing_rule_sets,
            policy: &default_client_policy(),
            dns_policy: &default_dns_policy(),
            available_core_capabilities: None,
        },
        &registry,
    )
}

/// Complete typed input for one client subscription document.
pub struct MihomoGenerationInput<'a> {
    pub settings: &'a PanelSettings,
    pub user: &'a SubscriptionUser,
    pub profiles: &'a [ProtocolProfile],
    pub secrets: &'a HashMap<String, String>,
    pub routing_rule_sets: &'a [RoutingRuleSet],
    pub policy: &'a ClientPolicy,
    pub dns_policy: &'a DnsPolicy,
    /// Installed runtime capabilities; `None` is reserved for offline tests/tools.
    pub available_core_capabilities: Option<&'a BTreeSet<String>>,
}

/// Generated document plus non-fatal unavailable-profile diagnostics.
pub struct MihomoGenerationOutput {
    pub yaml: String,
    pub warnings: Vec<String>,
}

/// Generates a Mihomo document without branching on concrete protocol IDs.
pub fn generate_mihomo_yaml_with_registry(
    input: MihomoGenerationInput<'_>,
    registry: &ProtocolRegistry,
) -> Result<String> {
    Ok(generate_mihomo_yaml_detailed(input, registry)?.yaml)
}

/// Generates a subscription while explicitly reporting skipped historical profiles.
pub fn generate_mihomo_yaml_detailed(
    input: MihomoGenerationInput<'_>,
    registry: &ProtocolRegistry,
) -> Result<MihomoGenerationOutput> {
    let MihomoGenerationInput {
        settings,
        user,
        profiles,
        secrets,
        routing_rule_sets,
        policy,
        dns_policy,
        available_core_capabilities,
    } = input;
    let enabled_profiles: Vec<_> = profiles.iter().filter(|profile| profile.enabled).collect();
    if enabled_profiles.is_empty() {
        bail!("no protocol profiles are enabled");
    }
    if user.subscription_token.trim().is_empty() {
        bail!("subscription token is empty");
    }

    let secret_values = secrets
        .iter()
        .map(|(name, value)| (name.clone(), value.clone()))
        .collect::<BTreeMap<_, _>>();
    let resolver = MapSecretResolver::new(&secret_values);
    let mut proxies = Vec::new();
    let mut available_profiles = Vec::new();
    let mut warnings = Vec::new();
    for profile in enabled_profiles {
        let Some(adapter) = registry.get(&profile.protocol_id) else {
            warnings.push(format!(
                "profile `{}` skipped: protocol adapter is unavailable",
                profile.name
            ));
            continue;
        };
        if available_core_capabilities.is_some_and(|capabilities| {
            !adapter
                .manifest()
                .required_core_capabilities
                .is_subset(capabilities)
        }) {
            warnings.push(format!(
                "profile `{}` skipped: compatible runtime is unavailable",
                profile.name
            ));
            continue;
        }
        proxies.push(adapter.render_client(&ClientRenderContext {
            profile,
            user,
            secrets: &resolver,
        })?);
        available_profiles.push(profile.clone());
    }
    if proxies.is_empty() {
        bail!("no enabled profile has an available protocol and runtime adapter");
    }

    let resolved_pools = policy.resolved_pools(&available_profiles)?;
    dns_policy.validate()?;
    let active_rule_sets = active_routing_rule_sets(routing_rule_sets);

    let doc = json!({
        "mixed-port": 7890,
        "allow-lan": false,
        "mode": "rule",
        "log-level": "info",
        "ipv6": false,
        "external-controller": "127.0.0.1:9090",
        "secret": user.subscription_token,
        "dns": dns_config(dns_policy, &active_rule_sets),
        "rule-providers": rule_provider_map(settings, &active_rule_sets),
        "proxies": proxies,
        "proxy-groups": proxy_groups(&resolved_pools),
        "rules": routing_rules(&active_rule_sets, policy, &available_profiles)?
    });

    Ok(MihomoGenerationOutput {
        yaml: serde_norway::to_string(&doc)?,
        warnings,
    })
}

fn dns_config(policy: &DnsPolicy, rule_sets: &[RoutingRuleSet]) -> serde_json::Value {
    let nameserver_policy = rule_sets
        .iter()
        .map(|rule_set| {
            let resolvers = if rule_set.target == "DIRECT" {
                &policy.direct_resolvers
            } else {
                &policy.remote_resolvers
            };
            (format!("rule-set:{}", rule_set.slug), json!(resolvers))
        })
        .collect::<serde_json::Map<_, _>>();
    json!({
        "enable": policy.enabled,
        "ipv6": policy.ipv6,
        "enhanced-mode": policy.enhanced_mode,
        "respect-rules": policy.respect_rules,
        "default-nameserver": policy.bootstrap_resolvers,
        "proxy-server-nameserver": policy.bootstrap_resolvers,
        "nameserver": policy.remote_resolvers,
        "direct-nameserver": policy.direct_resolvers,
        "direct-nameserver-follow-policy": true,
        "nameserver-policy": nameserver_policy,
    })
}

fn proxy_groups(pools: &[(crate::policy::TransportPool, Vec<String>)]) -> Vec<serde_json::Value> {
    pools
        .iter()
        .map(|(pool, members)| {
            let mut group = serde_json::Map::from_iter([
                ("name".to_string(), json!(pool.id)),
                ("type".to_string(), json!(pool.kind.mihomo_name())),
                ("proxies".to_string(), json!(members)),
            ]);
            if let Some(url) = &pool.test_url {
                group.insert("url".to_string(), json!(url));
            }
            if let Some(interval) = pool.interval_seconds {
                group.insert("interval".to_string(), json!(interval));
            }
            if let Some(timeout) = pool.timeout_ms {
                group.insert("timeout".to_string(), json!(timeout));
            }
            if let Some(tolerance) = pool.tolerance_ms {
                group.insert("tolerance".to_string(), json!(tolerance));
            }
            if let Some(max_failures) = pool.max_failures {
                group.insert("max-failed-times".to_string(), json!(max_failures));
            }
            group.insert("lazy".to_string(), json!(pool.lazy));
            if let Some(strategy) = &pool.strategy {
                group.insert("strategy".to_string(), json!(strategy));
            }
            serde_json::Value::Object(group)
        })
        .collect()
}

fn active_routing_rule_sets(rule_sets: &[RoutingRuleSet]) -> Vec<RoutingRuleSet> {
    rule_sets
        .iter()
        .filter(|rule_set| rule_set.enabled)
        .cloned()
        .collect()
}

fn rule_provider_map(
    settings: &PanelSettings,
    rule_sets: &[RoutingRuleSet],
) -> serde_json::Map<String, serde_json::Value> {
    let mut providers = serde_json::Map::new();

    for rule_set in rule_sets {
        providers.insert(
            rule_set.slug.clone(),
            json!({
                "type": "http",
                "behavior": "classical",
                "format": "yaml",
                "path": format!("./rules/{}.yaml", rule_set.slug),
                "url": format!("https://{}/rules/{}.yaml", settings.subscription_domain, rule_set.slug),
                "interval": 3600
            }),
        );
    }

    providers
}

fn routing_rules(
    rule_sets: &[RoutingRuleSet],
    policy: &ClientPolicy,
    profiles: &[ProtocolProfile],
) -> Result<Vec<String>> {
    let mut rules: Vec<_> = rule_sets
        .iter()
        .map(|rule_set| format!("RULE-SET,{},{}", rule_set.slug, rule_set.target))
        .collect();

    rules.extend(
        policy
            .resolved_rules(profiles)?
            .into_iter()
            .map(|(condition, target)| format!("{condition},{target}")),
    );
    Ok(rules)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adapter::{
        ClientRenderContext, ConfigField, ProtocolAdapter, ProtocolAdapterManifest, SecretRef,
        ServerFragment, ServerRenderContext, ADAPTER_API_VERSION,
    };
    use crate::models::ProxyRole;
    use crate::rules::default_routing_rule_sets;
    use std::{collections::BTreeSet, sync::Arc};

    struct ExternalProtocol {
        manifest: ProtocolAdapterManifest,
    }

    impl ProtocolAdapter for ExternalProtocol {
        fn manifest(&self) -> &ProtocolAdapterManifest {
            &self.manifest
        }

        fn fields(&self) -> &[ConfigField] {
            &[]
        }

        fn validate_config(&self, schema_version: u32, config: &serde_json::Value) -> Result<()> {
            if schema_version != 1 || !config.is_object() {
                bail!("invalid external adapter config");
            }
            Ok(())
        }

        fn migrate_config(
            &self,
            _from_version: u32,
            config: serde_json::Value,
        ) -> Result<(u32, serde_json::Value)> {
            Ok((1, config))
        }

        fn client_secret_references(&self, _config: &serde_json::Value) -> Result<Vec<SecretRef>> {
            Ok(Vec::new())
        }

        fn server_secret_references(&self, _config: &serde_json::Value) -> Result<Vec<SecretRef>> {
            Ok(Vec::new())
        }

        fn render_client(&self, context: &ClientRenderContext<'_>) -> Result<serde_json::Value> {
            Ok(json!({
                "name": context.profile.name,
                "type": "external-test",
                "server": context.profile.server,
                "port": context.profile.port,
            }))
        }

        fn render_server(&self, context: &ServerRenderContext<'_>) -> Result<ServerFragment> {
            Ok(ServerFragment {
                profile_id: context.profile.name.clone(),
                capability: "external-capability".to_string(),
                payload: json!({}),
                expected_user_ids: None,
                listeners: Vec::new(),
            })
        }
    }

    fn fixture_settings() -> PanelSettings {
        PanelSettings {
            panel_name: "Infiproxy test".to_string(),
            subscription_domain: "sub.example.test".to_string(),
            node_domain: "node.example.test".to_string(),
        }
    }

    fn fixture_user() -> SubscriptionUser {
        SubscriptionUser {
            username: "alice".to_string(),
            uuid: "11111111-1111-4111-8111-111111111111".to_string(),
            subscription_token: "fixture-subscription-token".to_string(),
        }
    }

    fn fixture_profile() -> ProtocolProfile {
        ProtocolProfile {
            name: "VLESS-XHTTP-SAFE".to_string(),
            protocol_id: "vless-reality-xhttp".to_string(),
            schema_version: 1,
            role: ProxyRole::AutoSafe,
            server: "node.example.test".to_string(),
            port: 8443,
            enabled: true,
            preferred_core_id: None,
            managed_resource_id: None,
            config: json!({
                "server_name": "www.microsoft.com",
                "path": "/api/v1",
                "public_key_secret": "xray.reality.public_key",
                "short_id_secret": "xray.reality.short_id",
                "private_key_secret": "xray.reality.private_key"
            }),
        }
    }

    #[test]
    fn generated_yaml_uses_profiles_and_configured_secrets() {
        let settings = fixture_settings();
        let user = fixture_user();
        let profiles = vec![fixture_profile()];

        let mut secrets = std::collections::HashMap::new();
        secrets.insert(
            "xray.reality.public_key".to_string(),
            "public-key-value".to_string(),
        );
        secrets.insert(
            "xray.reality.short_id".to_string(),
            "0123456789abcdef".to_string(),
        );

        let rules = default_routing_rule_sets();
        let yaml = generate_mihomo_yaml(&settings, &user, &profiles, &secrets, &rules).unwrap();
        let parsed: serde_norway::Value = serde_norway::from_str(&yaml).unwrap();

        assert!(yaml.contains("node.example.test"));
        assert!(yaml.contains("public-key-value"));
        assert!(!yaml.contains("xray.reality.short_id"));
        assert!(!yaml.contains("REPLACE_WITH_"));
        assert!(yaml.contains("AUTO-SAFE"));
        assert!(yaml.contains("RULE-SET,proxy-ai,AUTO-SAFE"));
        assert_eq!(
            parsed["proxies"][0]["xhttp-opts"]["host"],
            "www.microsoft.com"
        );
        assert_eq!(parsed["dns"]["enhanced-mode"], "redir-host");
        assert_eq!(parsed["dns"]["respect-rules"], true);
        assert!(parsed["dns"]["proxy-server-nameserver"].is_sequence());
        assert_eq!(
            parsed["dns"]["nameserver-policy"]["rule-set:banking-direct"][0],
            "system"
        );
        assert!(parsed["dns"]["nameserver-policy"]["rule-set:proxy-ai"][0]
            .as_str()
            .is_some_and(|resolver| resolver.starts_with("https://")));
    }

    #[test]
    fn generation_rejects_missing_secrets_and_empty_profiles() {
        let settings = fixture_settings();
        let user = fixture_user();
        let profiles = vec![fixture_profile()];

        let error = generate_mihomo_yaml(
            &settings,
            &user,
            &profiles,
            &std::collections::HashMap::new(),
            &default_routing_rule_sets(),
        )
        .unwrap_err();
        assert!(error.to_string().contains("unresolved"));

        let error = generate_mihomo_yaml(
            &settings,
            &user,
            &[],
            &std::collections::HashMap::new(),
            &[],
        )
        .unwrap_err();
        assert!(error
            .to_string()
            .contains("no protocol profiles are enabled"));
    }

    #[test]
    fn disabled_rule_sets_are_not_reintroduced() {
        let settings = fixture_settings();
        let user = fixture_user();
        let profiles = vec![fixture_profile()];
        let secrets = std::collections::HashMap::from([
            ("xray.reality.public_key".to_string(), "key".to_string()),
            ("xray.reality.short_id".to_string(), "id".to_string()),
        ]);

        let yaml = generate_mihomo_yaml(&settings, &user, &profiles, &secrets, &[]).unwrap();
        assert!(!yaml.contains("RULE-SET,"));
        assert!(!yaml.contains("/rules/"));
    }

    #[test]
    fn externally_added_protocol_renders_without_generic_assembler_changes() {
        let mut registry = ProtocolRegistry::default();
        registry
            .register(Arc::new(ExternalProtocol {
                manifest: ProtocolAdapterManifest {
                    api_version: ADAPTER_API_VERSION,
                    id: "external-test".to_string(),
                    display_name: "External test".to_string(),
                    schema_version: 1,
                    required_core_capabilities: BTreeSet::from(["external-capability".to_string()]),
                    user_participation: crate::adapter::UserParticipation::None,
                    listener_network: crate::adapter::ListenerNetwork::Tcp,
                    composition: crate::adapter::ProtocolComposition::opaque("external-test"),
                },
            }))
            .unwrap();
        let profile = ProtocolProfile {
            name: "EXTERNAL".to_string(),
            protocol_id: "external-test".to_string(),
            schema_version: 1,
            role: ProxyRole::Manual,
            server: "node.example.test".to_string(),
            port: 443,
            enabled: true,
            preferred_core_id: None,
            managed_resource_id: Some("external-resource".to_string()),
            config: json!({}),
        };

        let yaml = generate_mihomo_yaml_with_registry(
            MihomoGenerationInput {
                settings: &fixture_settings(),
                user: &fixture_user(),
                profiles: &[profile],
                secrets: &HashMap::new(),
                routing_rule_sets: &[],
                policy: &default_client_policy(),
                dns_policy: &default_dns_policy(),
                available_core_capabilities: None,
            },
            &registry,
        )
        .unwrap();
        assert!(yaml.contains("external-test"));
        assert!(yaml.contains("EXTERNAL"));
    }

    #[test]
    fn historical_profile_is_skipped_without_dangling_pool_members() {
        let settings = fixture_settings();
        let user = fixture_user();
        let mut historical = fixture_profile();
        historical.name = "HISTORICAL".to_string();
        historical.protocol_id = "removed-adapter".to_string();
        let profiles = vec![fixture_profile(), historical];
        let secrets = HashMap::from([
            (
                "xray.reality.public_key".to_string(),
                "public-key-value".to_string(),
            ),
            (
                "xray.reality.short_id".to_string(),
                "0123456789abcdef".to_string(),
            ),
        ]);
        let registry = crate::adapters::protocol_registry().unwrap();
        let generated = generate_mihomo_yaml_detailed(
            MihomoGenerationInput {
                settings: &settings,
                user: &user,
                profiles: &profiles,
                secrets: &secrets,
                routing_rule_sets: &[],
                policy: &default_client_policy(),
                dns_policy: &default_dns_policy(),
                available_core_capabilities: None,
            },
            &registry,
        )
        .unwrap();
        assert_eq!(generated.warnings.len(), 1);
        assert!(!generated.yaml.contains("HISTORICAL"));
        let parsed: serde_norway::Value = serde_norway::from_str(&generated.yaml).unwrap();
        assert!(parsed["proxy-groups"]
            .as_sequence()
            .unwrap()
            .iter()
            .all(|group| group["proxies"]
                .as_sequence()
                .is_none_or(|members| members.iter().all(|member| member != "HISTORICAL"))));
    }
}
