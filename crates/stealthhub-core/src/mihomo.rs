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
    rules::{classical_rule_with_target, RoutingRuleSet},
};

// GrimbirdUsers/ru-routing-dat recommends its jsDelivr mirror. Mihomo stores the
// downloaded geodata below its own home and keeps the last usable copy across updates.
pub const RU_GEOSITE_URL: &str =
    "https://cdn.jsdelivr.net/gh/GrimbirdUsers/ru-routing-dat@main/geosite.dat";
pub const RU_GEOIP_URL: &str =
    "https://cdn.jsdelivr.net/gh/GrimbirdUsers/ru-routing-dat@main/geoip.dat";
const HEALTH_CHECK_URL: &str = "https://www.gstatic.com/generate_204";

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
        "geodata-mode": true,
        "geodata-loader": "memconservative",
        "geo-auto-update": true,
        "geo-update-interval": 24,
        "geox-url": {
            "geosite": RU_GEOSITE_URL,
            "geoip": RU_GEOIP_URL,
        },
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
            if pool.test_url.as_deref() == Some(HEALTH_CHECK_URL) {
                group.insert("expected-status".to_string(), json!(204));
            }
            if pool.kind == crate::policy::PoolKind::Select {
                if let Some(first) = members.first() {
                    group.insert("default-selected".to_string(), json!(first));
                }
            }
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
            .map(|(condition, target)| {
                if condition.trim() == "MATCH" {
                    Ok(format!("MATCH,{target}"))
                } else {
                    classical_rule_with_target(condition.trim(), &target)
                }
            })
            .collect::<Result<Vec<_>>>()?,
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
    use std::{collections::BTreeSet, fs, process::Command, sync::Arc};

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
            display_name: "VLESS XHTTP Safe".to_string(),
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

    fn fixture_profiles() -> Vec<ProtocolProfile> {
        let rest = fixture_profile();
        let mut fast = rest.clone();
        fast.name = "VLESS-XHTTP-FAST".to_string();
        fast.display_name = "VLESS XHTTP Fast".to_string();
        fast.role = ProxyRole::Speed;
        fast.port = 8444;
        let mut disabled = rest.clone();
        disabled.name = "VLESS-XHTTP-DISABLED".to_string();
        disabled.display_name = "VLESS XHTTP Disabled".to_string();
        disabled.enabled = false;
        vec![rest, fast, disabled]
    }

    fn fixture_rule_sets() -> Vec<RoutingRuleSet> {
        let mut rule_sets = default_routing_rule_sets();
        let custom_direct = rule_sets
            .iter_mut()
            .find(|rule_set| rule_set.slug == "custom-direct")
            .expect("custom-direct fixture");
        custom_direct.enabled = true;
        custom_direct.payload = "DOMAIN,manual-direct.example".to_string();
        rule_sets
    }

    #[test]
    fn generated_yaml_uses_profiles_and_configured_secrets() {
        let settings = fixture_settings();
        let user = fixture_user();
        let profiles = fixture_profiles();

        let mut secrets = std::collections::HashMap::new();
        secrets.insert(
            "xray.reality.public_key".to_string(),
            "public-key-value".to_string(),
        );
        secrets.insert(
            "xray.reality.short_id".to_string(),
            "0123456789abcdef".to_string(),
        );

        let rules = fixture_rule_sets();
        let yaml = generate_mihomo_yaml(&settings, &user, &profiles, &secrets, &rules).unwrap();
        let parsed: serde_norway::Value = serde_norway::from_str(&yaml).unwrap();

        assert!(yaml.contains("node.example.test"));
        assert!(yaml.contains("public-key-value"));
        assert!(!yaml.contains("xray.reality.short_id"));
        assert!(!yaml.contains("REPLACE_WITH_"));
        assert!(!yaml.contains("VLESS-XHTTP-DISABLED"));
        assert!(yaml.contains("SMART-AUTO"));
        assert!(yaml.contains("RULE-SET,custom-direct,DIRECT"));
        for legacy in ["banking-direct", "direct-local", "proxy-ai", "streaming"] {
            assert!(!yaml.contains(legacy));
        }
        assert_eq!(
            parsed["proxies"][0]["xhttp-opts"]["host"],
            "www.microsoft.com"
        );
        assert_eq!(parsed["dns"]["enhanced-mode"], "redir-host");
        assert_eq!(parsed["dns"]["respect-rules"], true);
        assert!(parsed["dns"]["proxy-server-nameserver"].is_sequence());
        assert_eq!(
            parsed["dns"]["nameserver-policy"]["rule-set:custom-direct"][0],
            "system"
        );
        let generated_rules = parsed["rules"]
            .as_sequence()
            .expect("generated rules must be a sequence")
            .iter()
            .filter_map(serde_norway::Value::as_str)
            .collect::<Vec<_>>();
        assert_eq!(generated_rules[0], "RULE-SET,custom-direct,DIRECT");
        assert!(generated_rules.ends_with(&[
            "IP-CIDR,10.0.0.0/8,DIRECT,no-resolve",
            "IP-CIDR,172.16.0.0/12,DIRECT,no-resolve",
            "IP-CIDR,192.168.0.0/16,DIRECT,no-resolve",
            "GEOIP,RU,DIRECT,no-resolve",
            "MATCH,SMART-AUTO",
        ]));
        let generated_groups = parsed["proxy-groups"]
            .as_sequence()
            .expect("generated groups must be a sequence");
        let group = |name: &str| {
            generated_groups
                .iter()
                .find(|group| group["name"] == name)
                .expect("generated group is absent")
        };
        let group_members = |name: &str| {
            group(name)["proxies"]
                .as_sequence()
                .expect("group members must be a sequence")
                .iter()
                .map(|member| member.as_str().expect("group member must be a string"))
                .collect::<Vec<_>>()
        };
        assert_eq!(group_members("FAST-AUTO"), ["VLESS-XHTTP-FAST"]);
        assert_eq!(group("FAST-AUTO")["timeout"], 500);
        assert_eq!(group("FAST-AUTO")["interval"], 60);
        assert_eq!(group("FAST-AUTO")["lazy"], false);
        assert_eq!(group("FAST-AUTO")["expected-status"], 204);
        assert_eq!(group_members("REST-AUTO"), ["VLESS-XHTTP-SAFE"]);
        assert_eq!(group("REST-AUTO")["timeout"], 3_000);
        assert_eq!(group_members("SMART-AUTO"), ["FAST-AUTO", "REST-AUTO"]);
        assert_eq!(
            group_members("MANUAL"),
            [
                "SMART-AUTO",
                "FAST-AUTO",
                "REST-AUTO",
                "VLESS-XHTTP-SAFE",
                "VLESS-XHTTP-FAST",
                "DIRECT"
            ]
        );
        assert_eq!(group("MANUAL")["default-selected"], "SMART-AUTO");
        for obsolete in ["AUTO-SAFE", "SPEED", "RU-ACCESS", "BALANCE", "FAILOVER"] {
            assert!(generated_groups
                .iter()
                .all(|group| group["name"] != obsolete));
        }
        assert_eq!(parsed["geodata-mode"], true);
        assert_eq!(parsed["geo-auto-update"], true);
        assert_eq!(parsed["geo-update-interval"], 24);
        assert_eq!(parsed["geox-url"]["geosite"], RU_GEOSITE_URL);
        assert_eq!(parsed["geox-url"]["geoip"], RU_GEOIP_URL);
        for obsolete in ["AUTO-SAFE", "SPEED", "RU-ACCESS", "BALANCE"] {
            assert!(!generated_rules.iter().any(|rule| rule.contains(obsolete)));
        }
        let category_position = generated_rules
            .iter()
            .position(|rule| *rule == "GEOSITE,category-ru-whitelist,DIRECT")
            .expect("RU geosite rule is absent");
        let geoip_position = generated_rules
            .iter()
            .position(|rule| *rule == "GEOIP,RU,DIRECT,no-resolve")
            .expect("RU GeoIP rule is absent");
        let fallback_position = generated_rules
            .iter()
            .position(|rule| *rule == "MATCH,SMART-AUTO")
            .expect("SMART-AUTO fallback is absent");
        assert_eq!(
            generated_rules
                .iter()
                .filter(|rule| rule.starts_with("MATCH,"))
                .count(),
            1
        );
        assert!(category_position < geoip_position && geoip_position < fallback_position);
        assert!(!generated_rules
            .iter()
            .any(|rule| rule.starts_with("DOMAIN-SUFFIX,ru,")));
    }

    #[test]
    fn exact_mihomo_parser_accepts_generated_standard_routing_rules() -> Result<()> {
        let Some(binary) = std::env::var_os("INFIPROXY_TEST_MIHOMO_BIN") else {
            return Ok(());
        };
        let settings = fixture_settings();
        let user = fixture_user();
        let profiles = fixture_profiles();
        let secrets = HashMap::from([
            (
                "xray.reality.public_key".to_string(),
                "w1LlLliIbRGiRssXh-yKrLONwRaYlezwfihTFaCEaUw".to_string(),
            ),
            (
                "xray.reality.short_id".to_string(),
                "0123456789abcdef".to_string(),
            ),
        ]);
        let yaml =
            generate_mihomo_yaml(&settings, &user, &profiles, &secrets, &fixture_rule_sets())?;
        let directory = std::env::temp_dir().join(format!(
            "infiproxy-mihomo-subscription-routing-{}",
            uuid::Uuid::new_v4()
        ));
        let validation_home = directory.join("mihomo/home");
        fs::create_dir_all(&validation_home)?;
        let candidate = directory.join("subscription.yaml");
        fs::write(&candidate, yaml)?;
        let validate = || {
            Command::new(&binary)
                .arg("-d")
                .arg(&validation_home)
                .args(["-t", "-f"])
                .arg(&candidate)
                .output()
        };
        let first = validate()?;
        if !first.status.success() {
            bail!(
                "Mihomo v1.19.30 rejected generated subscription routing:\nstdout: {}\nstderr: {}",
                String::from_utf8_lossy(&first.stdout),
                String::from_utf8_lossy(&first.stderr),
            );
        }
        let cached = validate()?;
        fs::remove_dir_all(directory)?;
        if !cached.status.success()
            || String::from_utf8_lossy(&cached.stdout).contains("start download")
        {
            bail!(
                "Mihomo v1.19.30 did not reuse cached geodata:\nstdout: {}\nstderr: {}",
                String::from_utf8_lossy(&cached.stdout),
                String::from_utf8_lossy(&cached.stderr),
            );
        }
        Ok(())
    }

    #[test]
    fn generated_routing_is_stable_and_isolated_for_multiple_users() -> Result<()> {
        let settings = fixture_settings();
        let profiles = fixture_profiles();
        let secrets = HashMap::from([
            (
                "xray.reality.public_key".to_string(),
                "public-key-value".to_string(),
            ),
            (
                "xray.reality.short_id".to_string(),
                "0123456789abcdef".to_string(),
            ),
            (
                "xray.reality.private_key".to_string(),
                "server-private-key-must-not-leak".to_string(),
            ),
        ]);
        let alice = fixture_user();
        let bob = SubscriptionUser {
            username: "bob".to_string(),
            uuid: "22222222-2222-4222-8222-222222222222".to_string(),
            subscription_token: "bob-subscription-token".to_string(),
        };
        let alice_yaml =
            generate_mihomo_yaml(&settings, &alice, &profiles, &secrets, &fixture_rule_sets())?;
        let bob_yaml =
            generate_mihomo_yaml(&settings, &bob, &profiles, &secrets, &fixture_rule_sets())?;
        assert!(alice_yaml.contains(&alice.subscription_token));
        assert!(!alice_yaml.contains(&bob.subscription_token));
        assert!(!alice_yaml.contains(&bob.uuid));
        assert!(bob_yaml.contains(&bob.subscription_token));
        assert!(!bob_yaml.contains(&alice.subscription_token));
        assert!(!bob_yaml.contains(&alice.uuid));
        assert!(!alice_yaml.contains("server-private-key-must-not-leak"));
        assert!(!bob_yaml.contains("server-private-key-must-not-leak"));

        let alice_doc: serde_norway::Value = serde_norway::from_str(&alice_yaml)?;
        let bob_doc: serde_norway::Value = serde_norway::from_str(&bob_yaml)?;
        assert_eq!(alice_doc["proxy-groups"], bob_doc["proxy-groups"]);
        assert_eq!(alice_doc["rules"], bob_doc["rules"]);
        Ok(())
    }

    #[test]
    fn generation_rejects_missing_secrets_and_empty_profiles() {
        let settings = fixture_settings();
        let user = fixture_user();
        let profiles = fixture_profiles();

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
        let profiles = fixture_profiles();
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
            display_name: "External".to_string(),
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

        let mut fast = profile.clone();
        fast.name = "EXTERNAL-FAST".to_string();
        fast.display_name = "External Fast".to_string();
        fast.role = ProxyRole::Speed;
        let profiles = [profile, fast];
        let yaml = generate_mihomo_yaml_with_registry(
            MihomoGenerationInput {
                settings: &fixture_settings(),
                user: &fixture_user(),
                profiles: &profiles,
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
        let mut profiles = fixture_profiles();
        profiles.push(historical);
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
