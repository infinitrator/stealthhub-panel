//! Mihomo subscription YAML generation.
//!
//! The functions in this module convert persisted panel settings, protocol
//! profiles, secrets and routing rule sets into client-importable Mihomo config.
//! Inputs are explicit so generation can be tested without a database.

use anyhow::{bail, Result};
use serde_json::json;

use crate::models::{
    PanelSettings, ProtocolConfig, ProtocolProfile, ProxyRole, SubscriptionUser, UserUuidSource,
};
use crate::rules::RoutingRuleSet;

fn secret_value<'a>(
    secrets: &'a std::collections::HashMap<String, String>,
    secret_name: &'a str,
) -> Result<&'a str> {
    let value = secrets
        .get(secret_name)
        .map(String::as_str)
        .ok_or_else(|| anyhow::anyhow!("required secret is missing: {secret_name}"))?
        .trim();
    if value.is_empty() || value == secret_name || value.starts_with("REPLACE_WITH_") {
        bail!("required secret is not configured: {secret_name}");
    }
    Ok(value)
}

fn user_uuid<'a>(user: &'a SubscriptionUser, uuid_source: &UserUuidSource) -> Result<&'a str> {
    match uuid_source {
        UserUuidSource::SubscriptionUser => Ok(user.uuid.as_str()),
        UserUuidSource::StaticSecret => {
            bail!("static UUID profiles are unsupported without an explicit secret reference")
        }
    }
}

pub fn generate_mihomo_yaml(
    settings: &PanelSettings,
    user: &SubscriptionUser,
    profiles: &[ProtocolProfile],
    secrets: &std::collections::HashMap<String, String>,
    routing_rule_sets: &[RoutingRuleSet],
) -> Result<String> {
    let enabled_profiles: Vec<_> = profiles.iter().filter(|profile| profile.enabled).collect();
    if enabled_profiles.is_empty() {
        bail!("no protocol profiles are enabled");
    }
    if user.subscription_token.trim().is_empty() {
        bail!("subscription token is empty");
    }

    let proxies: Vec<_> = enabled_profiles
        .iter()
        .map(|profile| -> Result<_> {
            let proxy = match &profile.config {
                ProtocolConfig::VlessRealityXhttp {
                    uuid_source,
                    server_name,
                    path,
                    public_key_secret,
                    short_id_secret,
                } => json!({
                    "name": profile.name,
                    "type": "vless",
                    "server": profile.server,
                    "port": profile.port,
                    "udp": true,
                    "uuid": user_uuid(user, uuid_source)?,
                    "encryption": "",
                    "tls": true,
                    "servername": server_name,
                    "client-fingerprint": "chrome",
                    "reality-opts": {
                        "public-key": secret_value(secrets, public_key_secret)?,
                        "short-id": secret_value(secrets, short_id_secret)?
                    },
                    "network": "xhttp",
                    "xhttp-opts": {
                        "path": path,
                        "host": server_name
                    }
                }),
                ProtocolConfig::VlessRealityTcp {
                    uuid_source,
                    server_name,
                    public_key_secret,
                    short_id_secret,
                } => json!({
                    "name": profile.name,
                    "type": "vless",
                    "server": profile.server,
                    "port": profile.port,
                    "udp": true,
                    "uuid": user_uuid(user, uuid_source)?,
                    "encryption": "",
                    "tls": true,
                    "servername": server_name,
                    "client-fingerprint": "chrome",
                    "reality-opts": {
                        "public-key": secret_value(secrets, public_key_secret)?,
                        "short-id": secret_value(secrets, short_id_secret)?
                    }
                }),
                ProtocolConfig::Shadowsocks2022ShadowTls {
                    server_name,
                    password_secret,
                    shadow_tls_password_secret,
                } => json!({
                    "name": profile.name,
                    "type": "ss",
                    "server": profile.server,
                    "port": profile.port,
                    "cipher": "2022-blake3-aes-256-gcm",
                    "password": secret_value(secrets, password_secret)?,
                    "udp": true,
                    "plugin": "shadow-tls",
                    "client-fingerprint": "chrome",
                    "plugin-opts": {
                        "host": server_name,
                        "password": secret_value(secrets, shadow_tls_password_secret)?,
                        "version": 3
                    }
                }),
                ProtocolConfig::Hysteria2 {
                    password_secret,
                    sni,
                    obfs_password_secret,
                } => {
                    let mut proxy = json!({
                        "name": profile.name,
                        "type": "hysteria2",
                        "server": profile.server,
                        "port": profile.port,
                        "password": secret_value(secrets, password_secret)?,
                        "sni": sni,
                        "alpn": ["h3"]
                    });

                    if let Some(obfs_secret) = obfs_password_secret {
                        proxy["obfs"] = json!("salamander");
                        proxy["obfs-password"] = json!(secret_value(secrets, obfs_secret)?);
                    }

                    proxy
                }
                ProtocolConfig::AnyTls {
                    password_secret,
                    sni,
                } => json!({
                    "name": profile.name,
                    "type": "anytls",
                    "server": profile.server,
                    "port": profile.port,
                    "password": secret_value(secrets, password_secret)?,
                    "client-fingerprint": "chrome",
                    "udp": true,
                    "sni": sni
                }),
                ProtocolConfig::Tuic {
                    uuid_source,
                    password_secret,
                    sni,
                } => json!({
                    "name": profile.name,
                    "type": "tuic",
                    "server": profile.server,
                    "port": profile.port,
                    "uuid": user_uuid(user, uuid_source)?,
                    "password": secret_value(secrets, password_secret)?,
                    "udp": true,
                    "sni": sni,
                    "alpn": ["h3"]
                }),
            };
            Ok(proxy)
        })
        .collect::<Result<Vec<_>>>()?;

    let proxy_names: Vec<_> = enabled_profiles
        .iter()
        .map(|profile| profile.name.as_str())
        .collect();
    let auto_safe_names = names_for_roles(
        &enabled_profiles,
        &[ProxyRole::AutoSafe, ProxyRole::Compatibility],
        &proxy_names,
    );
    let speed_names = names_for_roles(&enabled_profiles, &[ProxyRole::Speed], &proxy_names);
    let ru_access_names = names_for_roles(&enabled_profiles, &[ProxyRole::RuAccess], &proxy_names);
    let active_rule_sets = active_routing_rule_sets(routing_rule_sets);

    let doc = json!({
        "mixed-port": 7890,
        "allow-lan": false,
        "mode": "rule",
        "log-level": "info",
        "ipv6": false,
        "external-controller": "127.0.0.1:9090",
        "secret": user.subscription_token,
        "rule-providers": rule_provider_map(settings, &active_rule_sets),
        "proxies": proxies,
        "proxy-groups": [
            {
                "name": "MANUAL",
                "type": "select",
                "proxies": manual_group(&proxy_names)
            },
            {
                "name": "AUTO-SAFE",
                "type": "url-test",
                "proxies": auto_safe_names,
                "url": "https://www.gstatic.com/generate_204",
                "interval": 300,
                "tolerance": 50
            },
            {
                "name": "FAILOVER",
                "type": "fallback",
                "proxies": auto_safe_names,
                "url": "https://www.gstatic.com/generate_204",
                "interval": 120
            },
            {
                "name": "BALANCE",
                "type": "load-balance",
                "strategy": "round-robin",
                "proxies": auto_safe_names,
                "url": "https://www.gstatic.com/generate_204",
                "interval": 180
            },
            {
                "name": "SPEED",
                "type": "select",
                "proxies": select_group(&speed_names, &auto_safe_names)
            },
            {
                "name": "RU-ACCESS",
                "type": "select",
                "proxies": select_group(&ru_access_names, &auto_safe_names)
            }
        ],
        "rules": routing_rules(&active_rule_sets)
    });

    Ok(serde_norway::to_string(&doc)?)
}

fn names_for_roles<'a>(
    profiles: &[&'a ProtocolProfile],
    roles: &[ProxyRole],
    fallback: &[&'a str],
) -> Vec<&'a str> {
    let mut names: Vec<_> = profiles
        .iter()
        .filter(|profile| roles.contains(&profile.role))
        .map(|profile| profile.name.as_str())
        .collect();

    if names.is_empty() {
        names.extend_from_slice(fallback);
    }

    names
}

fn select_group<'a>(preferred: &[&'a str], fallback: &[&'a str]) -> Vec<&'a str> {
    let mut names = preferred.to_vec();
    if names.is_empty() {
        names.extend_from_slice(fallback);
    }
    if !names.contains(&"DIRECT") {
        names.push("DIRECT");
    }
    names
}

fn manual_group<'a>(proxy_names: &'a [&'a str]) -> Vec<&'a str> {
    let mut names = vec!["AUTO-SAFE", "FAILOVER", "BALANCE", "SPEED", "RU-ACCESS"];
    names.extend_from_slice(proxy_names);
    names.push("DIRECT");
    names
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

fn routing_rules(rule_sets: &[RoutingRuleSet]) -> Vec<String> {
    let mut rules: Vec<_> = rule_sets
        .iter()
        .map(|rule_set| format!("RULE-SET,{},{}", rule_set.slug, rule_set.target))
        .collect();

    rules.push("GEOIP,RU,DIRECT".to_string());
    rules.push("IP-CIDR,10.0.0.0/8,DIRECT,no-resolve".to_string());
    rules.push("IP-CIDR,172.16.0.0/12,DIRECT,no-resolve".to_string());
    rules.push("IP-CIDR,192.168.0.0/16,DIRECT,no-resolve".to_string());
    rules.push("MATCH,MANUAL".to_string());
    rules
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{models::ProxyKind, rules::default_routing_rule_sets};

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
            kind: ProxyKind::VlessRealityXhttp,
            role: ProxyRole::AutoSafe,
            server: "node.example.test".to_string(),
            port: 8443,
            enabled: true,
            config: ProtocolConfig::VlessRealityXhttp {
                uuid_source: UserUuidSource::SubscriptionUser,
                server_name: "www.microsoft.com".to_string(),
                path: "/api/v1".to_string(),
                public_key_secret: "xray.reality.public_key".to_string(),
                short_id_secret: "xray.reality.short_id".to_string(),
            },
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
        assert!(error.to_string().contains("required secret is missing"));

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
}
