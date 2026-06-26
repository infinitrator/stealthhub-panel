use anyhow::Result;
use serde_json::json;

use crate::models::{
    PanelSettings, ProtocolConfig, ProtocolProfile, ProxyRole, SubscriptionUser, UserUuidSource,
};

fn secret_or_placeholder<'a>(
    secrets: &'a std::collections::HashMap<String, String>,
    secret_name: &'a str,
) -> &'a str {
    secrets
        .get(secret_name)
        .map(String::as_str)
        .unwrap_or(secret_name)
}

fn user_uuid(user: &SubscriptionUser, uuid_source: &UserUuidSource) -> String {
    match uuid_source {
        UserUuidSource::SubscriptionUser => user.uuid.clone(),
        UserUuidSource::StaticSecret => user.uuid.clone(),
    }
}

pub fn generate_mihomo_yaml(
    settings: &PanelSettings,
    user: &SubscriptionUser,
    profiles: &[ProtocolProfile],
    secrets: &std::collections::HashMap<String, String>,
) -> Result<String> {
    let enabled_profiles: Vec<_> = profiles.iter().filter(|profile| profile.enabled).collect();
    if enabled_profiles.is_empty() {
        return generate_demo_mihomo_yaml(settings, user);
    }

    let proxies: Vec<_> = enabled_profiles
        .iter()
        .map(|profile| match &profile.config {
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
                "uuid": user_uuid(user, uuid_source),
                "tls": true,
                "servername": server_name,
                "client-fingerprint": "chrome",
                "reality-opts": {
                    "public-key": secret_or_placeholder(secrets, public_key_secret),
                    "short-id": secret_or_placeholder(secrets, short_id_secret)
                },
                "network": "xhttp",
                "xhttp-opts": {
                    "path": path,
                    "host": [server_name]
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
                "uuid": user_uuid(user, uuid_source),
                "tls": true,
                "servername": server_name,
                "client-fingerprint": "chrome",
                "reality-opts": {
                    "public-key": secret_or_placeholder(secrets, public_key_secret),
                    "short-id": secret_or_placeholder(secrets, short_id_secret)
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
                "password": secret_or_placeholder(secrets, password_secret),
                "udp": true,
                "plugin": "shadow-tls",
                "client-fingerprint": "chrome",
                "plugin-opts": {
                    "host": server_name,
                    "password": secret_or_placeholder(secrets, shadow_tls_password_secret),
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
                    "password": secret_or_placeholder(secrets, password_secret),
                    "sni": sni,
                    "alpn": ["h3"]
                });

                if let Some(obfs_secret) = obfs_password_secret {
                    proxy["obfs"] = json!({
                        "type": "salamander",
                        "password": secret_or_placeholder(secrets, obfs_secret)
                    });
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
                "password": secret_or_placeholder(secrets, password_secret),
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
                "uuid": user_uuid(user, uuid_source),
                "password": secret_or_placeholder(secrets, password_secret),
                "udp": true,
                "sni": sni,
                "alpn": ["h3"]
            }),
        })
        .collect();

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

    let doc = json!({
        "mixed-port": 7890,
        "allow-lan": false,
        "mode": "rule",
        "log-level": "info",
        "ipv6": false,
        "external-controller": "127.0.0.1:9090",
        "rule-providers": {
            "banking-direct": {
                "type": "http",
                "behavior": "classical",
                "format": "yaml",
                "path": "./rules/banking-direct.yaml",
                "url": format!("https://{}/rules/banking-direct.yaml", settings.subscription_domain),
                "interval": 3600
            },
            "direct-local": {
                "type": "http",
                "behavior": "classical",
                "format": "yaml",
                "path": "./rules/direct-local.yaml",
                "url": format!("https://{}/rules/direct-local.yaml", settings.subscription_domain),
                "interval": 3600
            },
            "proxy-ai": {
                "type": "http",
                "behavior": "classical",
                "format": "yaml",
                "path": "./rules/proxy-ai.yaml",
                "url": format!("https://{}/rules/proxy-ai.yaml", settings.subscription_domain),
                "interval": 3600
            },
            "streaming": {
                "type": "http",
                "behavior": "classical",
                "format": "yaml",
                "path": "./rules/streaming.yaml",
                "url": format!("https://{}/rules/streaming.yaml", settings.subscription_domain),
                "interval": 3600
            }
        },
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
        "rules": [
            "RULE-SET,banking-direct,DIRECT",
            "RULE-SET,direct-local,DIRECT",
            "RULE-SET,proxy-ai,AUTO-SAFE",
            "RULE-SET,streaming,SPEED",
            "GEOIP,RU,DIRECT",
            "IP-CIDR,10.0.0.0/8,DIRECT,no-resolve",
            "IP-CIDR,172.16.0.0/12,DIRECT,no-resolve",
            "IP-CIDR,192.168.0.0/16,DIRECT,no-resolve",
            "MATCH,MANUAL"
        ]
    });

    Ok(serde_yaml::to_string(&doc)?)
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

pub fn generate_demo_mihomo_yaml(
    settings: &PanelSettings,
    user: &SubscriptionUser,
) -> Result<String> {
    let node = &settings.node_domain;

    // На этом этапе это демонстрационный config contract.
    // Реальные secrets, public-key, short-id, passwords будут браться из SQLite/secret store.
    let doc = json!({
        "mixed-port": 7890,
        "allow-lan": false,
        "mode": "rule",
        "log-level": "info",
        "ipv6": false,

        "external-controller": "127.0.0.1:9090",

        "rule-providers": {
            "banking-direct": {
                "type": "http",
                "behavior": "classical",
                "format": "yaml",
                "path": "./rules/banking-direct.yaml",
                "url": format!("https://{}/rules/banking-direct.yaml", settings.subscription_domain),
                "interval": 3600
            },
            "direct-local": {
                "type": "http",
                "behavior": "classical",
                "format": "yaml",
                "path": "./rules/direct-local.yaml",
                "url": format!("https://{}/rules/direct-local.yaml", settings.subscription_domain),
                "interval": 3600
            },
            "proxy-ai": {
                "type": "http",
                "behavior": "classical",
                "format": "yaml",
                "path": "./rules/proxy-ai.yaml",
                "url": format!("https://{}/rules/proxy-ai.yaml", settings.subscription_domain),
                "interval": 3600
            },
            "streaming": {
                "type": "http",
                "behavior": "classical",
                "format": "yaml",
                "path": "./rules/streaming.yaml",
                "url": format!("https://{}/rules/streaming.yaml", settings.subscription_domain),
                "interval": 3600
            }
        },

        "proxies": [
            {
                "name": "VLESS-XHTTP-SAFE",
                "type": "vless",
                "server": node,
                "port": 8443,
                "udp": true,
                "uuid": user.uuid,
                "tls": true,
                "servername": "www.microsoft.com",
                "client-fingerprint": "chrome",
                "reality-opts": {
                    "public-key": "REPLACE_WITH_REALITY_PUBLIC_KEY",
                    "short-id": "REPLACE_WITH_SHORT_ID"
                },
                "network": "xhttp",
                "xhttp-opts": {
                    "path": "/api/v1",
                    "host": ["www.microsoft.com"]
                }
            },
            {
                "name": "SS2022-SHADOWTLS-FALLBACK",
                "type": "ss",
                "server": node,
                "port": 9443,
                "cipher": "2022-blake3-aes-256-gcm",
                "password": "REPLACE_WITH_SS2022_PASSWORD",
                "udp": true,
                "plugin": "shadow-tls",
                "client-fingerprint": "chrome",
                "plugin-opts": {
                    "host": "www.apple.com",
                    "password": "REPLACE_WITH_SHADOWTLS_PASSWORD",
                    "version": 3
                }
            },
            {
                "name": "ANYTLS-EXPERIMENTAL",
                "type": "anytls",
                "server": node,
                "port": 10443,
                "password": "REPLACE_WITH_ANYTLS_PASSWORD",
                "client-fingerprint": "chrome",
                "udp": true,
                "sni": "www.apple.com"
            },
            {
                "name": "HYSTERIA2-SPEED",
                "type": "hysteria2",
                "server": node,
                "port": 443,
                "password": "REPLACE_WITH_HY2_PASSWORD",
                "sni": "www.bing.com",
                "alpn": ["h3"]
            },
            {
                "name": "TUIC-SPEED",
                "type": "tuic",
                "server": node,
                "port": 11443,
                "uuid": user.uuid,
                "password": "REPLACE_WITH_TUIC_PASSWORD",
                "udp": true,
                "sni": "www.github.com",
                "alpn": ["h3"]
            }
        ],

        "proxy-groups": [
            {
                "name": "MANUAL",
                "type": "select",
                "proxies": [
                    "AUTO-SAFE",
                    "FAILOVER",
                    "BALANCE",
                    "SPEED",
                    "VLESS-XHTTP-SAFE",
                    "SS2022-SHADOWTLS-FALLBACK",
                    "ANYTLS-EXPERIMENTAL",
                    "HYSTERIA2-SPEED",
                    "TUIC-SPEED",
                    "DIRECT"
                ]
            },
            {
                "name": "AUTO-SAFE",
                "type": "url-test",
                "proxies": [
                    "VLESS-XHTTP-SAFE",
                    "SS2022-SHADOWTLS-FALLBACK",
                    "ANYTLS-EXPERIMENTAL"
                ],
                "url": "https://www.gstatic.com/generate_204",
                "interval": 300,
                "tolerance": 50
            },
            {
                "name": "FAILOVER",
                "type": "fallback",
                "proxies": [
                    "VLESS-XHTTP-SAFE",
                    "ANYTLS-EXPERIMENTAL",
                    "SS2022-SHADOWTLS-FALLBACK"
                ],
                "url": "https://www.gstatic.com/generate_204",
                "interval": 120
            },
            {
                "name": "BALANCE",
                "type": "load-balance",
                "strategy": "round-robin",
                "proxies": [
                    "VLESS-XHTTP-SAFE",
                    "SS2022-SHADOWTLS-FALLBACK",
                    "ANYTLS-EXPERIMENTAL"
                ],
                "url": "https://www.gstatic.com/generate_204",
                "interval": 180
            },
            {
                "name": "SPEED",
                "type": "select",
                "proxies": [
                    "HYSTERIA2-SPEED",
                    "TUIC-SPEED",
                    "VLESS-XHTTP-SAFE"
                ]
            }
        ],

        "rules": [
            "RULE-SET,banking-direct,DIRECT",
            "RULE-SET,direct-local,DIRECT",
            "RULE-SET,proxy-ai,AUTO-SAFE",
            "RULE-SET,streaming,SPEED",
            "GEOIP,RU,DIRECT",
            "IP-CIDR,10.0.0.0/8,DIRECT,no-resolve",
            "IP-CIDR,172.16.0.0/12,DIRECT,no-resolve",
            "IP-CIDR,192.168.0.0/16,DIRECT,no-resolve",
            "MATCH,MANUAL"
        ]
    });

    Ok(serde_yaml::to_string(&doc)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{demo_settings, demo_user, ProxyKind};

    #[test]
    fn generated_yaml_uses_profiles_and_secret_names() {
        let settings = demo_settings();
        let user = demo_user();
        let profiles = vec![ProtocolProfile {
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
        }];

        let mut secrets = std::collections::HashMap::new();
        secrets.insert(
            "xray.reality.public_key".to_string(),
            "public-key-value".to_string(),
        );

        let yaml = generate_mihomo_yaml(&settings, &user, &profiles, &secrets).unwrap();

        assert!(yaml.contains("node.example.test"));
        assert!(yaml.contains("public-key-value"));
        assert!(yaml.contains("xray.reality.short_id"));
        assert!(yaml.contains("AUTO-SAFE"));
    }
}
