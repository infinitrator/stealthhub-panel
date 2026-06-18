use anyhow::Result;
use serde_json::json;

use crate::models::{DemoUser, PanelSettings};

pub fn generate_demo_mihomo_yaml(settings: &PanelSettings, user: &DemoUser) -> Result<String> {
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
