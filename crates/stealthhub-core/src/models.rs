use serde::{Deserialize, Serialize};

use crate::storage::UserRecord;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PanelSettings {
    pub panel_name: String,
    pub subscription_domain: String,
    pub node_domain: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubscriptionUser {
    pub username: String,
    pub uuid: String,
    pub subscription_token: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyEndpoint {
    pub name: String,
    pub kind: ProxyKind,
    pub server: String,
    pub port: u16,
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum ProxyKind {
    VlessRealityXhttp,
    VlessRealityTcp,
    Shadowsocks2022ShadowTls,
    Hysteria2,
    AnyTls,
    Tuic,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum ProxyRole {
    AutoSafe,
    Speed,
    Compatibility,
    RuAccess,
    Manual,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProtocolProfile {
    pub name: String,
    pub kind: ProxyKind,
    pub role: ProxyRole,
    pub server: String,
    pub port: u16,
    pub enabled: bool,
    pub config: ProtocolConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "kebab-case")]
pub enum ProtocolConfig {
    VlessRealityXhttp {
        uuid_source: UserUuidSource,
        server_name: String,
        path: String,
        public_key_secret: String,
        short_id_secret: String,
    },
    VlessRealityTcp {
        uuid_source: UserUuidSource,
        server_name: String,
        public_key_secret: String,
        short_id_secret: String,
    },
    Shadowsocks2022ShadowTls {
        server_name: String,
        password_secret: String,
        shadow_tls_password_secret: String,
    },
    Hysteria2 {
        password_secret: String,
        sni: String,
        obfs_password_secret: Option<String>,
    },
    AnyTls {
        password_secret: String,
        sni: String,
    },
    Tuic {
        uuid_source: UserUuidSource,
        password_secret: String,
        sni: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum UserUuidSource {
    SubscriptionUser,
    StaticSecret,
}

impl Default for PanelSettings {
    fn default() -> Self {
        demo_settings()
    }
}

impl ProtocolProfile {
    pub fn required_secret_names(&self) -> Vec<&str> {
        match &self.config {
            ProtocolConfig::VlessRealityXhttp {
                public_key_secret,
                short_id_secret,
                ..
            }
            | ProtocolConfig::VlessRealityTcp {
                public_key_secret,
                short_id_secret,
                ..
            } => vec![public_key_secret.as_str(), short_id_secret.as_str()],
            ProtocolConfig::Shadowsocks2022ShadowTls {
                password_secret,
                shadow_tls_password_secret,
                ..
            } => vec![
                password_secret.as_str(),
                shadow_tls_password_secret.as_str(),
            ],
            ProtocolConfig::Hysteria2 {
                password_secret,
                obfs_password_secret,
                ..
            } => {
                let mut names = vec![password_secret.as_str()];
                if let Some(secret) = obfs_password_secret.as_deref() {
                    names.push(secret);
                }
                names
            }
            ProtocolConfig::AnyTls {
                password_secret, ..
            }
            | ProtocolConfig::Tuic {
                password_secret, ..
            } => vec![password_secret.as_str()],
        }
    }
}

impl From<UserRecord> for SubscriptionUser {
    fn from(value: UserRecord) -> Self {
        Self {
            username: value.username,
            uuid: value.uuid,
            subscription_token: value.subscription_token,
        }
    }
}

pub fn demo_settings() -> PanelSettings {
    PanelSettings {
        panel_name: "Infiproxy".to_string(),
        subscription_domain: "sub.infiproxy.local".to_string(),
        node_domain: "node.infiproxy.local".to_string(),
    }
}

pub fn demo_user() -> SubscriptionUser {
    SubscriptionUser {
        username: "demo".to_string(),
        uuid: "11111111-1111-4111-8111-111111111111".to_string(),
        subscription_token: "demo".to_string(),
    }
}
