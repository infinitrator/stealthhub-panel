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

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ProxyKind {
    VlessRealityXhttp,
    Shadowsocks2022ShadowTls,
    Hysteria2,
    AnyTls,
    Tuic,
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
        panel_name: "StealthHub Panel".to_string(),
        subscription_domain: "atlas.stealthhub.cc".to_string(),
        node_domain: "iberia.stealthhub.cc".to_string(),
    }
}

pub fn demo_user() -> SubscriptionUser {
    SubscriptionUser {
        username: "demo".to_string(),
        uuid: "11111111-1111-4111-8111-111111111111".to_string(),
        subscription_token: "demo".to_string(),
    }
}
