//! Generic control-plane models persisted independently of concrete protocols.
//!
//! Protocol-specific options are versioned opaque JSON owned by adapters. This
//! lets new adapters be installed without changing the database schema or the
//! subscription assembler.

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::storage::UserRecord;

/// Global settings applied to generated client subscriptions.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PanelSettings {
    pub panel_name: String,
    pub subscription_domain: String,
    pub node_domain: String,
}

impl Default for PanelSettings {
    fn default() -> Self {
        Self {
            panel_name: "Infiproxy".to_string(),
            subscription_domain: "sub.infiproxy.local".to_string(),
            node_domain: "node.infiproxy.local".to_string(),
        }
    }
}

/// Enabled user data exposed to protocol adapters during rendering.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SubscriptionUser {
    pub username: String,
    pub uuid: String,
    pub subscription_token: String,
}

impl std::fmt::Debug for SubscriptionUser {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SubscriptionUser")
            .field("username", &self.username)
            .field("uuid", &"[REDACTED]")
            .field("subscription_token", &"[REDACTED]")
            .finish()
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

/// Abstract routing role used by generic policy and proxy-group assembly.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum ProxyRole {
    AutoSafe,
    Speed,
    Compatibility,
    RuAccess,
    Manual,
}

/// One adapter-owned protocol profile.
#[derive(Clone, Serialize, Deserialize, PartialEq)]
pub struct ProtocolProfile {
    /// Stable machine identity referenced by routing and runtime state.
    pub name: String,
    /// Operator-facing label; changing it never changes runtime identity.
    pub display_name: String,
    pub protocol_id: String,
    pub schema_version: u32,
    pub role: ProxyRole,
    pub server: String,
    pub port: u16,
    pub enabled: bool,
    pub preferred_core_id: Option<String>,
    pub managed_resource_id: Option<String>,
    pub config: Value,
}

impl std::fmt::Debug for ProtocolProfile {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ProtocolProfile")
            .field("name", &self.name)
            .field("display_name", &self.display_name)
            .field("protocol_id", &self.protocol_id)
            .field("schema_version", &self.schema_version)
            .field("role", &self.role)
            .field("server", &self.server)
            .field("port", &self.port)
            .field("enabled", &self.enabled)
            .field("preferred_core_id", &self.preferred_core_id)
            .field("managed_resource_id", &self.managed_resource_id)
            .field("config", &"[REDACTED]")
            .finish()
    }
}
