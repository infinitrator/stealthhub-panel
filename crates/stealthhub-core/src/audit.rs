//! Typed, secret-free contract for the administrative audit trail.
//!
//! Actions and object kinds are enums so route handlers cannot invent event
//! names. Metadata is deliberately closed and bounded: callers can record only
//! booleans and counts, never request bodies, credentials or arbitrary text.

use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditAction {
    OwnerCreated,
    PasswordChanged,
    UserCreated,
    UserEnabled,
    UserDisabled,
    UserSubscriptionTokenReset,
    UserDeleted,
    SettingsSaved,
    PanelAutoUpdatePolicyChanged,
    SecretCreated,
    SecretReplaced,
    SecretDeleted,
    ProtocolProfileSaved,
    ProtocolProfileEnabled,
    ProtocolProfileDisabled,
    DnsPolicySaved,
    TransportPoolSaved,
    TransportPoolDeleted,
    RoutingPolicySaved,
    RoutingPolicyDeleted,
    RuleSetSaved,
    RuleSetDeleted,
    RuleSetCloned,
    RuleEntrySaved,
    RuleEntryDeleted,
    RuleEntriesBulkAdded,
    RuleEntriesDeduplicated,
    RuleSourceSaved,
    RuleSourceDeleted,
    RuleSourceRefreshRequested,
    ModuleCheckRequested,
    ModuleInstallRequested,
    ModuleUpdateRequested,
    ModuleRemoveRequested,
    ModuleStartRequested,
    ModuleStopRequested,
    ModuleRestartRequested,
    ModuleAutoUpdatePolicyChanged,
    PanelUpdateRequested,
}

impl AuditAction {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::OwnerCreated => "owner.created",
            Self::PasswordChanged => "account.password-changed",
            Self::UserCreated => "user.created",
            Self::UserEnabled => "user.enabled",
            Self::UserDisabled => "user.disabled",
            Self::UserSubscriptionTokenReset => "user.subscription-token-reset",
            Self::UserDeleted => "user.deleted",
            Self::SettingsSaved => "settings.saved",
            Self::PanelAutoUpdatePolicyChanged => "panel.auto-update-policy-changed",
            Self::SecretCreated => "secret.created",
            Self::SecretReplaced => "secret.replaced",
            Self::SecretDeleted => "secret.deleted",
            Self::ProtocolProfileSaved => "protocol-profile.saved",
            Self::ProtocolProfileEnabled => "protocol-profile.enabled",
            Self::ProtocolProfileDisabled => "protocol-profile.disabled",
            Self::DnsPolicySaved => "routing.dns-policy-saved",
            Self::TransportPoolSaved => "routing.transport-pool-saved",
            Self::TransportPoolDeleted => "routing.transport-pool-deleted",
            Self::RoutingPolicySaved => "routing.policy-saved",
            Self::RoutingPolicyDeleted => "routing.policy-deleted",
            Self::RuleSetSaved => "routing.rule-set-saved",
            Self::RuleSetDeleted => "routing.rule-set-deleted",
            Self::RuleSetCloned => "routing.rule-set-cloned",
            Self::RuleEntrySaved => "routing.rule-entry-saved",
            Self::RuleEntryDeleted => "routing.rule-entry-deleted",
            Self::RuleEntriesBulkAdded => "routing.rule-entries-bulk-added",
            Self::RuleEntriesDeduplicated => "routing.rule-entries-deduplicated",
            Self::RuleSourceSaved => "routing.rule-source-saved",
            Self::RuleSourceDeleted => "routing.rule-source-deleted",
            Self::RuleSourceRefreshRequested => "routing.rule-source-refresh-requested",
            Self::ModuleCheckRequested => "module.check-requested",
            Self::ModuleInstallRequested => "module.install-requested",
            Self::ModuleUpdateRequested => "module.update-requested",
            Self::ModuleRemoveRequested => "module.remove-requested",
            Self::ModuleStartRequested => "module.start-requested",
            Self::ModuleStopRequested => "module.stop-requested",
            Self::ModuleRestartRequested => "module.restart-requested",
            Self::ModuleAutoUpdatePolicyChanged => "module.auto-update-policy-changed",
            Self::PanelUpdateRequested => "panel.update-requested",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditObjectType {
    Owner,
    AdminAccount,
    User,
    Settings,
    SecretReference,
    ProtocolProfile,
    DnsPolicy,
    TransportPool,
    RoutingPolicy,
    RuleSet,
    RuleEntry,
    RuleSource,
    Module,
    PanelUpdate,
}

impl AuditObjectType {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Owner => "owner",
            Self::AdminAccount => "admin-account",
            Self::User => "user",
            Self::Settings => "settings",
            Self::SecretReference => "secret-reference",
            Self::ProtocolProfile => "protocol-profile",
            Self::DnsPolicy => "dns-policy",
            Self::TransportPool => "transport-pool",
            Self::RoutingPolicy => "routing-policy",
            Self::RuleSet => "rule-set",
            Self::RuleEntry => "rule-entry",
            Self::RuleSource => "rule-source",
            Self::Module => "module",
            Self::PanelUpdate => "panel-update",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditOutcome {
    Succeeded,
    Requested,
}

impl AuditOutcome {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Succeeded => "succeeded",
            Self::Requested => "requested",
        }
    }
}

#[derive(Debug, Clone)]
pub struct AuditActor {
    pub admin_id: Option<i64>,
    pub username: String,
    pub role: &'static str,
}

impl AuditActor {
    pub fn initial_owner(username: impl Into<String>) -> Self {
        Self {
            admin_id: None,
            username: username.into(),
            role: "owner",
        }
    }
    pub fn owner(admin_id: i64, username: impl Into<String>) -> Self {
        Self {
            admin_id: Some(admin_id),
            username: username.into(),
            role: "owner",
        }
    }
    pub fn admin(admin_id: i64, username: impl Into<String>) -> Self {
        Self {
            admin_id: Some(admin_id),
            username: username.into(),
            role: "admin",
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuditMetadata {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub count: Option<u64>,
}

impl AuditMetadata {
    pub const fn none() -> Self {
        Self {
            enabled: None,
            count: None,
        }
    }
    pub const fn enabled(value: bool) -> Self {
        Self {
            enabled: Some(value),
            count: None,
        }
    }
    pub fn count(value: usize) -> Self {
        Self {
            enabled: None,
            count: Some(value as u64),
        }
    }
}

#[derive(Debug, Clone)]
pub struct NewAuditEvent {
    pub actor: AuditActor,
    pub action: AuditAction,
    pub object_type: AuditObjectType,
    pub object_id: String,
    pub outcome: AuditOutcome,
    pub metadata: AuditMetadata,
}

impl NewAuditEvent {
    pub fn validate(&self) -> Result<()> {
        if self.actor.username.is_empty() || self.actor.username.len() > 64 {
            bail!("invalid audit actor username");
        }
        if !matches!(self.actor.role, "owner" | "admin" | "system") {
            bail!("invalid audit actor role");
        }
        if self.object_id.is_empty() || self.object_id.len() > 192 {
            bail!("invalid audit object identifier");
        }
        if self.object_id.chars().any(char::is_control) {
            bail!("audit object identifier contains control characters");
        }
        if serde_json::to_vec(&self.metadata)?.len() > 512 {
            bail!("audit metadata exceeds the fixed bound");
        }
        Ok(())
    }
}
