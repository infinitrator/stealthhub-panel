//! Typed request and snapshot formats for the isolated Headscale control bridge.

use serde::{Deserialize, Serialize};

/// An owner-approved operation consumed by the root maintenance worker.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(tag = "action", rename_all = "kebab-case", deny_unknown_fields)]
pub enum HeadscaleRequest {
    /// Refresh the read-only user and node tables.
    Refresh,
    /// Create a local Headscale user.
    CreateUser { username: String },
    /// Create a pre-authentication key and expose it once in protected state.
    CreatePreAuthKey {
        user_id: u64,
        expiration: String,
        reusable: bool,
        ephemeral: bool,
    },
    /// Mark a node key as expired so the client must authenticate again.
    ExpireNode { node_id: u64 },
    /// Remove the last command result or secret from protected state.
    ClearResult,
}

/// Last known Headscale management state rendered by the web panel.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct HeadscaleSnapshot {
    pub updated_at: String,
    pub status: String,
    pub users: String,
    pub nodes: String,
    pub last_result: String,
    pub result_is_secret: bool,
}

/// Validates a local Headscale username accepted by the guided installer.
pub fn valid_username(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 63
        && !value.contains('@')
        && value
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '-'))
}

/// Accepts bounded Go-style durations such as `30m`, `24h`, or `168h`.
pub fn valid_expiration(value: &str) -> bool {
    let split = value
        .bytes()
        .position(|byte| !byte.is_ascii_digit())
        .unwrap_or(value.len());
    let (amount, unit) = value.split_at(split);
    !amount.is_empty()
        && amount.len() <= 4
        && amount.starts_with(|ch: char| ('1'..='9').contains(&ch))
        && amount.bytes().all(|byte| byte.is_ascii_digit())
        && matches!(unit, "m" | "h")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_control_inputs() {
        assert!(valid_username("admin-1"));
        assert!(!valid_username("bad user"));
        assert!(valid_expiration("24h"));
        assert!(valid_expiration("30m"));
        assert!(!valid_expiration("0h"));
        assert!(!valid_expiration("7d"));
    }
}
