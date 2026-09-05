//! Deterministic effective-access decisions for subscription users.
//!
//! Callers provide one UTC clock boundary so HTTP, storage and reconciliation
//! can apply identical disabled, expiry and stored-quota semantics.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Structured reasons that can independently block a subscription user.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct UserAccessState {
    pub disabled: bool,
    pub expired: bool,
    pub quota_exceeded: bool,
}

impl UserAccessState {
    /// Evaluates authoritative user fields at one explicit UTC instant.
    #[must_use]
    pub fn evaluate(
        enabled: bool,
        expires_at: Option<DateTime<Utc>>,
        traffic_limit_bytes: Option<i64>,
        traffic_used_bytes: i64,
        now: DateTime<Utc>,
    ) -> Self {
        Self {
            disabled: !enabled,
            expired: expires_at.is_some_and(|deadline| deadline <= now),
            quota_exceeded: traffic_limit_bytes.is_some_and(|limit| traffic_used_bytes >= limit),
        }
    }

    /// Whether account and per-user runtime authorization are currently allowed.
    #[must_use]
    pub const fn allowed(self) -> bool {
        !self.disabled && !self.expired && !self.quota_exceeded
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 9, 1, 12, 0, 0)
            .single()
            .expect("valid UTC test time")
    }

    #[test]
    fn active_user_is_allowed() {
        let state = UserAccessState::evaluate(true, None, None, 0, now());
        assert!(state.allowed());
        assert_eq!(
            state,
            UserAccessState {
                disabled: false,
                expired: false,
                quota_exceeded: false
            }
        );
    }

    #[test]
    fn disabled_user_is_blocked() {
        let state = UserAccessState::evaluate(false, None, None, 0, now());
        assert!(!state.allowed());
        assert!(state.disabled);
    }

    #[test]
    fn exact_expiry_boundary_is_blocked() {
        let state = UserAccessState::evaluate(true, Some(now()), None, 0, now());
        assert!(!state.allowed());
        assert!(state.expired);
    }

    #[test]
    fn future_expiry_remains_allowed() {
        let deadline = now() + chrono::Duration::seconds(1);
        assert!(UserAccessState::evaluate(true, Some(deadline), None, 0, now()).allowed());
    }

    #[test]
    fn quota_boundary_is_blocked() {
        let state = UserAccessState::evaluate(true, None, Some(1_024), 1_024, now());
        assert!(!state.allowed());
        assert!(state.quota_exceeded);
    }

    #[test]
    fn simultaneous_blocking_reasons_are_preserved() {
        let state = UserAccessState::evaluate(false, Some(now()), Some(10), 20, now());
        assert!(!state.allowed());
        assert!(state.disabled);
        assert!(state.expired);
        assert!(state.quota_exceeded);
    }
}
