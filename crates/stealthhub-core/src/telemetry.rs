//! Typed, non-secret runtime telemetry and cumulative-counter normalization.
//!
//! Telemetry is observed state. It never changes desired or applied state and
//! unsupported metrics are represented explicitly rather than as zero.

use std::collections::BTreeMap;

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};

/// Stable runtime metrics understood by generic inventory and UI code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TelemetryMetric {
    ProcessState,
    ListenerState,
    RuntimeVersion,
    ActiveConnections,
    AggregateTraffic,
    PerUserTraffic,
}

/// Truthful availability of one metric at observation time.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TelemetryState {
    Supported,
    Unsupported,
    Unavailable,
    Stale,
    Error,
}

/// A cumulative traffic counter sample from one runtime identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrafficCounters {
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub total_bytes: u64,
    pub active_connections: Option<u64>,
    pub continuity: String,
}

/// Safe delta between two cumulative samples.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TrafficDelta {
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub total_bytes: u64,
    pub reset: bool,
}

/// One canonical runtime observation. This structure cannot carry config or secrets.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeTelemetryObservation {
    pub runtime_id: String,
    pub observed_at: DateTime<Utc>,
    pub source: String,
    pub metrics: BTreeMap<TelemetryMetric, TelemetryState>,
    pub traffic: Option<TrafficCounters>,
    pub detail: Option<String>,
}

impl RuntimeTelemetryObservation {
    /// Marks otherwise available data stale without turning unsupported into stale.
    #[must_use]
    pub fn with_freshness(mut self, now: DateTime<Utc>, max_age: Duration) -> Self {
        if now.signed_duration_since(self.observed_at) > max_age {
            for state in self.metrics.values_mut() {
                if matches!(
                    *state,
                    TelemetryState::Supported | TelemetryState::Unavailable
                ) {
                    *state = TelemetryState::Stale;
                }
            }
        }
        self
    }
}

/// Normalizes cumulative counters without ever producing a negative delta.
#[must_use]
pub fn normalize_cumulative(
    previous: Option<&TrafficCounters>,
    current: &TrafficCounters,
) -> TrafficDelta {
    let continuous = previous.is_some_and(|old| {
        old.continuity == current.continuity
            && current.rx_bytes >= old.rx_bytes
            && current.tx_bytes >= old.tx_bytes
            && current.total_bytes >= old.total_bytes
    });
    let (rx_bytes, tx_bytes, total_bytes) = if continuous {
        let old = previous.expect("continuous samples have a predecessor");
        (
            current.rx_bytes - old.rx_bytes,
            current.tx_bytes - old.tx_bytes,
            current.total_bytes - old.total_bytes,
        )
    } else {
        (current.rx_bytes, current.tx_bytes, current.total_bytes)
    };
    TrafficDelta {
        rx_bytes,
        tx_bytes,
        total_bytes,
        reset: previous.is_some() && !continuous,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn counters(rx: u64, tx: u64, continuity: &str) -> TrafficCounters {
        TrafficCounters {
            rx_bytes: rx,
            tx_bytes: tx,
            total_bytes: rx + tx,
            active_connections: Some(2),
            continuity: continuity.into(),
        }
    }

    #[test]
    fn cumulative_deltas_handle_increase_reset_and_decrease() {
        let first = counters(10, 20, "pid-1");
        let next = counters(15, 28, "pid-1");
        assert_eq!(normalize_cumulative(None, &first).total_bytes, 30);
        assert_eq!(normalize_cumulative(Some(&first), &next).total_bytes, 13);

        let restarted = counters(1, 2, "pid-2");
        let delta = normalize_cumulative(Some(&next), &restarted);
        assert!(delta.reset);
        assert_eq!(delta.total_bytes, 3);

        let decreased = counters(1, 1, "pid-2");
        let delta = normalize_cumulative(Some(&restarted), &decreased);
        assert!(delta.reset);
        assert_eq!(delta.total_bytes, 2);
    }

    #[test]
    fn missing_intermediate_sample_remains_safe() {
        let old = counters(1, 2, "same-process");
        let current = counters(101, 202, "same-process");
        let delta = normalize_cumulative(Some(&old), &current);
        assert_eq!(
            (delta.rx_bytes, delta.tx_bytes, delta.total_bytes),
            (100, 200, 300)
        );
        assert!(!delta.reset);
    }

    #[test]
    fn unsupported_and_stale_are_distinct_and_serialization_is_deterministic() {
        let observed_at = DateTime::parse_from_rfc3339("2026-01-01T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let observation = RuntimeTelemetryObservation {
            runtime_id: "sing-box".into(),
            observed_at,
            source: "core-adapter".into(),
            metrics: BTreeMap::from([
                (TelemetryMetric::ProcessState, TelemetryState::Supported),
                (TelemetryMetric::PerUserTraffic, TelemetryState::Unsupported),
            ]),
            traffic: None,
            detail: None,
        }
        .with_freshness(observed_at + Duration::minutes(10), Duration::minutes(6));
        assert_eq!(
            observation.metrics[&TelemetryMetric::ProcessState],
            TelemetryState::Stale
        );
        assert_eq!(
            observation.metrics[&TelemetryMetric::PerUserTraffic],
            TelemetryState::Unsupported
        );
        assert_eq!(
            serde_json::to_string(&observation).unwrap(),
            serde_json::to_string(&observation).unwrap()
        );
    }
}
