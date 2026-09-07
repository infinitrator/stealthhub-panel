//! Low-frequency persistence of adapter-owned, non-secret runtime observations.

use std::{sync::Arc, time::Duration};

use sqlx::SqlitePool;
use stealthhub_core::{adapter::CoreRegistry, storage::record_runtime_telemetry};

const COLLECT_INTERVAL: Duration = Duration::from_secs(300);
const COLLECT_TIMEOUT: Duration = Duration::from_secs(20);

pub(crate) fn spawn_collector(pool: SqlitePool, registry: Arc<CoreRegistry>) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(COLLECT_INTERVAL);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            interval.tick().await;
            let registry = Arc::clone(&registry);
            let observed = tokio::time::timeout(
                COLLECT_TIMEOUT,
                tokio::task::spawn_blocking(move || registry.observations()),
            )
            .await;
            let observations = match observed {
                Ok(Ok(value)) => value,
                Ok(Err(error)) => {
                    tracing::warn!("telemetry collector task failed: {error}");
                    continue;
                }
                Err(_) => {
                    tracing::warn!("telemetry collector exceeded its bounded cycle");
                    continue;
                }
            };
            for observation in observations {
                if let Err(error) =
                    record_runtime_telemetry(&pool, &observation.telemetry, None).await
                {
                    tracing::warn!(
                        runtime = %observation.manifest.id,
                        "telemetry observation was not persisted: {error}"
                    );
                }
            }
        }
    });
}
