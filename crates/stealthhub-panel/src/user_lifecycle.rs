//! Durable convergence of time-driven user access transitions.

use std::time::Duration;

use anyhow::Result;
use chrono::Utc;
use sqlx::SqlitePool;
use stealthhub_core::storage::{
    evaluate_due_user_lifecycle_transitions, evaluate_user_lifecycle_transitions,
    mark_user_lifecycle_reconcile_published, UserLifecycleEvaluation,
};

use crate::reconcile_request;

const CHECK_INTERVAL: Duration = Duration::from_secs(30);

/// Starts an immediate startup repair followed by low-cost indexed checks.
pub(crate) fn spawn_checker(pool: SqlitePool) {
    tokio::spawn(async move {
        while let Err(error) = evaluate_and_publish(&pool, true).await {
            tracing::warn!("user lifecycle startup repair failed: {error}");
            tokio::time::sleep(CHECK_INTERVAL).await;
        }
        loop {
            tokio::time::sleep(CHECK_INTERVAL).await;
            if let Err(error) = evaluate_and_publish(&pool, false).await {
                tracing::warn!("user lifecycle convergence failed: {error}");
            }
        }
    });
}

async fn evaluate_and_publish(pool: &SqlitePool, repair: bool) -> Result<()> {
    let now = Utc::now();
    let evaluation = if repair {
        evaluate_user_lifecycle_transitions(pool, now).await?
    } else {
        evaluate_due_user_lifecycle_transitions(pool, now).await?
    };
    publish_evaluation(pool, evaluation).await
}

async fn publish_evaluation(pool: &SqlitePool, evaluation: UserLifecycleEvaluation) -> Result<()> {
    if let Some(generation) = evaluation.pending_generation {
        publish_and_acknowledge(pool, generation).await?;
        tracing::info!(
            generation,
            transitions = evaluation.access_transitions,
            "user lifecycle reconcile requested"
        );
    }
    Ok(())
}

/// Publishes an idempotent generation request before clearing its durable outbox.
pub(crate) async fn publish_and_acknowledge(pool: &SqlitePool, generation: u64) -> Result<()> {
    reconcile_request::publish(generation)?;
    mark_user_lifecycle_reconcile_published(pool, generation).await
}
