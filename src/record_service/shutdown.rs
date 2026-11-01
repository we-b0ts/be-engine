//! Bounded normal shutdown keeps Source and admitted sessions alive until publication.

use std::time::{Duration, Instant};

use anyhow::Result;
use brz_redis::Redis;
use tracing::{info, warn};

use super::proxy::Relay;
use crate::AppState;
use crate::recorder::{CaseInvalidation, CaseInvalidationContext};

pub(super) const CASE_DRAIN_BUDGET: Duration = Duration::from_secs(60);

pub(super) async fn drain<R: Redis + Clone + 'static>(
    state: &AppState,
    relay: &Relay<R>,
) -> Result<()> {
    let started = Instant::now();
    let requested_at = chrono::Utc::now();
    state
        .recorder()
        .write_shutdown_report(&serde_json::json!({
            "version": 1,
            "requested_at": requested_at,
            "trigger": "shutdown_signal",
            "phase": "case_drain",
            "outcome": "waiting",
            "case_drain_timeout_ms": CASE_DRAIN_BUDGET.as_millis(),
        }))
        .await?;
    info!(
        timeout_ms = CASE_DRAIN_BUDGET.as_millis(),
        "normal recording shutdown waiting for admitted cases"
    );
    let completed = async {
        tokio::join!(
            relay.drain(),
            state
                .inner
                .active_cases
                .wait_for_no_active_case(CASE_DRAIN_BUDGET)
        )
        .1
    };
    let outcome = tokio::select! {
        biased;
        _ = state.wait_for_interaction_source_stop() => "source_stop_required",
        _ = state.inner.active_cases.wait_for_quiescing() => "source_stop_required",
        completed = completed => if completed { "drained" } else { "case_drain_timeout" },
        _ = tokio::time::sleep_until(tokio::time::Instant::from_std(started + CASE_DRAIN_BUDGET)) => "case_drain_timeout",
    };
    let cases = if outcome == "case_drain_timeout" {
        let failure = CaseInvalidation::new(
            "shutdown_case_drain_timeout",
            format!("normal recording shutdown exceeded its {} ms case drain budget; Source will be stopped and this incomplete case cannot be published", CASE_DRAIN_BUDGET.as_millis()),
        ).with_context(CaseInvalidationContext {
            category: "recording_shutdown".to_owned(),
            elapsed_ms: started.elapsed().as_millis(),
            recorder_phase: "shutdown_case_drain".to_owned(),
            http_stream: None,
        });
        let cases = state.inner.active_cases.invalidate_shutdown_cases(failure);
        let mut report = Vec::new();
        for case in cases {
            if let Some(failure) = &case.failure {
                state
                    .recorder()
                    .retain_shutdown_failure(case.case.id, failure.clone())
                    .await;
            }
            report.push(serde_json::json!({
                "case_id": case.case.id,
                "rule_name": case.case.rule_name,
                "uri_group": case.case.uri_group,
                "invalidation_applied": case.failure.is_some(),
                "failure_reason": case.failure.map(|failure| failure.reason),
            }));
        }
        warn!(
            timeout_ms = CASE_DRAIN_BUDGET.as_millis(),
            "normal recording shutdown case drain timed out; preserving shutdown failure before stopping Source"
        );
        state.begin_case_quiescing();
        report
    } else {
        Vec::new()
    };
    state
        .recorder()
        .write_shutdown_report(&serde_json::json!({
            "version": 1,
            "requested_at": requested_at,
            "observed_at": chrono::Utc::now(),
            "trigger": "shutdown_signal",
            "phase": "before_source_stop",
            "outcome": outcome,
            "case_drain_timeout_ms": CASE_DRAIN_BUDGET.as_millis(),
            "elapsed_ms": started.elapsed().as_millis(),
            "cases": cases,
        }))
        .await
}
