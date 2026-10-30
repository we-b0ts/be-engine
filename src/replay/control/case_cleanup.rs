//! Failed primary responses drain actual I/O without inventing normal business work.
use super::*;
use std::collections::BTreeMap;
use tokio::time::Instant as TokioInstant;
mod pending;

#[derive(Debug, Default)]
pub(in crate::replay) struct CaseCleanup {
    failed: BTreeMap<String, TokioInstant>,
}

impl CaseCleanup {
    pub(super) fn deadline(&self, case: &str) -> Option<TokioInstant> {
        self.failed.get(case).copied()
    }

    pub(super) fn end(&mut self, case: &str) {
        self.failed.remove(case);
    }
}

pub(super) fn mark_failed(state: &mut ReplayState, case: &str) -> Result<()> {
    ensure!(
        state.active_case_id.as_deref() == Some(case) && state.finalized_at.is_none(),
        "primary failure requires the active, unfinalized Case"
    );
    // Retries cannot renew the error-cleanup budget.
    state
        .case_cleanup
        .failed
        .entry(case.into())
        .or_insert_with(|| TokioInstant::now() + dependency_tail::TARGET_STOP_CLEANUP_GRACE);
    state.redis.pubsub.native_clock.close_case(case);
    Ok(())
}

pub(super) async fn failure_description(
    state: &Arc<Mutex<ReplayState>>,
    error: &anyhow::Error,
) -> String {
    let error = format!("{error:#}");
    if error.contains("; pending=") {
        return error;
    }
    // An outer absolute deadline can cancel the inner drain before it gets
    // another poll. Capture the blockers before the runner stops Target.
    let state = state.lock().await;
    format!("{error}; pending={}", pending::snapshot(&state))
}

pub(in crate::replay) fn has_started(state: &ReplayState) -> bool {
    state.mysql.exchanges.iter().any(|exchange| {
        exchange.source == ReplaySource::Case
            && matches!(
                exchange.status,
                ReplayExchangeStatus::Responding | ReplayExchangeStatus::AwaitingClientTermination
            )
    }) || state.redis.has_case_in_flight()
        || state.kafka.has_case_in_flight()
        || state.connect_failures.has_in_flight()
        || state.memcached.has_case_in_flight()
        || state.motan.has_case_in_flight()
        || state.http_has_case_in_flight()
}

pub(super) async fn drain_started(
    state: &Arc<Mutex<ReplayState>>,
    case: &str,
    deadline: Option<TokioInstant>,
) -> Result<()> {
    drop(lock_drained(state, case, deadline).await?);
    Ok(())
}

/// Keep the final empty-I/O observation locked through Case ownership release.
pub(super) async fn lock_drained<'a>(
    state: &'a Arc<Mutex<ReplayState>>,
    case: &str,
    deadline: Option<TokioInstant>,
) -> Result<tokio::sync::MutexGuard<'a, ReplayState>> {
    let deadline = deadline
        .unwrap_or_else(|| TokioInstant::now() + dependency_tail::TARGET_STOP_CLEANUP_GRACE);
    loop {
        let state = state.lock().await;
        ensure!(
            state.active_case_id.as_deref() == Some(case),
            "Case ownership changed during dependency cleanup"
        );
        if !has_started(&state) {
            return Ok(state);
        }
        let now = TokioInstant::now();
        ensure!(
            now < deadline,
            "started dependency cleanup timed out; case ownership was retained; pending={}",
            pending::snapshot(&state)
        );
        drop(state);
        tokio::time::sleep(Duration::from_millis(25).min(deadline.saturating_duration_since(now)))
            .await;
    }
}
