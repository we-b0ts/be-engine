//! Failed primary responses drain actual I/O without inventing normal business work.
use super::*;
use std::collections::BTreeMap;
use tokio::time::Instant as TokioInstant;
mod client_abort;
mod pending;
pub(super) use client_abort::{lock_for_abort_release, mark_client_aborted};

#[derive(Debug, Default)]
pub(crate) struct CaseCleanup {
    failed: BTreeMap<String, TokioInstant>,
    client_abort: Option<(String, TokioInstant)>,
}

impl CaseCleanup {
    pub(super) fn deadline(&self, case: &str) -> Option<TokioInstant> {
        self.failed.get(case).copied()
    }

    pub(super) fn end(&mut self, case: &str) {
        self.failed.remove(case);
        if self.client_abort_at(case).is_some() {
            self.client_abort = None;
        }
    }

    pub(super) fn client_abort_at(&self, case: &str) -> Option<TokioInstant> {
        self.client_abort
            .as_ref()
            .filter(|(id, _)| id == case)
            .map(|(_, at)| *at)
    }
}

pub(super) fn mark_failed<P: ReplayProtocolSet>(
    state: &mut RuntimeState<P>,
    case: &str,
) -> Result<()> {
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
    state.protocols.close_case(case);
    Ok(())
}

pub(super) async fn failure_description<P: ReplayProtocolSet>(
    state: &Arc<Mutex<RuntimeState<P>>>,
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

pub(crate) fn has_started<P: ReplayProtocolSet>(state: &RuntimeState<P>) -> bool {
    state.has_protocol_io(InFlightScope::Case)
}

pub(super) async fn drain_started<P: ReplayProtocolSet>(
    state: &Arc<Mutex<RuntimeState<P>>>,
    case: &str,
    deadline: Option<TokioInstant>,
) -> Result<()> {
    drop(lock_drained(state, case, deadline).await?);
    Ok(())
}

/// Close header admission at the same linearization point as the final empty
/// observation. A header queued for Replay state already owns its atomic guard.
pub(super) async fn lock_for_release<'a, P: ReplayProtocolSet>(
    shared: &'a Arc<Mutex<RuntimeState<P>>>,
    case: &str,
    deadline: Option<TokioInstant>,
) -> Result<tokio::sync::MutexGuard<'a, RuntimeState<P>>> {
    let deadline = Some(
        deadline
            .unwrap_or_else(|| TokioInstant::now() + dependency_tail::TARGET_STOP_CLEANUP_GRACE),
    );
    loop {
        let state = lock_drained(shared, case, deadline).await?;
        if state.protocols.try_close_case(case) {
            return Ok(state);
        }
        drop(state);
    }
}

/// Keep the final empty-I/O observation locked through Case ownership release.
pub(super) async fn lock_drained<'a, P: ReplayProtocolSet>(
    state: &'a Arc<Mutex<RuntimeState<P>>>,
    case: &str,
    deadline: Option<TokioInstant>,
) -> Result<tokio::sync::MutexGuard<'a, RuntimeState<P>>> {
    let deadline = deadline
        .unwrap_or_else(|| TokioInstant::now() + dependency_tail::TARGET_STOP_CLEANUP_GRACE);
    loop {
        let changed = { state.lock().await.protocols.io_changed() };
        // Register before the empty check so a synchronous RAII release cannot
        // be lost between inspecting the counter and awaiting the notification.
        let notified = changed.notified();
        tokio::pin!(notified);
        notified.as_mut().enable();
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
        tokio::select! {
            _ = &mut notified => {},
            _ = tokio::time::sleep(Duration::from_millis(25).min(deadline.saturating_duration_since(now))) => {},
        }
    }
}
