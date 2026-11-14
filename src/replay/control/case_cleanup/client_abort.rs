//! Keep admission open during a bounded, rolling client-abort quiet window.
use super::*;
use crate::interaction::model::{CLIENT_ABORT_LIMIT, CLIENT_ABORT_QUIET};

pub(in crate::replay::control) fn mark_client_aborted(
    state: &mut ReplayState,
    case: &str,
) -> Result<()> {
    ensure!(
        state.active_case_id.as_deref() == Some(case) && state.finalized_at.is_none(),
        "client abort requires the active, unfinalized Case"
    );
    if state.case_cleanup.client_abort_at(case).is_none() {
        let at = TokioInstant::now();
        state.case_cleanup.client_abort = Some((case.into(), at));
        state.target_observations.watch_abort_tail(case, at);
    }
    Ok(())
}

pub(in crate::replay::control) async fn lock_for_abort_release<'a>(
    shared: &'a Arc<Mutex<ReplayState>>,
    case: &str,
    aborted: TokioInstant,
) -> Result<tokio::sync::MutexGuard<'a, ReplayState>> {
    let deadline = aborted + CLIENT_ABORT_LIMIT;
    let mut quiet_from = aborted;
    let mut previous = None;
    loop {
        let state = shared.lock().await;
        ensure!(
            state.active_case_id.as_deref() == Some(case),
            "Case ownership changed during client-abort cleanup"
        );
        let now = TokioInstant::now();
        if now >= deadline {
            drop(state);
            // The cap closes observation, not already accepted delivery.
            return lock_for_release(
                shared,
                case,
                Some(deadline + dependency_tail::TARGET_STOP_CLEANUP_GRACE),
            )
            .await;
        }
        let counts = dependency_tail::progress::counts(&state, case);
        let in_flight = has_started(&state);
        if in_flight || previous.is_some_and(|before| counts != before) {
            quiet_from = now;
        }
        previous = Some(counts);
        if let Some(activity) = state.target_observations.abort_tail_activity(case) {
            quiet_from = quiet_from.max(activity);
        }
        if !in_flight
            && now.saturating_duration_since(quiet_from) >= CLIENT_ABORT_QUIET
            && state.protocols.try_close_case(case)
        {
            return Ok(state);
        }
        drop(state);
        tokio::time::sleep_until((now + Duration::from_millis(25)).min(deadline)).await;
    }
}
