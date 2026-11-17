//! Source-side Socket.IO dependency admission after the connection closes.
use super::*;

const INITIAL_QUIET: Duration = Duration::from_secs(15);
const ACTIVE_QUIET: Duration = Duration::from_secs(60);
pub(crate) const SOCKETIO_CLOSE_LIMIT: Duration = Duration::from_secs(300);
pub(crate) const SOCKETIO_CLOSE_TAIL_TIMEOUT: &str = "socketio_close_tail_timeout";

#[derive(Debug, PartialEq, Eq)]
enum TailDecision {
    Wait(Instant),
    Quiet,
    Limit,
}

fn decision(
    closed: Instant,
    now: Instant,
    in_flight: usize,
    last: Instant,
    initial_quiet: Duration,
    active_quiet: Duration,
) -> TailDecision {
    let deadline = closed + SOCKETIO_CLOSE_LIMIT;
    let quiet = if in_flight > 0 || last > closed {
        active_quiet
    } else {
        initial_quiet
    };
    let quiet_at = last.max(closed) + quiet;
    if in_flight == 0 && quiet_at <= deadline && now >= quiet_at {
        TailDecision::Quiet
    } else if now >= deadline {
        TailDecision::Limit
    } else if in_flight > 0 {
        TailDecision::Wait(deadline)
    } else {
        TailDecision::Wait(quiet_at.min(deadline))
    }
}

impl ActiveCaseRegistry {
    pub(crate) fn socketio_close_limit_case(&self) -> Option<Uuid> {
        self.state
            .lock()
            .expect("active case registry poisoned")
            .socketio_close_limit_case
    }

    pub(crate) async fn observe_socketio_close_tail(&self, case_id: Uuid, closed: Instant) {
        let activity = {
            let state = self.state.lock().expect("active case registry poisoned");
            let Some(case) = state.active.iter().find(|item| item.case.id == case_id) else {
                return;
            };
            case.business_activity()
        };
        // Network fixtures exercise the same admission transitions without
        // waiting a minute per case. The production boundaries are tested below.
        let (mut initial_quiet, mut active_quiet) = (INITIAL_QUIET, ACTIVE_QUIET);
        if cfg!(test) {
            (initial_quiet, active_quiet) =
                (Duration::from_millis(150), Duration::from_millis(400));
        }
        let mut quiescing = self.quiescing.subscribe();
        loop {
            let changed = activity.changed();
            let wake_at = {
                let mut state = self.state.lock().expect("active case registry poisoned");
                if state.quiescing {
                    return;
                }
                let Some(case) = state.active.iter_mut().find(|item| item.case.id == case_id)
                else {
                    return;
                };
                if !case.accepting_dependencies {
                    return;
                }
                // Request admission and the last check share the registry lock.
                let (in_flight, last) = activity.snapshot();
                match decision(
                    closed,
                    Instant::now(),
                    in_flight,
                    last,
                    initial_quiet,
                    active_quiet,
                ) {
                    TailDecision::Wait(wake_at) => Some(wake_at),
                    TailDecision::Quiet => {
                        case.accepting_dependencies = false;
                        return;
                    }
                    TailDecision::Limit => {
                        case.accepting_dependencies = false;
                        if in_flight > 0 {
                            case.invalidation.get_or_insert_with(|| {
                                CaseInvalidation::new(
                                    SOCKETIO_CLOSE_TAIL_TIMEOUT,
                                    "Socket.IO close tail reached five minutes with dependencies still in flight",
                                )
                            });
                        }
                        state.socketio_close_limit_case = Some(case_id);
                        self.begin_quiescing_locked(&mut state);
                        tracing::warn!(%case_id, in_flight, "Socket.IO close tail reached its limit; stopping Source");
                        None
                    }
                }
            };
            let Some(wake_at) = wake_at else {
                // The supervisor keeps Recorder alive through Source termination.
                // Retain the case guard until admitted requests have ended.
                activity.wait_until_idle().await;
                return;
            };
            tokio::select! {
                _ = changed => {},
                _ = tokio::time::sleep_until(wake_at.into()) => {},
                _ = quiescing.wait_for(|closing| *closing) => return,
            }
        }
    }
}

#[cfg(test)]
mod tests;
