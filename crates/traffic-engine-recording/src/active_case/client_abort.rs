//! Retain the Source Case's admission after a connection closes with pending work.
use super::*;
use crate::interaction::model::{CLIENT_ABORT_LIMIT, CLIENT_ABORT_QUIET};

impl ActiveCaseRegistry {
    pub async fn observe_close_tail(&self, case: Uuid, closed: Instant) {
        let quiet = CLIENT_ABORT_QUIET;
        let deadline = closed + CLIENT_ABORT_LIMIT;
        let activity = {
            let state = self.state.lock().expect("active case registry poisoned");
            let Some(case) = state.active.iter().find(|item| item.case.id == case) else {
                return;
            };
            case.stream_tail
                .as_ref()
                .map_or_else(|| case.dependencies.clone(), |tail| tail.activity())
        };
        let mut quiescing = self.quiescing.subscribe();
        loop {
            let observed_quiet = tokio::select! {
                result = activity.wait_until_quiet_after(quiet, deadline, Some(closed)) => result,
                _ = quiescing.wait_for(|closing| *closing) => return,
            };
            let mut state = self.state.lock().expect("active case registry poisoned");
            let Some(case) = state.active.iter_mut().find(|item| item.case.id == case) else {
                return;
            };
            // This lock also owns request admission. Recheck quiescence before
            // closing the window, then let the ordinary drain finish admitted I/O.
            let (pending, last) = activity.snapshot();
            if !case.accepting_dependencies
                || !observed_quiet
                || (pending == 0 && last.max(closed).elapsed() >= quiet)
            {
                case.accepting_dependencies = false;
                return;
            }
        }
    }
}
