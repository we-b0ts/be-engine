//! Retain the Source Case's admission after a proven premature client end.
use super::*;
use crate::interaction::model::{CLIENT_ABORT_LIMIT, CLIENT_ABORT_QUIET};

impl ActiveCaseRegistry {
    pub(crate) async fn observe_client_abort_tail(&self, case: Uuid, aborted: Instant) {
        self.observe_client_abort_tail_until(case, aborted, CLIENT_ABORT_QUIET, CLIENT_ABORT_LIMIT)
            .await;
    }

    async fn observe_client_abort_tail_until(
        &self,
        case: Uuid,
        aborted: Instant,
        quiet: Duration,
        limit: Duration,
    ) {
        let deadline = aborted + limit;
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
                result = activity.wait_until_quiet_after(quiet, deadline, Some(aborted)) => result,
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
                || (pending == 0 && last.max(aborted).elapsed() >= quiet)
            {
                case.accepting_dependencies = false;
                return;
            }
        }
    }
}
