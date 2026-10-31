//! Lost-wakeup-safe waits retain the original independent Target observation.
use super::super::ReplayState;
use chrono::{DateTime, Utc};
use std::{pin::Pin, sync::Arc, time::Duration};
use tokio::{
    sync::{Notify, futures::OwnedNotified},
    time::Instant,
};

pub(in crate::replay) struct WaitRegistration {
    changed: Pin<Box<OwnedNotified>>,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::replay) enum WaitOutcome {
    Changed,
    Poll,
    Deadline,
}
impl WaitRegistration {
    pub(super) fn new(changed: Arc<Notify>) -> Self {
        let mut changed = Box::pin(changed.notified_owned());
        changed.as_mut().enable();
        Self { changed }
    }
    pub(in crate::replay) async fn wait(mut self, deadline: Instant) -> WaitOutcome {
        tokio::select! {
            biased;
            _=tokio::time::sleep_until(deadline)=>WaitOutcome::Deadline,
            _=&mut self.changed=>WaitOutcome::Changed,
            _=tokio::time::sleep(Duration::from_millis(100))=>WaitOutcome::Poll,
        }
    }
}

#[derive(Debug, Clone)]
pub(in crate::replay) struct RequestAdmission {
    pub(in crate::replay) case: Option<String>,
    pub(in crate::replay) event_index: Option<usize>,
    pub(in crate::replay) observed_at: Option<DateTime<Utc>>,
    pub(in crate::replay) observation_id: Option<uuid::Uuid>,
    pub(in crate::replay) observation_retained: bool,
    epoch: u64,
}
impl RequestAdmission {
    pub(in crate::replay) fn capture(
        state: &ReplayState,
        event_index: Option<usize>,
        observed_at: Option<DateTime<Utc>>,
        observation_id: Option<uuid::Uuid>,
        observation_retained: bool,
    ) -> Self {
        Self {
            case: state.active_case_id.clone(),
            event_index,
            observed_at,
            observation_id,
            observation_retained,
            epoch: state.admission_epoch,
        }
    }
    pub(in crate::replay) fn cancel_reason(&self, state: &ReplayState) -> Option<&'static str> {
        (state.active_case_id != self.case
            || state.finalized_at.is_some()
            || state.target_session_stopped
            || state.async_case_quiescing()
            || self
                .case
                .as_ref()
                .is_some_and(|case| state.target_stop_prepared.contains(case))
            || state.admission_epoch != self.epoch)
            .then_some("dependency Case stopped while awaiting predecessor delivery")
    }
}

impl ReplayState {
    pub(in crate::replay) fn advance_admission_epoch(&mut self) {
        self.admission_epoch = self
            .admission_epoch
            .checked_add(1)
            .expect("dependency admission epoch overflow");
    }
}
