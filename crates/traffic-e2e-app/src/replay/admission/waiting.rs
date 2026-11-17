//! Preserve the original Target observation across framework-owned retries.
use super::super::{ReplayProtocolSet, RuntimeState};
use chrono::{DateTime, Utc};

#[derive(Debug, Clone)]
pub(crate) struct RequestAdmission {
    pub(crate) case: Option<String>,
    pub(crate) event_index: Option<usize>,
    pub(crate) observed_at: Option<DateTime<Utc>>,
    pub(crate) observation_id: Option<uuid::Uuid>,
    pub(crate) observation_retained: bool,
    epoch: u64,
}
impl RequestAdmission {
    pub(crate) fn capture<P: ReplayProtocolSet>(
        state: &RuntimeState<P>,
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
    pub(crate) fn cancel_reason<P: ReplayProtocolSet>(
        &self,
        state: &RuntimeState<P>,
    ) -> Option<&'static str> {
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

impl<P: ReplayProtocolSet> RuntimeState<P> {
    pub(crate) fn admission_epoch(&self) -> u64 {
        self.admission_epoch
    }

    pub(crate) fn advance_admission_epoch(&mut self) {
        if let Some(run) = &self.run_sequence {
            for runtime in &run.runtimes {
                runtime.wake_requests();
            }
        }
        if let Some(sequence) = &self.active_sequence {
            sequence.wake_requests();
        }
        self.admission_epoch = self
            .admission_epoch
            .checked_add(1)
            .expect("dependency admission epoch overflow");
    }
}
