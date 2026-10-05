//! Keep complete request evidence and its admission ownership across service cancellation.
use std::future::Future;
use std::time::Instant;

use chrono::Utc;

use crate::active_case::DependencyTargets;
use crate::http::termination::ClientTermination;
use crate::recorder::{HttpExchangeEvent, RecorderEvent};
use crate::{AppState, DependencyExchangeOutcome};

pub(crate) struct PendingHttpCapture {
    state: AppState,
    targets: DependencyTargets,
    event: Option<HttpExchangeEvent>,
    started: Instant,
    termination: ClientTermination,
}

impl PendingHttpCapture {
    pub(crate) fn new(
        state: AppState,
        targets: DependencyTargets,
        event: HttpExchangeEvent,
        started: Instant,
        termination: ClientTermination,
    ) -> Self {
        Self {
            state,
            targets,
            event: Some(event),
            started,
            termination,
        }
    }

    pub(crate) async fn run<F: Future>(mut self, future: F) -> F::Output {
        let result = future.await;
        self.event = None;
        result
    }
}

impl Drop for PendingHttpCapture {
    fn drop(&mut self) {
        let Some(mut event) = self.event.take() else {
            return;
        };
        event.timestamp = Utc::now();
        if let Some(ended) = self.termination.observed_at() {
            event.outcome = DependencyExchangeOutcome::ClientTerminated;
            event.duration_ms = ended.saturating_duration_since(self.started).as_millis();
        } else {
            // Task cancellation or recorder shutdown is not evidence of a client timeout.
            event.error = Some(
                "HTTP dependency capture cancelled without observed client termination".into(),
            );
            event.duration_ms = self.started.elapsed().as_millis();
        }
        self.state
            .record_event_for_targets(RecorderEvent::HttpExchange(event), self.targets.clone());
    }
}
