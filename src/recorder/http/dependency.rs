//! Keep complete request evidence and its admission ownership across service cancellation.
use std::future::Future;
use std::time::Instant;

use chrono::Utc;

use crate::active_case::DependencyTargets;
use crate::http::termination::ClientTermination;
use crate::recorder::{HttpExchangeEvent, RecorderEvent};
use crate::{AppState, DependencyExchangeOutcome};

pub(crate) struct HttpCaptureContext {
    pub(crate) state: AppState,
    pub(crate) targets: DependencyTargets,
    pub(crate) event: HttpExchangeEvent,
    pub(crate) started: Instant,
    pub(crate) termination: ClientTermination,
}

impl HttpCaptureContext {
    pub(crate) fn accepts_server(
        &self,
        observed: crate::dependency::termination::ObservedTermination,
    ) -> bool {
        !self.termination.engine_stopped()
            && self
                .termination
                .cancelled_at()
                .is_none_or(|client| client > observed.at)
    }

    pub(crate) fn forward_server_termination(
        &self,
        observed: crate::dependency::termination::ObservedTermination,
    ) -> bool {
        if !self.accepts_server(observed)
            || self
                .termination
                .propagate_server(observed.termination)
                .is_err()
        {
            return false;
        }
        let mut event = self.event.clone();
        event.timestamp = Utc::now();
        event.outcome = DependencyExchangeOutcome::Terminated(observed.termination);
        event.duration_ms = observed
            .at
            .saturating_duration_since(self.started)
            .as_millis();
        event.error = None;
        self.state
            .record_event_for_targets(RecorderEvent::HttpExchange(event), self.targets.clone());
        true
    }
}

/// Complete Hyper's service future after the physical response side has ended.
/// Its writer is already shut down/reset, so no HTTP headers are synthesized.
pub(crate) fn closed_response()
-> hyper::Response<http_body_util::combinators::BoxBody<bytes::Bytes, std::io::Error>> {
    use http_body_util::BodyExt;
    hyper::Response::new(
        http_body_util::Empty::<bytes::Bytes>::new()
            .map_err(|never: std::convert::Infallible| match never {})
            .boxed(),
    )
}

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

    pub(crate) fn context(&self) -> HttpCaptureContext {
        HttpCaptureContext {
            state: self.state.clone(),
            targets: self.targets.clone(),
            event: self.event.as_ref().expect("pending capture").clone(),
            started: self.started,
            termination: self.termination.clone(),
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
        if let Some(ended) = self.termination.cancelled() {
            event.outcome = DependencyExchangeOutcome::Terminated(ended.termination);
            event.duration_ms = ended.at.saturating_duration_since(self.started).as_millis();
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
