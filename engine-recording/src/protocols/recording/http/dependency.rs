//! Keep complete request evidence and its admission ownership across service cancellation.
use std::future::Future;
use std::time::Instant;

use chrono::Utc;

use crate::active_case::DependencyTargets;
use crate::http::termination::ClientTermination;
use crate::protocols::recording::events::{HttpExchangeEvent, RecorderEvent};
use crate::{AppState, DependencyExchangeOutcome};

#[cfg(test)]
mod tests;

pub struct HttpCaptureContext {
    pub state: AppState,
    pub targets: DependencyTargets,
    pub event: HttpExchangeEvent,
    pub started: Instant,
    pub termination: ClientTermination,
}

impl HttpCaptureContext {
    pub async fn collect_response_body(
        &self,
        body: hyper::body::Incoming,
    ) -> anyhow::Result<bytes::Bytes> {
        use http_body_util::BodyExt;
        let bytes = body.collect().await?.to_bytes();
        anyhow::ensure!(
            !self.termination.engine_stopped(),
            "HTTP dependency response ended during engine cleanup before capture completed"
        );
        Ok(bytes)
    }

    pub fn accepts_server(
        &self,
        observed: crate::dependency::termination::ObservedTermination,
    ) -> bool {
        !self.termination.engine_stopped()
            && self
                .termination
                .cancelled_at()
                .is_none_or(|client| client > observed.at)
    }

    pub fn forward_server_termination(
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
        event.timestamp = crate::dependency::termination::observed_wall_time(observed.at);
        event.outcome = DependencyExchangeOutcome::Terminated(observed.termination);
        event.duration_ms = observed
            .at
            .saturating_duration_since(self.started)
            .as_millis();
        event.error = None;
        self.targets.record_output(event.outcome);
        self.state
            .record_event_for_targets(RecorderEvent::HttpExchange(event), self.targets.clone());
        true
    }
}

/// Complete Hyper's service future after the physical response side has ended.
/// Its writer is already shut down/reset, so no HTTP headers are synthesized.
pub fn closed_response()
-> hyper::Response<http_body_util::combinators::BoxBody<bytes::Bytes, std::io::Error>> {
    use http_body_util::BodyExt;
    hyper::Response::new(
        http_body_util::Empty::<bytes::Bytes>::new()
            .map_err(|never: std::convert::Infallible| match never {})
            .boxed(),
    )
}

pub struct PendingHttpCapture {
    state: AppState,
    targets: DependencyTargets,
    event: Option<HttpExchangeEvent>,
    started: Instant,
    termination: ClientTermination,
}

impl PendingHttpCapture {
    pub fn new(
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

    pub fn context(&self) -> HttpCaptureContext {
        HttpCaptureContext {
            state: self.state.clone(),
            targets: self.targets.clone(),
            event: self.event.as_ref().expect("pending capture").clone(),
            started: self.started,
            termination: self.termination.clone(),
        }
    }

    pub async fn run<F>(mut self, future: F) -> F::Output
    where
        F: Future<
            Output = hyper::Response<
                http_body_util::combinators::BoxBody<bytes::Bytes, std::io::Error>,
            >,
        >,
    {
        let result = future.await;
        self.event = None;
        crate::http::wire_events::record(
            result,
            self.targets.capture.clone(),
            self.termination.clone(),
        )
    }
}

impl Drop for PendingHttpCapture {
    fn drop(&mut self) {
        let Some(mut event) = self.event.take() else {
            return;
        };
        event.timestamp = Utc::now();
        if let Some(ended) = self.termination.cancelled() {
            event.timestamp = crate::dependency::termination::observed_wall_time(ended.at);
            event.outcome = DependencyExchangeOutcome::Terminated(ended.termination);
            event.duration_ms = ended.at.saturating_duration_since(self.started).as_millis();
        } else {
            // Task cancellation or recorder shutdown is not evidence of a client timeout.
            event.error = Some(
                "HTTP dependency capture cancelled without observed client termination".into(),
            );
            event.duration_ms = self.started.elapsed().as_millis();
        }
        if event.outcome.termination().is_some() {
            self.targets.record_output(event.outcome);
        }
        self.state
            .record_event_for_targets(RecorderEvent::HttpExchange(event), self.targets.clone());
    }
}
