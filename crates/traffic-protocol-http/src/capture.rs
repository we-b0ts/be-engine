//! Native HTTP capture completeness and event metadata.
use crate::events::HttpExchangeEvent;
use traffic_model::recording::ProtocolRef;
use traffic_protocol::capture::{CaptureEvidence, CaptureFacts};

impl CaptureEvidence for HttpExchangeEvent {
    fn event_type(&self) -> &'static str {
        "http_exchange"
    }
    fn capture_facts(&self) -> CaptureFacts {
        let complete = !self.request_body.truncated
            && self
                .response_body
                .as_ref()
                .is_none_or(|body| !body.truncated)
            && (self.response_status.is_some()
                || self.outcome.termination().is_some()
                || self.error.is_none());
        let mut facts = CaptureFacts::dependency(
            ProtocolRef::exchange("http", self.id),
            self.outcome.label(),
            complete,
        );
        facts.traffic_error = self.outcome.is_client_terminated()
            || self.outcome.is_server_terminated()
            || self.error.is_some()
            || self.response_status.is_some_and(|status| status >= 500);
        facts
    }
}
