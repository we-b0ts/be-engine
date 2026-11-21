//! Native HTTP capture completeness and event metadata.
use crate::events::HttpExchangeEvent;
use traffic_model::recording::ProtocolRef;
use traffic_protocol::{
    capture::{CaptureEvidence, CaptureFacts, RecordingLayout, RecordingScalar},
    observation::format_endpoint,
};

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
        )
        .with_recording_layout(RecordingLayout {
            protocol: "http",
            variant: "",
            event_type: self.event_type(),
            use_dependency_id: true,
            fields: &[("scheme", RecordingScalar::Text)],
            request_fields: &[
                "method",
                "uri",
                "authority",
                "request_headers",
                "request_body",
            ],
            response_fields: &[
                "response_status",
                "response_headers",
                "response_body",
                "response_stream",
                "discovered_tcp_targets",
            ],
        });
        facts.recording_target =
            crate::recorded::identity(&self.scheme, self.authority.as_deref(), &self.uri)
                .ok()
                .map(|(_, endpoint)| format_endpoint(&endpoint.host, endpoint.port));
        facts.recording_upstream = self.upstream_addr.map(|address| address.to_string());
        facts.outcome = self.outcome;
        facts.traffic_error = self.outcome.is_client_terminated()
            || self.outcome.is_server_terminated()
            || self.error.is_some()
            || self.response_status.is_some_and(|status| status >= 500);
        facts
    }
}
