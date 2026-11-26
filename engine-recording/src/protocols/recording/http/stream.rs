//! Bind native HTTP stream facts to recording ownership and publication.
pub use super::dependency::HttpCaptureContext as CaptureContext;
use crate::http::rewrite::{self, RewriteInput};
use crate::protocols::recording::events::RecorderEvent;
use crate::recorder::{CaseInvalidation, CaseInvalidationContext};
pub use stream_capture::is_stream;
use traffic_model::trace::OutputKind;
use traffic_protocol_http::stream_capture::{self, StreamHost};

#[cfg(test)]
mod tests;
#[cfg(test)]
use stream_capture::{Capture, CaptureBody};

struct Host(CaptureContext);
impl StreamHost for Host {
    fn activity(&self) {
        self.0.targets.note_stream_tail_activity();
    }
    fn source_stop_requested(&self) -> bool {
        self.0
            .state
            .inner
            .active_cases
            .source_stop_requested_for(&self.0.targets)
    }
    fn managed_session(&self) -> bool {
        self.0.state.session_events()
    }
    fn output(&self, output: OutputKind) {
        if let Some(capture) = &self.0.targets.capture {
            capture.output(output);
        }
    }
    fn finish(&self, event: traffic_protocol_http::events::HttpExchangeEvent) {
        self.0
            .state
            .record_event_for_targets(RecorderEvent::HttpExchange(event), self.0.targets.clone());
    }
    fn invalidate(
        &self,
        reason: &str,
        elapsed_ms: u128,
        native: serde_json::Value,
        recover_after_drain: bool,
    ) {
        if self.0.state.session_events()
            && let Some(capture) = &self.0.targets.capture
        {
            capture.note_terminal("http_stream_capture_incomplete".into(), false);
        }
        let context = CaseInvalidationContext {
            category: "http_stream_capture".into(),
            elapsed_ms,
            recorder_phase: self.0.state.recording_lifecycle_phase().into(),
            native: std::collections::BTreeMap::from([("http_stream".into(), native)]),
        };
        let mut failure =
            CaseInvalidation::new("http_stream_capture_incomplete", reason).with_context(context);
        if recover_after_drain {
            failure = failure.allow_drained_case_recovery();
        }
        for (case, _) in &self.0.targets.cases {
            self.0
                .state
                .invalidate_active_case(case.id, failure.clone());
        }
    }
}

fn native_context(context: CaptureContext) -> stream_capture::CaptureContext {
    stream_capture::CaptureContext {
        event: context.event.clone(),
        started: context.started,
        termination: context.termination.clone(),
        redact_headers: context.state.config().recording.redact_headers.clone(),
        drain_timeout: std::time::Duration::from_millis(
            context
                .state
                .config()
                .recording
                .case_dependency_drain_timeout_ms,
        ),
        requires_complete_body_rewrite: false,
        host: std::sync::Arc::new(Host(context)),
    }
}

pub fn response(
    upstream: hyper::Response<hyper::body::Incoming>,
    context: CaptureContext,
) -> hyper::Response<http_body_util::combinators::BoxBody<bytes::Bytes, std::io::Error>> {
    let method =
        hyper::Method::from_bytes(context.event.method.as_bytes()).expect("captured method");
    let uri = context
        .event
        .uri
        .parse::<hyper::Uri>()
        .expect("captured URI");
    let input = RewriteInput {
        method: &method,
        uri: &uri,
        authority: context.event.authority.as_deref(),
        status: upstream.status(),
        headers: upstream.headers(),
        body: &[],
    };
    let rewrite = &context.state.config().http_response_rewrite;
    let requires_rewrite = rewrite.is_enabled()
        && rewrite
            .rules
            .iter()
            .any(|rule| rewrite::matches(rule, &input));
    let mut native = native_context(context);
    native.requires_complete_body_rewrite = requires_rewrite;
    stream_capture::response(upstream, native)
}
