//! Native RESP capture completeness, controls and session evidence.
pub mod response;
use crate::events::{RedisConnectionEvent, RedisExchangeEvent, RedisPubSubPushEvent};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use traffic_model::{DependencyExchangeOutcome, recording::ProtocolRef};
use traffic_protocol::capture::{CaptureEvidence, CaptureFacts, SemanticRequirement};

impl CaptureEvidence for RedisConnectionEvent {
    fn event_type(&self) -> &'static str {
        "redis_connection"
    }
    fn capture_facts(&self) -> CaptureFacts {
        let mut facts =
            CaptureFacts::observation(ProtocolRef::observation(self.id, self.event_type()));
        facts.traffic_error = self.error.is_some();
        facts
    }
}

impl CaptureEvidence for RedisExchangeEvent {
    fn event_type(&self) -> &'static str {
        "redis_exchange"
    }
    fn capture_facts(&self) -> CaptureFacts {
        let complete = !self.response.truncated
            && self.args.iter().all(|arg| !arg.truncated)
            && !self
                .parse_warnings
                .iter()
                .any(|warning| warning.contains("incomplete") || warning.contains("interrupted"));
        let mut facts = CaptureFacts::dependency(
            ProtocolRef::connection("redis", self.connection_id, self.sequence),
            self.outcome.label(),
            complete,
        );
        facts.outcome = self.outcome;
        let successful_control = self.outcome == DependencyExchangeOutcome::Response
            && self.response_kind != "error"
            && self.replay_safe
            && (self.session_setup || self.command == "PING");
        facts.case_dependency = !is_client_library_info_exchange(self)
            && !successful_control
            && !self.cache_snapshot_hit;
        if !facts.case_dependency || self.command == "QUIT" {
            facts.semantic = SemanticRequirement::Observation;
        }
        facts
    }
}

impl CaptureEvidence for RedisPubSubPushEvent {
    fn event_type(&self) -> &'static str {
        "redis_pub_sub_push"
    }
    fn capture_facts(&self) -> CaptureFacts {
        CaptureFacts::dependency(
            ProtocolRef::observation(uuid::Uuid::new_v4(), self.event_type()),
            "delivery",
            !self.response.truncated,
        )
    }
}

pub fn is_client_library_info_exchange(exchange: &RedisExchangeEvent) -> bool {
    if !exchange.command.eq_ignore_ascii_case("CLIENT")
        || !exchange.replay_safe
        || exchange.outcome != DependencyExchangeOutcome::Response
        || exchange.response.truncated
        || !exchange.parse_warnings.is_empty()
    {
        return false;
    }
    let args = exchange
        .args
        .iter()
        .map(|capture| {
            if capture.truncated {
                return None;
            }
            match capture.encoding {
                "base64" => STANDARD.decode(&capture.data).ok(),
                "utf8" => Some(capture.data.as_bytes().to_vec()),
                _ => None,
            }
        })
        .collect::<Option<Vec<_>>>();
    args.is_some_and(|args| crate::is_client_library_info(&exchange.command, &args))
}
pub mod connection;
mod session;
mod subscriptions;
pub use session::{CaptureSessionState, is_terminal_quit, sanitize_and_classify};
pub use subscriptions::Subscriptions;
