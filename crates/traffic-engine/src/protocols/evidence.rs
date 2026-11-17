//! Application assembly for native and transport evidence capabilities.
#[cfg(test)]
use crate::dependency::attribution::DependencyOwner;
use anyhow::Result;
use serde_json::Value;
use traffic_model::recording::ProtocolRef;
use traffic_protocol::evidence::EvidenceAdapter;
use traffic_protocol::observation::{TrafficInteraction, optional_endpoint};

pub(super) struct TransportEvidence;
impl EvidenceAdapter for TransportEvidence {
    fn schema(&self) -> &'static str {
        "transport/evidence/v1"
    }
    fn event_types(&self) -> &'static [&'static str] {
        &["udp_datagram", "tcp_gateway_connection", "proxy_error"]
    }
    fn include_in_recording_summary(&self, _event: &Value) -> bool {
        true
    }
    fn recording_summary(
        &self,
    ) -> Option<Box<dyn traffic_protocol::observation::RecordingSummary>> {
        Some(Box::new(
            super::recording::summary::TransportSummary::default(),
        ))
    }
    fn supports_replay(&self, _event: &Value) -> bool {
        false
    }
    fn finite_reference(&self, event: &Value) -> Result<Option<ProtocolRef>> {
        anyhow::ensure!(
            event["event_type"] != "udp_datagram",
            "finite-tail UDP replay is unsupported"
        );
        Ok(None)
    }
    fn interaction(&self, event: &Value) -> Option<TrafficInteraction> {
        if event["event_type"] != "udp_datagram" {
            return None;
        }
        let endpoint = optional_endpoint(
            event["target_host"].as_str(),
            event["target_port"]
                .as_u64()
                .and_then(|port| u16::try_from(port).ok()),
            event["target_addr"]
                .as_str()
                .or_else(|| event["upstream_addr"].as_str()),
        );
        Some(TrafficInteraction {
            protocol: "udp".into(),
            endpoint,
            operation: event["protocol"].as_str()?.to_owned(),
        })
    }
}

pub use traffic_recorder::supports_replay as supports;

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;
    fn semantic_replay_unsupported(event: &Value, owner: &DependencyOwner) -> bool {
        !supports(
            event,
            owner,
            crate::protocols::default_providers().evidence(),
        )
    }
    use serde_json::json;

    #[test]
    fn unsupported_semantics_follow_the_effective_owner_and_keep_unknown_kinds_closed() {
        let case = DependencyOwner::Case {
            origin_case_id: Uuid::new_v4(),
            task_instance: None,
        };
        let process = DependencyOwner::Process {
            process_epoch: Uuid::new_v4(),
            source_task: "worker".into(),
            invocation: None,
        };
        let failure = json!({"event_type":"dependency_connect_failure"});
        assert!(!semantic_replay_unsupported(&failure, &case));
        assert!(semantic_replay_unsupported(&failure, &process));
        for event in [
            json!({"event_type":"udp_datagram"}),
            json!({"event_type":"unimplemented_exchange"}),
            json!({"event_type":"mysql_exchange", "parse_warnings":["unsupported result framing"]}),
            json!({"event_type":"redis_exchange", "replay_safe":false}),
            json!({"event_type":"mysql_exchange", "replay_safe":false}),
            json!({"event_type":"http_exchange", "replay_safe":false}),
        ] {
            assert!(semantic_replay_unsupported(&event, &case));
            assert!(semantic_replay_unsupported(&event, &process));
        }
    }
}
