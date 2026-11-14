//! Application assembly for native and transport evidence capabilities.
use crate::dependency::attribution::DependencyOwner;
use serde_json::Value;
use traffic_protocol::evidence::{EvidenceAdapter, EvidenceRegistry};
use traffic_protocol::observation::{TrafficInteraction, format_endpoint, optional_endpoint};

/// Compatibility for existing protocols outside the current native-crate extraction.
pub(super) struct ExistingEvidence;
impl EvidenceAdapter for ExistingEvidence {
    fn schema(&self) -> &'static str {
        "existing/semantic-evidence/v1"
    }
    fn event_types(&self) -> &'static [&'static str] {
        &[
            "memcached_exchange",
            "motan_exchange",
            "kafka_produce",
            "kafka_fetch",
            "kafka_delivery",
        ]
    }
    fn supports_replay(&self, event: &Value) -> bool {
        event["replay_safe"] != false
    }
    fn interaction(&self, event: &Value) -> Option<TrafficInteraction> {
        let (protocol, operation) = match event["event_type"].as_str()? {
            "memcached_exchange" => {
                let command = event["command"].as_str()?.to_ascii_lowercase();
                if matches!(command.as_str(), "version" | "noop") {
                    return None;
                }
                ("memcached", command)
            }
            "kafka_produce" => ("kafka", "produce".into()),
            "kafka_fetch" => ("kafka", "fetch".into()),
            "motan_exchange" if event["heartbeat"] != true => (
                "motan",
                event["method_name"]
                    .as_str()
                    .or_else(|| event["command"].as_str())?
                    .to_owned(),
            ),
            _ => return None,
        };
        let endpoint = event["target_host"]
            .as_str()
            .zip(
                event["target_port"]
                    .as_u64()
                    .and_then(|port| u16::try_from(port).ok()),
            )
            .map(|(host, port)| format_endpoint(host, port));
        Some(TrafficInteraction {
            protocol: protocol.into(),
            endpoint,
            operation,
        })
    }
}

pub(super) struct TransportEvidence;
impl EvidenceAdapter for TransportEvidence {
    fn schema(&self) -> &'static str {
        "transport/evidence/v1"
    }
    fn event_types(&self) -> &'static [&'static str] {
        &["udp_datagram"]
    }
    fn supports_replay(&self, _event: &Value) -> bool {
        false
    }
    fn interaction(&self, event: &Value) -> Option<TrafficInteraction> {
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

pub(crate) fn supports(
    event: &Value,
    owner: &DependencyOwner,
    registry: &EvidenceRegistry,
) -> bool {
    if event["event_type"] == "dependency_connect_failure" {
        return matches!(owner, DependencyOwner::Case { .. })
            && event["replay_safe"] != false
            && event["capture_complete"] != false
            && event["_capture_complete"] != false;
    }
    registry.supports_replay(event)
}

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
