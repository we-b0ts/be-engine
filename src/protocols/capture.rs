//! Application composition of native capture evidence and transport observations.
use crate::dependency::observation::ProtocolRef;
use crate::recorder::RecorderEvent;
use traffic_protocol::capture::{CaptureEvidence, CaptureFacts, SemanticRequirement};

impl CaptureEvidence for RecorderEvent {
    fn event_type(&self) -> &'static str {
        self.kind()
    }

    fn capture_facts(&self) -> CaptureFacts {
        use RecorderEvent::*;
        match self {
            HttpExchange(event) => event.capture_facts(),
            MysqlConnection(event) => event.capture_facts(),
            MysqlQuery(event) => event.capture_facts(),
            MysqlPacket(event) => event.capture_facts(),
            MysqlResponse(event) => event.capture_facts(),
            MysqlExchange(event) => event.capture_facts(),
            MysqlTlsRejected(event) => event.capture_facts(),
            RedisConnection(event) => event.capture_facts(),
            RedisExchange(event) => event.capture_facts(),
            RedisPubSubPush(event) => event.capture_facts(),
            DependencyConnectFailure(event) => {
                let mut facts = CaptureFacts::dependency(
                    ProtocolRef::observation(event.id, self.kind()),
                    "connect_failed",
                    true,
                );
                facts.traffic_error = true;
                facts
            }
            TcpGatewayConnection(event) => {
                let mut facts =
                    CaptureFacts::observation(ProtocolRef::observation(event.id, self.kind()));
                if event.client_to_server_bytes > 0 || event.server_to_client_bytes > 0 {
                    facts.semantic = SemanticRequirement::Mandatory;
                }
                facts.traffic_error = event.error.is_some();
                facts
            }
            UdpDatagram(event) => {
                let mut facts = CaptureFacts::dependency(
                    ProtocolRef::observation(event.id, self.kind()),
                    "datagram",
                    !event.payload.truncated,
                );
                facts.traffic_error = event.error.is_some();
                facts
            }
            ProxyError(event) => {
                let mut facts =
                    CaptureFacts::observation(ProtocolRef::observation(event.id, self.kind()));
                facts.terminal = "capture_failed".into();
                facts.complete = false;
                facts.traffic_error = true;
                facts
            }
            AccessPolicyAllow(event) => failed_observation(event.id, self.kind()),
            ReadonlyRejection(event) => failed_observation(event.id, self.kind()),
            MemcachedConnection(event) => {
                let mut facts =
                    CaptureFacts::observation(ProtocolRef::observation(event.id, self.kind()));
                facts.traffic_error = event.error.is_some();
                facts
            }
            KafkaConnection(event) => {
                let mut facts =
                    CaptureFacts::observation(ProtocolRef::observation(event.id, self.kind()));
                facts.traffic_error = event.error.is_some();
                facts
            }
            MotanConnection(event) => {
                let mut facts =
                    CaptureFacts::observation(ProtocolRef::observation(event.id, self.kind()));
                facts.traffic_error = event.error.is_some();
                facts
            }
            MemcachedExchange(event) => {
                let mut facts = CaptureFacts::dependency(
                    ProtocolRef::connection("memcached", event.connection_id, event.sequence),
                    event.outcome.label(),
                    event.response_status != "incomplete"
                        && event.response_frames.iter().all(|body| !body.truncated)
                        && event.args.iter().all(|arg| !arg.truncated)
                        && event.key.as_ref().is_none_or(|body| !body.truncated)
                        && event.value.as_ref().is_none_or(|body| !body.truncated)
                        && event.extras.as_ref().is_none_or(|body| !body.truncated),
                );
                facts.outcome = event.outcome;
                facts
            }
            KafkaProduce(event) => {
                let mut facts = CaptureFacts::dependency(
                    ProtocolRef::connection("kafka", event.connection_id, event.request_sequence),
                    event.outcome.label(),
                    event.value.as_ref().is_none_or(|body| !body.truncated)
                        && event.key.as_ref().is_none_or(|body| !body.truncated)
                        && event
                            .headers
                            .iter()
                            .all(|header| header.value.as_ref().is_none_or(|body| !body.truncated)),
                );
                facts.outcome = event.outcome;
                facts
            }
            KafkaFetch(event) => {
                let mut facts = CaptureFacts::dependency(
                    ProtocolRef::connection("kafka", event.connection_id, event.sequence),
                    event.outcome.label(),
                    true,
                );
                facts.outcome = event.outcome;
                facts
            }
            KafkaDelivery(event) => CaptureFacts::dependency(
                ProtocolRef::connection("kafka", event.connection_id, event.fetch_sequence),
                "delivery",
                event.value.as_ref().is_none_or(|body| !body.truncated)
                    && event.key.as_ref().is_none_or(|body| !body.truncated)
                    && event
                        .headers
                        .iter()
                        .all(|header| header.value.as_ref().is_none_or(|body| !body.truncated)),
            ),
            MotanExchange(event) => {
                let mut facts = CaptureFacts::dependency(
                    ProtocolRef::connection("motan", event.connection_id, event.sequence),
                    event.outcome.label(),
                    !event.request.truncated && !event.response.truncated,
                );
                facts.outcome = event.outcome;
                if event.heartbeat {
                    facts.semantic = SemanticRequirement::Observation;
                }
                facts.traffic_error = event.response_status == "exception" || !event.replay_safe;
                facts
            }
        }
    }
}

impl RecorderEvent {
    pub(crate) fn capture_complete(&self) -> bool {
        self.capture_facts().complete
    }
}

fn failed_observation(id: uuid::Uuid, kind: &str) -> CaptureFacts {
    let mut facts = CaptureFacts::observation(ProtocolRef::observation(id, kind));
    facts.traffic_error = true;
    facts
}
