//! Protocol-owned pairing facts projected without reinterpreting wire payloads.
use crate::dependency::observation::ProtocolRef;
use crate::recorder::RecorderEvent;

impl RecorderEvent {
    pub(crate) fn capture_complete(&self) -> bool {
        terminal(self).1
    }
}

pub(super) fn protocol_ref(event: &RecorderEvent) -> ProtocolRef {
    match event {
        RecorderEvent::HttpExchange(e) => ProtocolRef::exchange("http", e.id),
        RecorderEvent::MysqlQuery(e) => {
            ProtocolRef::connection("mysql", e.connection_id, e.sequence)
        }
        RecorderEvent::MysqlResponse(e) => {
            ProtocolRef::connection("mysql", e.connection_id, e.query_sequence)
        }
        RecorderEvent::MysqlExchange(e) => {
            ProtocolRef::connection("mysql", e.connection_id, e.query_sequence)
        }
        RecorderEvent::RedisExchange(e) => {
            ProtocolRef::connection("redis", e.connection_id, e.sequence)
        }
        RecorderEvent::MemcachedExchange(e) => {
            ProtocolRef::connection("memcached", e.connection_id, e.sequence)
        }
        RecorderEvent::KafkaProduce(e) => {
            ProtocolRef::connection("kafka", e.connection_id, e.request_sequence)
        }
        RecorderEvent::KafkaFetch(e) => {
            ProtocolRef::connection("kafka", e.connection_id, e.sequence)
        }
        RecorderEvent::KafkaDelivery(e) => {
            ProtocolRef::connection("kafka", e.connection_id, e.fetch_sequence)
        }
        RecorderEvent::MotanExchange(e) => {
            ProtocolRef::connection("motan", e.connection_id, e.sequence)
        }
        _ => ProtocolRef::observation(observation_id(event), event.kind()),
    }
}

fn observation_id(event: &RecorderEvent) -> uuid::Uuid {
    match event {
        RecorderEvent::DependencyConnectFailure(e) => e.id,
        RecorderEvent::TcpGatewayConnection(e) => e.id,
        RecorderEvent::UdpDatagram(e) => e.id,
        RecorderEvent::RedisConnection(e) => e.id,
        RecorderEvent::MemcachedConnection(e) => e.id,
        RecorderEvent::KafkaConnection(e) => e.id,
        RecorderEvent::MotanConnection(e) => e.id,
        RecorderEvent::MysqlConnection(e) => e.id,
        RecorderEvent::MysqlPacket(e) => e.id,
        RecorderEvent::MysqlTlsRejected(e) => e.id,
        RecorderEvent::AccessPolicyAllow(e) => e.id,
        RecorderEvent::ReadonlyRejection(e) => e.id,
        RecorderEvent::ProxyError(e) => e.id,
        // A push is an independent observation, not another use of the request
        // sequence. Its physical identity is the admission's exchange_id.
        _ => uuid::Uuid::new_v4(),
    }
}

pub(in crate::recorder) fn terminal(event: &RecorderEvent) -> (String, bool) {
    use RecorderEvent::*;
    match event {
        HttpExchange(e) => (
            e.outcome.label().into(),
            !e.request_body.truncated
                && e.response_body.as_ref().is_none_or(|b| !b.truncated)
                && (e.response_status.is_some()
                    || e.outcome.termination().is_some()
                    || e.error.is_none()),
        ),
        MysqlExchange(e) => (
            e.outcome.label().into(),
            e.response.status != "incomplete"
                && !e.response.rows_truncated
                && e.params
                    .as_ref()
                    .is_none_or(|params| params.iter().all(mysql_value_complete))
                && e.response.rows.iter().flatten().all(mysql_value_complete)
                && e.response
                    .wire_prefix
                    .iter()
                    .all(|packet| !packet.packet.truncated),
        ),
        RedisExchange(e) => (
            e.outcome.label().into(),
            !e.response.truncated
                && e.args.iter().all(|a| !a.truncated)
                && !e
                    .parse_warnings
                    .iter()
                    .any(|w| w.contains("incomplete") || w.contains("interrupted")),
        ),
        RedisPubSubPush(e) => ("delivery".into(), !e.response.truncated),
        MemcachedExchange(e) => (
            e.outcome.label().into(),
            e.response_status != "incomplete"
                && e.response_frames.iter().all(|b| !b.truncated)
                && e.args.iter().all(|arg| !arg.truncated)
                && e.key.as_ref().is_none_or(|value| !value.truncated)
                && e.value.as_ref().is_none_or(|value| !value.truncated)
                && e.extras.as_ref().is_none_or(|value| !value.truncated),
        ),
        KafkaProduce(e) => (
            e.outcome.label().into(),
            e.value.as_ref().is_none_or(|v| !v.truncated)
                && e.key.as_ref().is_none_or(|v| !v.truncated)
                && e.headers
                    .iter()
                    .all(|header| header.value.as_ref().is_none_or(|v| !v.truncated)),
        ),
        KafkaFetch(e) => (e.outcome.label().into(), true),
        KafkaDelivery(e) => (
            "delivery".into(),
            e.value.as_ref().is_none_or(|v| !v.truncated)
                && e.key.as_ref().is_none_or(|v| !v.truncated)
                && e.headers
                    .iter()
                    .all(|header| header.value.as_ref().is_none_or(|v| !v.truncated)),
        ),
        MotanExchange(e) => (
            e.outcome.label().into(),
            !e.request.truncated && !e.response.truncated,
        ),
        DependencyConnectFailure(_) => ("connect_failed".into(), true),
        UdpDatagram(e) => ("datagram".into(), !e.payload.truncated),
        ProxyError(_) => ("capture_failed".into(), false),
        _ => ("observation".into(), true),
    }
}

fn mysql_value_complete(value: &crate::recorder::MysqlValue) -> bool {
    value.raw.as_ref().is_none_or(|raw| !raw.truncated)
}

pub(super) fn is_debug(event: &RecorderEvent) -> bool {
    matches!(
        event,
        RecorderEvent::MysqlQuery(_)
            | RecorderEvent::MysqlResponse(_)
            | RecorderEvent::MysqlPacket(_)
    )
}
