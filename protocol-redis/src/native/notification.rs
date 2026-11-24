//! Confirmed RESP2 pushes share the host's evidence and value delivery path.
use std::{collections::BTreeMap, sync::Arc, time::Duration};

use anyhow::{Context, Result, ensure};
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use traffic_model::recording::ProtocolRef;
use traffic_protocol::{
    capture::{CaptureEvidence, CaptureFacts, RecordingLayout, RecordingScalar},
    connection::{Endpoint, RecordedExchange, RecordedInput},
    message::{MessageEncoder, ProjectedMessage, ProjectedValue, ProtocolMessage},
};
use uuid::Uuid;

use crate::{RedisSubscriptionKind, events::RedisPubSubPushEvent, pubsub::frame};

#[derive(Serialize)]
pub(super) struct CapturedPush {
    pub id: Uuid,
    pub notification_kind: &'static str,
    #[serde(flatten)]
    pub event: RedisPubSubPushEvent,
}

impl CaptureEvidence for CapturedPush {
    fn event_type(&self) -> &'static str {
        "redis_pub_sub_push"
    }

    fn capture_facts(&self) -> CaptureFacts {
        CaptureFacts::dependency(
            anchored_reference(
                self.id,
                self.event.connection_id,
                self.event.subscription_sequence,
            ),
            "delivery",
            self.event.replay_safe && !self.event.response.truncated,
        )
        .with_recording_layout(RecordingLayout {
            protocol: "redis",
            variant: "push",
            event_type: self.event_type(),
            fields: &[
                ("subscription_sequence", RecordingScalar::Integer),
                ("source_after_id", RecordingScalar::Integer),
                ("database", RecordingScalar::Integer),
                ("username", RecordingScalar::Text),
                ("notification_kind", RecordingScalar::Text),
            ],
            request_fields: &[],
            response_fields: &["response"],
            use_dependency_id: true,
        })
    }
}

pub(super) fn recorded(event: &Value) -> Result<RecordedExchange> {
    let capture = crate::recorded::RecordedCapture::deserialize(&event["response"])?;
    describe(
        event,
        Arc::new(NotificationMessage::decode(capture.decode()?.into())?),
    )
}

#[derive(Deserialize)]
struct PushHeader {
    replay_safe: bool,
    database: i64,
    connection_id: Uuid,
    subscription_sequence: u64,
    target_host: String,
    target_port: u16,
    duration_ms: u64,
}

pub(super) fn describe(
    event: &Value,
    response: Arc<dyn MessageEncoder>,
) -> Result<RecordedExchange> {
    ensure!(
        event["rpc_request"].is_null(),
        "correlated Redis RPC notifications require an RPC capability"
    );
    let push = PushHeader::deserialize(event)?;
    ensure!(
        push.replay_safe && push.subscription_sequence > 0 && push.database >= 0,
        "Redis notification has unsafe session evidence"
    );
    let after = ProtocolRef::connection("redis", push.connection_id, push.subscription_sequence);
    let reference = reference(event)?;
    ensure!(
        anchor(&reference)?.is_none_or(|reference| reference == after),
        "Redis notification changed its Source anchor"
    );
    Ok(RecordedExchange {
        reference,
        endpoint: Endpoint {
            host: traffic_protocol::observation::normalize_host(&push.target_host),
            port: push.target_port,
        },
        lane: None,
        response_delay: Duration::ZERO,
        input: RecordedInput::Emission {
            after,
            offset: Duration::from_millis(push.duration_ms),
        },
        response,
    })
}

pub(crate) fn reference(event: &Value) -> Result<ProtocolRef> {
    if let Some(value) = event["capture"].get("protocol_ref") {
        let reference: ProtocolRef = serde_json::from_value(value.clone())?;
        ensure!(
            reference.protocol() == "redis",
            "Redis notification has a foreign capture reference"
        );
        if let Some(id) = event["id"].as_str() {
            ensure!(
                reference
                    .fields()
                    .get("exchange_id")
                    .and_then(Value::as_str)
                    == Some(id),
                "Redis notification has inconsistent capture references"
            );
        }
        return Ok(reference);
    }
    if let Some(id) = event["id"].as_str() {
        let (connection, sequence) = subscription_identity(event)?;
        return Ok(anchored_reference(id.parse()?, connection, sequence));
    }
    // Older flat events have no event UUID. Retain their immutable native identity.
    ProtocolRef::new(
        "redis",
        json!({"notification":{
            "connection_id":event["connection_id"], "subscription_sequence":event["subscription_sequence"],
            "timestamp":event["timestamp"], "duration_ms":event["duration_ms"]
        }}),
    )
}

fn anchored_reference(id: Uuid, connection: Uuid, sequence: u64) -> ProtocolRef {
    ProtocolRef::new(
        "redis",
        json!({
            "exchange_id":id,
            "after":ProtocolRef::connection("redis", connection, sequence)
        }),
    )
    .expect("Redis notification identity")
}

pub(super) fn anchor(reference: &ProtocolRef) -> Result<Option<ProtocolRef>> {
    if let Some(after) = reference.fields().get("after") {
        return Ok(Some(serde_json::from_value(after.clone())?));
    }
    let Some(legacy) = reference.fields().get("notification") else {
        return Ok(None);
    };
    let (connection, sequence) = subscription_identity(legacy)?;
    Ok(Some(ProtocolRef::connection("redis", connection, sequence)))
}

fn subscription_identity(event: &Value) -> Result<(Uuid, u64)> {
    let connection = serde_json::from_value(event["connection_id"].clone())?;
    let sequence = event["subscription_sequence"]
        .as_u64()
        .context("Redis notification sequence is absent")?;
    Ok((connection, sequence))
}

pub(super) struct NotificationMessage {
    original: Bytes,
    push: frame::Push,
}

pub(super) fn kind_name(kind: RedisSubscriptionKind) -> &'static str {
    match kind {
        RedisSubscriptionKind::Channel => "message",
        RedisSubscriptionKind::Pattern => "pmessage",
        RedisSubscriptionKind::ShardChannel => "smessage",
    }
}

impl NotificationMessage {
    pub(super) fn decode(original: Bytes) -> Result<Self> {
        let push = frame::decode(&original)?.context("Redis notification has no push frame")?;
        Ok(Self { original, push })
    }

    fn encode_packet(&self, values: &BTreeMap<String, Bytes>) -> Result<(Bytes, usize)> {
        ensure!(
            values.len() == 1,
            "Redis notification value inventory changed"
        );
        let payload = values
            .get("/payload")
            .context("Redis notification payload is absent")?;
        if *payload == self.push.payload {
            return Ok((self.original.clone(), 0));
        }
        let subject = self.push.subject.as_ref();
        let parts: &[&[u8]] = match self.push.kind {
            RedisSubscriptionKind::Channel => &[b"message", subject, payload],
            RedisSubscriptionKind::Pattern => &[b"pmessage", subject, &self.push.channel, payload],
            RedisSubscriptionKind::ShardChannel => &[b"smessage", subject, payload],
        };
        let packet = crate::encode_array(parts);
        // Converting the Vec to Bytes retains its capacity and may allocate a
        // shared owner in addition to the packet buffer.
        let retained = packet
            .capacity()
            .saturating_add(std::mem::size_of::<Bytes>());
        Ok((packet.into(), retained))
    }
}

impl ProtocolMessage for NotificationMessage {
    fn project(&self) -> Result<ProjectedMessage> {
        let kind = kind_name(self.push.kind);
        Ok(ProjectedMessage {
            structure: json!({"kind":kind}),
            values: BTreeMap::from([(
                "/payload".into(),
                ProjectedValue::bytes(self.push.payload.clone()),
            )]),
        })
    }

    fn locate(&self, selector: &Value) -> Result<Vec<String>> {
        ensure!(
            selector == &json!({"kind":"value"}),
            "unsupported Redis notification selector"
        );
        Ok(vec!["/payload".into()])
    }

    fn evidence(&self, selector: &Value) -> Result<Value> {
        self.locate(selector)?;
        let capture = traffic_model::capture::capture_body(&self.push.payload, usize::MAX);
        Ok(json!({"values":[{"location":"/payload","capture":capture}]}))
    }
}

impl MessageEncoder for NotificationMessage {
    fn prefetch_retained_bytes(&self) -> Option<usize> {
        // All push fields are slices of the same original frame allocation.
        Some(std::mem::size_of::<Self>() + self.original.len())
    }

    fn prefetch_packet(&self, values: &BTreeMap<String, Bytes>) -> Result<Option<(Bytes, usize)>> {
        self.encode_packet(values).map(Some)
    }

    fn encode(&self, values: &BTreeMap<String, Bytes>) -> Result<Bytes> {
        self.encode_packet(values).map(|(bytes, _)| bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn projected_payload_and_unchanged_output_share_the_original_frame() {
        let raw = Bytes::from(crate::encode_array(&[b"message", b"events", b"a\0b"]));
        let message = NotificationMessage::decode(raw.clone()).unwrap();
        let projected = message.project().unwrap();
        let payload = &projected.values["/payload"].bytes;
        assert_eq!(payload.as_ref(), b"a\0b");
        assert_eq!(payload.as_ptr(), raw[raw.len() - 5..].as_ptr());
        let values = BTreeMap::from([("/payload".into(), payload.clone())]);
        let output = message.encode(&values).unwrap();
        assert_eq!(output.as_ptr(), raw.as_ptr());
        let (prefetched, retained) = message.prefetch_packet(&values).unwrap().unwrap();
        assert_eq!(prefetched.as_ptr(), raw.as_ptr());
        assert_eq!(retained, 0);
        assert_eq!(
            message.prefetch_retained_bytes(),
            Some(std::mem::size_of_val(&message) + raw.len())
        );

        let values = BTreeMap::from([("/payload".into(), Bytes::from_static(b"translated"))]);
        let (prefetched, retained) = message.prefetch_packet(&values).unwrap().unwrap();
        assert_eq!(prefetched, message.encode(&values).unwrap());
        assert!(retained >= prefetched.len());
    }
}
