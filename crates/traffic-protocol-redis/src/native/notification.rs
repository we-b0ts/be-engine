//! Confirmed RESP2 pushes share the host's evidence and value delivery path.
use std::{collections::BTreeMap, sync::Arc, time::Duration};

use anyhow::{Context, Result, ensure};
use bytes::Bytes;
use serde::Serialize;
use serde_json::{Value, json};
use traffic_model::recording::ProtocolRef;
use traffic_protocol::{
    capture::{CaptureEvidence, CaptureFacts, RecordingLayout, RecordingScalar},
    connection::{Endpoint, RecordedExchange, RecordedInput},
    message::{MessageEncoder, ProjectedMessage, ProjectedValue, ProtocolMessage},
};
use uuid::Uuid;

use crate::{
    RedisPubSubPush, RedisSubscriptionKind, events::RedisPubSubPushEvent, recorded::RecordedPush,
};

#[derive(Serialize)]
pub(super) struct CapturedPush {
    pub id: Uuid,
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
            ],
            request_fields: &[],
            response_fields: &["response"],
            use_dependency_id: true,
        })
    }
}

pub(super) fn recorded(event: &Value) -> Result<RecordedExchange> {
    ensure!(
        event["rpc_request"].is_null(),
        "correlated Redis RPC notifications require an RPC capability"
    );
    let push: RecordedPush = serde_json::from_value(event.clone())?;
    ensure!(
        push.replay_safe && push.subscription_sequence > 0 && push.database >= 0,
        "Redis notification has unsafe session evidence"
    );
    let response = NotificationMessage::decode(push.response.decode()?.into())?;
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
        response: Arc::new(response),
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
    push: RedisPubSubPush,
}

impl NotificationMessage {
    pub(super) fn decode(original: Bytes) -> Result<Self> {
        let push =
            crate::parse_pubsub_push(&original)?.context("Redis notification has no push frame")?;
        Ok(Self { original, push })
    }
}

impl ProtocolMessage for NotificationMessage {
    fn project(&self) -> Result<ProjectedMessage> {
        let kind = match self.push.subscription_kind {
            RedisSubscriptionKind::Channel => "message",
            RedisSubscriptionKind::Pattern => "pmessage",
            RedisSubscriptionKind::ShardChannel => "smessage",
        };
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
    fn encode(&self, values: &BTreeMap<String, Bytes>) -> Result<Bytes> {
        ensure!(
            values.len() == 1,
            "Redis notification value inventory changed"
        );
        let payload = values
            .get("/payload")
            .context("Redis notification payload is absent")?;
        if payload.as_ref() == self.push.payload {
            return Ok(self.original.clone());
        }
        let subject = self.push.subject.as_slice();
        let parts: &[&[u8]] = match self.push.subscription_kind {
            RedisSubscriptionKind::Channel => &[b"message", subject, payload],
            RedisSubscriptionKind::Pattern => &[b"pmessage", subject, &self.push.channel, payload],
            RedisSubscriptionKind::ShardChannel => &[b"smessage", subject, payload],
        };
        Ok(crate::encode_array(parts).into())
    }
}
