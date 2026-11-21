//! RESP notification lanes and adapter metadata stay with the native owner.
use anyhow::Result;
use serde_json::{Value, json};
use traffic_protocol::evidence::index::{IndexProjection, StreamProjection, erase_capture};

pub(super) fn project(event: &Value) -> Result<IndexProjection> {
    let mut projection = IndexProjection::record(event.clone());
    if event["event_type"] == "redis_pub_sub_push" {
        projection.stream = notification(event)?;
        erase_capture(&mut projection.record["response"]);
        if projection.stream.is_some() {
            projection.record["duration_ms"] = 0.into();
        }
    } else if event["event_type"] == "redis_exchange"
        && !crate::is_pubsub_command(event["command"].as_str().unwrap_or_default())
    {
        erase_capture(&mut projection.record["response"]);
    }
    if let Some(endpoint) = crate::index::endpoint(event) {
        projection.endpoints.push(endpoint);
    }
    if event["event_type"] == "redis_connection" {
        projection.observations.push(event.clone());
    }
    Ok(projection)
}

fn notification(event: &Value) -> Result<Option<StreamProjection>> {
    if !event["rpc_request"].is_null()
        || event["replay_safe"] != true
        || event["response"]["truncated"] == true
    {
        return Ok(None);
    }
    let (Some(connection), Some(sequence), Some(duration_ms)) = (
        event["connection_id"].as_str(),
        event["subscription_sequence"].as_u64(),
        event["duration_ms"].as_u64(),
    ) else {
        return Ok(None);
    };
    if sequence == 0 {
        return Ok(None);
    }
    let capture: crate::recorded::RecordedCapture =
        match serde_json::from_value(event["response"].clone()) {
            Ok(capture) => capture,
            Err(_) => return Ok(None),
        };
    let raw = match capture.decode() {
        Ok(raw) if raw.len() <= 64 * 1024 * 1024 => raw,
        _ => return Ok(None),
    };
    let frame = match crate::parse_pubsub_push(&raw) {
        Ok(Some(frame)) => frame,
        _ => return Ok(None),
    };
    let kind = match frame.subscription_kind {
        crate::RedisSubscriptionKind::Channel => "channel",
        crate::RedisSubscriptionKind::Pattern => "pattern",
        crate::RedisSubscriptionKind::ShardChannel => "shard_channel",
    };
    Ok(Some(StreamProjection {
        identity: json!({"connection":connection,"sequence":sequence,"kind":kind,"subject":frame.subject,
            "host":event["target_host"],"port":event["target_port"],"database":event["database"],"username":event["username"]}),
        duration_ms,
        timestamp: event
            .get("timestamp")
            .cloned()
            .map(serde_json::from_value)
            .transpose()?
            .flatten(),
        metadata: json!({
            "adapter_echo":crate::socketio_rpc::echo_digest(&frame.channel, &frame.payload),
            "adapter_namespace":crate::socketio_rpc::notification_namespace(&frame.channel, &frame.payload),
            "adapter_request":crate::socketio_rpc::notification_request(&frame.channel, &frame.payload).map(|identity| (frame.channel, identity))
        }),
    }))
}

pub(super) fn proof(event: &Value) -> Value {
    traffic_protocol::evidence::index::select_without(event, &["response", "raw"], &["args"])
}
pub(super) fn complete(event: &Value) -> bool {
    event["replay_safe"] != false && event["response"]["truncated"] != true
}
