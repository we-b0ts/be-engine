//! Decoded RESP2 push fields share the original frame's storage.
use anyhow::{Context, Result, ensure};
use bytes::Bytes;
use redis_protocol::resp2::{decode::decode_bytes, types::BytesFrame};

use crate::RedisSubscriptionKind;

pub(crate) struct Push {
    pub kind: RedisSubscriptionKind,
    pub subject: Bytes,
    pub channel: Bytes,
    pub payload: Bytes,
}

pub(crate) fn decode(raw: &Bytes) -> Result<Option<Push>> {
    let (frame, consumed) = decode_bytes(raw)?.context("incomplete Redis Pub/Sub push")?;
    ensure!(
        consumed == raw.len(),
        "Redis Pub/Sub push contains trailing bytes"
    );
    let BytesFrame::Array(values) = frame else {
        return Ok(None);
    };
    let mut values = values.into_iter();
    let Some(tag) = values.next().and_then(string) else {
        return Ok(None);
    };
    let (kind, expected_len) = if tag.eq_ignore_ascii_case(b"message") {
        (RedisSubscriptionKind::Channel, 3)
    } else if tag.eq_ignore_ascii_case(b"pmessage") {
        (RedisSubscriptionKind::Pattern, 4)
    } else if tag.eq_ignore_ascii_case(b"smessage") {
        (RedisSubscriptionKind::ShardChannel, 3)
    } else {
        return Ok(None);
    };
    ensure!(
        values.len() + 1 == expected_len,
        "Redis Pub/Sub push must contain {expected_len} elements"
    );
    let subject = values
        .next()
        .and_then(string)
        .context("Redis Pub/Sub push subscription subject must be a string")?;
    let channel = if kind == RedisSubscriptionKind::Pattern {
        values.next().and_then(string)
    } else {
        Some(subject.clone())
    };
    let (Some(channel), Some(payload)) = (channel, values.next().and_then(string)) else {
        anyhow::bail!("Redis Pub/Sub push channel and payload must be strings");
    };
    Ok(Some(Push {
        kind,
        subject,
        channel,
        payload,
    }))
}

fn string(value: BytesFrame) -> Option<Bytes> {
    match value {
        BytesFrame::BulkString(value) | BytesFrame::SimpleString(value) => Some(value),
        _ => None,
    }
}
