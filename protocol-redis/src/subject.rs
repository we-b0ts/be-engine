//! Validate and translate native Pub/Sub subjects without changing payload bytes.
use crate::{RedisSubscriptionKind, pubsub::frame};
use anyhow::{Context, Result, ensure};
use bytes::Bytes;

pub fn translate(
    bytes: &[u8],
    kind: RedisSubscriptionKind,
    source: &[u8],
    target: &[u8],
) -> Result<Vec<u8>> {
    let tag = translated_tag(kind)?;
    let frame = frame::decode(&Bytes::copy_from_slice(bytes))?
        .context("notification frame is unavailable")?;
    ensure!(
        frame.kind == kind && frame.subject.as_ref() == source,
        "notification subject differs from its Source subscription"
    );
    Ok(crate::encode_array(&[tag, target, &frame.payload]))
}

pub(crate) fn translate_frame(frame: &frame::Push, target: &[u8]) -> Result<Vec<u8>> {
    let tag = translated_tag(frame.kind)?;
    Ok(crate::encode_array(&[tag, target, &frame.payload]))
}

fn translated_tag(kind: RedisSubscriptionKind) -> Result<&'static [u8]> {
    // Generated key contracts currently select SUBSCRIBE, not patterns. A
    // changed pattern does not prove the concrete publication channel changed.
    match kind {
        RedisSubscriptionKind::Channel => Ok(b"message"),
        RedisSubscriptionKind::ShardChannel => Ok(b"smessage"),
        RedisSubscriptionKind::Pattern => {
            anyhow::bail!("generated pattern subscriptions require a concrete channel contract")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn translation_preserves_binary_payload_and_requires_the_exact_native_subject() {
        let payload = b"\0source\r\n\xff";
        for (kind, tag) in [
            (RedisSubscriptionKind::Channel, b"message".as_slice()),
            (RedisSubscriptionKind::ShardChannel, b"smessage".as_slice()),
        ] {
            let raw = crate::encode_array(&[tag, b"source", payload]);
            assert_eq!(
                translate(&raw, kind, b"source", b"longer-target").unwrap(),
                crate::encode_array(&[tag, b"longer-target", payload])
            );
            assert!(translate(&raw, kind, b"other-source", b"target").is_err());
            assert!(translate(&raw, RedisSubscriptionKind::Pattern, b"source", b"target").is_err());
        }
    }
}
