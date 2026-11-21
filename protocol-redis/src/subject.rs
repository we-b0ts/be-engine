//! Validate and translate native Pub/Sub subjects without changing payload bytes.
use crate::{RedisSubscriptionKind, parse_pubsub_push};
use anyhow::{Context, Result, ensure};

pub fn translate(
    bytes: &[u8],
    kind: RedisSubscriptionKind,
    source: &[u8],
    target: &[u8],
) -> Result<Vec<u8>> {
    // Generated key contracts currently select SUBSCRIBE, not patterns. A
    // changed pattern does not prove the concrete publication channel changed.
    let tag: &[u8] = match kind {
        RedisSubscriptionKind::Channel => b"message",
        RedisSubscriptionKind::ShardChannel => b"smessage",
        RedisSubscriptionKind::Pattern => {
            anyhow::bail!("generated pattern subscriptions require a concrete channel contract")
        }
    };
    let frame = parse_pubsub_push(bytes)?.context("notification frame is unavailable")?;
    ensure!(
        frame.subscription_kind == kind && frame.subject == source,
        "notification subject differs from its Source subscription"
    );
    Ok(crate::encode_array(&[tag, target, &frame.payload]))
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
