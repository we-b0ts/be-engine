//! Route a notification through its actual, already accepted subscription.
use super::*;
use std::borrow::Cow;

pub(super) fn render<'a>(
    pubsub: &PubSubState,
    client: Uuid,
    slot: PushId,
    bytes: &'a [u8],
) -> Result<Cow<'a, [u8]>> {
    let (record, kind, subject) = match slot {
        PushId::Inline(index) => {
            let push = &pubsub.pushes[index];
            (&push.record, push.kind, push.subject.as_slice())
        }
        PushId::Indexed { lane, .. } => {
            let lane = &pubsub.indexed.lanes[lane];
            (&lane.record, lane.kind, lane.subject.as_slice())
        }
    };
    let subscription = pubsub
        .subscriptions
        .iter()
        .find(|subscription| {
            subscription.client == client
                && subscription.source_connection == record.connection_id
                && subscription.sequence == record.subscription_sequence
                && subscription.kind == kind
                && !subscription.sender.is_closed()
        })
        .context("notification subscription is unavailable")?;
    // Most subscriptions use a stable channel. Do not decode/copy those frames
    // or consult unrelated identity mappings, even for large payloads.
    if subject == subscription.subject {
        return Ok(Cow::Borrowed(bytes));
    }
    translate(bytes, kind, subject, &subscription.subject).map(Cow::Owned)
}

fn translate(
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
    Ok(crate::redis::encode_array(&[tag, target, &frame.payload]))
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
            let raw = crate::redis::encode_array(&[tag, b"source", payload]);
            assert_eq!(
                translate(&raw, kind, b"source", b"longer-target").unwrap(),
                crate::redis::encode_array(&[tag, b"longer-target", payload])
            );
            assert!(translate(&raw, kind, b"other-source", b"target").is_err());
            assert!(translate(&raw, RedisSubscriptionKind::Pattern, b"source", b"target").is_err());
        }
    }
}
