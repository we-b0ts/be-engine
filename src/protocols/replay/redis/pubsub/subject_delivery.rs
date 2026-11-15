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
    traffic_protocol_redis::subject::translate(bytes, kind, subject, &subscription.subject)
        .map(Cow::Owned)
}
