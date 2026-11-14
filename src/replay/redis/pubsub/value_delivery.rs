//! Ordinary Case notification values share declared JSON delivery contracts.
use super::*;
use crate::value_contract::{json::AnchorClocks, time::ClockPair};
use std::borrow::Cow;
pub(super) mod causality;

#[derive(Clone)]
pub(in crate::replay::redis) struct Prepared {
    decoded: crate::value_codec::DecodedValue,
    predecessors: Vec<causality::Predecessor>,
}

impl std::fmt::Debug for Prepared {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PreparedNotification")
            .field("predecessors", &self.predecessors.len())
            .finish_non_exhaustive()
    }
}

pub(super) fn prepare(replay: &mut ReplayState, delivery: &Delivery) -> Result<Option<Prepared>> {
    let original = &delivery.bytes;
    let Some(case) = delivery
        .case_id
        .as_deref()
        .filter(|_| delivery.matched.is_none())
    else {
        return Ok(None);
    };
    let PushId::Inline(index) = delivery.push else {
        return Ok(None);
    };
    let push = &replay.protocols.redis.pubsub.pushes[index];
    if push.source != ReplaySource::Case || push.case_id.as_deref() != Some(case) {
        return Ok(None);
    }
    let owner = &replay.protocols.redis.request_contracts;
    if owner
        .global_json()
        .is_none_or(|global| global.fields.is_empty())
    {
        return Ok(None);
    }
    let frame = parse_pubsub_push(original)?.context("notification frame is unavailable")?;
    let Ok(decoded) =
        crate::value_codec::CodecView::decode(&crate::policy::Codec::Json, &frame.payload)
    else {
        return Ok(None);
    };
    // Native Socket.IO owners already translate their own comparison copies,
    // RPC callbacks and self-echoes. Never reinterpret Target echo bytes as Source.
    // Ordinary documents are decoded once. Only a possible protocol envelope
    // needs the native adapter's complete shape and identity validation.
    let native = match decoded.logical["method"].as_str() {
        Some("emit") if decoded.logical["callback"].is_null() => {
            rpc::notification_namespace(&frame.channel, &frame.payload).is_some()
        }
        Some("emit") => rpc::notification_request(&frame.channel, &frame.payload).is_some(),
        Some("callback") => rpc::callback(&frame.payload).ok().flatten().is_some(),
        _ => false,
    };
    if native {
        return Ok(None);
    }
    let timestamp = push.record.timestamp;
    let predecessors = causality::predecessors(
        &mut replay.protocols.redis,
        case,
        timestamp,
        &decoded.logical,
    )?;
    Ok(Some(Prepared {
        decoded,
        predecessors,
    }))
}

pub(super) fn ready(replay: &ReplayState, delivery: &Delivery) -> Result<bool> {
    let Some(value) = &delivery.value else {
        return Ok(true);
    };
    let case = delivery
        .case_id
        .as_deref()
        .context("notification has no Case")?;
    value
        .predecessors
        .iter()
        .try_fold(true, |ready, predecessor| {
            Ok(predecessor.ready(&replay.protocols.redis, case)? && ready)
        })
}

pub(super) fn render<'a>(
    replay: &ReplayState,
    delivery: &'a mut Delivery,
) -> Result<Cow<'a, [u8]>> {
    let Some(prepared) = delivery.value.take() else {
        return Ok(Cow::Borrowed(&delivery.bytes));
    };
    let original = &delivery.bytes;
    let case = delivery
        .case_id
        .as_deref()
        .context("notification has no Case")?;
    let PushId::Inline(index) = delivery.push else {
        anyhow::bail!("ordinary notification has no inline Source");
    };
    let push = &replay.protocols.redis.pubsub.pushes[index];
    let owner = &replay.protocols.redis.request_contracts;
    let global = owner
        .global_json()
        .context("notification contract disappeared")?;
    let now = chrono::Utc::now();
    let requests = owner.request_times(case);
    let event = ClockPair {
        source: push.record.timestamp,
        target: Some(now),
    };
    let clocks = AnchorClocks {
        case: ClockPair {
            source: requests.source,
            target: requests.target,
        },
        dependency: event,
        delivery: event,
        observation: Some(event),
    };
    let value = crate::replay::contract_value::Delivery::prepare_decoded_global(
        prepared.decoded,
        global,
        clocks,
    )?;
    let (body, identities) = value.render_with_identities(now, owner, case)?;
    // Match ordinary recorded-read semantics: known IDs use their committed
    // counterpart; unknown selected inputs acquire an exact Source anchor.
    owner.commit_identity(identities)?;
    let frame = parse_pubsub_push(original)?.context("notification frame is unavailable")?;
    if body == frame.payload {
        Ok(Cow::Borrowed(original))
    } else {
        replace_payload(original, &frame.payload, &body).map(Cow::Owned)
    }
}

fn replace_payload(original: &[u8], source: &[u8], target: &[u8]) -> Result<Vec<u8>> {
    if source == target {
        return Ok(original.to_vec());
    }
    let payload_start = original
        .len()
        .checked_sub(source.len() + 2)
        .context("notification payload range is invalid")?;
    ensure!(
        original.ends_with(b"\r\n")
            && original.get(payload_start..original.len() - 2) == Some(source),
        "notification payload is not its final bulk value"
    );
    let header_start = original[..payload_start.saturating_sub(2)]
        .iter()
        .rposition(|byte| *byte == b'\n')
        .map(|position| position + 1)
        .context("notification payload header is unavailable")?;
    ensure!(
        original[header_start] == b'$',
        "notification payload requires a bulk header"
    );
    let mut result = original[..header_start].to_vec();
    result.extend_from_slice(format!("${}\r\n", target.len()).as_bytes());
    result.extend_from_slice(target);
    result.extend_from_slice(b"\r\n");
    Ok(result)
}
