//! Bound delivery gaps using only original Socket.IO ACK identities and clocks.
use super::*;

pub(super) fn fences(
    input: &InputTranscript,
    tracked: &TrackedInputs,
    response_path: &Path,
    end_ms: u64,
) -> Result<Vec<Fence>> {
    let checkpoints = if tracked.unacknowledged.first().is_some_and(|(first, _)| {
        tracked
            .ack_ids
            .values()
            .any(|(sequence, _)| sequence > first)
    }) {
        source_acks(input, tracked, response_path, end_ms)?
    } else {
        BTreeMap::new()
    };
    let mut fences: Vec<_> = tracked
        .unacknowledged
        .iter()
        .map(|&(sequence, from_ms)| Fence {
            from_ms,
            resume_after_ms: checkpoints
                .range((
                    std::ops::Bound::Excluded(sequence),
                    std::ops::Bound::Unbounded,
                ))
                .filter_map(|(_, &at)| at)
                .min(),
        })
        .collect();
    if let Some(from_ms) = tracked.close_ms {
        fences.push(Fence {
            from_ms,
            resume_after_ms: None,
        });
    }
    Ok(fences)
}

fn source_acks(
    input: &InputTranscript,
    tracked: &TrackedInputs,
    path: &Path,
    end_ms: u64,
) -> Result<BTreeMap<u64, Option<u64>>> {
    let Some(mut response) = read::<Value>(path)? else {
        return Ok(BTreeMap::new());
    };
    crate::interaction::private::decrypt_output(&mut response, path)
        .context("native notification ACK checkpoint could not be authenticated")?;
    let Some(events) = response
        .pointer("/interaction/events")
        .and_then(Value::as_array)
    else {
        return Ok(BTreeMap::new());
    };
    let namespaces = namespaces(input);
    let mut checkpoints = BTreeMap::new();
    for event in events {
        let message = &event["message"];
        let Some(data) = message["data"]
            .as_str()
            .filter(|data| message["kind"] == "text" && data.starts_with("43"))
        else {
            continue;
        };
        let Ok(EngineIoPacket::Message(packet)) =
            decode_engine_io_text(data, input.policy.max_message_bytes)
        else {
            continue;
        };
        if packet.kind != SocketIoKind::Ack || !namespaces.contains(&packet.namespace) {
            continue;
        }
        let Some(&(sequence, sent)) = packet.id.and_then(|id| tracked.ack_ids.get(&id)) else {
            continue;
        };
        let at = event["offset_ms"]
            .as_u64()
            .filter(|&at| sent <= at && at < end_ms);
        // Repeated IDs or invalid clocks cannot certify a new delivery interval.
        checkpoints
            .entry(sequence)
            .and_modify(|known| *known = None)
            .or_insert(at);
    }
    Ok(checkpoints)
}
