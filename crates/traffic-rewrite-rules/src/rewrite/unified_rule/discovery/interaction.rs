//! Bounded private SSE decoding supplies drafts, never inferred identity permission.
use super::*;
use crate::interaction::model::Protocol as InteractionProtocol;

pub(super) fn observe(
    drafts: &mut Drafts,
    pair: &crate::primary_protocol::assertion::ResponsePayloadPair,
    api: &str,
    witness: &str,
    schemas: Option<&CompiledPolicy>,
    offset: usize,
) -> Result<Option<usize>> {
    let Some(source) = pair
        .source_interaction
        .as_ref()
        .filter(|s| s.protocol == InteractionProtocol::Sse)
    else {
        return Ok(None);
    };
    let targets = pair
        .target_interaction
        .as_ref()
        .filter(|s| s.protocol == InteractionProtocol::Sse)
        .map(|s| s.events.iter().filter(|e| !e.heartbeat).collect::<Vec<_>>())
        .unwrap_or_default();
    for (index, source) in source
        .events
        .iter()
        .filter(|e| !e.heartbeat)
        .enumerate()
        .skip(offset)
    {
        if drafts.observations >= OBSERVATION_LIMIT {
            drafts.limited = true;
            return Ok(Some(index));
        }
        drafts.observations += 1;
        let event_times = crate::value_contract::time::ClockPair {
            source: event_clock(pair.interaction_times.source, source.offset_ms),
            target: targets
                .get(index)
                .and_then(|event| event_clock(pair.interaction_times.target, event.offset_ms)),
        };
        let Ok(source) = crate::primary_protocol::assertion::decode_sse(&source.message) else {
            continue;
        };
        let Some(source_json) = crate::json_value::parse(source.data.as_bytes()) else {
            continue;
        };
        let target = targets
            .get(index)
            .and_then(|e| crate::primary_protocol::assertion::decode_sse(&e.message).ok())
            .filter(|e| e.event == source.event);
        let event = source.event.as_deref().unwrap_or("message");
        let selector = source_json
            .get("type")
            .and_then(Value::as_str)
            .filter(|t| {
                !t.is_empty()
                    && t.len() <= 256
                    && !t.contains('*')
                    && !t.chars().any(char::is_control)
            })
            .map_or_else(|| json!(event), |t| json!({"event":event,"json_type":t}));
        let base = json!({"surface":"api.response","match":{"api":api},
            "slot":{"sse_data":selector}});
        drafts.observe(
            source.data.as_bytes(),
            target.as_ref().map(|e| e.data.as_bytes()),
            base,
            &format!("{witness}:sse:{index}"),
            AnchorClocks::for_response(pair.request_times, event_times),
            schemas,
            None,
        )?;
    }
    Ok(None)
}

fn event_clock(
    started: Option<chrono::DateTime<chrono::Utc>>,
    offset_ms: u64,
) -> Option<chrono::DateTime<chrono::Utc>> {
    started?.checked_add_signed(chrono::TimeDelta::try_milliseconds(
        i64::try_from(offset_ms).ok()?,
    )?)
}
