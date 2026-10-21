//! Bounded private SSE decoding supplies drafts, never inferred identity permission.
use super::*;
use crate::interaction::model::Protocol as InteractionProtocol;

pub(super) fn observe(
    drafts: &mut Drafts,
    pair: &crate::replay::ResponsePayloadPair,
    api: &str,
    witness: &str,
    schemas: Option<&CompiledPolicy>,
) -> Result<()> {
    let Some(source) = pair
        .source_interaction
        .as_ref()
        .filter(|s| s.protocol == InteractionProtocol::Sse)
    else {
        return Ok(());
    };
    let targets = pair
        .target_interaction
        .as_ref()
        .filter(|s| s.protocol == InteractionProtocol::Sse)
        .map(|s| s.events.iter().filter(|e| !e.heartbeat).collect::<Vec<_>>())
        .unwrap_or_default();
    for (index, source) in source.events.iter().filter(|e| !e.heartbeat).enumerate() {
        if drafts.observations >= OBSERVATION_LIMIT {
            drafts.limited = true;
            break;
        }
        drafts.observations += 1;
        let Ok(source) = crate::replay::decode_sse(&source.message) else {
            continue;
        };
        if crate::json_value::parse(source.data.as_bytes()).is_none() {
            continue;
        }
        let target = targets
            .get(index)
            .and_then(|e| crate::replay::decode_sse(&e.message).ok())
            .filter(|e| e.event == source.event);
        let base = json!({"surface":"api.response","match":{"api":api},
            "slot":{"sse_data":source.event.as_deref().unwrap_or("message")}});
        drafts.observe(
            source.data.as_bytes(),
            target.as_ref().map(|e| e.data.as_bytes()),
            base,
            &format!("{witness}:sse:{index}"),
            AnchorClocks {
                case: pair.times,
                dependency: pair.times,
                ..Default::default()
            },
            schemas,
        )?;
    }
    Ok(())
}
