//! Decode the SSE envelope and its JSON data separately, preserving all framing.
use super::*;
use crate::interaction::stream::SseEvent;
use crate::policy::Slot;

pub(crate) fn decode_sse(message: &WireMessage) -> Result<SseEvent> {
    ensure!(
        message.kind == MessageKind::Text,
        "SSE message requires text evidence"
    );
    let value = crate::json_value::parse(message.data.as_bytes())
        .ok_or_else(|| anyhow::anyhow!("SSE envelope requires complete unique-member JSON"))?;
    serde_json::from_value(value).map_err(|_| anyhow::anyhow!("SSE envelope has an invalid shape"))
}

pub(super) fn compare_message(
    source: &WireMessage,
    target: &WireMessage,
    rules: &[&CompiledRule],
    times: super::super::RequestTimes,
    pointer: &str,
) -> Comparison {
    let mut result = Comparison::default();
    let Ok(source_event) = decode_sse(source) else {
        mismatch(&mut result, pointer);
        return result;
    };
    let selected = rules.iter().copied().filter(|rule| {
        matches!(&rule.rule.slot, Slot::SseData(event) if event == source_event.event.as_deref().unwrap_or("message"))
    }).collect::<Vec<_>>();
    if selected.is_empty() {
        if source != target {
            mismatch(&mut result, pointer);
        }
        return result;
    }
    let Ok(target_event) = decode_sse(target) else {
        mismatch(&mut result, pointer);
        return result;
    };
    for (field, equal) in [
        ("event", source_event.event == target_event.event),
        ("id", source_event.id == target_event.id),
        ("retry", source_event.retry == target_event.retry),
    ] {
        if !equal {
            mismatch(&mut result, &format!("{pointer}/sse/{field}"));
        }
    }
    let checked = (|| -> Result<Comparison> {
        let codec = crate::value_codec::CodecPlan::compile(&crate::policy::Codec::Json)?;
        let source = codec.decode(source_event.data.as_bytes())?;
        let target = codec.decode(target_event.data.as_bytes())?;
        ensure!(
            selected.iter().all(|r| r
                .rule
                .contract
                .keys()
                .all(|p| crate::value_contract::json::pointer_observed(&source.logical, p))),
            "SSE Source selected field is absent"
        );
        crate::value_contract::encoded::compare_decoded(
            &source,
            &target,
            &selected,
            crate::value_contract::json::AnchorClocks {
                case: times,
                dependency: times,
                ..Default::default()
            },
        )
    })();
    match checked {
        Ok(mut checked) => {
            for diff in &mut checked.differences {
                diff.pointer = format!("{pointer}/sse/data{}", diff.pointer);
            }
            result.merge_and_validate(checked);
        }
        Err(_) => result.differences.push(Difference {
            pointer: format!("{pointer}/sse/data"),
            reason: "SSE data contract requires complete unique-member JSON and all selected Source fields".into(),
        }),
    }
    result
}
