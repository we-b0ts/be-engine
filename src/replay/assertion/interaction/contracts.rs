//! Decode the SSE envelope and its JSON data separately, preserving all framing.
use super::*;
use crate::interaction::stream::SseEvent;

#[cfg(test)]
mod global_tests;

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
    global: Option<&crate::policy::CompiledJsonPolicy>,
    times: super::super::RequestTimes,
    pointer: &str,
) -> Comparison {
    let mut result = Comparison::default();
    let Ok(source_event) = decode_sse(source) else {
        mismatch(&mut result, pointer);
        return result;
    };
    if global.is_none() {
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
    let checked = crate::value_contract::global::compare(
        source_event.data.as_bytes(),
        target_event.data.as_bytes(),
        global.expect("global JSON field strategy checked"),
        &[],
        crate::value_contract::json::AnchorClocks {
            case: times,
            dependency: times,
            ..Default::default()
        },
    );
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
