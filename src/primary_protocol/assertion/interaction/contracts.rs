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
    clocks: crate::value_contract::json::AnchorClocks,
    pointer: &str,
    copies: &crate::value_contract::time_copies::DeliveredTimeCopies,
    observed: super::super::RequestTimes,
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
    let checked = compare_data(
        source_event.data.as_bytes(),
        target_event.data.as_bytes(),
        global.expect("global JSON field strategy checked"),
        &[],
        clocks,
        copies,
        observed,
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

fn compare_data(
    source: &[u8],
    target: &[u8],
    plan: &crate::policy::CompiledJsonPolicy,
    rules: &[&crate::policy::CompiledRule],
    clocks: crate::value_contract::json::AnchorClocks,
    copies: &crate::value_contract::time_copies::DeliveredTimeCopies,
    observed: super::super::RequestTimes,
) -> Result<Comparison> {
    use crate::value_codec::CodecView;
    if crate::json_value::parse(source).is_none() {
        return crate::value_contract::global::compare(source, target, plan, rules, clocks);
    }
    let source = CodecView::decode(&crate::policy::Codec::Json, source)?;
    let target = CodecView::decode(&crate::policy::Codec::Json, target)?;
    let proofs = copies.proofs(&source.logical, plan, clocks, observed)?;
    crate::value_contract::global::compare_decoded_with_time_copies(
        &source, &target, plan, rules, clocks, &proofs,
    )
}
