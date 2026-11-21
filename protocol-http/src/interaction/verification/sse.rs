//! Decode the SSE envelope and its JSON data separately, preserving all framing.
use super::*;
use crate::interaction::stream::SseEvent;

pub fn decode_sse(message: &WireMessage) -> Result<SseEvent> {
    ensure!(
        message.kind == MessageKind::Text,
        "SSE message requires text evidence"
    );
    let value = traffic_codec_json::parse(message.data.as_bytes())
        .ok_or_else(|| anyhow::anyhow!("SSE envelope requires complete unique-member JSON"))?;
    serde_json::from_value(value).map_err(|_| anyhow::anyhow!("SSE envelope has an invalid shape"))
}

pub fn compare_message(
    source: &WireMessage,
    target: &WireMessage,
    values: Option<&dyn ValueComparator>,
    clocks: AnchorClocks,
    pointer: &str,
) -> Comparison {
    let mut result = Comparison::default();
    let Ok(source_event) = decode_sse(source) else {
        mismatch(&mut result, pointer);
        return result;
    };
    if values.is_none() {
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
    let checked = values.expect("selected value comparator").compare_sse_data(
        source_event.data.as_bytes(),
        target_event.data.as_bytes(),
        clocks,
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
