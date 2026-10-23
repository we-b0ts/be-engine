//! Decode the SSE envelope and its JSON data separately, preserving all framing.
use super::*;
use crate::interaction::stream::SseEvent;
use crate::policy::Slot;

#[cfg(test)]
mod clock_scope_tests;
#[cfg(test)]
mod tests;

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
    let source_json = crate::json_value::parse(source_event.data.as_bytes());
    let selected = rules
        .iter()
        .copied()
        .filter(|rule| {
            let Slot::SseData(selector) = &rule.rule.slot else {
                return false;
            };
            selector.event() == source_event.event.as_deref().unwrap_or("message")
                && selector.json_type().is_none_or(|expected| {
                    source_json
                        .as_ref()
                        .and_then(|v| v.get("type"))
                        .and_then(serde_json::Value::as_str)
                        == Some(expected)
                })
        })
        .collect::<Vec<_>>();
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
        let mut checked = crate::value_contract::encoded::compare_decoded(
            &source,
            &target,
            &selected,
            crate::value_contract::json::AnchorClocks {
                case: times,
                dependency: times,
                ..Default::default()
            },
        )?;
        // A broad event-only rule cannot relax another rule's discriminator.
        if selected
            .iter()
            .any(|r| matches!(&r.rule.slot, Slot::SseData(s) if s.json_type().is_some()))
            && source.logical.get("type") != target.logical.get("type")
        {
            checked.differences.push(Difference {
                pointer: "/type".into(),
                reason: "SSE JSON type discriminator changed".into(),
            });
        }
        Ok(checked)
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
