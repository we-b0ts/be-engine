//! HTTP stream data positions bind to the shared value execution services.
use anyhow::{Context, Result};
pub use traffic_protocol_http::data_stream::Document;

pub fn compare(
    source: &Document,
    target: &Document,
    plan: &crate::policy::CompiledJsonPolicy,
    clocks: crate::value_contract::json::AnchorClocks,
) -> Result<crate::value_contract::json::Comparison> {
    use crate::{
        policy::Codec,
        value_codec::CodecView,
        value_contract::{
            global,
            json::{Comparison, Difference},
        },
    };
    let mut result = Comparison::default();
    if !source.same_encoding(target) {
        result.differences.push(Difference {
            pointer: "$stream".into(),
            reason: "structured stream encoding changed".into(),
        });
    }
    if source.events.len() != target.events.len() {
        result.differences.push(Difference {
            pointer: "$sse/events".into(),
            reason: "SSE event count changed".into(),
        });
    }
    for (index, (source, target)) in source.events.iter().zip(&target.events).enumerate() {
        let pointer = format!("$sse/events/{index}");
        if source.event != target.event || source.id != target.id || source.retry != target.retry {
            result.differences.push(Difference {
                pointer: pointer.clone(),
                reason: "SSE envelope changed".into(),
            });
        }
        let mut comparison =
            if let Ok(decoded) = CodecView::decode(&Codec::Json, source.data.as_bytes()) {
                let target = CodecView::decode(&Codec::Json, target.data.as_bytes())
                    .context("Target SSE data changed from Source JSON encoding")?;
                global::compare_decoded(&decoded, &target, plan, &[], clocks)?
            } else {
                let mut comparison = Comparison::default();
                if source.data != target.data {
                    comparison.differences.push(Difference {
                        pointer: String::new(),
                        reason: "opaque SSE data changed".into(),
                    });
                }
                comparison
            };
        comparison.scope_schema_clocks(index);
        for difference in &mut comparison.differences {
            difference.pointer = format!("{pointer}/data{}", difference.pointer);
        }
        result.merge_and_validate(comparison);
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn sse_data_edits_preserve_envelope_heartbeats_and_unknown_sentinels() {
        let bytes = b": heartbeat\r\nevent: delta\r\nid: fixed\r\ndata: {\r\ndata: \"created_at\":1005}\r\n\r\ndata: [DONE]\r\n\r\n";
        let source = Document::decode(bytes).unwrap();
        assert_eq!(
            source
                .render(
                    &source
                        .events
                        .iter()
                        .map(|event| event.data.as_bytes().to_vec())
                        .collect::<Vec<_>>()
                )
                .unwrap(),
            bytes
        );
        let values = vec![br#"{"created_at":2005}"#.to_vec(), b"[DONE]".to_vec()];
        let output = source.render(&values).unwrap();
        assert!(output.starts_with(b": heartbeat\r\nevent: delta\r\nid: fixed\r\ndata: "));
        assert!(output.ends_with(b"data: [DONE]\r\n\r\n"));
        let target = Document::decode(&output).unwrap();
        assert_eq!(
            crate::json_value::parse(target.events[0].data.as_bytes()).unwrap()["created_at"],
            2005
        );
        let plan = crate::policy::parse_and_compile_policy("format: traffic-policy/v3\njson:\n  fields:\n    /created_at: {kind: time, formats: [unix_seconds]}\n").unwrap().global_json.unwrap();
        let clocks = crate::value_contract::json::AnchorClocks {
            dependency: crate::value_contract::time::ClockPair {
                source: chrono::DateTime::from_timestamp(1000, 0),
                target: chrono::DateTime::from_timestamp(2000, 0),
            },
            ..Default::default()
        };
        assert!(compare(&source, &target, &plan, clocks).unwrap().passed());
    }
}
