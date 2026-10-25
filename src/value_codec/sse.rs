//! Complete SSE data carriers with lossless edits outside JSON data bytes.
use crate::interaction::{
    model::Protocol,
    stream::{SseEvent, StreamDecoder},
};
use anyhow::{Context, Result, ensure};
use std::ops::Range;

#[derive(Debug, Clone)]
pub(crate) struct Document {
    json_lines: bool,
    original: Vec<u8>,
    ranges: Vec<Vec<Range<usize>>>,
    pub(crate) events: Vec<SseEvent>,
}

impl Document {
    pub(crate) fn decode(bytes: &[u8]) -> Result<Self> {
        ensure!(bytes.len() <= 1024 * 1024, "SSE payload exceeds 1 MiB");
        std::str::from_utf8(bytes).context("SSE payload is not UTF-8")?;
        let mut decoder = StreamDecoder::new(Protocol::Sse, 1024 * 1024)?;
        let messages = decoder.feed(bytes)?;
        decoder.finish()?;
        let events = messages
            .into_iter()
            .filter(|message| !message.heartbeat)
            .map(|message| {
                serde_json::from_str::<SseEvent>(&message.message.data).map_err(Into::into)
            })
            .collect::<Result<Vec<_>>>()?;
        if events.is_empty() {
            return Self::decode_json_lines(bytes);
        }
        let mut ranges = Vec::new();
        let mut current = Vec::new();
        let mut start = 0;
        while start < bytes.len() {
            let end = bytes[start..]
                .iter()
                .position(|byte| matches!(byte, b'\r' | b'\n'))
                .map(|offset| start + offset)
                .context("incomplete SSE line")?;
            let line = &bytes[start..end];
            if line.is_empty() {
                if !current.is_empty() {
                    ranges.push(std::mem::take(&mut current));
                }
            } else if let Some(data) = line.strip_prefix(b"data:") {
                let space = usize::from(data.starts_with(b" "));
                current.push(start + 5 + space..end);
            } else if line == b"data" {
                current.push(end..end);
            }
            start = end + 1;
            if bytes.get(end) == Some(&b'\r') && bytes.get(start) == Some(&b'\n') {
                start += 1;
            }
        }
        ensure!(
            current.is_empty() && ranges.len() == events.len(),
            "SSE data layout is incomplete"
        );
        Ok(Self {
            json_lines: false,
            original: bytes.to_vec(),
            ranges,
            events,
        })
    }

    fn decode_json_lines(bytes: &[u8]) -> Result<Self> {
        let mut ranges = Vec::new();
        let mut events = Vec::new();
        let mut start = 0;
        for line in bytes.split_inclusive(|byte| *byte == b'\n') {
            ensure!(line.ends_with(b"\n"), "incomplete JSON line");
            let content = line.strip_suffix(b"\n").unwrap();
            let content = content.strip_suffix(b"\r").unwrap_or(content);
            if !content.iter().all(u8::is_ascii_whitespace) {
                ensure!(
                    crate::json_value::parse(content).is_some(),
                    "stream line has no known JSON format"
                );
                ranges.push(std::iter::once(start..start + content.len()).collect());
                events.push(SseEvent {
                    event: None,
                    id: None,
                    retry: None,
                    data: std::str::from_utf8(content)?.into(),
                });
            }
            start += line.len();
        }
        ensure!(
            events.len() >= 2,
            "payload has no complete structured stream"
        );
        Ok(Self {
            json_lines: true,
            original: bytes.to_vec(),
            ranges,
            events,
        })
    }

    pub(crate) fn render(&self, values: &[Vec<u8>]) -> Result<Vec<u8>> {
        ensure!(
            values.len() == self.events.len(),
            "SSE event count changed during delivery"
        );
        let mut output = Vec::with_capacity(self.original.len());
        let mut previous = 0;
        for ((event, ranges), value) in self.events.iter().zip(&self.ranges).zip(values) {
            if event.data.as_bytes() == value {
                continue;
            }
            for (index, range) in ranges.iter().enumerate() {
                output.extend_from_slice(&self.original[previous..range.start]);
                if index == 0 {
                    output.extend_from_slice(value);
                }
                previous = range.end;
            }
        }
        output.extend_from_slice(&self.original[previous..]);
        Ok(output)
    }

    pub(crate) fn map_offset(&self, target: &Self, offset: usize) -> Result<usize> {
        ensure!(
            offset <= self.original.len() && self.ranges.len() == target.ranges.len(),
            "SSE stream byte inventory changed"
        );
        let mut previous = (0, 0);
        for (source, target) in self.ranges.iter().zip(&target.ranges) {
            ensure!(
                source.len() == target.len(),
                "SSE data line inventory changed"
            );
            for (source, target) in source.iter().zip(target) {
                if offset < source.start {
                    return Ok(previous.1 + offset - previous.0);
                }
                if offset <= source.end {
                    let within = if source.is_empty() {
                        0
                    } else {
                        (offset - source.start) * target.len() / source.len()
                    };
                    return Ok(target.start + within);
                }
                previous = (source.end, target.end);
            }
        }
        Ok(previous.1 + offset - previous.0)
    }
}

pub(crate) fn compare(
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
    if source.json_lines != target.json_lines {
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
        let plan = crate::policy::parse_and_compile_policy("format: traffic-policy/v2\njson:\n  fields:\n    /created_at: {kind: time, formats: [unix_seconds]}\n").unwrap().global_json.unwrap();
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
