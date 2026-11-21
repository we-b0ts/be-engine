//! Complete SSE and JSON-line response framing with lossless data replacement.
use crate::interaction::{
    model::Protocol,
    stream::{SseEvent, StreamDecoder},
};
use anyhow::{Context, Result, ensure};
use std::ops::Range;

#[derive(Debug, Clone)]
pub struct Document {
    json_lines: bool,
    original: Vec<u8>,
    ranges: Vec<Vec<Range<usize>>>,
    pub events: Vec<SseEvent>,
}

impl Document {
    pub fn same_encoding(&self, other: &Self) -> bool {
        self.json_lines == other.json_lines
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        ensure!(
            bytes.len() <= crate::limits::MAX_BODY_BYTES,
            "SSE payload exceeds 64 MiB"
        );
        std::str::from_utf8(bytes).context("SSE payload is not UTF-8")?;
        let mut decoder = StreamDecoder::new(Protocol::Sse, crate::limits::MAX_BODY_BYTES)?;
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
                    traffic_codec_json::parse(content).is_some(),
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

    pub fn render(&self, values: &[Vec<u8>]) -> Result<Vec<u8>> {
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

    pub fn map_offset(&self, target: &Self, offset: usize) -> Result<usize> {
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
