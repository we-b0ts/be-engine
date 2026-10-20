//! Incremental logical framing, independent of HTTP body chunk boundaries.

use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};

use super::{
    model::{Protocol, WireMessage},
    policy::StreamTerminal,
};

pub(crate) fn response_protocol(headers: &hyper::HeaderMap) -> Option<Protocol> {
    let content = headers
        .get(hyper::header::CONTENT_TYPE)?
        .to_str()
        .ok()?
        .split(';')
        .next()?
        .trim()
        .to_ascii_lowercase();
    match content.as_str() {
        "text/event-stream" => Some(Protocol::Sse),
        "application/x-ndjson" | "application/ndjson" => Some(Protocol::Ndjson),
        "application/octet-stream" => Some(Protocol::RawStream),
        _ => None,
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SseEvent {
    pub event: Option<String>,
    pub data: String,
    pub id: Option<String>,
    pub retry: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamMessage {
    pub message: WireMessage,
    pub heartbeat: bool,
}

impl StreamMessage {
    pub fn is_terminal_for(
        &self,
        protocol: Protocol,
        terminal: &Option<StreamTerminal>,
    ) -> Result<bool> {
        if self.heartbeat {
            return Ok(false);
        }
        let Some(terminal) = terminal else {
            return Ok(false);
        };
        let bytes = self.message.decode()?;
        let text = std::str::from_utf8(&bytes)?;
        let sse = if protocol == Protocol::Sse {
            serde_json::from_str::<SseEvent>(text).ok()
        } else {
            None
        };
        let body = sse.as_ref().map_or(text, |event| event.data.as_str());
        Ok(match terminal {
            StreamTerminal::SseEvent { event } => sse
                .as_ref()
                .is_some_and(|message| message.event.as_deref().unwrap_or("message") == event),
            StreamTerminal::Text { value } => body == value,
            StreamTerminal::Json { pointer, value } => {
                crate::json_value::parse_with_limit(body.as_bytes(), body.len())
                    .and_then(|document| document.pointer(pointer).cloned())
                    .as_ref()
                    == Some(value)
            }
        })
    }
}

pub struct StreamDecoder {
    protocol: Protocol,
    limit: usize,
    buffer: Vec<u8>,
    pending_wire: Vec<u8>,
    sse: SseState,
    skip_lf: bool,
    first_line: bool,
    finished: bool,
}

#[derive(Default)]
struct SseState {
    event: Option<String>,
    data: Vec<String>,
    data_bytes: usize,
    id: Option<String>,
    retry: Option<u64>,
}

impl StreamDecoder {
    pub fn new(protocol: Protocol, max_message_bytes: usize) -> Result<Self> {
        ensure!(
            max_message_bytes > 0,
            "stream message limit must be positive"
        );
        ensure!(
            !matches!(protocol, Protocol::SocketIo | Protocol::WebSocket),
            "WebSocket requires its own message decoder"
        );
        Ok(Self {
            protocol,
            limit: max_message_bytes,
            buffer: Vec::new(),
            pending_wire: Vec::new(),
            sse: SseState::default(),
            skip_lf: false,
            first_line: true,
            finished: false,
        })
    }

    pub fn feed(&mut self, bytes: &[u8]) -> Result<Vec<StreamMessage>> {
        ensure!(!self.finished, "stream decoder has already finished");
        if self.protocol == Protocol::RawStream {
            return Ok(if bytes.is_empty() {
                Vec::new()
            } else {
                vec![StreamMessage {
                    message: WireMessage::binary(bytes),
                    heartbeat: false,
                }]
            });
        }
        self.buffer.extend_from_slice(bytes);
        let mut messages = Vec::new();
        loop {
            if self.skip_lf {
                if self.buffer.is_empty() {
                    break;
                }
                if self.buffer[0] == b'\n' {
                    self.buffer.remove(0);
                    if !self.pending_wire.is_empty() {
                        self.pending_wire.push(b'\n');
                    }
                }
                self.skip_lf = false;
            }
            let separator = self.buffer.iter().position(|byte| {
                *byte == b'\n' || (self.protocol == Protocol::Sse && *byte == b'\r')
            });
            let Some(end) = separator else {
                break;
            };
            ensure!(end <= self.limit, "stream line exceeds configured limit");
            let delimiter = self.buffer[end];
            let mut line: Vec<_> = self.buffer.drain(..=end).collect();
            let starts_message = self.pending_wire.is_empty();
            self.pending_wire.extend_from_slice(&line);
            line.pop();
            if self.protocol == Protocol::Ndjson && line.last() == Some(&b'\r') {
                line.pop();
            }
            self.skip_lf = self.protocol == Protocol::Sse && delimiter == b'\r';
            let standalone_heartbeat = starts_message
                && (line.starts_with(b":")
                    || (self.first_line
                        && line
                            .strip_prefix(b"\xef\xbb\xbf")
                            .is_some_and(|text| text.starts_with(b":"))));
            self.line(&line, &mut messages)?;
            if self.protocol == Protocol::Ndjson || line.is_empty() || standalone_heartbeat {
                self.pending_wire.clear();
            }
            ensure!(
                self.pending_wire.len() <= self.limit,
                "unfinished stream message exceeds configured limit"
            );
        }
        ensure!(
            self.pending_wire.len().saturating_add(self.buffer.len()) <= self.limit,
            "stream line exceeds configured limit"
        );
        Ok(messages)
    }

    pub fn finish(&mut self) -> Result<Vec<StreamMessage>> {
        ensure!(!self.finished, "stream decoder has already finished");
        self.finished = true;
        let mut messages = Vec::new();
        if self.protocol == Protocol::Ndjson && !self.buffer.is_empty() {
            let line = std::mem::take(&mut self.buffer);
            self.line(&line, &mut messages)?;
        } else if self.protocol == Protocol::Sse {
            // An unterminated SSE event is not a complete observation.
            ensure!(
                self.buffer.is_empty() && self.sse.data.is_empty(),
                "SSE stream ended in a partial event"
            );
        }
        Ok(messages)
    }

    /// Keep transport cancellation separate from successful logical framing.
    pub fn partial_message(&self) -> Option<WireMessage> {
        if self.pending_wire.is_empty() && self.buffer.is_empty() && self.sse.data.is_empty() {
            return None;
        }
        let mut bytes = self.pending_wire.clone();
        bytes.extend_from_slice(&self.buffer);
        Some(WireMessage::binary(&bytes))
    }

    pub fn validate_boundary(&self) -> Result<()> {
        ensure!(
            self.buffer.is_empty() && self.sse.data.is_empty(),
            "stream observation ended within a partial message"
        );
        Ok(())
    }

    fn line(&mut self, raw: &[u8], messages: &mut Vec<StreamMessage>) -> Result<()> {
        let text = std::str::from_utf8(raw).context("stream line is not UTF-8")?;
        let text = if self.first_line {
            self.first_line = false;
            text.strip_prefix('\u{feff}').unwrap_or(text)
        } else {
            text
        };
        match self.protocol {
            Protocol::Sse => self.sse_line(text, messages),
            Protocol::Ndjson if text.trim().is_empty() => Ok(()),
            Protocol::Ndjson => {
                let json = crate::json_value::parse_with_limit(text.as_bytes(), self.limit)
                    .context("NDJSON record must be complete JSON with unique members")?;
                messages.push(StreamMessage {
                    message: WireMessage::text(serde_json::to_string(&json)?),
                    heartbeat: false,
                });
                Ok(())
            }
            _ => bail!("unsupported line-oriented stream protocol"),
        }
    }

    fn sse_line(&mut self, line: &str, messages: &mut Vec<StreamMessage>) -> Result<()> {
        if line.is_empty() {
            if !self.sse.data.is_empty() {
                let event = SseEvent {
                    event: self.sse.event.take(),
                    data: self.sse.data.join("\n"),
                    id: self.sse.id.clone(),
                    retry: self.sse.retry,
                };
                messages.push(StreamMessage {
                    message: WireMessage::text(serde_json::to_string(&event)?),
                    heartbeat: false,
                });
                self.sse.data.clear();
                self.sse.data_bytes = 0;
            }
            self.sse.event = None;
            return Ok(());
        }
        if line.starts_with(':') {
            messages.push(StreamMessage {
                message: WireMessage::text(line),
                heartbeat: true,
            });
            return Ok(());
        }
        let (field, value) = line.split_once(':').unwrap_or((line, ""));
        let value = value.strip_prefix(' ').unwrap_or(value);
        match field {
            "data" => {
                self.sse.data_bytes = self
                    .sse
                    .data_bytes
                    .saturating_add(value.len())
                    .saturating_add(1);
                ensure!(
                    self.sse.data_bytes <= self.limit,
                    "SSE event exceeds configured limit"
                );
                self.sse.data.push(value.to_owned());
            }
            "event" => self.sse.event = Some(value.to_owned()),
            "id" if !value.contains('\0') => self.sse.id = Some(value.to_owned()),
            "retry" if !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit()) => {
                self.sse.retry = value.parse().ok()
            }
            _ => {}
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sse_framing_survives_every_single_byte_boundary_and_ignores_comment_heartbeats() {
        let bytes =
            "\u{feff}: ping\r\nid: 7\r\nevent: complete\r\ndata: 你\r\ndata: 好\r\n\r\n".as_bytes();
        let mut decoder = StreamDecoder::new(Protocol::Sse, 1024).unwrap();
        let mut events = Vec::new();
        for byte in bytes {
            events.extend(decoder.feed(&[*byte]).unwrap());
        }
        events.extend(decoder.finish().unwrap());
        assert_eq!(events.len(), 2);
        assert!(events[0].heartbeat);
        let data: SseEvent = serde_json::from_str(&events[1].message.data).unwrap();
        assert_eq!(data.data, "你\n好");
        assert_eq!(data.id.as_deref(), Some("7"));
        assert!(
            events[1]
                .is_terminal_for(
                    Protocol::Sse,
                    &Some(StreamTerminal::SseEvent {
                        event: "complete".into()
                    })
                )
                .unwrap()
        );
    }

    #[test]
    fn ndjson_is_independent_of_chunks_and_partial_sse_never_looks_complete() {
        let mut decoder = StreamDecoder::new(Protocol::Ndjson, 64).unwrap();
        assert!(decoder.feed(b"{\"a\":").unwrap().is_empty());
        let mut messages = decoder.feed(b"1}\n{\"a\":2}").unwrap();
        messages.extend(decoder.finish().unwrap());
        assert_eq!(messages.len(), 2);
        let mut sse = StreamDecoder::new(Protocol::Sse, 64).unwrap();
        sse.feed(b"data: partial\n").unwrap();
        assert!(sse.finish().is_err());
    }

    #[test]
    fn multiline_budget_and_invalid_json_fail_explicitly() {
        let mut decoder = StreamDecoder::new(Protocol::Sse, 12).unwrap();
        assert!(decoder.feed(b"data: aaaaa\ndata: bbbbbb\n\n").is_err());
        let mut decoder = StreamDecoder::new(Protocol::Ndjson, 64).unwrap();
        assert!(decoder.feed(b"not-json\n").is_err());
        let mut decoder = StreamDecoder::new(Protocol::Ndjson, 64).unwrap();
        assert!(decoder.feed(b"{\"id\":1,\"id\":2}\n").is_err());
    }

    #[test]
    fn cancelled_prefix_retains_exact_wire_bytes_across_all_chunk_boundaries() {
        let complete = b"data: first\r\n\r\n";
        let partial = b"event: update\r\n: keepalive\r\ndata: \xe4\xbd";
        for split in 0..=partial.len() {
            let mut decoder = StreamDecoder::new(Protocol::Sse, 1024).unwrap();
            assert_eq!(decoder.feed(complete).unwrap().len(), 1);
            let mut comments = decoder.feed(&partial[..split]).unwrap();
            comments.extend(decoder.feed(&partial[split..]).unwrap());
            assert!(comments.iter().all(|message| message.heartbeat));
            assert_eq!(
                decoder.partial_message().unwrap().decode().unwrap(),
                partial
            );
            assert!(decoder.validate_boundary().is_err());
            assert!(
                decoder.finish().is_err(),
                "EOF cannot certify a cancelled prefix"
            );
        }
    }

    #[test]
    fn ndjson_cancelled_suffix_is_not_parsed_as_a_completed_record() {
        let mut decoder = StreamDecoder::new(Protocol::Ndjson, 1024).unwrap();
        assert_eq!(
            decoder.feed(b"{\"done\":1}\n{\"pending\":").unwrap().len(),
            1
        );
        assert_eq!(
            decoder.partial_message().unwrap().decode().unwrap(),
            b"{\"pending\":"
        );
    }

    #[test]
    fn client_close_keeps_metadata_only_suffixes_and_bounds_unfinished_wire() {
        for prefix in [b"event: delta\n".as_slice(), b"id: 7\r\n"] {
            let mut decoder = StreamDecoder::new(Protocol::Sse, 64).unwrap();
            assert!(decoder.feed(prefix).unwrap().is_empty());
            // Normal SSE EOF may discard a metadata-only event. A client close
            // still retains exactly what was observed for independent comparison.
            decoder.validate_boundary().unwrap();
            assert_eq!(decoder.partial_message().unwrap().decode().unwrap(), prefix);
            decoder.finish().unwrap();
        }
        let mut decoder = StreamDecoder::new(Protocol::Sse, 8).unwrap();
        decoder.feed(b"data: x\n").unwrap();
        assert!(decoder.feed(b"y").is_err());
    }
}
