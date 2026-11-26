//! Primary interactions stored on the sealed Source timeline.

use std::{
    io::{BufRead, BufReader, Read, Write},
    path::Path,
    str::{self, FromStr},
};

use anyhow::{Context, Result, ensure};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use bytes::Bytes;
use serde::de::DeserializeOwned;
use serde_json::Value;
use traffic_model::{
    recording::identity::IdentityKind, session::SessionEvent, trace::RecordedEvent,
};
use uuid::Uuid;

use crate::{
    format::{INLINE_BYTES, PayloadRef},
    source::{recording, segment_window::SegmentWindow},
};

pub const FILE: &str = "events.tsv";

mod window;
pub use window::{
    PrimaryDispatchWindow, PrimaryRoute, WindowFailureOwner, primary_dispatch_window,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrimaryEventKind {
    SourceStart,
    Ready,
    Stop,
    SourceExit,
    PrimaryRequest,
    PrimaryResponseHeaders,
    PrimaryResponsePart,
    PrimaryResponseTrailers,
    PrimaryResponseEnd,
    PrimaryCancel,
}

pub(crate) fn primary_kind(token: &[u8]) -> Option<PrimaryEventKind> {
    use PrimaryEventKind::*;
    Some(match token {
        b"source_start" => SourceStart,
        b"ready" => Ready,
        b"stop" => Stop,
        b"source_exit" => SourceExit,
        b"primary_request" => PrimaryRequest,
        b"primary_response_headers" => PrimaryResponseHeaders,
        b"primary_response_part" => PrimaryResponsePart,
        b"primary_response_trailers" => PrimaryResponseTrailers,
        b"primary_response_end" => PrimaryResponseEnd,
        b"primary_cancel" => PrimaryCancel,
        _ => return None,
    })
}

pub(crate) struct PendingSessionEvent {
    row: Vec<u8>,
    payload_len: Option<usize>,
}

pub(crate) fn split(
    event: &RecordedEvent<SessionEvent>,
    request_sequence: Option<u64>,
) -> Result<(PendingSessionEvent, Option<Vec<u8>>)> {
    use SessionEvent::*;
    let mut row = Vec::new();
    write!(
        row,
        "{}\t{}\t{}",
        event.sequence,
        event.offset_micros,
        event.event.kind()
    )?;
    let request = || {
        request_sequence
            .filter(|&request| request > 0 && request < event.sequence)
            .context("primary event has no preceding request sequence")
    };
    let payload = match &event.event {
        SourceStart | Ready | Stop => None,
        SourceExit { status } => {
            match status {
                Some(status) => write!(row, "\t{status}")?,
                None => row.extend_from_slice(b"\t-"),
            }
            None
        }
        PrimaryRequest { request, .. } => {
            row.push(b'\t');
            Some(serde_json::to_vec(request)?)
        }
        PrimaryResponseHeaders { response, .. } => {
            write!(row, "\t{}\t", request()?)?;
            encode_document(&mut row, response)?
        }
        PrimaryResponsePart {
            part, data_base64, ..
        } => {
            write!(row, "\t{}\t{part}\t", request()?)?;
            let data = STANDARD.decode(data_base64)?;
            if data.is_empty() {
                row.push(b'-');
                None
            } else {
                Some(data)
            }
        }
        PrimaryResponseTrailers { trailers, .. } => {
            write!(row, "\t{}\t", request()?)?;
            encode_document(&mut row, trailers)?
        }
        PrimaryResponseEnd { .. } => {
            write!(row, "\t{}", request()?)?;
            None
        }
        PrimaryCancel { reason, .. } => {
            write!(row, "\t{}\t", request()?)?;
            serde_json::to_writer(&mut row, reason)?;
            None
        }
    };
    let payload_len = payload.as_ref().map(Vec::len);
    Ok((PendingSessionEvent { row, payload_len }, payload))
}

fn encode_document(row: &mut Vec<u8>, document: &Value) -> Result<Option<Vec<u8>>> {
    let bytes = serde_json::to_vec(document)?;
    if bytes.len() > INLINE_BYTES || document.get("body").is_some_and(|body| !body.is_null()) {
        return Ok(Some(bytes));
    }
    row.extend_from_slice(&bytes);
    Ok(None)
}

impl PendingSessionEvent {
    pub(crate) fn encode(mut self, reference: Option<&PayloadRef>) -> Result<Vec<u8>> {
        ensure!(
            self.payload_len.map(|len| len as u64) == reference.map(|reference| reference.length),
            "invalid primary payload reference"
        );
        if let Some(reference) = reference {
            write!(
                self.row,
                "path:{}:{}:{}",
                reference.segment, reference.offset, reference.length
            )?;
        }
        self.row.push(b'\n');
        Ok(self.row)
    }
}

pub(crate) fn parse_prefix(row: &[u8]) -> Result<(u64, u64, &[u8], &[u8])> {
    let row = row.strip_suffix(b"\n").unwrap_or(row);
    let mut cells = row.splitn(4, |&byte| byte == b'\t');
    let seq = parse(field(&mut cells, "sequence")?, "sequence")?;
    let offset = parse(field(&mut cells, "offset")?, "offset")?;
    let kind = field(&mut cells, "kind")?;
    Ok((seq, offset, kind, cells.next().unwrap_or_default()))
}

fn field<'a>(cells: &mut impl Iterator<Item = &'a [u8]>, name: &str) -> Result<&'a [u8]> {
    cells
        .next()
        .filter(|cell| !cell.is_empty())
        .with_context(|| format!("missing {name}"))
}

fn parse<T>(value: &[u8], name: &str) -> Result<T>
where
    T: FromStr,
    T::Err: std::error::Error + Send + Sync + 'static,
{
    str::from_utf8(value)?
        .parse()
        .with_context(|| format!("invalid {name}"))
}

/// Body parts are read as slices of recorded payload segments for Replay.
pub enum ReplayEvent {
    Event(SessionEvent),
    ResponsePart {
        exchange: Uuid,
        part: u64,
        data: Bytes,
    },
}

impl ReplayEvent {
    fn into_event(self) -> SessionEvent {
        match self {
            Self::Event(event) => event,
            Self::ResponsePart {
                exchange,
                part,
                data,
            } => SessionEvent::PrimaryResponsePart {
                exchange,
                part,
                data_base64: STANDARD.encode(&data),
            },
        }
    }
}

pub struct ReplayEvents {
    input: BufReader<Box<dyn Read + Send>>,
    segments: SegmentWindow,
    recording_id: Uuid,
    first_sequence: u64,
    line: Vec<u8>,
    row: usize,
    previous: (u64, u64),
    source_started: bool,
    finished: bool,
}

/// Open the complete primary event stream without loading its payloads.
///
/// # Safety
///
/// The sealed payload files must remain unchanged while the reader or any of
/// its returned byte slices are live.
pub unsafe fn read_for_replay(root: &Path) -> Result<ReplayEvents> {
    open(root, |root| {
        // SAFETY: the caller maintains the lifetime of the immutable segments.
        unsafe { SegmentWindow::new(root) }
    })
}

fn open(
    root: &Path,
    open_segments: impl FnOnce(std::path::PathBuf) -> SegmentWindow,
) -> Result<ReplayEvents> {
    let (root, manifest) = recording::manifest(root)?;
    ensure!(
        manifest.capture_complete,
        "Source session capture is incomplete"
    );
    ensure!(
        manifest
            .files
            .iter()
            .any(|file| file.path == FILE && file.length > 0),
        "sealed recording has no session events"
    );
    let input = crate::session_integrity::events(&root, &manifest)?;
    Ok(ReplayEvents {
        input: BufReader::new(input),
        segments: open_segments(root).with_seal(&manifest),
        recording_id: manifest.run_epoch,
        first_sequence: 0,
        line: Vec::new(),
        row: 0,
        previous: (0, 0),
        source_started: false,
        finished: false,
    })
}

/// Rebuild the evidence model including its base64 representation of body parts.
pub fn evidence_events(
    root: &Path,
) -> Result<impl Iterator<Item = Result<RecordedEvent<SessionEvent>>> + use<>> {
    evidence_events_from(root, 0)
}

pub fn evidence_events_from(
    root: &Path,
    first_sequence: u64,
) -> Result<impl Iterator<Item = Result<RecordedEvent<SessionEvent>>> + use<>> {
    let mut events = open(root, SegmentWindow::new_copying)?;
    events.first_sequence = first_sequence;
    Ok(events.map(|event| {
        let RecordedEvent {
            sequence,
            offset_micros,
            event,
        } = event?;
        Ok(RecordedEvent {
            sequence,
            offset_micros,
            event: event.into_event(),
        })
    }))
}

pub fn read(root: &Path) -> Result<Vec<RecordedEvent<SessionEvent>>> {
    evidence_events(root)?.collect()
}

impl Iterator for ReplayEvents {
    type Item = Result<RecordedEvent<ReplayEvent>>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.finished {
            return None;
        }
        let row = self
            .read_next()
            .with_context(|| format!("parse {FILE} row {}", self.row));
        self.finished = !matches!(row, Ok(Some(_)));
        row.transpose()
    }
}

impl ReplayEvents {
    fn read_next(&mut self) -> Result<Option<RecordedEvent<ReplayEvent>>> {
        loop {
            self.line.clear();
            if self.input.read_until(b'\n', &mut self.line)? == 0 {
                ensure!(
                    self.source_started,
                    "Source session does not start with a process launch"
                );
                return Ok(None);
            }
            self.row += 1;
            let (sequence, offset_micros, kind, payload) = parse_prefix(&self.line)?;
            ensure!(
                sequence > self.previous.0 && offset_micros >= self.previous.1,
                "unordered session event {sequence}"
            );
            self.previous = (sequence, offset_micros);
            let Some(kind) = primary_kind(kind) else {
                continue;
            };
            ensure!(
                self.source_started || kind == PrimaryEventKind::SourceStart,
                "Source session does not start with a process launch"
            );
            self.source_started = true;
            if sequence < self.first_sequence {
                continue;
            }
            let event = decode(
                kind,
                sequence,
                payload,
                self.recording_id,
                &mut self.segments,
            )?;
            return Ok(Some(RecordedEvent {
                sequence,
                offset_micros,
                event,
            }));
        }
    }
}

fn decode(
    kind: PrimaryEventKind,
    sequence: u64,
    payload: &[u8],
    recording_id: Uuid,
    segments: &mut SegmentWindow,
) -> Result<ReplayEvent> {
    let mut cells = (!payload.is_empty())
        .then(|| payload.split(|&byte| byte == b'\t'))
        .into_iter()
        .flatten();
    let event = match kind {
        PrimaryEventKind::SourceStart => SessionEvent::SourceStart,
        PrimaryEventKind::Ready => SessionEvent::Ready,
        PrimaryEventKind::Stop => SessionEvent::Stop,
        PrimaryEventKind::SourceExit => SessionEvent::SourceExit {
            status: match field(&mut cells, "exit status")? {
                b"-" => None,
                status => Some(parse(status, "exit status")?),
            },
        },
        PrimaryEventKind::PrimaryRequest => SessionEvent::PrimaryRequest {
            exchange: IdentityKind::Case.bridge(recording_id, sequence),
            request: decode_document(field(&mut cells, "primary request")?, segments)?,
        },
        PrimaryEventKind::PrimaryResponseHeaders => SessionEvent::PrimaryResponseHeaders {
            exchange: linked_exchange(&mut cells, recording_id, sequence)?,
            response: decode_document(field(&mut cells, "primary response")?, segments)?,
        },
        PrimaryEventKind::PrimaryResponsePart => {
            let exchange = linked_exchange(&mut cells, recording_id, sequence)?;
            let part = parse(field(&mut cells, "part")?, "part")?;
            let data = match field(&mut cells, "part payload")? {
                b"-" => Bytes::new(),
                cell => segments.read(&parse_reference(cell)?)?,
            };
            ensure!(
                cells.next().is_none(),
                "unexpected primary response part fields"
            );
            return Ok(ReplayEvent::ResponsePart {
                exchange,
                part,
                data,
            });
        }
        PrimaryEventKind::PrimaryResponseTrailers => SessionEvent::PrimaryResponseTrailers {
            exchange: linked_exchange(&mut cells, recording_id, sequence)?,
            trailers: decode_document(field(&mut cells, "primary trailers")?, segments)?,
        },
        PrimaryEventKind::PrimaryResponseEnd => SessionEvent::PrimaryResponseEnd {
            exchange: linked_exchange(&mut cells, recording_id, sequence)?,
        },
        PrimaryEventKind::PrimaryCancel => SessionEvent::PrimaryCancel {
            exchange: linked_exchange(&mut cells, recording_id, sequence)?,
            reason: serde_json::from_slice(field(&mut cells, "cancellation reason")?)?,
        },
    };
    ensure!(cells.next().is_none(), "unexpected primary event fields");
    Ok(ReplayEvent::Event(event))
}

fn linked_exchange<'a>(
    cells: &mut impl Iterator<Item = &'a [u8]>,
    recording_id: Uuid,
    sequence: u64,
) -> Result<Uuid> {
    let request = linked_request_sequence(field(cells, "primary request sequence")?, sequence)?;
    Ok(IdentityKind::Case.bridge(recording_id, request))
}

fn linked_request_sequence(cell: &[u8], sequence: u64) -> Result<u64> {
    let request: u64 = parse(cell, "primary request sequence")?;
    ensure!(
        request > 0 && request < sequence,
        "primary event has no preceding request sequence"
    );
    Ok(request)
}

fn decode_document<T: DeserializeOwned>(cell: &[u8], segments: &mut SegmentWindow) -> Result<T> {
    if cell.starts_with(b"path:") {
        return Ok(serde_json::from_slice(
            &segments.read(&parse_reference(cell)?)?,
        )?);
    }
    Ok(serde_json::from_slice(cell)?)
}

fn parse_reference(cell: &[u8]) -> Result<PayloadRef> {
    let reference = cell
        .strip_prefix(b"path:")
        .context("missing primary payload reference")?;
    str::from_utf8(reference)?
        .parse()
        .context("invalid primary payload reference")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn primary_parts_link_to_the_request_sequence_and_read_raw_payloads() -> Result<()> {
        let root = tempfile::tempdir()?;
        fs::create_dir(root.path().join("payload"))?;
        let recording_id = Uuid::new_v4();
        let exchange = Uuid::new_v4();
        let expected_exchange = IdentityKind::Case.bridge(recording_id, 12);
        let request = serde_json::json!({"method": "POST", "uri": "/test", "body": "value"});
        let (pending, body) = split(
            &RecordedEvent {
                sequence: 12,
                offset_micros: 15,
                event: SessionEvent::PrimaryRequest {
                    exchange,
                    request: request.clone(),
                },
            },
            None,
        )?;
        let body = body.context("request must use external payload storage")?;
        let request_reference = PayloadRef {
            segment: 0,
            offset: 0,
            length: body.len() as u64,
        };
        let request_row = pending.encode(Some(&request_reference))?;

        let data = b"\x00first\xff\npart\t";
        let (pending, part) = split(
            &RecordedEvent {
                sequence: 19,
                offset_micros: 30,
                event: SessionEvent::PrimaryResponsePart {
                    exchange,
                    part: 1,
                    data_base64: STANDARD.encode(data),
                },
            },
            Some(12),
        )?;
        let part = part.context("response part must use external payload storage")?;
        assert_eq!(&part, data);
        let part_reference = PayloadRef {
            segment: 0,
            offset: body.len() as u64,
            length: part.len() as u64,
        };
        let part_row = pending.encode(Some(&part_reference))?;
        fs::write(root.path().join(PayloadRef::path(0)), [body, part].concat())?;

        assert!(request_row.starts_with(b"12\t15\tprimary_request\tpath:"));
        assert!(part_row.starts_with(b"19\t30\tprimary_response_part\t12\t1\tpath:"));
        let mut segments = SegmentWindow::new_copying(root.path().to_owned());
        let (sequence, _, kind, data) = parse_prefix(&request_row)?;
        let event = decode(
            primary_kind(kind).unwrap(),
            sequence,
            data,
            recording_id,
            &mut segments,
        )?;
        assert!(matches!(
            event,
            ReplayEvent::Event(SessionEvent::PrimaryRequest { exchange, request: actual })
                if exchange == expected_exchange && actual == request
        ));
        let (sequence, _, kind, cell) = parse_prefix(&part_row)?;
        let event = decode(
            primary_kind(kind).unwrap(),
            sequence,
            cell,
            recording_id,
            &mut segments,
        )?;
        assert!(matches!(
            event,
            ReplayEvent::ResponsePart { exchange, part: 1, data }
                if exchange == expected_exchange && data.as_ref() == b"\x00first\xff\npart\t"
        ));
        Ok(())
    }
}
