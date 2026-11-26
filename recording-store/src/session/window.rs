//! Select primary route metadata from a bounded forward window of Source time.

use std::{
    collections::BTreeMap,
    io::{BufRead, BufReader},
    path::Path,
};

use anyhow::{Context, Result, ensure};
use serde::Deserialize;
use traffic_model::{recording::identity::IdentityKind, trace::CaptureEvent};
use uuid::Uuid;

use super::{
    PrimaryEventKind, decode_document, linked_request_sequence, parse, parse_prefix, primary_kind,
};
use crate::{
    event_format, session_integrity,
    source::{recording, segment_window::SegmentWindow},
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrimaryRoute {
    pub method: String,
    pub path: String,
}

#[derive(Debug, PartialEq, Eq)]
pub enum WindowFailureOwner {
    Request(PrimaryRoute),
    Startup,
    Shutdown,
}

#[derive(Debug)]
pub struct PrimaryDispatchWindow {
    pub through_sequence: u64,
    pub requests: BTreeMap<u64, PrimaryRoute>,
    pub failure_owner: Option<WindowFailureOwner>,
}

/// Scan through the requested Source time window. Preceding request rows
/// contribute references for exact ownership lookup, without reading their
/// documents. Dependency and response payloads are never opened.
pub fn primary_dispatch_window(
    root: &Path,
    failed_sequence: u64,
    duration_micros: u64,
    after_sequence: u64,
) -> Result<PrimaryDispatchWindow> {
    let (root, manifest) = recording::manifest(root)?;
    ensure!(
        manifest.capture_complete,
        "Source session capture is incomplete"
    );
    let input = session_integrity::events(&root, &manifest)?;
    let mut scanner = WindowScanner {
        epoch: manifest.run_epoch,
        segments: SegmentWindow::new_copying(root).with_seal(&manifest),
        preceding_requests: BTreeMap::new(),
        dependency_requests: BTreeMap::new(),
    };
    scanner.scan(
        BufReader::with_capacity(64 * 1024, input),
        failed_sequence,
        duration_micros,
        after_sequence,
    )
}

struct WindowScanner {
    epoch: Uuid,
    segments: SegmentWindow,
    preceding_requests: BTreeMap<u64, Vec<u8>>,
    dependency_requests: BTreeMap<u64, u64>,
}

impl WindowScanner {
    fn scan(
        &mut self,
        mut input: impl BufRead,
        failed_sequence: u64,
        duration_micros: u64,
        after_sequence: u64,
    ) -> Result<PrimaryDispatchWindow> {
        let mut row = Vec::new();
        let mut previous = (0, 0);
        let mut through_sequence = 0;
        let mut requests = BTreeMap::new();
        let mut failure_owner = None;
        let mut end_offset = None;
        while input.read_until(b'\n', &mut row)? != 0 {
            let (sequence, offset, kind, fields) = parse_prefix(&row)?;
            ensure!(
                sequence > previous.0 && offset >= previous.1,
                "unordered session event {sequence}"
            );
            previous = (sequence, offset);
            if sequence < failed_sequence {
                self.observe_preceding(sequence, kind, fields, &row)?;
            } else {
                if sequence == failed_sequence {
                    end_offset = Some(offset.saturating_add(duration_micros));
                    failure_owner = self.failure_owner(sequence, kind, fields, &row)?;
                    if duration_micros == 0 {
                        through_sequence = sequence;
                        break;
                    }
                    self.preceding_requests.clear();
                    self.dependency_requests.clear();
                }
                let end = end_offset.with_context(|| {
                    format!("Source session does not contain failed sequence {failed_sequence}")
                })?;
                if offset > end {
                    break;
                }
                if sequence > after_sequence && kind == b"primary_request" {
                    let route = match (sequence == failed_sequence, &failure_owner) {
                        (true, Some(WindowFailureOwner::Request(route))) => Some(route.clone()),
                        (true, _) => None,
                        (false, _) => self.read_route(fields)?,
                    };
                    if let Some(route) = route {
                        requests.insert(sequence, route);
                    }
                }
                through_sequence = sequence;
            }
            row.clear();
        }
        ensure!(
            end_offset.is_some(),
            "Source session does not contain failed sequence {failed_sequence}"
        );
        Ok(PrimaryDispatchWindow {
            through_sequence,
            requests,
            failure_owner,
        })
    }

    fn observe_preceding(
        &mut self,
        sequence: u64,
        kind: &[u8],
        fields: &[u8],
        row: &[u8],
    ) -> Result<()> {
        match kind {
            b"primary_request" => {
                self.preceding_requests.insert(sequence, fields.to_vec());
            }
            // The third capture-start field is the admitted Case. Most
            // Source Session dependencies carry no admission link.
            b"capture_started" if !fields.ends_with(b"\t-") => {
                if let Some(request) = self.admitted_request(row)? {
                    self.dependency_requests.insert(sequence, request);
                }
            }
            b"capture_terminated" if !self.dependency_requests.is_empty() => {
                let dependency = parse(first_field(fields), "dependency sequence")?;
                self.dependency_requests.remove(&dependency);
            }
            _ => {}
        }
        Ok(())
    }

    fn failure_owner(
        &mut self,
        sequence: u64,
        kind: &[u8],
        fields: &[u8],
        row: &[u8],
    ) -> Result<Option<WindowFailureOwner>> {
        use PrimaryEventKind::*;
        let request = match primary_kind(kind) {
            Some(SourceStart | Ready) => return Ok(Some(WindowFailureOwner::Startup)),
            Some(Stop | SourceExit) => return Ok(Some(WindowFailureOwner::Shutdown)),
            Some(PrimaryRequest) => return self.read_route(fields).map(|route| Some(owner(route))),
            Some(
                PrimaryResponseHeaders
                | PrimaryResponsePart
                | PrimaryResponseTrailers
                | PrimaryResponseEnd
                | PrimaryCancel,
            ) => Some(linked_request_sequence(first_field(fields), sequence)?),
            None if kind == b"capture_started" => self.admitted_request(row)?,
            None if matches!(
                kind,
                b"wire_output_started"
                    | b"wire_output"
                    | b"wire_output_cancelled"
                    | b"capture_terminated"
            ) =>
            {
                let dependency = parse(first_field(fields), "dependency sequence")?;
                self.dependency_requests.get(&dependency).copied()
            }
            None => None,
        };
        let Some(request) = request else {
            return Ok(None);
        };
        let Some(document) = self.preceding_requests.remove(&request) else {
            return Ok(None);
        };
        self.read_route(&document).map(|route| Some(owner(route)))
    }

    fn admitted_request(&self, row: &[u8]) -> Result<Option<u64>> {
        match event_format::decode_stream_event(row, self.epoch)? {
            Some(event) => match event.event {
                CaptureEvent::Started { admitted_case, .. } => Ok(
                    admitted_case.and_then(|case| IdentityKind::Case.sequence(self.epoch, case))
                ),
                _ => Ok(None),
            },
            None => Ok(None),
        }
    }

    fn read_route(&mut self, document: &[u8]) -> Result<Option<PrimaryRoute>> {
        #[derive(Deserialize)]
        struct RequestFields {
            method: String,
            uri: String,
            #[serde(default, rename = "_session_probe")]
            probe: bool,
        }
        let request: RequestFields = decode_document(document, &mut self.segments)?;
        if request.probe {
            return Ok(None);
        }
        let uri: http::Uri = request.uri.parse().context("invalid primary URI")?;
        Ok(Some(PrimaryRoute {
            method: request.method,
            path: uri.path().to_owned(),
        }))
    }
}

fn first_field(fields: &[u8]) -> &[u8] {
    fields
        .split(|&byte| byte == b'\t')
        .next()
        .unwrap_or_default()
}

fn owner(route: Option<PrimaryRoute>) -> WindowFailureOwner {
    route.map_or(WindowFailureOwner::Startup, WindowFailureOwner::Request)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::writer::{
        JsonlBufferSettings, JsonlWriterPool, LedgerFiles, tests::write_session_manifest,
    };
    use serde_json::json;
    use traffic_model::{
        recording::CapturePhase,
        session::SessionEvent,
        trace::{OutputKind, RecordedEvent},
    };

    #[tokio::test]
    async fn window_uses_exact_links_and_stops_after_the_source_minute() -> Result<()> {
        let temporary = tempfile::tempdir()?;
        let root = temporary.path();
        let epoch = Uuid::new_v4();
        let process = Uuid::new_v4();
        let mut ledger = LedgerFiles::initialize_for_mode(root, epoch, process, true).await?;
        let mut files = JsonlWriterPool::new(JsonlBufferSettings {
            capacity: 4096,
            flush_interval: std::time::Duration::from_secs(30),
        });
        let first = IdentityKind::Case.bridge(epoch, 2);
        for (sequence, offset_micros, event) in [
            (1, 0, SessionEvent::SourceStart),
            (
                2,
                10,
                SessionEvent::PrimaryRequest {
                    exchange: first,
                    request: json!({"method": "POST", "uri": "/previous"}),
                },
            ),
            (3, 20, SessionEvent::PrimaryResponseEnd { exchange: first }),
        ] {
            ledger
                .append_session_event(
                    &mut files,
                    &RecordedEvent {
                        sequence,
                        offset_micros,
                        event,
                    },
                )
                .await?;
        }
        for (sequence, event) in [
            (
                4,
                CaptureEvent::Started {
                    dependency_sequence: 4,
                    phase: CapturePhase::Runtime,
                    observed_case: None,
                    admitted_case: Some(first),
                },
            ),
            (
                5,
                CaptureEvent::Output {
                    dependency_sequence: 4,
                    output: OutputKind::End,
                },
            ),
            (
                6,
                CaptureEvent::Started {
                    dependency_sequence: 6,
                    phase: CapturePhase::Runtime,
                    observed_case: Some(first),
                    admitted_case: None,
                },
            ),
        ] {
            ledger
                .append_event(
                    &mut files,
                    &RecordedEvent {
                        sequence,
                        offset_micros: sequence * 10,
                        event,
                    },
                )
                .await?;
        }
        for (sequence, offset_micros, path) in [
            (7, 61, "/included?detail=yes"),
            (8, 62, "/probe"),
            (9, 60_000_060, "/last"),
            (10, 60_000_061, "/outside"),
        ] {
            ledger.append_session_event(&mut files, &RecordedEvent {
                sequence,
                offset_micros,
                event: SessionEvent::PrimaryRequest {
                    exchange: IdentityKind::Case.bridge(epoch, sequence),
                    request: json!({"method": "GET", "uri": path, "_session_probe": sequence == 8}),
                },
            }).await?;
        }
        write_session_manifest(root, epoch, process, ledger.seal(&mut files).await?)?;

        for seq in [3, 4, 5] {
            let exact = primary_dispatch_window(root, seq, 0, 0)?;
            assert_eq!(exact.through_sequence, seq);
            assert_eq!(
                exact.failure_owner,
                Some(WindowFailureOwner::Request(PrimaryRoute {
                    method: "POST".into(),
                    path: "/previous".into(),
                }))
            );
        }
        let window = primary_dispatch_window(root, 6, 60_000_000, 0)?;
        assert_eq!(window.through_sequence, 9);
        assert_eq!(window.failure_owner, None);
        assert_eq!(
            window
                .requests
                .iter()
                .map(|(&seq, route)| (seq, route.path.as_str()))
                .collect::<Vec<_>>(),
            [(7, "/included"), (9, "/last")],
        );
        let rolled = primary_dispatch_window(root, 7, 60_000_000, window.through_sequence)?;
        assert_eq!(rolled.through_sequence, 10);
        assert_eq!(rolled.requests.keys().copied().collect::<Vec<_>>(), [10]);
        assert!(matches!(
            rolled.failure_owner,
            Some(WindowFailureOwner::Request(_))
        ));
        Ok(())
    }
}
