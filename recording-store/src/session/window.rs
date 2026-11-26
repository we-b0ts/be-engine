//! Select matchable requests and exact ownership from a bounded Source time window.

use std::{
    collections::{BTreeMap, BTreeSet},
    io::{BufRead, BufReader},
    iter::Peekable,
    path::Path,
};

use anyhow::{Context, Result, ensure};
use traffic_model::{
    recording::{CapturePhase, identity::IdentityKind},
    trace::CaptureEvent,
};
use uuid::Uuid;

use super::{
    PrimaryEventKind, PrimaryRoute, linked_request_sequence, parse, parse_prefix, primary_kind,
    request_lookup::read_primary_route,
};
use crate::{
    event_format, session_integrity, session_schedule, session_summary,
    source::{recording, segment_window::SegmentWindow},
};

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
    pub dependencies: BTreeMap<u64, Option<WindowFailureOwner>>,
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
    let unscheduled = if manifest
        .files
        .iter()
        .any(|file| file.path == session_summary::FILE)
    {
        session_summary::read(&root)?
            .unscheduled_admissions
            .into_iter()
            .collect()
    } else {
        BTreeSet::new()
    };
    let schedule: Schedule = if manifest
        .files
        .iter()
        .any(|file| file.path == session_schedule::FILE)
    {
        Box::new(session_schedule::read(&root)?)
    } else {
        Box::new(std::iter::empty())
    };
    let mut scanner = WindowScanner {
        epoch: manifest.run_epoch,
        segments: SegmentWindow::new_copying(root).with_seal(&manifest),
        primary_requests: BTreeMap::new(),
        dependency_owners: BTreeMap::new(),
        unscheduled,
        schedule: schedule.peekable(),
    };
    scanner.scan(
        BufReader::with_capacity(64 * 1024, input),
        failed_sequence,
        duration_micros,
        after_sequence,
    )
}

type Schedule = Box<dyn Iterator<Item = Result<session_schedule::SessionDecision>>>;

enum RequestRoute {
    Encoded(Vec<u8>),
    Resolved(Option<PrimaryRoute>),
}

#[derive(Clone, Copy)]
enum OwnerLink {
    Request(u64),
    Startup,
    Shutdown,
}

struct WindowScanner {
    epoch: Uuid,
    segments: SegmentWindow,
    primary_requests: BTreeMap<u64, RequestRoute>,
    dependency_owners: BTreeMap<u64, OwnerLink>,
    unscheduled: BTreeSet<u64>,
    schedule: Peekable<Schedule>,
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
        let mut dependencies = BTreeMap::new();
        let mut failure_owner = None;
        let mut end_offset = None;
        while input.read_until(b'\n', &mut row)? != 0 {
            let (sequence, offset, kind, fields) = parse_prefix(&row)?;
            ensure!(
                sequence > previous.0 && offset >= previous.1,
                "unordered session event {sequence}"
            );
            previous = (sequence, offset);
            if sequence == failed_sequence {
                end_offset = Some(offset.saturating_add(duration_micros));
            }
            if sequence >= failed_sequence {
                let end = end_offset.with_context(|| {
                    format!("Source session does not contain failed sequence {failed_sequence}")
                })?;
                if offset > end {
                    break;
                }
                through_sequence = sequence;
            }
            self.observe(sequence, kind, fields, &row)?;
            if sequence == failed_sequence {
                failure_owner = self.failure_owner(sequence, kind, fields)?;
                if duration_micros == 0 {
                    break;
                }
            }
            if sequence >= failed_sequence && sequence > after_sequence {
                match kind {
                    b"primary_request" => {
                        if let Some(WindowFailureOwner::Request(route)) =
                            self.request_owner(sequence)?
                        {
                            requests.insert(sequence, route);
                        }
                    }
                    b"capture_started" if self.target_admission_required(sequence)? => {
                        dependencies.insert(sequence, self.dependency_owner(sequence)?);
                    }
                    _ => {}
                }
            }
            if kind == b"capture_terminated" && !self.dependency_owners.is_empty() {
                let dependency = parse(first_field(fields), "dependency sequence")?;
                self.dependency_owners.remove(&dependency);
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
            dependencies,
            failure_owner,
        })
    }

    fn observe(&mut self, sequence: u64, kind: &[u8], fields: &[u8], row: &[u8]) -> Result<()> {
        match kind {
            b"primary_request" => {
                self.primary_requests
                    .insert(sequence, RequestRoute::Encoded(fields.to_vec()));
            }
            // Runtime observations without an admitted Case carry no ownership link.
            b"capture_started"
                if !fields.starts_with(b"runtime\t") || !fields.ends_with(b"\t-") =>
            {
                if let Some(link) = self.admission_owner(row)? {
                    self.dependency_owners.insert(sequence, link);
                }
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
    ) -> Result<Option<WindowFailureOwner>> {
        use PrimaryEventKind::*;
        match primary_kind(kind) {
            Some(SourceStart | Ready) => Ok(Some(WindowFailureOwner::Startup)),
            Some(Stop | SourceExit) => Ok(Some(WindowFailureOwner::Shutdown)),
            Some(PrimaryRequest) => self.request_owner(sequence),
            Some(
                PrimaryResponseHeaders
                | PrimaryResponsePart
                | PrimaryResponseTrailers
                | PrimaryResponseEnd
                | PrimaryCancel,
            ) => self.request_owner(linked_request_sequence(first_field(fields), sequence)?),
            None if kind == b"capture_started" => self.dependency_owner(sequence),
            None if matches!(
                kind,
                b"wire_output_started"
                    | b"wire_output"
                    | b"wire_output_cancelled"
                    | b"capture_terminated"
            ) =>
            {
                let dependency = parse(first_field(fields), "dependency sequence")?;
                self.dependency_owner(dependency)
            }
            None => Ok(None),
        }
    }

    fn admission_owner(&self, row: &[u8]) -> Result<Option<OwnerLink>> {
        let Some(event) = event_format::decode_stream_event(row, self.epoch)? else {
            return Ok(None);
        };
        let CaptureEvent::Started {
            phase,
            admitted_case,
            ..
        } = event.event
        else {
            return Ok(None);
        };
        if let Some(case) = admitted_case {
            return Ok(IdentityKind::Case
                .sequence(self.epoch, case)
                .map(OwnerLink::Request));
        }
        Ok(match phase {
            CapturePhase::Startup => Some(OwnerLink::Startup),
            CapturePhase::Runtime => None,
            CapturePhase::Shutdown => Some(OwnerLink::Shutdown),
        })
    }

    fn dependency_owner(&mut self, sequence: u64) -> Result<Option<WindowFailureOwner>> {
        match self.dependency_owners.get(&sequence).copied() {
            Some(OwnerLink::Request(request)) => self.request_owner(request),
            Some(OwnerLink::Startup) => Ok(Some(WindowFailureOwner::Startup)),
            Some(OwnerLink::Shutdown) => Ok(Some(WindowFailureOwner::Shutdown)),
            None => Ok(None),
        }
    }

    fn request_owner(&mut self, sequence: u64) -> Result<Option<WindowFailureOwner>> {
        let route = match self.primary_requests.get(&sequence) {
            Some(RequestRoute::Encoded(document)) => {
                read_primary_route(document, &mut self.segments)?
            }
            Some(RequestRoute::Resolved(route)) => return Ok(Some(owner(route.clone()))),
            None => return Ok(None),
        };
        self.primary_requests
            .insert(sequence, RequestRoute::Resolved(route.clone()));
        Ok(Some(owner(route)))
    }

    fn target_admission_required(&mut self, sequence: u64) -> Result<bool> {
        while let Some(decision) = self.schedule.peek() {
            if decision
                .as_ref()
                .is_ok_and(|decision| decision.sequence > sequence)
            {
                break;
            }
            let decision = self.schedule.next().expect("peeked schedule decision")?;
            if decision.sequence == sequence && decision.driver_prelude.is_some() {
                return Ok(false);
            }
        }
        Ok(!self.unscheduled.contains(&sequence))
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
    use traffic_protocol::connection::DriverPrelude;

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
        for (sequence, event) in [
            (
                7,
                CaptureEvent::MessageStarted {
                    dependency_sequence: 7,
                },
            ),
            (
                8,
                CaptureEvent::Output {
                    dependency_sequence: 7,
                    output: OutputKind::End,
                },
            ),
            (
                9,
                CaptureEvent::Started {
                    dependency_sequence: 9,
                    phase: CapturePhase::Shutdown,
                    observed_case: None,
                    admitted_case: None,
                },
            ),
            (
                10,
                CaptureEvent::Started {
                    dependency_sequence: 10,
                    phase: CapturePhase::Runtime,
                    observed_case: None,
                    admitted_case: None,
                },
            ),
            (
                11,
                CaptureEvent::Started {
                    dependency_sequence: 11,
                    phase: CapturePhase::Runtime,
                    observed_case: None,
                    admitted_case: None,
                },
            ),
        ] {
            ledger
                .append_event(
                    &mut files,
                    &RecordedEvent {
                        sequence,
                        offset_micros: 60,
                        event,
                    },
                )
                .await?;
        }
        ledger.note_unscheduled_admission(10);
        for (sequence, offset_micros, path) in [
            (12, 61, "/included?detail=yes"),
            (13, 62, "/probe"),
            (14, 60_000_060, "/last"),
            (15, 60_000_061, "/outside"),
        ] {
            ledger.append_session_event(&mut files, &RecordedEvent {
                sequence,
                offset_micros,
                event: SessionEvent::PrimaryRequest {
                    exchange: IdentityKind::Case.bridge(epoch, sequence),
                    request: json!({"method": "GET", "uri": path, "_session_probe": sequence == 13}),
                },
            }).await?;
        }
        let decisions = vec![session_schedule::SessionDecision {
            sequence: 11,
            step: None,
            driver_prelude: Some(DriverPrelude::MysqlSqlalchemyPymysql),
        }];
        let identities = ledger.seal_with_schedule(&mut files, decisions).await?;
        write_session_manifest(root, epoch, process, identities)?;

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
        let before = primary_dispatch_window(root, 3, 60_000_000, 0)?;
        assert_eq!(
            before.dependencies.get(&4),
            Some(&Some(WindowFailureOwner::Request(PrimaryRoute {
                method: "POST".into(),
                path: "/previous".into(),
            })))
        );
        let window = primary_dispatch_window(root, 6, 60_000_000, 0)?;
        assert_eq!(window.through_sequence, 14);
        assert_eq!(window.failure_owner, None);
        assert_eq!(
            window.dependencies,
            [(6, None), (9, Some(WindowFailureOwner::Shutdown))].into(),
        );
        assert_eq!(
            window
                .requests
                .iter()
                .map(|(&seq, route)| (seq, route.path.as_str()))
                .collect::<Vec<_>>(),
            [(12, "/included"), (14, "/last")],
        );
        let rolled = primary_dispatch_window(root, 12, 60_000_000, window.through_sequence)?;
        assert_eq!(rolled.through_sequence, 15);
        assert_eq!(rolled.requests.keys().copied().collect::<Vec<_>>(), [15]);
        assert!(matches!(
            rolled.failure_owner,
            Some(WindowFailureOwner::Request(_))
        ));
        Ok(())
    }
}
