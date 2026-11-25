//! One immutable Source event catalog shared by all prepared Case scopes.
use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use anyhow::{Result, ensure};
use traffic_model::trace::{CaptureEvent, OutputKind, RecordedEvent};

use crate::{EventKind, SequencePlan, SourceEvent};

#[derive(Debug)]
pub struct SequenceCatalog {
    events: Box<[SourceEvent]>,
    postings: HashMap<u64, Vec<usize>>,
}

impl SequenceCatalog {
    pub fn prepare(
        events: impl IntoIterator<Item = RecordedEvent<CaptureEvent>>,
    ) -> Result<Arc<Self>> {
        Self::try_prepare(events.into_iter().map(Ok))
    }

    pub fn try_prepare(
        events: impl IntoIterator<Item = Result<RecordedEvent<CaptureEvent>>>,
    ) -> Result<Arc<Self>> {
        let source = project_events(events)?;
        SequencePlan::compile(source.iter().copied())?;
        let mut postings = HashMap::<u64, Vec<usize>>::new();
        for (index, event) in source.iter().enumerate() {
            postings
                .entry(event.dependency_sequence)
                .or_default()
                .push(index);
        }
        Ok(Arc::new(Self {
            events: source.into_boxed_slice(),
            postings,
        }))
    }

    /// Traverse only the selected dependencies' postings, then freeze their
    /// original global order once. Payloads and foreign Cases are never read.
    pub fn scope(&self, dependencies: impl IntoIterator<Item = u64>) -> Result<Arc<SequencePlan>> {
        let mut selected = Vec::new();
        let mut unique = HashSet::new();
        for dependency in dependencies {
            if !unique.insert(dependency) {
                continue;
            }
            let positions = self.postings.get(&dependency).ok_or_else(|| {
                anyhow::anyhow!("dependency {dependency} has no recorded event trace")
            })?;
            selected.extend(positions.iter().map(|index| self.events[*index]));
        }
        selected.sort_unstable_by_key(|event| event.sequence);
        SequencePlan::compile(selected)
    }
}

impl SequencePlan {
    pub fn compile_recorded(
        events: impl IntoIterator<Item = Result<RecordedEvent<CaptureEvent>>>,
    ) -> Result<Arc<Self>> {
        Self::compile(project_events(events)?)
    }

    pub fn compile_session(
        events: impl IntoIterator<Item = Result<SessionPlanEvent>>,
    ) -> Result<Arc<Self>> {
        let events = project_timeline(events)?;
        ensure!(
            events
                .windows(2)
                .all(|pair| pair[0].offset_micros <= pair[1].offset_micros),
            "session Source event offsets are not monotonic"
        );
        Self::compile(events)
    }
}

pub enum SessionPlanEvent {
    Dependency(RecordedEvent<CaptureEvent>),
    Driver(SourceEvent),
}

fn project_events(
    events: impl IntoIterator<Item = Result<RecordedEvent<CaptureEvent>>>,
) -> Result<Vec<SourceEvent>> {
    let mut projected = project_timeline(
        events
            .into_iter()
            .map(|event| event.map(SessionPlanEvent::Dependency)),
    )?;
    projected.sort_unstable_by_key(|event| event.sequence);
    Ok(projected)
}

fn project_timeline(
    events: impl IntoIterator<Item = Result<SessionPlanEvent>>,
) -> Result<Vec<SourceEvent>> {
    let mut source = Vec::new();
    let mut sequences = HashSet::new();
    let mut wire_terminals = HashSet::new();
    let mut capture_terminals = HashSet::new();
    let mut output_starts = std::collections::HashMap::new();
    let mut cancelled = HashSet::new();
    for record in events {
        let record = match record? {
            SessionPlanEvent::Dependency(record) => record,
            SessionPlanEvent::Driver(event) => {
                source.push(event);
                continue;
            }
        };
        let started = matches!(&record.event, CaptureEvent::OutputStarted { .. });
        ensure!(
            record.sequence != 0 && sequences.insert(record.sequence),
            "invalid or duplicate recording event sequence"
        );
        let (dependency_sequence, kind) = match record.event {
            CaptureEvent::OutputCancelled {
                dependency_sequence,
                started_sequence,
            } => {
                ensure!(
                    output_starts.get(&started_sequence) == Some(&dependency_sequence)
                        && cancelled.insert(started_sequence),
                    "Source output cancellation has no matching start"
                );
                continue;
            }
            CaptureEvent::Output {
                dependency_sequence,
                output,
                ..
            }
            | CaptureEvent::OutputStarted {
                dependency_sequence,
                output,
                ..
            } => {
                if started {
                    output_starts.insert(record.sequence, dependency_sequence);
                }
                let kind = match output {
                    OutputKind::Headers => EventKind::ResponseHeaders,
                    OutputKind::Part => EventKind::ResponsePart,
                    OutputKind::End => EventKind::ResponseEnd,
                    OutputKind::NoResponse => EventKind::NoResponse,
                    OutputKind::TargetStop => EventKind::TargetStop,
                    OutputKind::Terminated { termination } => match termination.side {
                        traffic_model::TerminationSide::Client => EventKind::ClientTermination,
                        _ => EventKind::ServerTermination,
                    },
                };
                if kind.is_terminal() && !started {
                    wire_terminals.insert(dependency_sequence);
                }
                (
                    dependency_sequence,
                    if started { kind.started() } else { kind },
                )
            }
            CaptureEvent::MessageStarted {
                dependency_sequence,
                ..
            } => (dependency_sequence, EventKind::Message),
            CaptureEvent::Started {
                dependency_sequence,
                ..
            } => (dependency_sequence, EventKind::Request),
            CaptureEvent::Terminal {
                dependency_sequence,
                outcome,
                ..
            } => {
                let kind = match outcome.as_str() {
                    "client_terminated" => EventKind::ClientTermination,
                    "server_terminated" => EventKind::ServerTermination,
                    "no_response" => EventKind::NoResponse,
                    _ => EventKind::ResponseEnd,
                };
                capture_terminals.insert(record.sequence);
                (dependency_sequence, kind)
            }
            CaptureEvent::Bound { .. }
            | CaptureEvent::Sealed
            | CaptureEvent::PrimaryBoundary { .. }
            | CaptureEvent::Input { .. } => continue,
        };
        source.push(SourceEvent {
            sequence: record.sequence,
            dependency_sequence,
            offset_micros: record.offset_micros,
            kind,
        });
    }
    source.retain(|event| {
        !cancelled.contains(&event.sequence)
            && !(capture_terminals.contains(&event.sequence)
                && wire_terminals.contains(&event.dependency_sequence))
    });
    Ok(source)
}
