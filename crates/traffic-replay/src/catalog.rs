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
        let mut source = Vec::new();
        let mut sequences = HashSet::new();
        let mut wire_terminals = HashSet::new();
        let mut capture_terminals = Vec::new();
        for record in events {
            let record = record?;
            let started = matches!(&record.event, CaptureEvent::OutputStarted { .. });
            ensure!(
                record.sequence != 0 && sequences.insert(record.sequence),
                "invalid or duplicate recording event sequence"
            );
            let (dependency_sequence, kind) = match record.event {
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
                    capture_terminals.push(SourceEvent {
                        sequence: record.sequence,
                        dependency_sequence,
                        offset_micros: record.offset_micros,
                        kind,
                    });
                    continue;
                }
                CaptureEvent::Bound { .. }
                | CaptureEvent::Sealed { .. }
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
        source.extend(
            capture_terminals
                .into_iter()
                .filter(|event| !wire_terminals.contains(&event.dependency_sequence)),
        );
        source.sort_unstable_by_key(|event| event.sequence);
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
