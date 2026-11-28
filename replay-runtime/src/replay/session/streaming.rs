//! Read a bounded upcoming window of the sealed Session in global Source order.
use super::{Session, TIMER_SCOPE, driver_event, locations::Locations};
use crate::replay::*;
use std::collections::{HashMap, VecDeque};
use std::iter::Peekable;
use traffic_model::trace::{CaptureEvent, OutputKind, RecordedEvent};
use traffic_protocol::connection::{DriverPrelude, ReplaySessionStep};
use traffic_recording_store::{
    session_schedule::{self, SessionDecision},
    session_summary::SessionSummary,
    session_timeline::{self, SessionTimelineEvent},
    source::{FileStamp, RecordReader, RecordRef, RecordSource, RecordStream},
};
use traffic_replay::{EventKind, SequenceRuntime, SourceEvent, StreamEvent};

const LOW_WATER: usize = 256;
const BATCH_EVENTS: usize = 128;
const BATCH_BYTES: u64 = 8 * 1024 * 1024;
const MAX_ACTIVE_DEPENDENCIES: usize = 16_384;

type Tape<T> = Box<dyn Iterator<Item = Result<T>> + Send>;

pub(in crate::replay) struct Source {
    timeline: Tape<SessionTimelineEvent>,
    decisions: Peekable<Tape<SessionDecision>>,
    descriptor_tape: RecordStream,
    descriptors: Arc<RecordSource>,
    displaced: Locations,
    active: HashMap<u64, Trace>,
    cancelled_starts: BTreeSet<u64>,
    pending_cancellations: HashMap<u64, u64>,
    unscheduled_admissions: BTreeSet<u64>,
    timer_anchors: BTreeMap<u64, EventKind>,
    mandatory_count: usize,
    mandatory_seen: usize,
    at: Option<u64>,
}

#[derive(Default)]
struct Trace {
    outputs: VecDeque<(u64, EventKind)>,
}

struct Admission {
    sequence: u64,
    reference: RecordRef,
    step: Option<ReplaySessionStep>,
    prelude: Option<DriverPrelude>,
    emission: bool,
}

struct Entry {
    event: Option<StreamEvent>,
    admission: Option<Admission>,
}

struct Batch {
    entries: Vec<Entry>,
    end: Option<Result<(), (Option<u64>, anyhow::Error)>>,
}

impl Source {
    pub(in crate::replay) fn open(
        root: &Path,
        summary: SessionSummary,
        mandatory_count: usize,
        timer_anchors: BTreeMap<u64, EventKind>,
        reader: Arc<std::sync::Mutex<RecordReader>>,
    ) -> Result<(Self, StreamEvent)> {
        let mut timeline = Box::new(session_timeline::read(root)?) as Tape<_>;
        let first = match timeline.next().transpose()? {
            Some(SessionTimelineEvent::Primary(event)) => driver_event(event),
            _ => anyhow::bail!("Session timeline does not start with Source launch"),
        };
        ensure!(
            first.kind == EventKind::SessionSourceStart,
            "Session timeline does not start with Source launch"
        );
        let path = root.join(traffic_recording_store::session::FILE);
        let descriptor_tape = RecordStream::open_for_replay(&path)?;
        let descriptors = RecordSource::new(&path, FileStamp::read_native(&path)?, reader);
        let decisions = Box::new(session_schedule::read(root)?) as Tape<_>;
        let mut source = Self {
            timeline,
            decisions: decisions.peekable(),
            descriptor_tape,
            descriptors,
            displaced: Default::default(),
            active: Default::default(),
            cancelled_starts: summary.cancelled_output_starts.into_iter().collect(),
            pending_cancellations: Default::default(),
            unscheduled_admissions: summary.unscheduled_admissions.into_iter().collect(),
            timer_anchors,
            mandatory_count,
            mandatory_seen: 0,
            at: Some(first.sequence),
        };
        source.validate_anchor(first)?;
        Ok((
            source,
            StreamEvent {
                source: first,
                receipt_start: None,
            },
        ))
    }

    fn locate(&mut self, sequence: u64, runtime: &SequenceRuntime) -> Result<RecordRef> {
        if let Some(location) = self.displaced.take(sequence)? {
            return Ok(self.descriptors.reference(location));
        }
        while let Some((candidate, location)) =
            self.descriptor_tape.next_session_reference_for_replay()?
        {
            if candidate == sequence {
                return Ok(self.descriptors.reference(location));
            }
            self.displaced.insert(candidate, location)?;
            ensure!(
                !runtime.failed(),
                "Session stopped before Source preparation completed"
            );
        }
        anyhow::bail!("Source dependency {sequence} has no compact descriptor")
    }

    fn decision(&mut self, sequence: u64) -> Result<Option<SessionDecision>> {
        match self.decisions.peek() {
            Some(Ok(decision)) if decision.sequence > sequence => Ok(None),
            Some(Ok(decision)) if decision.sequence < sequence => {
                anyhow::bail!(
                    "Source scope decision {} has no matching admission",
                    decision.sequence
                )
            }
            Some(_) => self.decisions.next().transpose(),
            None => Ok(None),
        }
    }

    fn validate_anchor(&mut self, event: SourceEvent) -> Result<()> {
        if let Some((&sequence, &kind)) = self.timer_anchors.first_key_value()
            && sequence <= event.sequence
        {
            ensure!(
                sequence == event.sequence && kind == event.kind,
                "Replay timer anchor {sequence} does not identify a {kind:?} in the Source session"
            );
            self.timer_anchors.pop_first();
        }
        Ok(())
    }

    fn dependency(
        &mut self,
        event: RecordedEvent<CaptureEvent>,
        runtime: &SequenceRuntime,
    ) -> Result<Option<Entry>> {
        let Some(dependency) = event.event.dependency_sequence() else {
            return Ok(None);
        };
        let mut admission = None;
        let (kind, receipt_start) = match event.event {
            CaptureEvent::Started { .. } | CaptureEvent::MessageStarted { .. } => {
                ensure!(
                    dependency == event.sequence,
                    "Source dependency admission is out of order"
                );
                let decision = self.decision(dependency)?;
                if self.unscheduled_admissions.remove(&dependency) {
                    ensure!(
                        decision.is_none(),
                        "excluded Source observation has a scope decision"
                    );
                    return Ok(None);
                }
                let (step, prelude) = decision.map_or((None, None), |decision| {
                    (decision.step, decision.driver_prelude)
                });
                let reference = self.locate(dependency, runtime)?;
                self.mandatory_seen += 1;
                let emission = matches!(event.event, CaptureEvent::MessageStarted { .. });
                admission = Some(Admission {
                    sequence: dependency,
                    reference,
                    step,
                    prelude,
                    emission,
                });
                if prelude.is_some() {
                    return Ok(Some(Entry {
                        event: None,
                        admission,
                    }));
                }
                ensure!(
                    self.active.len() < MAX_ACTIVE_DEPENDENCIES
                        && self.active.insert(dependency, Trace::default()).is_none(),
                    "Session outstanding dependency limit exceeded at Source sequence {dependency}"
                );
                (
                    if emission {
                        EventKind::Message
                    } else {
                        EventKind::Request
                    },
                    None,
                )
            }
            CaptureEvent::OutputStarted { output, .. } => {
                if self.cancelled_starts.remove(&event.sequence) {
                    self.pending_cancellations
                        .insert(event.sequence, dependency);
                    return Ok(None);
                }
                let Some(trace) = self.active.get_mut(&dependency) else {
                    return Ok(None);
                };
                let (started, delivered) = output_kinds(output);
                trace.outputs.push_back((event.sequence, delivered));
                (started, None)
            }
            CaptureEvent::OutputCancelled {
                started_sequence, ..
            } => {
                ensure!(
                    self.pending_cancellations.remove(&started_sequence) == Some(dependency),
                    "Source output cancellation at {} has no matching start",
                    event.sequence,
                );
                return Ok(None);
            }
            CaptureEvent::Output { output, .. } => {
                let Some(trace) = self.active.get_mut(&dependency) else {
                    return Ok(None);
                };
                let (_, delivered) = output_kinds(output);
                let receipt_start = if let Some((started, expected)) = trace.outputs.pop_front() {
                    ensure!(
                        expected == delivered,
                        "Source output at {} differs from its start",
                        event.sequence
                    );
                    Some(started)
                } else {
                    None
                };
                if terminal(delivered) {
                    ensure!(
                        trace.outputs.is_empty(),
                        "Source dependency terminated with outstanding outputs"
                    );
                    self.active.remove(&dependency);
                }
                (delivered, receipt_start)
            }
            CaptureEvent::Terminal { outcome, .. } => {
                let Some(trace) = self.active.remove(&dependency) else {
                    return Ok(None);
                };
                ensure!(
                    trace.outputs.is_empty(),
                    "Source dependency capture terminated with outstanding outputs"
                );
                let delivered = match outcome.as_str() {
                    "client_terminated" => EventKind::ClientTermination,
                    "server_terminated" => EventKind::ServerTermination,
                    "no_response" => EventKind::NoResponse,
                    _ => EventKind::ResponseEnd,
                };
                (delivered, None)
            }
            _ => return Ok(None),
        };
        let source = SourceEvent {
            sequence: event.sequence,
            offset_micros: event.offset_micros,
            dependency_sequence: dependency,
            kind,
        };
        Ok(Some(Entry {
            event: Some(StreamEvent {
                source,
                receipt_start,
            }),
            admission,
        }))
    }

    fn next(&mut self, runtime: &SequenceRuntime) -> Result<Option<Entry>> {
        loop {
            self.at = None;
            let Some(row) = self.timeline.next().transpose()? else {
                break;
            };
            let entry = match row {
                SessionTimelineEvent::Primary(event) => {
                    self.at = Some(event.sequence);
                    Some(Entry {
                        event: Some(StreamEvent {
                            source: driver_event(event),
                            receipt_start: None,
                        }),
                        admission: None,
                    })
                }
                SessionTimelineEvent::Dependency(event) => {
                    self.at = Some(event.sequence);
                    self.dependency(event, runtime)?
                }
            };
            if let Some(entry) = entry {
                if let Some(event) = &entry.event {
                    self.validate_anchor(event.source)?;
                }
                return Ok(Some(entry));
            }
        }
        ensure!(
            self.active.is_empty(),
            "Source Session ended with unterminated dependencies"
        );
        ensure!(
            self.cancelled_starts.is_empty()
                && self.pending_cancellations.is_empty()
                && self.unscheduled_admissions.is_empty(),
            "Source Session disposition has no matching lifecycle row"
        );
        ensure!(
            self.decisions.next().transpose()?.is_none(),
            "Source scope decision has no matching admission"
        );
        ensure!(
            self.timer_anchors.is_empty(),
            "Replay timer anchor is outside the Source Session"
        );
        ensure!(
            self.mandatory_seen == self.mandatory_count,
            "Source scheduled {} mandatory dependencies; the seal declares {}",
            self.mandatory_seen,
            self.mandatory_count
        );
        Ok(None)
    }

    fn read_batch(&mut self, runtime: &SequenceRuntime) -> Batch {
        let mut entries = Vec::with_capacity(BATCH_EVENTS);
        let mut bytes = 0;
        while entries.len() < BATCH_EVENTS && bytes < BATCH_BYTES {
            match self.next(runtime) {
                Ok(Some(entry)) => {
                    bytes += entry
                        .admission
                        .as_ref()
                        .map_or(0, |admission| admission.reference.location.length);
                    entries.push(entry);
                }
                Ok(None) => {
                    return Batch {
                        entries,
                        end: Some(Ok(())),
                    };
                }
                Err(error) => {
                    return Batch {
                        entries,
                        end: Some(Err((self.at, error))),
                    };
                }
            }
        }
        Batch { entries, end: None }
    }

    #[cfg(test)]
    pub(super) fn append_test_window(&mut self, runtime: &SequenceRuntime) -> Result<()> {
        let Batch { entries, end } = self.read_batch(runtime);
        let complete = end
            .context("fixture exceeds one Source window")?
            .map_err(|(_, error)| error);
        complete?;
        runtime.push_stream(
            entries
                .into_iter()
                .filter_map(|entry| entry.event)
                .collect(),
            true,
        )
    }
}

fn output_kinds(output: OutputKind) -> (EventKind, EventKind) {
    use EventKind::*;
    match output {
        OutputKind::Headers => (ResponseHeadersStarted, ResponseHeaders),
        OutputKind::Part => (ResponsePartStarted, ResponsePart),
        OutputKind::End => (ResponseEndStarted, ResponseEnd),
        OutputKind::NoResponse => (NoResponseStarted, NoResponse),
        OutputKind::TargetStop => (TargetStopStarted, TargetStop),
        OutputKind::Terminated { termination } => match termination.side {
            traffic_model::TerminationSide::Client => (ClientTerminationStarted, ClientTermination),
            _ => (ServerTerminationStarted, ServerTermination),
        },
    }
}

fn terminal(kind: EventKind) -> bool {
    matches!(
        kind,
        EventKind::ResponseEnd
            | EventKind::ClientTermination
            | EventKind::ServerTermination
            | EventKind::NoResponse
            | EventKind::TargetStop
    )
}

pub(in crate::replay) async fn install<P: ReplayProtocolSet>(
    state: &mut RuntimeState<P>,
    summary: SessionSummary,
    mandatory_count: usize,
    reader: Arc<std::sync::Mutex<RecordReader>>,
    timeout: std::time::Duration,
) -> Result<Source> {
    let root = state.root_dir.clone();
    let anchors = state.timers.stream_session_anchors(TIMER_SCOPE)?;
    let cap = control::input_timing::source_fast_cap(state).map(std::time::Duration::from_millis);
    let runtime = SequenceRuntime::streaming_session(cap, anchors.keys().copied());
    let (source, first) = tokio::task::spawn_blocking(move || {
        Source::open(&root, summary, mandatory_count, anchors, reader)
    })
    .await
    .context("Session source opening task failed")??;
    runtime.push_stream(vec![first], false)?;
    state.native.configure_session_identities(mandatory_count)?;
    state.timers.activate(Some(TIMER_SCOPE));
    state.native.core.lifecycle.sequence.attach_run(
        traffic_replay::SequenceBinding::streaming_session(runtime.clone()),
    );
    let mut session = Session::new(runtime, timeout);
    session.prefetch = Some(super::prefetch::Responses::rolling());
    state.session_events = Some(session);
    Ok(source)
}

pub(in crate::replay) async fn start<P: ReplayProtocolSet>(
    state: &Arc<Mutex<RuntimeState<P>>>,
    source: Source,
) {
    let mut locked = state.lock().await;
    let targets = locked
        .targets
        .iter()
        .cloned()
        .map(|target| {
            (
                TargetKey {
                    host: target.host.clone(),
                    port: target.port,
                },
                target,
            )
        })
        .collect();
    let session = locked.session_events.as_mut().expect("streaming Session");
    let runtime = session.runtime.clone();
    let state = Arc::downgrade(state);
    let prefetch = session.prefetch.clone().expect("rolling prefetch");
    session.stream_task =
        Some(tokio::spawn(produce(source, runtime, state, targets, prefetch)).abort_handle());
}

async fn produce<P: ReplayProtocolSet>(
    mut source: Source,
    runtime: Arc<SequenceRuntime>,
    state: std::sync::Weak<Mutex<RuntimeState<P>>>,
    mut targets: BTreeMap<TargetKey, ReplayTarget>,
    prefetch: Arc<super::prefetch::Responses>,
) {
    let mut changed = runtime.subscribe();
    while runtime.progress().matched == 0 && !runtime.failed() {
        if changed.changed().await.is_err() {
            return;
        }
    }
    while !runtime.failed() {
        if runtime.buffered() > LOW_WATER {
            if changed.changed().await.is_err() {
                return;
            }
            continue;
        }
        let prepare = runtime.clone();
        let result = tokio::task::spawn_blocking(move || {
            let batch = source.read_batch(&prepare);
            (source, batch)
        })
        .await;
        let (next, batch) = match result {
            Ok(loaded) => loaded,
            Err(error) => {
                fail_after_prefix(&runtime, &state, None, error.into()).await;
                return;
            }
        };
        source = next;
        let Batch { entries, mut end } = batch;
        let mut events = Vec::with_capacity(entries.len());
        let mut responses = Vec::new();
        let released = {
            let Some(state) = state.upgrade() else {
                return;
            };
            let mut state = state.lock().await;
            if runtime.failed() || state.finalized_at.is_some() {
                return;
            }
            let root = state.root_dir.clone();
            let result = state.native.core.discard_completed(&runtime);
            if result.is_ok() {
                for Entry { event, admission } in entries {
                    if let Some(admission) = admission {
                        let sequence = admission.sequence;
                        match register(&mut state.native, &root, &mut targets, admission) {
                            Ok(Some(index)) => {
                                if let Some(response) =
                                    state.native.stored_response_preparation(index)
                                {
                                    responses.push((index, response));
                                }
                            }
                            Ok(None) => {}
                            Err(error) => {
                                end = Some(Err((Some(sequence), error)));
                                break;
                            }
                        }
                    }
                    events.extend(event);
                }
            }
            state.native.core.seal();
            result
        };
        if let Err(error) = released {
            fail_after_prefix(&runtime, &state, None, error).await;
            return;
        }
        prefetch.submit(responses);
        let finished = matches!(&end, Some(Ok(())));
        if let Err(error) = runtime.push_stream(events, finished) {
            fail_after_prefix(&runtime, &state, source.at, error).await;
            return;
        }
        match end {
            Some(Ok(())) => return,
            Some(Err((sequence, error))) => {
                fail_after_prefix(&runtime, &state, sequence, error).await;
                return;
            }
            None => {}
        }
    }
}

fn register(
    native: &mut native::Inventory,
    root: &Path,
    targets: &mut BTreeMap<TargetKey, ReplayTarget>,
    admission: Admission,
) -> Result<Option<usize>> {
    let sequence = admission.sequence;
    let reference = admission.reference;
    let metadata = reference.load_metadata()?;
    ensure!(
        metadata["capture"]["sequence"].as_u64() == Some(sequence)
            && metadata["capture"]["semantic_required"] == true,
        "Source dependency descriptor at sequence {sequence} is not mandatory"
    );
    if let Some(proof) = admission.prelude {
        ensure!(
            admission.step.is_none(),
            "Source driver prelude has a business step"
        );
        native.exclude_driver_prelude(&metadata, proof)?;
        return Ok(None);
    }
    let secrets = traffic_engine_replay::request_headers::SourceSecrets::new(root);
    if admission.emission
        && admission.step.is_none()
        && native.register_stored_emission(
            &metadata,
            ReplaySource::Startup,
            targets,
            reference.clone(),
            &secrets,
        )?
    {
        return Ok(Some(usize::try_from(sequence)?));
    }
    if !admission.emission
        && native.register_stored_request(
            &metadata,
            ReplaySource::Startup,
            targets,
            reference.clone(),
            &secrets,
            admission.step.clone(),
        )?
    {
        return Ok(Some(usize::try_from(sequence)?));
    }
    let event = reference.load_value()?;
    native.register_scoped(
        &event,
        ReplaySource::Startup,
        None,
        reference.location.line,
        targets,
        &secrets,
        admission.step,
    )?;
    ensure!(
        native
            .core
            .exchanges
            .get(usize::try_from(sequence)?)
            .is_some(),
        "mandatory Source dependency at sequence {sequence} is unavailable"
    );
    Ok(Some(usize::try_from(sequence)?))
}

async fn fail_after_prefix<P: ReplayProtocolSet>(
    runtime: &SequenceRuntime,
    state: &std::sync::Weak<Mutex<RuntimeState<P>>>,
    sequence: Option<u64>,
    error: anyhow::Error,
) {
    let mut changed = runtime.subscribe();
    while !runtime.failed() {
        if runtime.buffered() == 0 {
            if let Some(state) = state.upgrade()
                && let Some(session) = &mut state.lock().await.session_events
            {
                session.fail(
                    sequence,
                    None,
                    &format!("prepare Source Session event: {error:#}"),
                );
            }
            return;
        }
        if changed.changed().await.is_err() {
            return;
        }
    }
}
