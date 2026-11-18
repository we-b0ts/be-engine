//! Run-wide request admission and capture lifetime, independent of business ownership.
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use chrono::{DateTime, Utc};
use tokio::sync::Notify;
use uuid::Uuid;

use traffic_model::recording::{CaptureCoverage, CapturePhase, ProtocolRef};

use super::writer::RecorderWriter;

pub(crate) mod persistence;

pub use traffic_model::trace::CaptureEvent as LifecycleRecord;

#[derive(Clone)]
pub struct CaptureRegistry(Arc<Registry>);

struct Registry {
    process_epoch: Uuid,
    state: Mutex<State>,
    changed: Notify,
    writer: RecorderWriter,
}

#[derive(Default)]
struct State {
    closed: bool,
    admitted: u64,
    terminal: u64,
    failures: u64,
    inventory_gaps: bool,
    pending: BTreeMap<Uuid, u64>,
    incomplete: Vec<Uuid>,
}

#[derive(Clone)]
pub struct CaptureReservation(Arc<Admission>);

pub struct OutputReservation {
    capture: CaptureReservation,
    event: traffic_model::trace::RecordedEvent<LifecycleRecord>,
}

impl OutputReservation {
    pub fn commit(self) {
        let LifecycleRecord::OutputStarted { output, .. } = &self.event.event else {
            unreachable!("reserved output event");
        };
        let mut facts = self.capture.0.facts.lock().expect("capture facts poisoned");
        if facts.wire_terminal {
            return;
        }
        let receipt = self
            .capture
            .0
            .registry
            .0
            .writer
            .clock
            .event(LifecycleRecord::Output {
                exchange_id: self.capture.0.exchange_id,
                dependency_sequence: self.capture.0.sequence,
                output: *output,
            });
        use traffic_model::trace::OutputKind;
        facts.wire_terminal = matches!(
            output,
            OutputKind::End
                | OutputKind::NoResponse
                | OutputKind::TargetStop
                | OutputKind::Terminated { .. }
        );
        let result = self
            .capture
            .0
            .registry
            .0
            .writer
            .try_record_sequenced_lifecycle(self.event)
            .and_then(|()| {
                self.capture
                    .0
                    .registry
                    .0
                    .writer
                    .try_record_sequenced_lifecycle(receipt?)
            });
        if result.is_err() {
            self.capture.0.registry.mark_inventory_gap();
        }
    }
}

struct Admission {
    registry: CaptureRegistry,
    exchange_id: Uuid,
    sequence: u64,
    phase: CapturePhase,
    observed_case: Option<Uuid>,
    admitted_case: Option<Uuid>,
    started_at: DateTime<Utc>,
    facts: Mutex<AdmissionFacts>,
}

struct AdmissionFacts {
    transformations: Vec<Arc<traffic_model::recording::Transformation>>,
    wire_terminal: bool,
    protocol_ref: ProtocolRef,
    terminal: Option<(String, bool)>,
    next_effect: u32,
}

impl std::fmt::Debug for CaptureReservation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("CaptureReservation")
            .field(&self.0.exchange_id)
            .finish()
    }
}

impl CaptureRegistry {
    pub fn input(
        &self,
        case_id: Uuid,
        input_sequence: u64,
        kind: traffic_model::trace::InputKind,
    ) -> anyhow::Result<()> {
        let result = self.0.writer.try_record_lifecycle(LifecycleRecord::Input {
            case_id,
            input_sequence,
            kind,
        });
        if result.is_err() {
            self.mark_inventory_gap();
        }
        result
    }
    pub fn new(writer: RecorderWriter, process_epoch: Uuid) -> Self {
        Self(Arc::new(Registry {
            process_epoch,
            state: Mutex::new(State::default()),
            changed: Notify::new(),
            writer,
        }))
    }

    pub fn begin(
        &self,
        phase: CapturePhase,
        observed_case: Option<Uuid>,
        admitted_case: Option<Uuid>,
    ) -> Option<CaptureReservation> {
        let exchange_id = Uuid::new_v4();
        let started_at = Utc::now();
        let mut state = self.0.state.lock().expect("capture registry poisoned");
        if state.closed {
            state.inventory_gaps = true;
            return None;
        }
        let started = self
            .0
            .writer
            .clock
            .begin_dependency(|sequence| LifecycleRecord::Started {
                exchange_id,
                dependency_sequence: sequence,
                process_epoch: self.0.process_epoch,
                phase,
                observed_case,
                admitted_case,
                started_at,
            });
        let (sequence, event) = match started {
            Ok(started) => started,
            Err(_) => {
                state.inventory_gaps = true;
                return None;
            }
        };
        state.admitted += 1;
        state.pending.insert(exchange_id, sequence);
        if self.0.writer.try_record_sequenced_lifecycle(event).is_err() {
            state.inventory_gaps = true;
        }
        Some(CaptureReservation(Arc::new(Admission {
            registry: self.clone(),
            exchange_id,
            sequence,
            phase,
            observed_case,
            admitted_case,
            started_at,
            facts: Mutex::new(AdmissionFacts {
                transformations: Vec::new(),
                wire_terminal: false,
                protocol_ref: ProtocolRef::observation(exchange_id, "pending_dependency"),
                terminal: None,
                next_effect: 0,
            }),
        })))
    }

    pub fn close(&self) {
        self.0
            .state
            .lock()
            .expect("capture registry poisoned")
            .closed = true;
    }

    pub fn mark_inventory_gap(&self) {
        self.0
            .state
            .lock()
            .expect("capture registry poisoned")
            .inventory_gaps = true;
    }

    pub async fn drain(&self, timeout: std::time::Duration) -> bool {
        tokio::time::timeout(timeout, async {
            loop {
                let changed = self.0.changed.notified();
                if self
                    .0
                    .state
                    .lock()
                    .expect("capture registry poisoned")
                    .pending
                    .is_empty()
                {
                    return;
                }
                changed.await;
            }
        })
        .await
        .is_ok()
    }

    pub fn epoch(&self) -> Uuid {
        self.0.process_epoch
    }

    pub fn finish_incomplete(&self) {
        let mut state = self.0.state.lock().expect("capture registry poisoned");
        let pending = state.pending.keys().copied().collect::<Vec<_>>();
        for exchange_id in &pending {
            if self
                .0
                .writer
                .try_record_lifecycle(LifecycleRecord::Terminal {
                    exchange_id: *exchange_id,
                    dependency_sequence: state.pending[exchange_id],
                    outcome: "incomplete_at_stop".into(),
                    capture_complete: false,
                })
                .is_err()
            {
                state.inventory_gaps = true;
            }
        }
        state.terminal += pending.len() as u64;
        state.failures += pending.len() as u64;
        state.incomplete.extend(pending);
        state.pending.clear();
    }

    pub fn coverage(&self) -> CaptureCoverage {
        let state = self.0.state.lock().expect("capture registry poisoned");
        CaptureCoverage {
            admitted: state.admitted,
            terminal: state.terminal,
            capture_failures: state.failures,
            inventory_gaps: state.inventory_gaps,
            pending: state
                .pending
                .keys()
                .chain(state.incomplete.iter())
                .copied()
                .collect(),
        }
    }
}

impl CaptureReservation {
    pub fn exchange_id(&self) -> Uuid {
        self.0.exchange_id
    }
    pub fn wire_terminal(&self) -> bool {
        self.0
            .facts
            .lock()
            .expect("capture facts poisoned")
            .wire_terminal
    }
    pub fn transformed(&self, transformation: traffic_model::recording::Transformation) {
        self.0
            .facts
            .lock()
            .expect("capture facts poisoned")
            .transformations
            .push(Arc::new(transformation));
    }
    pub fn output(&self, output: traffic_model::trace::OutputKind) {
        if let Some(reserved) = self.prepare_output(output) {
            reserved.commit();
        }
    }

    /// Reserve ordering before bytes become visible. Publication still requires
    /// the actual flush, keeping a client's causally subsequent request later.
    pub fn prepare_output(
        &self,
        output: traffic_model::trace::OutputKind,
    ) -> Option<OutputReservation> {
        if self.wire_terminal() {
            return None;
        }
        match self
            .0
            .registry
            .0
            .writer
            .clock
            .event(LifecycleRecord::OutputStarted {
                exchange_id: self.0.exchange_id,
                dependency_sequence: self.0.sequence,
                output,
            }) {
            Ok(event) => Some(OutputReservation {
                capture: self.clone(),
                event,
            }),
            Err(_) => {
                self.0.registry.mark_inventory_gap();
                None
            }
        }
    }

    pub fn delivery_failed(&self) {
        if !self
            .0
            .facts
            .lock()
            .expect("capture facts poisoned")
            .wire_terminal
        {
            self.note_terminal("wire_delivery_failed".into(), false);
        }
    }
    pub fn bind_protocol(&self, protocol_ref: ProtocolRef) {
        let mut facts = self.0.facts.lock().expect("capture facts poisoned");
        if facts.protocol_ref == protocol_ref {
            return;
        }
        facts.protocol_ref = protocol_ref.clone();
        if self
            .0
            .registry
            .0
            .writer
            .try_record_lifecycle(LifecycleRecord::Bound {
                exchange_id: self.0.exchange_id,
                dependency_sequence: self.0.sequence,
                protocol_ref,
            })
            .is_err()
        {
            self.0
                .registry
                .0
                .state
                .lock()
                .expect("capture registry poisoned")
                .inventory_gaps = true;
        }
    }

    pub fn finish_metadata(&self, outcome: &str) {
        self.note_terminal(outcome.into(), true);
    }

    pub fn note_terminal(&self, outcome: String, complete: bool) {
        let mut facts = self.0.facts.lock().expect("capture facts poisoned");
        match &mut facts.terminal {
            Some((_, previous_complete)) => *previous_complete &= complete,
            None => facts.terminal = Some((outcome, complete)),
        }
    }

    pub fn metadata(
        &self,
        attribution: traffic_model::attribution::DependencyOwner,
        semantic_required: bool,
    ) -> traffic_model::recording::CaptureMetadata {
        let mut facts = self.0.facts.lock().expect("capture facts poisoned");
        let effect_index = facts.next_effect;
        facts.next_effect += 1;
        traffic_model::recording::CaptureMetadata {
            transformations: facts.transformations.clone(),
            exchange_id: self.0.exchange_id,
            sequence: self.0.sequence,
            process_epoch: self.0.registry.epoch(),
            phase: self.0.phase,
            observed_case: self.0.observed_case,
            admitted_case: self.0.admitted_case,
            started_at: self.0.started_at,
            protocol_ref: facts.protocol_ref.clone(),
            attribution,
            matched_rule_id: None,
            matched_rule_ids: Vec::new(),
            effect_index,
            semantic_required,
        }
    }
}

impl Drop for Admission {
    fn drop(&mut self) {
        let terminal = self
            .facts
            .lock()
            .expect("capture facts poisoned")
            .terminal
            .take()
            .unwrap_or_else(|| ("capture_dropped_without_terminal".into(), false));
        let mut state = self
            .registry
            .0
            .state
            .lock()
            .expect("capture registry poisoned");
        if state.pending.remove(&self.exchange_id).is_none() {
            return;
        }
        if self
            .registry
            .0
            .writer
            .try_record_lifecycle(LifecycleRecord::Terminal {
                exchange_id: self.exchange_id,
                dependency_sequence: self.sequence,
                outcome: terminal.0,
                capture_complete: terminal.1,
            })
            .is_err()
        {
            state.inventory_gaps = true;
        }
        state.terminal += 1;
        if !terminal.1 {
            state.failures += 1;
        }
        self.registry.0.changed.notify_waiters();
    }
}
