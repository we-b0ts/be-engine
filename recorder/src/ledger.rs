//! Run-wide request admission and capture lifetime, independent of business ownership.
use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};

use chrono::{DateTime, Utc};
use tokio::sync::Notify;
use uuid::Uuid;

use traffic_model::recording::{CaptureCoverage, CapturePhase, ProtocolRef};
use traffic_model::trace::OutputKind;

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
    pending: BTreeMap<Uuid, PendingAdmission>,
    incomplete: Vec<Uuid>,
}

struct PendingAdmission {
    sequence: u64,
    outputs: BTreeSet<u64>,
}

#[derive(Clone)]
pub struct CaptureReservation(Arc<Admission>);

pub struct OutputReservation {
    capture: CaptureReservation,
    output: OutputKind,
    started_sequence: Option<u64>,
}

impl OutputReservation {
    pub fn commit(mut self) {
        self.finish(true);
    }

    fn finish(&mut self, delivered: bool) {
        let Some(started_sequence) = self.started_sequence.take() else {
            return;
        };
        let admission = &self.capture.0;
        let mut facts = admission.facts.lock().expect("capture facts poisoned");
        let registry = &admission.registry.0;
        let mut state = registry.state.lock().expect("capture registry poisoned");
        let Some(pending) = state.pending.get_mut(&admission.exchange_id) else {
            return;
        };
        pending.outputs.remove(&started_sequence);
        let event = if delivered && !facts.wire_terminal {
            facts.wire_terminal = matches!(
                self.output,
                OutputKind::End
                    | OutputKind::NoResponse
                    | OutputKind::TargetStop
                    | OutputKind::Terminated { .. }
            );
            LifecycleRecord::Output {
                dependency_sequence: admission.sequence,
                output: self.output,
            }
        } else {
            LifecycleRecord::OutputCancelled {
                dependency_sequence: admission.sequence,
                started_sequence,
            }
        };
        if registry.writer.try_record_lifecycle(event).is_err() {
            state.inventory_gaps = true;
        }
    }
}

impl Drop for OutputReservation {
    fn drop(&mut self) {
        self.finish(false);
    }
}

struct Admission {
    registry: CaptureRegistry,
    exchange_id: Uuid,
    sequence: u64,
    message: bool,
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
    pub fn note_successful_connection(&self) -> anyhow::Result<()> {
        let result = self.0.writer.try_record_successful_connection();
        if result.is_err() {
            self.mark_inventory_gap();
        }
        result
    }

    pub fn session_event(
        &self,
        event: traffic_model::session::SessionEvent,
    ) -> anyhow::Result<u64> {
        let result = self.0.writer.try_record_session_event(event);
        if result.is_err() {
            self.mark_inventory_gap();
        }
        result
    }

    pub fn primary_boundary(&self, case_id: Uuid, boundary: traffic_model::trace::PrimaryBoundary) {
        if self
            .0
            .writer
            .try_record_lifecycle(LifecycleRecord::PrimaryBoundary { case_id, boundary })
            .is_err()
        {
            self.mark_inventory_gap();
        }
    }

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
        self.begin_interaction(phase, observed_case, admitted_case, false)
    }

    pub fn begin_message(
        &self,
        phase: CapturePhase,
        observed_case: Option<Uuid>,
        admitted_case: Option<Uuid>,
    ) -> Option<CaptureReservation> {
        self.begin_interaction(phase, observed_case, admitted_case, true)
    }

    fn begin_interaction(
        &self,
        phase: CapturePhase,
        observed_case: Option<Uuid>,
        admitted_case: Option<Uuid>,
        message: bool,
    ) -> Option<CaptureReservation> {
        let started_at = Utc::now();
        let mut state = self.0.state.lock().expect("capture registry poisoned");
        if state.closed {
            state.inventory_gaps = true;
            return None;
        }
        let started = self.0.writer.try_publish_lifecycle(|sequence| {
            if message {
                LifecycleRecord::MessageStarted {
                    dependency_sequence: sequence,
                }
            } else {
                LifecycleRecord::Started {
                    dependency_sequence: sequence,
                    phase,
                    observed_case,
                    admitted_case,
                }
            }
        });
        let sequence = match started {
            Ok(sequence) => sequence,
            Err(_) => {
                state.inventory_gaps = true;
                self.0.writer.clock.next_dependency().ok()?
            }
        };
        let exchange_id = traffic_model::recording::identity::IdentityKind::Dependency
            .bridge(self.0.writer.clock.recording_id(), sequence);
        state.admitted += 1;
        state.pending.insert(
            exchange_id,
            PendingAdmission {
                sequence,
                outputs: Default::default(),
            },
        );
        Some(CaptureReservation(Arc::new(Admission {
            registry: self.clone(),
            exchange_id,
            sequence,
            message,
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

    pub fn next_case_id(&self) -> Uuid {
        self.0.writer.clock.next_case_id()
    }

    pub fn recording_id(&self) -> Uuid {
        self.0.writer.clock.recording_id()
    }

    pub fn next_connection_id(&self) -> Uuid {
        self.0.writer.clock.next_connection_id()
    }

    pub fn finish_incomplete(&self) {
        let mut state = self.0.state.lock().expect("capture registry poisoned");
        let pending = std::mem::take(&mut state.pending);
        for admission in pending.values() {
            for &started_sequence in &admission.outputs {
                if self
                    .0
                    .writer
                    .try_record_lifecycle(LifecycleRecord::OutputCancelled {
                        dependency_sequence: admission.sequence,
                        started_sequence,
                    })
                    .is_err()
                {
                    state.inventory_gaps = true;
                }
            }
            if self
                .0
                .writer
                .try_record_lifecycle(LifecycleRecord::Terminal {
                    dependency_sequence: admission.sequence,
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
        state.incomplete.extend(pending.into_keys());
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
    pub fn dependency_id(&self) -> u64 {
        self.0.sequence
    }

    pub(crate) fn is_message(&self) -> bool {
        self.0.message
    }

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

    /// Publish the output attempt before bytes become visible. Its delivery
    /// receipt is published separately after the successful write.
    pub fn prepare_output(
        &self,
        output: traffic_model::trace::OutputKind,
    ) -> Option<OutputReservation> {
        let facts = self.0.facts.lock().expect("capture facts poisoned");
        if facts.wire_terminal {
            return None;
        }
        let registry = &self.0.registry.0;
        let mut state = registry.state.lock().expect("capture registry poisoned");
        let pending = state.pending.get_mut(&self.0.exchange_id)?;
        match registry
            .writer
            .try_publish_lifecycle(|_| LifecycleRecord::OutputStarted {
                dependency_sequence: self.0.sequence,
                output,
            }) {
            Ok(started_sequence) => {
                pending.outputs.insert(started_sequence);
                Some(OutputReservation {
                    capture: self.clone(),
                    output,
                    started_sequence: Some(started_sequence),
                })
            }
            Err(_) => {
                state.inventory_gaps = true;
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
        self.0
            .facts
            .lock()
            .expect("capture facts poisoned")
            .protocol_ref = protocol_ref;
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
