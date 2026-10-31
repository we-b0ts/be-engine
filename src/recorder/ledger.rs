//! Run-wide request admission and capture lifetime, independent of business ownership.
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use chrono::{DateTime, Utc};
use serde::Serialize;
use tokio::sync::Notify;
use uuid::Uuid;

use crate::dependency::observation::{CaptureCoverage, CapturePhase, ProtocolRef};

use super::writer::RecorderWriter;

pub(super) mod event;
pub(super) mod persistence;
#[cfg(test)]
mod tests;

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "event_type", rename_all = "snake_case")]
pub(super) enum LifecycleRecord {
    #[serde(rename = "capture_started")]
    Started {
        exchange_id: Uuid,
        process_epoch: Uuid,
        phase: CapturePhase,
        observed_case: Option<Uuid>,
        admitted_case: Option<Uuid>,
        started_at: DateTime<Utc>,
    },
    #[serde(rename = "capture_bound")]
    Bound {
        exchange_id: Uuid,
        protocol_ref: ProtocolRef,
    },
    #[serde(rename = "capture_terminated")]
    Terminal {
        exchange_id: Uuid,
        outcome: String,
        capture_complete: bool,
    },
    #[serde(rename = "capture_sealed")]
    Sealed {
        process_epoch: Uuid,
        coverage: CaptureCoverage,
    },
}

#[derive(Clone)]
pub(crate) struct CaptureRegistry(Arc<Registry>);

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
    pending: BTreeMap<Uuid, ()>,
    incomplete: Vec<Uuid>,
}

#[derive(Clone)]
pub(crate) struct CaptureReservation(Arc<Admission>);

struct Admission {
    registry: CaptureRegistry,
    exchange_id: Uuid,
    phase: CapturePhase,
    observed_case: Option<Uuid>,
    admitted_case: Option<Uuid>,
    started_at: DateTime<Utc>,
    facts: Mutex<AdmissionFacts>,
}

struct AdmissionFacts {
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
    pub(super) fn new(writer: RecorderWriter, process_epoch: Uuid) -> Self {
        Self(Arc::new(Registry {
            process_epoch,
            state: Mutex::new(State::default()),
            changed: Notify::new(),
            writer,
        }))
    }

    pub(crate) fn begin(
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
        state.admitted += 1;
        state.pending.insert(exchange_id, ());
        if self
            .0
            .writer
            .try_record_lifecycle(LifecycleRecord::Started {
                exchange_id,
                process_epoch: self.0.process_epoch,
                phase,
                observed_case,
                admitted_case,
                started_at,
            })
            .is_err()
        {
            state.inventory_gaps = true;
        }
        Some(CaptureReservation(Arc::new(Admission {
            registry: self.clone(),
            exchange_id,
            phase,
            observed_case,
            admitted_case,
            started_at,
            facts: Mutex::new(AdmissionFacts {
                protocol_ref: ProtocolRef::Observation {
                    event_id: exchange_id,
                    kind: "pending_dependency".into(),
                },
                terminal: None,
                next_effect: 0,
            }),
        })))
    }

    pub(crate) fn close(&self) {
        self.0
            .state
            .lock()
            .expect("capture registry poisoned")
            .closed = true;
    }

    pub(crate) fn mark_inventory_gap(&self) {
        self.0
            .state
            .lock()
            .expect("capture registry poisoned")
            .inventory_gaps = true;
    }

    pub(crate) async fn drain(&self, timeout: std::time::Duration) -> bool {
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

    pub(super) fn epoch(&self) -> Uuid {
        self.0.process_epoch
    }

    pub(super) fn finish_incomplete(&self) {
        let mut state = self.0.state.lock().expect("capture registry poisoned");
        let pending = state.pending.keys().copied().collect::<Vec<_>>();
        for exchange_id in &pending {
            if self
                .0
                .writer
                .try_record_lifecycle(LifecycleRecord::Terminal {
                    exchange_id: *exchange_id,
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

    pub(super) fn coverage(&self) -> CaptureCoverage {
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
    pub(crate) fn bind_protocol(&self, protocol_ref: ProtocolRef) {
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

    pub(crate) fn finish_metadata(&self, outcome: &str) {
        self.note_terminal(outcome.into(), true);
    }

    pub(super) fn note_terminal(&self, outcome: String, complete: bool) {
        let mut facts = self.0.facts.lock().expect("capture facts poisoned");
        match &mut facts.terminal {
            Some((_, previous_complete)) => *previous_complete &= complete,
            None => facts.terminal = Some((outcome, complete)),
        }
    }

    pub(super) fn metadata(
        &self,
        attribution: crate::dependency::attribution::DependencyOwner,
        semantic_required: bool,
    ) -> crate::dependency::observation::CaptureMetadata {
        let mut facts = self.0.facts.lock().expect("capture facts poisoned");
        let effect_index = facts.next_effect;
        facts.next_effect += 1;
        crate::dependency::observation::CaptureMetadata {
            exchange_id: self.0.exchange_id,
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
