//! Prepared event order and finite delivery transactions, independent of protocols.
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;

use anyhow::{Result, bail, ensure};
use serde::{Deserialize, Serialize};

pub mod index;
pub mod output;
pub mod preparation;
pub mod report;
pub mod request;
pub mod request_wait;
pub mod rules;
mod scope;
pub use scope::ReplaySource;
mod startup;
pub use startup::StartupCounts;
mod status;
pub use status::ReplayExchangeStatus;
mod sequence_binding;
pub use sequence_binding::SequenceBinding;
mod waiting;
pub use waiting::{WaitOutcome, WaitRegistration};
mod request_order;
pub use request_order::RequestOrder;
mod admission;
pub use admission::{Barrier, ClaimKind, ClaimTicket, DeliveryGuard, Finish, Lifecycle};

mod catalog;
pub use catalog::SequenceCatalog;
mod runtime;
pub use runtime::{PendingRequest, SequenceClaim, SequenceRuntime};
mod ingress;
pub use ingress::AdmissionQueue;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventKind {
    Request,
    ResponseHeaders,
    ResponsePart,
    ResponseEnd,
    ClientTermination,
    ServerTermination,
    NoResponse,
    TargetStop,
    ResponseHeadersStarted,
    ResponsePartStarted,
    ResponseEndStarted,
    ClientTerminationStarted,
    ServerTerminationStarted,
    NoResponseStarted,
    TargetStopStarted,
}

impl EventKind {
    fn started(self) -> Self {
        match self {
            Self::ResponseHeaders => Self::ResponseHeadersStarted,
            Self::ResponsePart => Self::ResponsePartStarted,
            Self::ResponseEnd => Self::ResponseEndStarted,
            Self::ClientTermination => Self::ClientTerminationStarted,
            Self::ServerTermination => Self::ServerTerminationStarted,
            Self::NoResponse => Self::NoResponseStarted,
            Self::TargetStop => Self::TargetStopStarted,
            kind => kind,
        }
    }
    fn delivered(self) -> Self {
        match self {
            Self::ResponseHeadersStarted => Self::ResponseHeaders,
            Self::ResponsePartStarted => Self::ResponsePart,
            Self::ResponseEndStarted => Self::ResponseEnd,
            Self::ClientTerminationStarted => Self::ClientTermination,
            Self::ServerTerminationStarted => Self::ServerTermination,
            Self::NoResponseStarted => Self::NoResponse,
            Self::TargetStopStarted => Self::TargetStop,
            kind => kind,
        }
    }
    fn is_started(self) -> bool {
        self != self.delivered()
    }
    fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::ResponseEnd
                | Self::ClientTermination
                | Self::ServerTermination
                | Self::NoResponse
                | Self::TargetStop
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceEvent {
    pub sequence: u64,
    pub dependency_sequence: u64,
    pub offset_micros: u64,
    pub kind: EventKind,
}

#[derive(Debug, Clone, Copy)]
struct PreparedEvent {
    source: SourceEvent,
    slot: usize,
    receipt_cursor: usize,
}

/// Compiled once for a frozen scope. Live execution only indexes the cursor
/// and dense slot state; it never scans unrelated Source dependencies.
#[derive(Debug)]
pub struct SequencePlan {
    events: Box<[PreparedEvent]>,
    slots: HashMap<u64, usize>,
}

impl SequencePlan {
    pub fn compile(events: impl IntoIterator<Item = SourceEvent>) -> Result<Arc<Self>> {
        let mut prepared: Vec<PreparedEvent> = Vec::new();
        let mut slots = HashMap::new();
        let mut complete = Vec::new();
        let mut open = Vec::<VecDeque<usize>>::new();
        let mut previous = 0;
        for source in events {
            ensure!(
                source.sequence > previous,
                "Source event order is not strictly increasing"
            );
            ensure!(
                source.dependency_sequence != 0,
                "Source dependency sequence is zero"
            );
            previous = source.sequence;
            let slot = if source.kind == EventKind::Request {
                let slot = slots.len();
                ensure!(
                    slots.insert(source.dependency_sequence, slot).is_none(),
                    "Source dependency has duplicate request events"
                );
                complete.push(false);
                open.push(VecDeque::new());
                slot
            } else {
                let slot = *slots
                    .get(&source.dependency_sequence)
                    .ok_or_else(|| anyhow::anyhow!("Source response has no preceding request"))?;
                ensure!(
                    !complete[slot],
                    "Source dependency has an event after its terminal event"
                );
                if source.kind.is_started() {
                    open[slot].push_back(prepared.len());
                } else if let Some(start) = open[slot].pop_front() {
                    ensure!(
                        prepared[start].source.kind.delivered() == source.kind,
                        "Source output receipt differs from its start"
                    );
                    prepared[start].receipt_cursor = prepared.len();
                }
                complete[slot] = source.kind.is_terminal();
                slot
            };
            prepared.push(PreparedEvent {
                source,
                slot,
                receipt_cursor: prepared.len(),
            });
        }
        ensure!(
            complete.iter().all(|terminal| *terminal),
            "Source dependency has no terminal event"
        );
        ensure!(
            open.iter().all(VecDeque::is_empty),
            "Source output has no delivery receipt"
        );
        Ok(Arc::new(Self {
            events: prepared.into_boxed_slice(),
            slots,
        }))
    }

    pub fn event_count(&self) -> usize {
        self.events.len()
    }

    pub fn dependency_count(&self) -> usize {
        self.slots.len()
    }

    pub fn contains(&self, dependency: u64) -> bool {
        self.slots.contains_key(&dependency)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SlotState {
    Available,
    Admitted,
    Delivering,
    Consumed,
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Admission {
    Accepted,
    Waiting(SourceEvent),
}

/// A receipt is bound to the exact reserved cursor and delivery generation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeliveryTicket {
    cursor: usize,
    generation: u64,
    slot: usize,
}

#[derive(Debug)]
pub struct SequenceScheduler {
    plan: Arc<SequencePlan>,
    cursor: usize,
    slots: Vec<SlotState>,
    generation: u64,
    pending_delivery: HashMap<usize, (DeliveryTicket, bool)>,
    diagnosis: Option<(usize, u64)>,
    failed: bool,
}

impl SequenceScheduler {
    fn consecutive_parts(&self, dependency: u64, limit: usize) -> usize {
        let mut count = 0;
        let mut cursor = self.cursor;
        while count < limit {
            let Some(event) = self.plan.events.get(cursor) else {
                break;
            };
            if event.source.dependency_sequence != dependency {
                break;
            }
            match event.source.kind {
                EventKind::ResponsePart => {
                    count += 1;
                    cursor += 1;
                }
                EventKind::ResponsePartStarted
                    if count > 0 && event.receipt_cursor == cursor + 1 =>
                {
                    cursor += 1
                }
                _ => break,
            }
        }
        count
    }
    fn receipt_source(&self, ticket: DeliveryTicket) -> SourceEvent {
        self.plan.events[ticket.cursor].source
    }
    fn receipt_published(&self, ticket: DeliveryTicket) -> bool {
        self.cursor > ticket.cursor
    }

    pub fn new(plan: Arc<SequencePlan>) -> Self {
        let count = plan.dependency_count();
        Self {
            slots: vec![SlotState::Available; count],
            plan,
            cursor: 0,
            generation: 0,
            pending_delivery: HashMap::new(),
            diagnosis: None,
            failed: false,
        }
    }

    pub fn expected(&self) -> Option<SourceEvent> {
        self.plan.events.get(self.cursor).map(|event| event.source)
    }

    /// Call after the current native request and shared value rules have matched.
    /// A later request stays outside the finite claim until its recorded turn.
    pub fn admit(&mut self, dependency_sequence: u64) -> Result<Admission> {
        ensure!(!self.failed, "Replay sequence has failed");
        let slot = self.plan.slots.get(&dependency_sequence).ok_or_else(|| {
            anyhow::anyhow!("request has no dependency in the frozen Source scope")
        })?;
        ensure!(
            self.slots[*slot] == SlotState::Available,
            "dependency is already admitted"
        );
        let Some(next) = self.plan.events.get(self.cursor) else {
            bail!("request arrived after the recorded event sequence completed");
        };
        if next.source.kind != EventKind::Request
            || next.source.dependency_sequence != dependency_sequence
        {
            return Ok(Admission::Waiting(next.source));
        }
        ensure!(
            self.slots[next.slot] == SlotState::Available,
            "dependency is already admitted"
        );
        self.slots[next.slot] = SlotState::Admitted;
        self.cursor += 1;
        self.drain_receipts();
        Ok(Admission::Accepted)
    }

    /// A native output start authorizes I/O and releases subsequent readers.
    /// Its separately ordered completion still requires the actual wire receipt.
    pub fn reserve_delivery(&mut self, dependency_sequence: u64) -> Result<Option<DeliveryTicket>> {
        ensure!(!self.failed, "Replay sequence has failed");
        let Some(next) = self.plan.events.get(self.cursor).copied() else {
            return Ok(None);
        };
        if next.source.kind == EventKind::Request
            || next.source.dependency_sequence != dependency_sequence
        {
            return Ok(None);
        }
        ensure!(
            !self.pending_delivery.contains_key(&next.receipt_cursor),
            "sequence output is already reserved"
        );
        ensure!(
            matches!(
                self.slots[next.slot],
                SlotState::Admitted | SlotState::Delivering
            ),
            "output has no admitted request"
        );
        self.generation = self
            .generation
            .checked_add(1)
            .ok_or_else(|| anyhow::anyhow!("delivery generation exhausted"))?;
        let ticket = DeliveryTicket {
            cursor: next.receipt_cursor,
            generation: self.generation,
            slot: next.slot,
        };
        self.pending_delivery.insert(ticket.cursor, (ticket, false));
        self.slots[next.slot] = SlotState::Delivering;
        if next.source.kind.is_started() {
            self.cursor += 1;
            self.drain_receipts();
        }
        Ok(Some(ticket))
    }

    pub fn finish_delivery(&mut self, ticket: DeliveryTicket, succeeded: bool) -> Result<()> {
        ensure!(!self.failed, "Replay sequence has failed");
        ensure!(
            self.pending_delivery.get(&ticket.cursor).copied() == Some((ticket, false)),
            "delivery receipt is stale or already committed"
        );
        if !succeeded {
            self.slots[ticket.slot] = SlotState::Failed;
            self.failed = true;
            bail!("recorded event delivery failed");
        }
        self.pending_delivery.insert(ticket.cursor, (ticket, true));
        self.drain_receipts();
        Ok(())
    }

    fn drain_receipts(&mut self) {
        while let Some(next) = self.plan.events.get(self.cursor) {
            let Some((ticket, true)) = self.pending_delivery.get(&self.cursor).copied() else {
                break;
            };
            if ticket.cursor != self.cursor {
                break;
            }
            self.pending_delivery.remove(&self.cursor);
            self.slots[next.slot] = if next.source.kind.is_terminal() {
                SlotState::Consumed
            } else {
                SlotState::Admitted
            };
            self.cursor += 1;
        }
    }

    /// Deduplicate a bounded missing-request diagnosis under one ownership view.
    pub fn missing_request(&mut self, ownership_revision: u64) -> Option<SourceEvent> {
        let expected = self.expected()?;
        if expected.kind != EventKind::Request
            || self.diagnosis == Some((self.cursor, ownership_revision))
        {
            return None;
        }
        self.diagnosis = Some((self.cursor, ownership_revision));
        Some(expected)
    }

    pub fn consumed(&self, dependency_sequence: u64) -> bool {
        self.plan
            .slots
            .get(&dependency_sequence)
            .is_some_and(|slot| self.slots[*slot] == SlotState::Consumed)
    }

    pub fn complete(&self) -> bool {
        !self.failed && self.cursor == self.plan.events.len()
    }

    pub fn abort(&mut self) {
        self.failed = true;
    }
    pub fn failed(&self) -> bool {
        self.failed
    }
}

#[cfg(test)]
mod tests;

pub mod candidate_selection;
pub mod case;
pub mod command;
pub mod exchange;
pub mod input;
