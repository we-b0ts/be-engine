//! Shared finite dependency admission and delivery transactions.
//!
//! Callers retain the existing ReplayState mutex for claim/finalization. The
//! per-claim receipt publishes wire progress without acquiring that mutex.
use super::{ReplayExchangeStatus, ReplaySource};
use std::collections::HashMap;
use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicU8, Ordering},
};
use tokio::sync::Notify;

mod order;
pub(super) mod request;
mod waiting;
pub(super) use order::RequestOrder;
pub(super) use waiting::{RequestAdmission, WaitOutcome, WaitRegistration};
#[cfg(test)]
mod tests;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Barrier {
    Admitted,
    Delivered,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ClaimKind {
    Response,
    ClientTermination,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum NativeClaimKind {
    ReusableSnapshot,
    StateObservation,
    ActivityRefresh,
    AppendStream,
}

/// Native repeat/coalescing operators own their explicit multi-slot accounting.
/// Ordinary finite exchanges must always carry a shared finite ticket.
#[derive(Debug, Clone)]
pub(super) enum Claim {
    Finite(ClaimTicket),
    Native(NativeClaimKind),
}

const CLAIMED: u8 = 0;
const WIRE: u8 = 1;
const CONSUMED: u8 = 2;
const FAILED: u8 = 3;

#[derive(Debug)]
struct Receipt {
    phase: AtomicU8,
    awaiting_termination: AtomicBool,
}

#[derive(Debug, Clone)]
pub(super) struct ClaimTicket {
    index: usize,
    generation: u64,
    receipt: Arc<Receipt>,
    changed: Arc<Notify>,
    cancelled: Arc<std::sync::Mutex<Vec<(usize, u64)>>>,
    // Inventory observers never own this lease. The last actual matched
    // request cancels even if delivery's future has not been polled yet.
    _owner: Option<Arc<ClaimOwner>>,
}
#[derive(Debug)]
struct ClaimOwner {
    ticket: ClaimTicket,
}
impl Drop for ClaimOwner {
    fn drop(&mut self) {
        cancel(&self.ticket);
    }
}
impl ClaimTicket {
    pub(super) fn observer(&self) -> Self {
        Self {
            index: self.index,
            generation: self.generation,
            receipt: self.receipt.clone(),
            changed: self.changed.clone(),
            cancelled: self.cancelled.clone(),
            _owner: None,
        }
    }
    /// Publish after the actual native wire operation has succeeded. This fact
    /// is deliberately distinct from successful evidence/semantic commit.
    pub(super) fn publish_wire(&self) -> bool {
        let changed = self
            .receipt
            .phase
            .compare_exchange(CLAIMED, WIRE, Ordering::AcqRel, Ordering::Acquire)
            .is_ok();
        if changed {
            self.changed.notify_waiters();
        }
        changed
    }
    pub(super) fn satisfies(&self, barrier: Barrier) -> bool {
        let phase = self.receipt.phase.load(Ordering::Acquire);
        phase == CONSUMED
            || barrier == Barrier::Admitted
                && !self.receipt.awaiting_termination.load(Ordering::Acquire)
                && matches!(phase, CLAIMED | WIRE)
    }
    pub(super) fn guard(&self) -> DeliveryGuard {
        DeliveryGuard {
            ticket: self.clone(),
            armed: true,
        }
    }
}

/// Cancellation cannot leave a live receipt that unblocks another request.
/// The finite slot remains unused until its owner reconciles the failed receipt.
pub(super) struct DeliveryGuard {
    ticket: ClaimTicket,
    armed: bool,
}
impl DeliveryGuard {
    /// Native delivery transferred its owning ticket to an asynchronous related
    /// effect. The lease still cancels if that queued owner is later discarded.
    pub(super) fn handoff(mut self) {
        self.armed = false;
    }
}
impl Drop for DeliveryGuard {
    fn drop(&mut self) {
        if self.armed {
            cancel(&self.ticket);
        }
    }
}
fn cancel(ticket: &ClaimTicket) {
    let receipt = &ticket.receipt;
    let mut phase = receipt.phase.load(Ordering::Acquire);
    while matches!(phase, CLAIMED | WIRE) {
        match receipt.phase.compare_exchange_weak(
            phase,
            FAILED,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => {
                ticket
                    .cancelled
                    .lock()
                    .expect("cancelled dependency claims")
                    .push((ticket.index, ticket.generation));
                ticket.changed.notify_waiters();
                break;
            }
            Err(current) => phase = current,
        }
    }
}

#[derive(Debug, Default)]
struct Slot {
    generation: u64,
    receipt: Option<Arc<Receipt>>,
}

#[derive(Debug, Default)]
pub(super) struct Lifecycle {
    // Sparse by actual claims: the first request in a late Case must not
    // allocate/initialize every unrelated earlier inventory position.
    slots: HashMap<usize, Slot>,
    changed: Arc<Notify>,
    cancelled: Arc<std::sync::Mutex<Vec<(usize, u64)>>>,
}

#[derive(Debug)]
pub(super) enum Finish<T> {
    Committed(T),
    Failed(anyhow::Error),
    Unchanged,
}

impl Lifecycle {
    pub(super) fn notify_waiters(&self) {
        self.changed.notify_waiters();
    }
    pub(super) fn claim(
        &mut self,
        index: usize,
        status: &mut ReplayExchangeStatus,
        kind: ClaimKind,
    ) -> Option<ClaimTicket> {
        if !status.is_available() {
            return None;
        }
        let slot = self.slots.entry(index).or_default();
        slot.generation = slot
            .generation
            .checked_add(1)
            .expect("finite claim generation overflow");
        let receipt = Arc::new(Receipt {
            phase: AtomicU8::new(CLAIMED),
            awaiting_termination: AtomicBool::new(kind == ClaimKind::ClientTermination),
        });
        slot.receipt = Some(receipt.clone());
        *status = match kind {
            ClaimKind::Response => ReplayExchangeStatus::Responding,
            ClaimKind::ClientTermination => ReplayExchangeStatus::AwaitingClientTermination,
        };
        let mut ticket = ClaimTicket {
            index,
            generation: slot.generation,
            receipt,
            changed: self.changed.clone(),
            cancelled: self.cancelled.clone(),
            _owner: None,
        };
        ticket._owner = Some(Arc::new(ClaimOwner {
            ticket: ticket.observer(),
        }));
        Some(ticket)
    }
    fn current(&self, ticket: &ClaimTicket) -> bool {
        self.slots.get(&ticket.index).is_some_and(|slot| {
            slot.generation == ticket.generation
                && slot
                    .receipt
                    .as_ref()
                    .is_some_and(|receipt| Arc::ptr_eq(receipt, &ticket.receipt))
        })
    }
    pub(super) fn wire_delivered(&self, ticket: &ClaimTicket) -> bool {
        self.current(ticket) && ticket.publish_wire()
    }
    pub(super) fn wait_client(
        &self,
        ticket: &ClaimTicket,
        status: &mut ReplayExchangeStatus,
    ) -> bool {
        if !self.current(ticket)
            || !matches!(ticket.receipt.phase.load(Ordering::Acquire), CLAIMED | WIRE)
        {
            return false;
        }
        *status = ReplayExchangeStatus::AwaitingClientTermination;
        ticket
            .receipt
            .awaiting_termination
            .store(true, Ordering::Release);
        true
    }
    /// The shared success/error transaction owns the only terminal transition.
    /// Native adapters provide only their protocol evidence/semantic commit.
    pub(super) fn finish<T>(
        &mut self,
        ticket: &ClaimTicket,
        status: &mut ReplayExchangeStatus,
        commit: impl FnOnce() -> anyhow::Result<T>,
    ) -> Finish<T> {
        if self.current(ticket)
            && ticket.receipt.phase.load(Ordering::Acquire) == FAILED
            && !matches!(
                *status,
                ReplayExchangeStatus::Consumed | ReplayExchangeStatus::Failed
            )
        {
            self.fail(ticket, status);
            return Finish::Failed(anyhow::anyhow!(
                "dependency delivery was cancelled before commit"
            ));
        }
        if !self.current(ticket)
            || matches!(
                *status,
                ReplayExchangeStatus::Consumed | ReplayExchangeStatus::Failed
            )
            || ticket.receipt.phase.load(Ordering::Acquire) != WIRE
        {
            return Finish::Unchanged;
        }
        match commit() {
            Ok(value) => {
                if ticket
                    .receipt
                    .phase
                    .compare_exchange(WIRE, CONSUMED, Ordering::AcqRel, Ordering::Acquire)
                    .is_err()
                {
                    self.fail(ticket, status);
                    return Finish::Unchanged;
                }
                *status = ReplayExchangeStatus::Consumed;
                self.changed.notify_waiters();
                Finish::Committed(value)
            }
            Err(error) => {
                self.fail(ticket, status);
                Finish::Failed(error)
            }
        }
    }
    pub(super) fn complete(
        &mut self,
        ticket: &ClaimTicket,
        status: &mut ReplayExchangeStatus,
    ) -> bool {
        matches!(
            self.finish(ticket, status, || Ok(())),
            Finish::Committed(())
        )
    }
    pub(super) fn fail(&mut self, ticket: &ClaimTicket, status: &mut ReplayExchangeStatus) -> bool {
        if !self.current(ticket)
            || matches!(
                *status,
                ReplayExchangeStatus::Consumed | ReplayExchangeStatus::Failed
            )
        {
            return false;
        }
        let mut phase = ticket.receipt.phase.load(Ordering::Acquire);
        loop {
            if phase == CONSUMED {
                return false;
            }
            if phase == FAILED {
                break;
            }
            match ticket.receipt.phase.compare_exchange_weak(
                phase,
                FAILED,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => break,
                Err(current) => phase = current,
            }
        }
        *status = ReplayExchangeStatus::Failed;
        self.changed.notify_waiters();
        true
    }
    pub(super) fn satisfies(
        status: ReplayExchangeStatus,
        source: ReplaySource,
        barrier: Barrier,
    ) -> bool {
        status.is_consumed()
            || barrier == Barrier::Admitted
                && source == ReplaySource::Case
                && status == ReplayExchangeStatus::Responding
    }
    pub(super) fn live_status(
        &self,
        index: usize,
        fallback: ReplayExchangeStatus,
    ) -> ReplayExchangeStatus {
        if !matches!(
            fallback,
            ReplayExchangeStatus::Responding | ReplayExchangeStatus::AwaitingClientTermination
        ) {
            return fallback;
        }
        match self
            .slots
            .get(&index)
            .and_then(|slot| slot.receipt.as_ref())
            .map(|receipt| receipt.phase.load(Ordering::Acquire))
        {
            Some(FAILED) => ReplayExchangeStatus::Failed,
            Some(CONSUMED) => ReplayExchangeStatus::Consumed,
            _ => fallback,
        }
    }
    pub(super) fn synchronize(&self, index: usize, status: &mut ReplayExchangeStatus) -> bool {
        let next = self.live_status(index, *status);
        let changed = next != *status;
        *status = next;
        changed
    }
    /// Sparse report overlays inspect actual cancellations, never all inventory.
    pub(super) fn cancelled_indices(&self) -> Vec<usize> {
        self.cancelled
            .lock()
            .expect("cancelled dependency claims")
            .iter()
            .filter_map(|(index, generation)| {
                self.slots
                    .get(index)
                    .filter(|slot| slot.generation == *generation)
                    .and_then(|slot| slot.receipt.as_ref())
                    .filter(|receipt| receipt.phase.load(Ordering::Acquire) == FAILED)
                    .map(|_| *index)
            })
            .collect()
    }
    /// Register while holding ReplayState's mutex, before releasing it to wait.
    pub(super) fn subscribe(&self) -> WaitRegistration {
        WaitRegistration::new(self.changed.clone())
    }
    pub(super) fn wait_for(&self, index: usize, barrier: Barrier) -> Option<WaitRegistration> {
        let receipt = self.slots.get(&index)?.receipt.as_ref()?;
        let phase = receipt.phase.load(Ordering::Acquire);
        let satisfied = phase == CONSUMED
            || barrier == Barrier::Admitted
                && !receipt.awaiting_termination.load(Ordering::Acquire)
                && matches!(phase, CLAIMED | WIRE);
        (!satisfied && matches!(phase, CLAIMED | WIRE)).then(|| self.subscribe())
    }
}
