//! Bounded asynchronous admission and real delivery receipts over a prepared cursor.
use crate::{Admission, DeliveryTicket, EventKind, SequencePlan, SequenceScheduler, SourceEvent};
use anyhow::{Context, Result, ensure};
use std::sync::{Arc, Mutex};
use tokio::{sync::watch, time::Instant};

const MAX_PENDING_REQUESTS: usize = 256;
const MAX_PENDING_BYTES: usize = 64 * 1024 * 1024;

#[derive(Debug)]
pub struct SequenceRuntime {
    state: Mutex<State>,
    changed: watch::Sender<u64>,
    requests_changed: watch::Sender<u64>,
    plan: Arc<SequencePlan>,
}

#[derive(Debug)]
struct State {
    scheduler: SequenceScheduler,
    pending: usize,
    pending_bytes: usize,
}

impl SequenceRuntime {
    pub fn new(plan: Arc<SequencePlan>) -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(State {
                scheduler: SequenceScheduler::new(plan.clone()),
                pending: 0,
                pending_bytes: 0,
            }),
            changed: watch::channel(0).0,
            requests_changed: watch::channel(0).0,
            plan,
        })
    }

    pub fn expected(&self) -> Option<SourceEvent> {
        self.state
            .lock()
            .expect("sequence runtime poisoned")
            .scheduler
            .expected()
    }

    pub fn contains(&self, dependency: u64) -> bool {
        self.plan.contains(dependency)
    }

    pub fn subscribe(&self) -> watch::Receiver<u64> {
        self.changed.subscribe()
    }

    pub fn subscribe_requests(&self) -> watch::Receiver<u64> {
        self.requests_changed.subscribe()
    }

    pub fn wake_requests(&self) {
        self.requests_changed
            .send_modify(|revision| *revision = revision.wrapping_add(1));
    }

    pub fn failed(&self) -> bool {
        self.state
            .lock()
            .expect("sequence runtime poisoned")
            .scheduler
            .failed()
    }

    pub fn abort(&self) {
        self.state
            .lock()
            .expect("sequence runtime poisoned")
            .scheduler
            .abort();
        self.notify();
    }

    fn notify(&self) {
        self.changed
            .send_modify(|revision| *revision = revision.wrapping_add(1));
        let state = self.state.lock().expect("sequence runtime poisoned");
        let request = state.scheduler.failed()
            || state
                .scheduler
                .expected()
                .is_none_or(|event| event.kind == EventKind::Request);
        drop(state);
        if request {
            self.wake_requests();
        }
    }

    pub fn admit(self: &Arc<Self>, dependency: u64) -> Result<SequenceClaim> {
        let mut state = self.state.lock().expect("sequence runtime poisoned");
        ensure!(
            state.scheduler.admit(dependency)? == Admission::Accepted,
            "request is earlier than its recorded sequence"
        );
        drop(state);
        self.notify();
        Ok(SequenceClaim(Arc::new(Claim {
            runtime: self.clone(),
            dependency,
            delivery: Mutex::new(Delivery::Waiting),
        })))
    }

    pub fn pending(self: &Arc<Self>, bytes: usize) -> Result<PendingRequest> {
        let mut state = self.state.lock().expect("sequence runtime poisoned");
        let pending_bytes = state
            .pending_bytes
            .checked_add(bytes)
            .context("pending request byte count overflow")?;
        ensure!(
            state.pending < MAX_PENDING_REQUESTS && pending_bytes <= MAX_PENDING_BYTES,
            "early dependency requests exceed the pending queue budget"
        );
        state.pending += 1;
        state.pending_bytes = pending_bytes;
        Ok(PendingRequest {
            runtime: self.clone(),
            bytes,
        })
    }

    pub fn missing_request(&self, ownership_revision: u64) -> Option<SourceEvent> {
        self.state
            .lock()
            .expect("sequence runtime poisoned")
            .scheduler
            .missing_request(ownership_revision)
    }

    pub fn complete(&self) -> bool {
        self.state
            .lock()
            .expect("sequence runtime poisoned")
            .scheduler
            .complete()
    }
}

pub struct PendingRequest {
    runtime: Arc<SequenceRuntime>,
    bytes: usize,
}

impl Drop for PendingRequest {
    fn drop(&mut self) {
        let mut state = self
            .runtime
            .state
            .lock()
            .expect("sequence runtime poisoned");
        state.pending -= 1;
        state.pending_bytes -= self.bytes;
    }
}

#[derive(Debug, Clone)]
pub struct SequenceClaim(Arc<Claim>);

#[derive(Debug)]
struct Claim {
    runtime: Arc<SequenceRuntime>,
    dependency: u64,
    delivery: Mutex<Delivery>,
}

#[derive(Debug, Clone, Copy)]
enum Delivery {
    Waiting,
    Reserved {
        ticket: DeliveryTicket,
        source: SourceEvent,
    },
    Published {
        ticket: DeliveryTicket,
        source: SourceEvent,
    },
    Finished,
    Failed,
}

impl Delivery {
    fn refresh(&mut self, scheduler: &SequenceScheduler) {
        if let Self::Published { ticket, source } = *self
            && scheduler.receipt_published(ticket)
        {
            *self = if source.kind.is_terminal() {
                Self::Finished
            } else {
                Self::Waiting
            };
        }
    }
}

impl SequenceClaim {
    pub fn belongs_to(&self, runtime: &SequenceRuntime) -> bool {
        std::ptr::eq(self.0.runtime.as_ref(), runtime)
    }
    pub fn pending(&self, bytes: usize) -> Result<PendingRequest> {
        self.0.runtime.pending(bytes)
    }
    pub fn reserved_kind(&self) -> Option<EventKind> {
        self.reserved_event().map(|event| event.kind)
    }
    pub fn reserved_event(&self) -> Option<SourceEvent> {
        match *self.0.delivery.lock().expect("sequence delivery poisoned") {
            Delivery::Reserved { source, .. } => Some(source),
            _ => None,
        }
    }
    pub fn fail(&self) {
        let mut delivery = self.0.delivery.lock().expect("sequence delivery poisoned");
        let mut state = self
            .0
            .runtime
            .state
            .lock()
            .expect("sequence runtime poisoned");
        delivery.refresh(&state.scheduler);
        if !matches!(*delivery, Delivery::Finished | Delivery::Failed) {
            state.scheduler.abort();
            *delivery = Delivery::Failed;
            drop(state);
            drop(delivery);
            self.0.runtime.notify();
        }
    }
    pub async fn wait_delivery(&self, deadline: Instant) -> Result<()> {
        self.wait_output(deadline, false, None).await
    }
    pub async fn wait_body_delivery(&self, deadline: Instant) -> Result<()> {
        self.wait_body_delivery_after(deadline, None).await
    }
    pub async fn wait_body_delivery_after(
        &self,
        deadline: Instant,
        after: Option<u64>,
    ) -> Result<()> {
        self.wait_output(deadline, true, after).await
    }

    async fn wait_output(
        &self,
        deadline: Instant,
        after_headers: bool,
        after: Option<u64>,
    ) -> Result<()> {
        let mut changed = self.0.runtime.subscribe();
        loop {
            {
                let mut delivery = self.0.delivery.lock().expect("sequence delivery poisoned");
                let mut state = self
                    .0
                    .runtime
                    .state
                    .lock()
                    .expect("sequence runtime poisoned");
                delivery.refresh(&state.scheduler);
                ensure!(
                    !state.scheduler.failed()
                        && !matches!(*delivery, Delivery::Finished | Delivery::Failed),
                    "sequence delivery is already finished or failed"
                );
                if let Delivery::Reserved { source, .. } = *delivery
                    && !(after_headers && source.kind == EventKind::ResponseHeaders)
                    && Some(source.sequence) != after
                {
                    return Ok(());
                }
                let headers = state
                    .scheduler
                    .expected()
                    .is_some_and(|event| event.kind.delivered() == EventKind::ResponseHeaders);
                if matches!(*delivery, Delivery::Waiting)
                    && !(after_headers && headers)
                    && let Some(ticket) = state.scheduler.reserve_delivery(self.0.dependency)?
                {
                    let source = state.scheduler.receipt_source(ticket);
                    *delivery = Delivery::Reserved { ticket, source };
                    drop(state);
                    drop(delivery);
                    self.0.runtime.notify();
                    return Ok(());
                }
            }
            tokio::time::timeout_at(deadline, changed.changed())
                .await
                .context("recorded output sequence wait timed out")?
                .context("recorded output sequence closed")?;
        }
    }

    /// Publish only after successful native write/flush or observed termination.
    /// A completed operation can await its recorded commit position while the
    /// framework continues accepting causally subsequent requests.
    pub fn publish(&self) -> Result<()> {
        self.publish_parts(1)
    }
    pub fn consecutive_parts(&self, limit: usize) -> usize {
        {
            let delivery = self.0.delivery.lock().expect("sequence delivery poisoned");
            if limit == 0
                || !matches!(
                    *delivery,
                    Delivery::Reserved {
                        source: SourceEvent {
                            kind: EventKind::ResponsePart,
                            ..
                        },
                        ..
                    }
                )
            {
                return 0;
            }
            self.0
                .runtime
                .state
                .lock()
                .expect("sequence runtime poisoned")
                .scheduler
                .consecutive_parts(self.0.dependency, limit)
                .max(1)
        }
    }
    pub fn publish_parts(&self, count: usize) -> Result<()> {
        let mut delivery = self.0.delivery.lock().expect("sequence delivery poisoned");
        let Delivery::Reserved { mut ticket, source } = *delivery else {
            anyhow::bail!("sequence output has no reserved wire delivery");
        };
        let mut state = self
            .0
            .runtime
            .state
            .lock()
            .expect("sequence runtime poisoned");
        ensure!(
            count > 0
                && (count == 1
                    || state.scheduler.consecutive_parts(self.0.dependency, count) == count),
            "wire receipt crosses a recorded output barrier"
        );
        state.scheduler.finish_delivery(ticket, true)?;
        for _ in 1..count {
            ticket = state
                .scheduler
                .reserve_delivery(self.0.dependency)?
                .context("contiguous output reservation is unavailable")?;
            state.scheduler.finish_delivery(ticket, true)?;
        }
        *delivery = if source.kind.is_terminal() {
            Delivery::Published { ticket, source }
        } else {
            Delivery::Waiting
        };
        delivery.refresh(&state.scheduler);
        drop(state);
        drop(delivery);
        self.0.runtime.notify();
        Ok(())
    }
    pub fn complete(&self) -> bool {
        let mut delivery = self.0.delivery.lock().expect("sequence delivery poisoned");
        let state = self
            .0
            .runtime
            .state
            .lock()
            .expect("sequence runtime poisoned");
        delivery.refresh(&state.scheduler);
        matches!(*delivery, Delivery::Finished)
    }
    pub async fn wait_complete(&self, deadline: Instant) -> Result<()> {
        let mut changed = self.0.runtime.subscribe();
        while !self.complete() {
            ensure!(!self.0.runtime.failed(), "sequence delivery failed");
            tokio::time::timeout_at(deadline, changed.changed())
                .await
                .context("sequence wire completion timed out")?
                .context("sequence runtime closed")?;
        }
        Ok(())
    }
}

impl Drop for Claim {
    fn drop(&mut self) {
        let mut delivery = self.delivery.lock().expect("sequence delivery poisoned");
        let mut state = self
            .runtime
            .state
            .lock()
            .expect("sequence runtime poisoned");
        delivery.refresh(&state.scheduler);
        if !matches!(*delivery, Delivery::Finished | Delivery::Failed) {
            state.scheduler.abort();
            drop(state);
            drop(delivery);
            self.runtime.notify();
        }
    }
}
