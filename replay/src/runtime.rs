//! Bounded asynchronous admission and real delivery receipts over a prepared cursor.
use crate::{
    Admission, DeliveryTicket, EventKind, SequencePlan, SequenceScheduler, SourceEvent, StreamEvent,
};
use anyhow::{Context, Result, ensure};
use std::sync::{Arc, Mutex};
use tokio::{
    sync::watch,
    time::{Duration, Instant},
};

mod frontier;
pub use frontier::FrontierWait;
use frontier::FrontierWaiters;
mod message_batch;
pub use message_batch::{MessageBatch, PublishedMessageBatch};

const MAX_PENDING_REQUESTS: usize = 256;
const MAX_PENDING_BYTES: usize = 64 * 1024 * 1024;

#[derive(Debug)]
pub struct SequenceRuntime {
    state: Mutex<State>,
    changed: watch::Sender<u64>,
    requests_changed: watch::Sender<u64>,
    messages_changed: watch::Sender<()>,
    fast_gap_cap: Option<Duration>,
    session_timing: bool,
    streaming: bool,
}

#[derive(Debug, Clone, Copy, serde::Serialize)]
pub struct SequenceProgress {
    pub matched: usize,
    pub total: Option<usize>,
    pub last_sequence: Option<u64>,
    pub expected: Option<SourceEvent>,
    pub complete: bool,
    pub failed: bool,
}

#[derive(Debug)]
struct State {
    scheduler: SequenceScheduler,
    pending: usize,
    pending_bytes: usize,
    progressed_at: Option<Instant>,
    target_exited: bool,
    frontier_waiters: FrontierWaiters,
    message_batch_reserved: bool,
}

struct Notifications {
    requests: bool,
    messages: bool,
    frontier: Vec<Arc<tokio::sync::Notify>>,
}

impl State {
    fn notifications(&mut self, progressed_or_gate_released: bool) -> Notifications {
        let failed = self.scheduler.failed();
        let expected = self.scheduler.expected();
        Notifications {
            requests: failed || expected.is_none_or(|event| event.kind == EventKind::Request),
            messages: failed
                || progressed_or_gate_released
                    && expected.is_some_and(|event| event.kind == EventKind::Message),
            frontier: if failed
                || progressed_or_gate_released && (expected.is_some() || self.scheduler.complete())
            {
                self.frontier_waiters.take_ready(if failed {
                    u64::MAX
                } else {
                    expected.map_or(u64::MAX, |event| event.sequence)
                })
            } else {
                Vec::new()
            },
        }
    }

    fn record_progress(&mut self) {
        self.progressed_at = Some(Instant::now());
    }

    fn output_due(&self, dependency: u64, cap: Duration) -> Option<Instant> {
        let next = self.scheduler.expected().filter(|event| {
            event.dependency_sequence == dependency
                && matches!(
                    event.kind.delivered(),
                    EventKind::ResponseHeaders | EventKind::ResponsePart | EventKind::ResponseEnd
                )
        })?;
        self.event_due(next, Some(cap))
    }

    fn event_due(&self, next: SourceEvent, cap: Option<Duration>) -> Option<Instant> {
        if cap == Some(Duration::ZERO) {
            return None;
        }
        let previous = self.scheduler.previous()?;
        let gap = Duration::from_micros(next.offset_micros.saturating_sub(previous.offset_micros));
        self.progressed_at?
            .checked_add(cap.map_or(gap, |cap| gap.min(cap)))
    }
}

impl SequenceRuntime {
    pub fn new(plan: Arc<SequencePlan>) -> Arc<Self> {
        Self::with_fast_gap_cap(plan, None)
    }

    pub fn with_fast_gap_cap(plan: Arc<SequencePlan>, fast_gap_cap: Option<Duration>) -> Arc<Self> {
        Self::with_request_gates(plan, fast_gap_cap, std::iter::empty())
    }

    /// External prerequisites can delay a real recorded request. They cannot consume it.
    pub fn with_request_gates(
        plan: Arc<SequencePlan>,
        fast_gap_cap: Option<Duration>,
        request_gates: impl IntoIterator<Item = u64>,
    ) -> Arc<Self> {
        Self::prepare(plan, fast_gap_cap, request_gates, false)
    }

    pub fn with_session_timing(
        plan: Arc<SequencePlan>,
        fast_gap_cap: Option<Duration>,
        event_gates: impl IntoIterator<Item = u64>,
    ) -> Arc<Self> {
        Self::prepare(plan, fast_gap_cap, event_gates, true)
    }

    fn prepare(
        plan: Arc<SequencePlan>,
        fast_gap_cap: Option<Duration>,
        event_gates: impl IntoIterator<Item = u64>,
        session_timing: bool,
    ) -> Arc<Self> {
        Self::new_runtime(
            SequenceScheduler::new(plan),
            fast_gap_cap,
            event_gates,
            session_timing,
            false,
        )
    }

    pub fn streaming_session(
        fast_gap_cap: Option<Duration>,
        event_gates: impl IntoIterator<Item = u64>,
    ) -> Arc<Self> {
        let empty = SequencePlan::compile([]).expect("empty Source plan");
        Self::new_runtime(
            SequenceScheduler::streaming(empty),
            fast_gap_cap,
            event_gates,
            true,
            true,
        )
    }

    fn new_runtime(
        mut scheduler: SequenceScheduler,
        fast_gap_cap: Option<Duration>,
        gates: impl IntoIterator<Item = u64>,
        session_timing: bool,
        streaming: bool,
    ) -> Arc<Self> {
        scheduler.event_gates.extend(gates);
        Arc::new(Self {
            state: Mutex::new(State {
                scheduler,
                pending: 0,
                pending_bytes: 0,
                progressed_at: None,
                target_exited: false,
                frontier_waiters: FrontierWaiters::default(),
                message_batch_reserved: false,
            }),
            changed: watch::channel(0).0,
            requests_changed: watch::channel(0).0,
            messages_changed: watch::channel(()).0,
            fast_gap_cap,
            session_timing,
            streaming,
        })
    }

    pub fn is_streaming(&self) -> bool {
        self.streaming
    }

    pub fn buffered(&self) -> usize {
        self.state
            .lock()
            .expect("sequence runtime poisoned")
            .scheduler
            .buffered()
    }

    pub fn push_stream(&self, batch: Vec<StreamEvent>, finished: bool) -> Result<()> {
        ensure!(self.streaming, "Session sequence has no streaming schedule");
        let mut state = self.state.lock().expect("sequence runtime poisoned");
        let previous = state.scheduler.previous();
        let was_empty = state.scheduler.expected().is_none();
        let result = state.scheduler.push_stream(batch, finished);
        if previous != state.scheduler.previous() {
            state.record_progress();
        }
        let mut notifications = state.notifications(true);
        notifications.requests |= was_empty;
        drop(state);
        self.notify(notifications);
        result
    }

    fn tracks_progress(&self) -> bool {
        self.session_timing || self.fast_gap_cap.is_some()
    }

    pub(crate) fn is_session_trace(&self) -> bool {
        self.session_timing
    }

    pub fn expected(&self) -> Option<SourceEvent> {
        self.state
            .lock()
            .expect("sequence runtime poisoned")
            .scheduler
            .expected()
    }

    pub fn progress(&self) -> SequenceProgress {
        let state = self.state.lock().expect("sequence runtime poisoned");
        SequenceProgress {
            matched: state.scheduler.cursor,
            total: state.scheduler.total(),
            last_sequence: state.scheduler.previous().map(|event| event.sequence),
            expected: state.scheduler.expected(),
            complete: state.scheduler.complete(),
            failed: state.scheduler.failed(),
        }
    }

    pub fn driver_event(&self, sequence: u64) -> Option<SourceEvent> {
        let state = self.state.lock().expect("sequence runtime poisoned");
        let scheduler = &state.scheduler;
        let found = if self.streaming {
            (scheduler.cursor..scheduler.cursor + scheduler.buffered())
                .filter_map(|index| scheduler.event_at(index))
                .find_map(|entry| (entry.source.sequence == sequence).then_some(entry.source))
        } else {
            scheduler.plan.event(sequence)
        };
        found.filter(|event| event.kind.is_session_driver_event())
    }

    pub fn driver_due(&self, sequence: u64) -> Option<Instant> {
        let state = self.state.lock().expect("sequence runtime poisoned");
        self.driver_due_at_frontier(&state, sequence)
    }

    fn driver_due_at_frontier(&self, state: &State, sequence: u64) -> Option<Instant> {
        let next = state
            .scheduler
            .expected()
            .filter(|event| event.sequence == sequence && event.kind.is_scheduled_driver_input())?;
        state.event_due(next, self.fast_gap_cap)
    }

    pub fn commit_driver(&self, sequence: u64) -> Result<()> {
        let mut state = self.state.lock().expect("sequence runtime poisoned");
        ensure!(
            self.driver_due_at_frontier(&state, sequence)
                .is_none_or(|due| Instant::now() >= due),
            "driver event {sequence} is earlier than its scheduled delivery"
        );
        let source_exit = state
            .scheduler
            .expected()
            .is_some_and(|event| event.kind == EventKind::SessionSourceExit);
        state.scheduler.commit_driver(sequence)?;
        state.target_exited |= source_exit;
        state.record_progress();
        let notifications = state.notifications(true);
        drop(state);
        self.notify(notifications);
        Ok(())
    }

    pub(crate) fn admissible_request(&self) -> Option<SourceEvent> {
        let state = self.state.lock().expect("sequence runtime poisoned");
        state.scheduler.expected().filter(|event| {
            event.kind == EventKind::Request && !state.scheduler.event_is_gated(event.sequence)
        })
    }

    pub(crate) fn admissible_message(&self) -> Option<SourceEvent> {
        let state = self.state.lock().expect("sequence runtime poisoned");
        if state.message_batch_reserved || state.scheduler.failed() {
            return None;
        }
        state.scheduler.expected().filter(|event| {
            event.kind == EventKind::Message && !state.scheduler.event_is_gated(event.sequence)
        })
    }

    pub fn event_is_gated(&self, sequence: u64) -> bool {
        self.state
            .lock()
            .expect("sequence runtime poisoned")
            .scheduler
            .event_is_gated(sequence)
    }

    /// Accept a prerequisite receipt only while its recorded request is at the frontier.
    pub fn release_request_gate(&self, sequence: u64) -> Result<()> {
        self.release_event_gate(sequence)
    }

    /// Release the prerequisite once its recorded event reaches the frontier.
    pub fn release_event_gate(&self, sequence: u64) -> Result<()> {
        let mut state = self.state.lock().expect("sequence runtime poisoned");
        ensure!(
            !state.scheduler.failed()
                && state
                    .scheduler
                    .expected()
                    .is_some_and(|event| event.sequence == sequence)
                && state.scheduler.event_gates.remove(&sequence),
            "event gate is stale or already released"
        );
        let notifications = state.notifications(true);
        drop(state);
        self.notify(notifications);
        Ok(())
    }

    pub fn contains(&self, dependency: u64) -> bool {
        self.state
            .lock()
            .expect("sequence runtime poisoned")
            .scheduler
            .slot_status(dependency)
            .is_some()
    }

    pub fn subscribe(&self) -> watch::Receiver<u64> {
        self.changed.subscribe()
    }

    pub fn subscribe_requests(&self) -> watch::Receiver<u64> {
        self.requests_changed.subscribe()
    }

    /// Wake when an emission can enter the sequence, or when the sequence fails.
    pub fn subscribe_messages(&self) -> watch::Receiver<()> {
        self.messages_changed.subscribe()
    }

    /// Register only if the frontier has yet to reach the requested sequence.
    /// A `None` result means it has reached or passed the sequence, or failed.
    pub fn wait_for_frontier(&self, sequence: u64) -> Option<FrontierWait<'_>> {
        let mut state = self.state.lock().expect("sequence runtime poisoned");
        if !state.scheduler.failed()
            && state.scheduler.expected().map_or_else(
                || !state.scheduler.complete(),
                |event| event.sequence < sequence,
            )
        {
            Some(state.frontier_waiters.register(self, sequence))
        } else {
            None
        }
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
        let mut state = self.state.lock().expect("sequence runtime poisoned");
        state.scheduler.abort();
        let notifications = state.notifications(false);
        drop(state);
        self.notify(notifications);
    }

    fn notify(&self, notifications: Notifications) {
        self.changed
            .send_modify(|revision| *revision = revision.wrapping_add(1));
        if notifications.requests {
            self.wake_requests();
        }
        if notifications.messages {
            let _ = self.messages_changed.send(());
        }
        for waiter in notifications.frontier {
            waiter.notify_one();
        }
    }

    pub fn admit(self: &Arc<Self>, dependency: u64) -> Result<SequenceClaim> {
        let mut state = self.state.lock().expect("sequence runtime poisoned");
        ensure!(
            !state.message_batch_reserved,
            "sequence frontier is reserved for a message batch"
        );
        ensure!(
            state.scheduler.admit(dependency)? == Admission::Accepted,
            "request is earlier than its recorded sequence"
        );
        if self.tracks_progress() {
            state.record_progress();
        }
        let notifications = state.notifications(true);
        drop(state);
        self.notify(notifications);
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
        after_target_exit: bool,
    },
    TerminalPublished(DeliveryTicket),
    Finished,
    Failed,
}

impl Delivery {
    fn refresh(&mut self, scheduler: &SequenceScheduler) {
        if let Self::TerminalPublished(ticket) = *self
            && scheduler.receipt_published(ticket)
        {
            *self = Self::Finished;
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

    /// A reserved output may be invalidated by a failure on another connection.
    pub fn sequence_failed(&self) -> bool {
        self.0.runtime.failed()
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
            let notifications = state.notifications(false);
            drop(state);
            drop(delivery);
            self.0.runtime.notify(notifications);
        }
    }
    pub async fn wait_delivery(&self, deadline: Instant) -> Result<()> {
        self.wait_output(Some(deadline), false, None).await
    }
    pub(crate) async fn wait_initial_delivery(&self) -> Result<()> {
        let deadline =
            (!self.0.runtime.is_session_trace()).then(|| Instant::now() + Duration::from_secs(30));
        self.wait_output(deadline, false, None).await
    }
    pub(crate) async fn wait_target_stop(&self) -> Result<()> {
        ensure!(
            self.0.runtime.is_session_trace(),
            "native Target-stop output requires a managed Source session"
        );
        // This stream may stay open for the rest of the session. Its terminal
        // wait ends with the driver-controlled Target exit or a Replay failure.
        self.wait_output(None, false, None).await?;
        let Delivery::Reserved {
            source:
                SourceEvent {
                    kind: EventKind::TargetStop,
                    ..
                },
            after_target_exit,
            ..
        } = *self.0.delivery.lock().expect("sequence delivery poisoned")
        else {
            anyhow::bail!("native output differs from its recorded Target-stop boundary");
        };
        ensure!(
            after_target_exit,
            "recorded native Target-stop output precedes the observed Target exit"
        );
        Ok(())
    }
    pub(crate) async fn wait_client_termination(&self) -> Result<()> {
        self.wait_output(None, false, None).await?;
        ensure!(
            self.reserved_kind() == Some(EventKind::ClientTermination),
            "native output differs from its recorded Client-termination boundary"
        );
        Ok(())
    }
    pub async fn wait_body_delivery(&self, deadline: Instant) -> Result<()> {
        self.wait_body_delivery_after(deadline, None).await
    }
    pub async fn wait_body_delivery_after(
        &self,
        deadline: Instant,
        after: Option<u64>,
    ) -> Result<()> {
        self.wait_output(Some(deadline), true, after).await
    }

    async fn wait_output(
        &self,
        deadline: Option<Instant>,
        after_headers: bool,
        after: Option<u64>,
    ) -> Result<()> {
        let mut changes = None;
        loop {
            let mut due = None;
            let changed = {
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
                let waiting_for_headers = after_headers
                    && state
                        .scheduler
                        .expected()
                        .is_some_and(|event| event.kind.delivered() == EventKind::ResponseHeaders);
                if matches!(*delivery, Delivery::Waiting) && !waiting_for_headers {
                    due = self
                        .0
                        .runtime
                        .fast_gap_cap
                        .and_then(|cap| state.output_due(self.0.dependency, cap))
                        .filter(|due| *due > Instant::now());
                    if due.is_none() {
                        let previous = state.scheduler.previous();
                        if let Some(ticket) = state.scheduler.reserve_delivery(self.0.dependency)? {
                            let source = ticket.receipt;
                            *delivery = Delivery::Reserved {
                                ticket,
                                source,
                                after_target_exit: state.target_exited,
                            };
                            let progressed = state.scheduler.previous() != previous;
                            if progressed && self.0.runtime.tracks_progress() {
                                state.record_progress();
                            }
                            let notifications = state.notifications(progressed);
                            drop(state);
                            drop(delivery);
                            self.0.runtime.notify(notifications);
                            return Ok(());
                        }
                    }
                }
                // Subscribe before releasing the lock that protects the cursor.
                changes.get_or_insert_with(|| self.0.runtime.subscribe())
            };
            if let Some(due) = due.filter(|due| deadline.is_none_or(|deadline| *due < deadline)) {
                tokio::select! {
                    result = changed.changed() => { result.context("recorded output sequence closed")?; }
                    _ = tokio::time::sleep_until(due) => {}
                }
                continue;
            }
            if let Some(deadline) = deadline {
                tokio::time::timeout_at(deadline, changed.changed())
                    .await
                    .context("recorded output sequence wait timed out")?
                    .context("recorded output sequence closed")?;
            } else {
                changed
                    .changed()
                    .await
                    .context("recorded output sequence closed")?;
            }
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
            if self.0.runtime.session_timing
                || self
                    .0
                    .runtime
                    .fast_gap_cap
                    .is_some_and(|cap| !cap.is_zero())
            {
                return 1;
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
        let Delivery::Reserved {
            mut ticket, source, ..
        } = *delivery
        else {
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
        let previous = state.scheduler.previous();
        state.scheduler.finish_delivery(ticket, true)?;
        for _ in 1..count {
            ticket = state
                .scheduler
                .reserve_delivery(self.0.dependency)?
                .context("contiguous output reservation is unavailable")?;
            state.scheduler.finish_delivery(ticket, true)?;
        }
        let progressed = state.scheduler.previous() != previous;
        if progressed && self.0.runtime.tracks_progress() {
            state.record_progress();
        }
        *delivery = if source.kind.is_terminal() {
            Delivery::TerminalPublished(ticket)
        } else {
            Delivery::Waiting
        };
        delivery.refresh(&state.scheduler);
        let notifications = state.notifications(progressed);
        drop(state);
        drop(delivery);
        self.0.runtime.notify(notifications);
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
        // The scheduler owns a flushed terminal receipt until its Source
        // position arrives, even after the connection releases its claim.
        if matches!(
            *self.delivery.get_mut().expect("sequence delivery poisoned"),
            Delivery::Waiting | Delivery::Reserved { .. }
        ) {
            self.runtime.abort();
        }
    }
}
