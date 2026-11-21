//! Observe, select, wait and commit requests through a shared execution flow.
use crate::request_wait::RequestWait;
use crate::{Barrier, Lifecycle, WaitOutcome, WaitRegistration};
use std::sync::Arc;
use tokio::{sync::Mutex, time::Instant};

/// The application supplies lifecycle observations without exposing its state
/// representation to protocol implementations.
pub trait ExecutionState {
    type Observation;
    fn is_finalized(&self) -> bool;
    fn cancel_reason(&self, observation: &Self::Observation) -> Option<&'static str>;
    fn sequence_wait(&self, bytes: usize) -> Option<RequestWait>;
    fn record_missing(&mut self, observation: &Self::Observation, waiter: &RequestWait);
}

/// Register a dependency under the same ownership lock as its predicate.
pub struct WaitDependency<'a> {
    lifecycle: &'a Lifecycle,
    slot: Option<(usize, Barrier)>,
    deadline: Option<Instant>,
}
impl<'a> WaitDependency<'a> {
    pub fn changed(lifecycle: &'a Lifecycle) -> Self {
        Self {
            lifecycle,
            slot: None,
            deadline: None,
        }
    }
    pub fn slot(lifecycle: &'a Lifecycle, index: usize, barrier: Barrier) -> Self {
        Self {
            lifecycle,
            slot: Some((index, barrier)),
            deadline: None,
        }
    }
    pub fn until(mut self, deadline: Instant) -> Self {
        self.deadline = Some(deadline);
        self
    }
    fn register(self) -> Option<(WaitRegistration, Option<Instant>)> {
        let registration = match self.slot {
            Some((index, barrier)) => self.lifecycle.wait_for(index, barrier),
            None => Some(self.lifecycle.subscribe()),
        }?;
        Some((registration, self.deadline))
    }
}

/// Framework operations supply request data and outcomes to one concurrent executor.
pub trait RequestAdapter<S: ExecutionState> {
    type Matched;
    type Error;
    fn sequence_request_bytes(&self) -> Option<usize> {
        None
    }
    fn sequence_wait_allowed(&self, _state: &S, _error: &Self::Error) -> bool {
        true
    }
    fn on_sequence_wait(&mut self, _state: &mut S) {}
    fn observe_once(&mut self, state: &mut S) -> S::Observation;
    fn try_select(
        &mut self,
        state: &mut S,
        observation: &S::Observation,
    ) -> Result<Self::Matched, Self::Error>;
    fn wait_dependency<'a>(
        &self,
        _state: &'a S,
        _observation: &S::Observation,
        _error: &Self::Error,
    ) -> Option<WaitDependency<'a>> {
        None
    }
    fn interrupted(&self, reason: &'static str) -> Self::Error;
    fn on_selected(
        &mut self,
        _state: &mut S,
        _observation: &S::Observation,
        _matched: &mut Self::Matched,
    ) -> Result<(), Self::Error> {
        Ok(())
    }
    fn on_rejected(&mut self, _state: &mut S, _observation: &S::Observation, _error: &Self::Error) {
    }
}

pub async fn execute<S: ExecutionState, A: RequestAdapter<S>>(
    shared: &Arc<Mutex<S>>,
    adapter: &mut A,
    deadline: Instant,
) -> Result<A::Matched, A::Error> {
    let mut state = shared.lock().await;
    if state.is_finalized() {
        // Sealed reports and evidence are immutable. Do not observe, select or
        // report this terminal rejection through native mutation hooks.
        return Err(adapter.interrupted("Replay session is finalized"));
    }
    let observation = adapter.observe_once(&mut state);
    let mut sequence_wait = adapter
        .sequence_request_bytes()
        .and_then(|bytes| state.sequence_wait(bytes));
    let mut result = adapter.try_select(&mut state, &observation);
    'select: while let Err(error) = &result {
        if sequence_wait.as_ref().is_some_and(|wait| wait.failed()) {
            result = Err(adapter.interrupted("recorded dependency delivery failed"));
            break;
        }
        if adapter.sequence_wait_allowed(&state, error)
            && let Some(waiter) = &mut sequence_wait
            && let Some(until) = waiter.deadline(deadline)
        {
            if waiter.reserve().is_err() {
                result = Err(adapter.interrupted("early dependency request queue budget exceeded"));
                break;
            }
            adapter.on_sequence_wait(&mut state);
            drop(state);
            let changed = waiter.wait(until).await;
            state = shared.lock().await;
            if let Some(reason) = state.cancel_reason(&observation) {
                result = Err(adapter.interrupted(reason));
                break;
            }
            if !changed {
                state.record_missing(&observation, waiter);
                result = Err(adapter.interrupted("next recorded dependency request timed out"));
                break;
            }
            result = adapter.try_select(&mut state, &observation);
            continue;
        }
        let Some((mut waiter, mut local_deadline)) = adapter
            .wait_dependency(&state, &observation, error)
            .and_then(WaitDependency::register)
        else {
            break;
        };
        loop {
            drop(state);
            let outcome = waiter
                .wait(local_deadline.map_or(deadline, |local| local.min(deadline)))
                .await;
            state = shared.lock().await;
            if state.is_finalized() {
                return Err(adapter.interrupted("Replay session is finalized"));
            }
            if let Some(reason) = state.cancel_reason(&observation) {
                result = Err(adapter.interrupted(reason));
                break 'select;
            }
            if outcome == WaitOutcome::Deadline {
                // A bounded native retry still reports the specific blocker.
                if local_deadline.is_none_or(|local| local > deadline) {
                    result =
                        Err(adapter.interrupted("dependency predecessor delivery wait timed out"));
                }
                break 'select;
            }
            // A notification may concern another lane. Recheck only the native
            // dependency, without decoding/observing/selecting this request again.
            if let Some((next, next_deadline)) = adapter
                .wait_dependency(&state, &observation, error)
                .and_then(WaitDependency::register)
            {
                waiter = next;
                local_deadline = next_deadline;
            } else {
                break;
            }
        }
        result = adapter.try_select(&mut state, &observation);
    }
    if let Ok(matched) = &mut result
        && let Err(error) = adapter.on_selected(&mut state, &observation, matched)
    {
        result = Err(error);
    }
    if let Err(error) = &result {
        adapter.on_rejected(&mut state, &observation, error);
    }
    result
}

#[cfg(test)]
#[path = "request_tests.rs"]
mod tests;
