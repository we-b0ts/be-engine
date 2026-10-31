//! The common request engine owns observe/select/wait/cancel/retry sequencing.
use super::super::ReplayState;
use super::{Barrier, Lifecycle, RequestAdmission, WaitOutcome, WaitRegistration};
use std::sync::Arc;
use tokio::{sync::Mutex, time::Instant};

/// A native adapter describes the dependency it needs; registration and waiting
/// remain in the common engine while ReplayState's existing mutex is held.
pub(in crate::replay) struct WaitDependency<'a> {
    lifecycle: &'a Lifecycle,
    slot: Option<(usize, Barrier)>,
}
impl<'a> WaitDependency<'a> {
    pub(in crate::replay) fn changed(lifecycle: &'a Lifecycle) -> Self {
        Self {
            lifecycle,
            slot: None,
        }
    }
    pub(in crate::replay) fn slot(
        lifecycle: &'a Lifecycle,
        index: usize,
        barrier: Barrier,
    ) -> Self {
        Self {
            lifecycle,
            slot: Some((index, barrier)),
        }
    }
    fn register(self) -> Option<WaitRegistration> {
        match self.slot {
            Some((index, barrier)) => self.lifecycle.wait_for(index, barrier),
            None => Some(self.lifecycle.subscribe()),
        }
    }
}

/// Closed protocol implementations supply native projection/constraints and
/// reporting hooks, rather than reimplementing the concurrent execution loop.
pub(in crate::replay) trait DependencyRequestAdapter {
    type Matched;
    type Error;
    fn observe_once(&mut self, state: &mut ReplayState) -> RequestAdmission;
    fn try_select(
        &mut self,
        state: &mut ReplayState,
        observation: &RequestAdmission,
    ) -> Result<Self::Matched, Self::Error>;
    fn wait_dependency<'a>(
        &self,
        _state: &'a ReplayState,
        _observation: &RequestAdmission,
        _error: &Self::Error,
    ) -> Option<WaitDependency<'a>> {
        None
    }
    fn interrupted(&self, reason: &'static str) -> Self::Error;
    fn on_selected(
        &mut self,
        _state: &mut ReplayState,
        _observation: &RequestAdmission,
        _matched: &mut Self::Matched,
    ) -> Result<(), Self::Error> {
        Ok(())
    }
    fn on_rejected(
        &mut self,
        _state: &mut ReplayState,
        _observation: &RequestAdmission,
        _error: &Self::Error,
    ) {
    }
}

pub(in crate::replay) async fn execute<A: DependencyRequestAdapter>(
    shared: &Arc<Mutex<ReplayState>>,
    adapter: &mut A,
    deadline: Instant,
) -> Result<A::Matched, A::Error> {
    let mut state = shared.lock().await;
    if state.finalized_at.is_some() {
        // Sealed reports and evidence are immutable. Do not observe, select or
        // report this terminal rejection through native mutation hooks.
        return Err(adapter.interrupted("Replay session is finalized"));
    }
    let observation = adapter.observe_once(&mut state);
    let mut result = adapter.try_select(&mut state, &observation);
    'select: while let Err(error) = &result {
        let Some(mut waiter) = adapter
            .wait_dependency(&state, &observation, error)
            .and_then(WaitDependency::register)
        else {
            break;
        };
        loop {
            drop(state);
            let outcome = waiter.wait(deadline).await;
            state = shared.lock().await;
            if state.finalized_at.is_some() {
                return Err(adapter.interrupted("Replay session is finalized"));
            }
            let interrupted = observation.cancel_reason(&state).or_else(|| {
                (outcome == WaitOutcome::Deadline)
                    .then_some("dependency predecessor delivery wait timed out")
            });
            if let Some(reason) = interrupted {
                result = Err(adapter.interrupted(reason));
                break 'select;
            }
            // A notification may concern another lane. Recheck only the native
            // dependency, without decoding/observing/selecting this request again.
            if let Some(next) = adapter
                .wait_dependency(&state, &observation, error)
                .and_then(WaitDependency::register)
            {
                waiter = next;
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
