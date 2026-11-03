//! Fixed candidate probes with a separate five-minute business-idle fallback.
use super::*;
use crate::active_case::activity::DependencyActivity;

const PROBE: Duration = Duration::from_secs(1);

#[derive(Debug)]
pub(super) struct Ending {
    candidate_generation: u64,
    probe_started: Option<Instant>,
    pub(super) closed: Option<Instant>,
}

impl Ending {
    pub(super) fn report(&self, request_started: Instant) -> serde_json::Value {
        let started = self.probe_started.expect("a closed ending has a probe");
        serde_json::json!({
            "reason": "probe_completed",
            "probe_ms": PROBE.as_millis(),
            "started_after_ms": started.saturating_duration_since(request_started).as_millis(),
            "elapsed_ms": self.closed.expect("ending closed").saturating_duration_since(started).as_millis(),
        })
    }
}

impl AsyncObservation {
    pub(super) fn needs_ending_probe(&self) -> bool {
        !self.scope.all_ends_matched()
    }

    pub(super) fn complete_all_ends(&self) {
        *self.ending.lock().expect("async ending poisoned") = None;
    }

    pub(super) fn observe_candidate(&self, activity: &DependencyActivity, generation: u64) {
        let current = activity.request_snapshot().1;
        *self.ending.lock().expect("async ending poisoned") = Some(Ending {
            candidate_generation: generation,
            probe_started: (self.primary_complete.load(Ordering::Acquire) && current == generation)
                .then(Instant::now),
            closed: None,
        });
    }

    pub(super) fn activate_ending(&self, activity: &DependencyActivity) {
        let generation = activity.request_snapshot().1;
        let mut ending = self.ending.lock().expect("async ending poisoned");
        if let Some(ending) = ending.as_mut()
            && ending.probe_started.is_none()
            && ending.candidate_generation == generation
        {
            ending.probe_started = Some(Instant::now());
        }
    }
}

impl ActiveCaseRegistry {
    pub(super) async fn wait_async_candidate(
        &self,
        case_id: Uuid,
        observation: &AsyncObservation,
    ) -> Option<AsyncSignal> {
        let activity = {
            let state = self.state.lock().expect("active case registry poisoned");
            state
                .active
                .iter()
                .find(|case| case.case.id == case_id)?
                .business_activity()
        };
        loop {
            tokio::select! {
                biased;
                signal = observation.wait() => return Some(signal),
                _ = self.wait_for_quiescing() => {
                    observation.stop();
                },
                _ = activity.wait_until_quiet(IDLE) => {
                    let mut state = self.state.lock().expect("active case registry poisoned");
                    if state.quiescing {
                        observation.stop();
                    }
                    if let Some(signal) = observation.ended.borrow().clone() {
                        return Some(signal);
                    }
                    let case = state.active.iter_mut().find(|case| case.case.id == case_id)?;
                    if !activity.is_quiet(IDLE) {
                        continue;
                    }
                    case.accepting_dependencies = false;
                    return Some(observation.idle());
                },
            }
        }
    }

    pub(super) async fn finish_async_ending(
        &self,
        case_id: Uuid,
        observation: &AsyncObservation,
    ) -> Option<Arc<DependencyActivity>> {
        let activity = {
            let state = self.state.lock().expect("active case registry poisoned");
            let case = state.active.iter().find(|case| case.case.id == case_id)?;
            let activity = case.business_activity();
            observation.activate_ending(&activity);
            activity
        };
        let mut changed = observation.ended.subscribe();
        loop {
            let wake_at = {
                let mut state = self.state.lock().expect("active case registry poisoned");
                let quiescing = state.quiescing;
                let case = state
                    .active
                    .iter_mut()
                    .find(|case| case.case.id == case_id)?;
                let failed = changed
                    .borrow_and_update()
                    .as_ref()
                    .is_some_and(|signal| signal.end_reason != AsyncEndReason::Resource);
                if failed {
                    case.accepting_dependencies = false;
                    return Some(activity);
                }
                if !observation.needs_ending_probe() {
                    // The last missing end closes admission in the event
                    // observer. No probe remains once all ends have completed.
                    case.accepting_dependencies = false;
                    return Some(activity);
                }
                if quiescing {
                    observation.stop();
                    case.accepting_dependencies = false;
                    return Some(activity);
                }
                let (in_flight, generation) = activity.request_snapshot();
                if in_flight == 0 && activity.is_quiet(IDLE) {
                    case.accepting_dependencies = false;
                    observation.idle();
                    return Some(activity);
                }
                let mut ending = observation.ending.lock().expect("async ending poisoned");
                let ending = ending.as_mut().expect("candidate observed before ending");
                if generation != ending.candidate_generation {
                    // Silence cannot restore this probe. Only a new matching
                    // exchange may grant another one-second observation.
                    ending.probe_started = None;
                }
                let probe_at = match ending.probe_started {
                    Some(started) if Instant::now() >= started + PROBE => {
                        if in_flight == 0 {
                            // Request reservation and this closure share the
                            // registry lock, including the timer boundary race.
                            case.accepting_dependencies = false;
                            ending.closed = Some(Instant::now());
                            return Some(activity);
                        }
                        None
                    }
                    Some(started) => Some(started + PROBE),
                    None => None,
                };
                let idle_at = (in_flight == 0).then(|| activity.snapshot().1 + IDLE);
                probe_at.into_iter().chain(idle_at).min()
            };
            tokio::select! {
                _ = async {
                    match wake_at {
                        Some(wake_at) => tokio::time::sleep_until(tokio::time::Instant::from_std(wake_at)).await,
                        None => std::future::pending().await,
                    }
                } => {},
                _ = activity.changed() => {},
                _ = changed.changed() => {},
                _ = self.wait_for_quiescing() => observation.stop(),
            }
        }
    }
}

#[cfg(test)]
mod tests;
