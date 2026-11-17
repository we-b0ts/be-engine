//! Async capture closes on observed completion, business inactivity or explicit stop.
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::sync::watch;
use uuid::Uuid;

use super::{ActiveCaseRegistry, DependencyDrainResult, DependencyTargets};
use crate::recorder::CaseContext;
use crate::recorder::async_api::CompletionEvent;
use crate::recorder::async_api::{AsyncEndReason, AsyncScope, AsyncSignal};

mod ending;
use ending::Ending;

const IDLE: Duration = Duration::from_secs(5 * 60);

#[derive(Debug)]
pub(super) struct AsyncObservation {
    scope: AsyncScope,
    started: Instant,
    deadline: Instant,
    ended: watch::Sender<Option<AsyncSignal>>,
    stop_requested_at: Mutex<Option<SourceStopMoment>>,
    primary_complete: AtomicBool,
    ending: Mutex<Option<Ending>>,
}

#[derive(Debug, Clone, Copy)]
struct SourceStopMoment {
    monotonic: Instant,
    wall: chrono::DateTime<chrono::Utc>,
}

impl AsyncObservation {
    pub(super) fn mark_source_stop(&self) {
        self.stop_requested_at
            .lock()
            .expect("async stop clock poisoned")
            .get_or_insert_with(|| SourceStopMoment {
                monotonic: Instant::now(),
                wall: chrono::Utc::now(),
            });
    }

    pub(super) fn source_stop_requested(&self) -> bool {
        self.stop_requested_at
            .lock()
            .expect("async stop clock poisoned")
            .is_some()
    }

    pub(super) fn source_stop_wall_time(&self) -> Option<chrono::DateTime<chrono::Utc>> {
        self.stop_requested_at
            .lock()
            .expect("async stop clock poisoned")
            .map(|at| at.wall)
    }
    fn finish(&self, signal: AsyncSignal) {
        self.ended.send_if_modified(|current| {
            if current.as_ref().is_some_and(|current| {
                !matches!(
                    current.end_reason,
                    AsyncEndReason::Resource | AsyncEndReason::Idle
                )
            }) {
                return false;
            }
            *current = Some(signal.clone());
            true
        });
    }

    fn timeout(&self) {
        self.finish(AsyncSignal {
            end_reason: AsyncEndReason::Timeout,
            resource_index: None,
            event_type: None,
        });
    }

    fn stop(&self) {
        self.mark_source_stop();
        self.finish(AsyncSignal {
            end_reason: AsyncEndReason::Stopped,
            resource_index: None,
            event_type: None,
        });
    }

    fn idle(&self) -> AsyncSignal {
        let signal = AsyncSignal {
            end_reason: AsyncEndReason::Idle,
            resource_index: None,
            event_type: None,
        };
        self.finish(signal.clone());
        signal
    }

    fn complete_primary(&self, activity: &super::activity::DependencyActivity) {
        if !self.primary_complete.swap(true, Ordering::AcqRel) {
            // A long primary response never contributes silence to the async
            // post-response fallback.
            activity.touch();
        }
    }

    async fn wait(&self) -> AsyncSignal {
        let mut changed = self.ended.subscribe();
        loop {
            if let Some(signal) = changed.borrow_and_update().clone() {
                return signal;
            }
            let _ = changed.changed().await;
        }
    }
}

impl ActiveCaseRegistry {
    pub(crate) fn observe_async_capture(
        &self,
        event: &traffic_protocol::capture::CaptureSnapshot,
        targets: &DependencyTargets,
    ) {
        self.observe_async_completion(
            &crate::recorder::async_api::CapturedCompletion {
                event,
                identity: targets
                    .capture
                    .as_ref()
                    .map(|capture| capture.exchange_id()),
            },
            targets,
            true,
            event.facts().complete,
            event.kind(),
        );
    }

    pub(crate) fn select_async_response(&self, case_id: Uuid, body: Option<&serde_json::Value>) {
        let mut state = self.state.lock().expect("active case registry poisoned");
        let Some(case) = state.active.iter_mut().find(|case| case.case.id == case_id) else {
            return;
        };
        let Some(observation) = case.async_api.as_ref() else {
            return;
        };
        let (selected, signal) = observation.scope.select_response(body);
        observation.complete_primary(&case.business_activity());
        if !selected {
            case.async_api = None;
        } else if let Some(signal) = signal {
            if signal.end_reason == AsyncEndReason::Resource && observation.needs_ending_probe() {
                observation.observe_candidate(
                    &case.business_activity(),
                    observation
                        .scope
                        .selected_signal_generation()
                        .unwrap_or_default(),
                );
            } else {
                if signal.end_reason == AsyncEndReason::Resource {
                    observation.complete_all_ends();
                }
                case.accepting_dependencies = false;
            }
            observation.finish(signal);
        }
    }

    pub(crate) fn async_source_stop_requested(&self, case_id: Uuid) -> bool {
        self.state
            .lock()
            .expect("active case registry poisoned")
            .active
            .iter()
            .find(|case| case.case.id == case_id)
            .and_then(|case| case.async_api.as_ref())
            .is_some_and(|observation| observation.source_stop_requested())
    }

    pub(crate) fn configure_async_api(
        &self,
        case_id: Uuid,
        scope: AsyncScope,
        started: Instant,
        timeout: Duration,
    ) {
        let mut state = self.state.lock().expect("active case registry poisoned");
        if let Some(case) = state.active.iter_mut().find(|case| case.case.id == case_id) {
            case.async_api = Some(Arc::new(AsyncObservation {
                scope,
                started,
                deadline: started.checked_add(timeout).unwrap_or(started),
                ended: watch::channel(None).0,
                stop_requested_at: Mutex::new(None),
                primary_complete: AtomicBool::new(false),
                ending: Mutex::new(None),
            }));
        }
    }

    pub(crate) fn observe_async_completion(
        &self,
        event: &dyn CompletionEvent,
        targets: &DependencyTargets,
        recorded_in_case: bool,
        capture_complete: bool,
        event_type: &'static str,
    ) {
        if !recorded_in_case || targets.process_owned_rule.is_some() {
            return;
        }
        let mut state = self.state.lock().expect("active case registry poisoned");
        if !capture_complete
            && state.active.iter().any(|case| {
                case.async_api.is_some()
                    && targets
                        .cases
                        .iter()
                        .any(|(target, _)| target.id == case.case.id)
            })
        {
            // Failure completion wakes the primary publisher. Establish global
            // shutdown and its original Case before that publisher can finish.
            self.begin_quiescing_locked(&mut state);
        }
        let stopping = state.quiescing;
        for (target, _) in &targets.cases {
            let Some(case) = state
                .active
                .iter_mut()
                .find(|case| case.case.id == target.id)
            else {
                continue;
            };
            let Some(observation) = case.async_api.as_ref() else {
                continue;
            };
            if !capture_complete {
                case.invalidation.get_or_insert_with(|| {
                    crate::recorder::CaseInvalidation::new(
                        "dependency_capture_incomplete",
                        "asynchronous dependency capture is incomplete",
                    )
                });
                case.accepting_dependencies = false;
                observation.mark_source_stop();
                observation.finish(AsyncSignal {
                    end_reason: AsyncEndReason::DependencyFailure,
                    resource_index: None,
                    event_type: Some(event_type),
                });
                continue;
            }
            let activity = case.business_activity();
            let generation = activity.request_snapshot().1;
            let completed_reason = observation
                .ended
                .borrow()
                .as_ref()
                .map(|signal| signal.end_reason);
            let completed_resource = completed_reason == Some(AsyncEndReason::Idle)
                || completed_reason == Some(AsyncEndReason::Resource)
                    && (!observation.needs_ending_probe()
                        || observation
                            .ending
                            .lock()
                            .expect("async ending poisoned")
                            .as_ref()
                            .is_some_and(|ending| ending.closed.is_some()));
            if completed_resource {
                // Accepted I/O may finish after the request budget. Once the
                // lifecycle closed normally, only a real capture failure above
                // can change that result; writer drain is not another timeout.
                continue;
            }
            if stopping {
                observation.stop();
                continue;
            }
            if !observation.primary_complete.load(Ordering::Acquire)
                && Instant::now() >= observation.deadline
            {
                observation.timeout();
            } else if let Some(signal) = observation.scope.observe_at(event, generation) {
                if signal.end_reason == AsyncEndReason::Resource && observation.needs_ending_probe()
                {
                    observation.observe_candidate(&activity, generation);
                } else if signal.end_reason == AsyncEndReason::Resource {
                    observation.complete_all_ends();
                }
                if observation.primary_complete.load(Ordering::Acquire)
                    && (signal.end_reason != AsyncEndReason::Resource
                        || !observation.needs_ending_probe())
                {
                    case.accepting_dependencies = false;
                }
                observation.finish(signal);
            }
        }
    }

    pub(super) async fn drain_async_api(
        &self,
        case_id: Uuid,
        cleanup: Duration,
    ) -> Option<DependencyDrainResult> {
        let observation = {
            let mut state = self.state.lock().expect("active case registry poisoned");
            let case = state
                .active
                .iter_mut()
                .find(|case| case.case.id == case_id)?;
            let observation = case.async_api.clone()?;
            observation.complete_primary(&case.business_activity());
            if observation.ended.borrow().as_ref().is_some_and(|signal| {
                signal.end_reason != AsyncEndReason::Resource || !observation.needs_ending_probe()
            }) {
                case.accepting_dependencies = false;
            }
            observation
        };
        // A fast worker may finish before the primary response. Its signal is
        // retained, while this method is called only after primary capture ends.
        let mut signal = self.wait_async_candidate(case_id, &observation).await?;
        let ending_activity =
            if signal.end_reason == AsyncEndReason::Resource && observation.needs_ending_probe() {
                self.finish_async_ending(case_id, &observation).await
            } else {
                None
            };
        if let Some(current) = observation.ended.borrow().clone() {
            signal = current;
        }
        let dependencies = {
            let mut state = self.state.lock().expect("active case registry poisoned");
            let Some(case) = state.active.iter_mut().find(|case| case.case.id == case_id) else {
                return Some(DependencyDrainResult::Drained);
            };
            case.accepting_dependencies = false;
            case.dependencies.clone()
        };
        if !matches!(
            signal.end_reason,
            AsyncEndReason::Resource | AsyncEndReason::Idle
        ) {
            // The old worker can still run after an error/deadline. The existing
            // supervisor stops Source normally before another Case is admitted.
            observation.mark_source_stop();
            self.begin_quiescing();
        }
        // Successful probing already established that real I/O is idle. A
        // deadline/failure retains the existing Source-stop and drain path.
        drop(ending_activity);
        let now = Instant::now();
        if !dependencies
            .wait_until_idle_until(now.checked_add(cleanup).unwrap_or(now))
            .await
        {
            observation.mark_source_stop();
            self.begin_quiescing();
            // Source stop/reset supplies the real termination observations.
            // Preserve original request ownership through their final writes.
            dependencies.wait_until_idle().await;
        }
        Some(DependencyDrainResult::Drained)
    }

    pub(crate) fn async_api_report(
        &self,
        case_id: Uuid,
    ) -> Option<(CaseContext, serde_json::Value)> {
        let state = self.state.lock().expect("active case registry poisoned");
        let case = state.active.iter().find(|case| case.case.id == case_id)?;
        let observation = case.async_api.as_ref()?;
        let signal = observation.ended.borrow().clone()?;
        let ending = observation.ending.lock().expect("async ending poisoned");
        let ending = ending.as_ref();
        if signal.end_reason == AsyncEndReason::Resource
            && observation.needs_ending_probe()
            && ending.is_none_or(|ending| ending.closed.is_none())
        {
            return None;
        }
        let business_complete = signal.end_reason == AsyncEndReason::Resource && ending.is_none();
        let source_stop_after_ms = observation
            .stop_requested_at
            .lock()
            .expect("async stop clock poisoned")
            .map(|at| {
                at.monotonic
                    .saturating_duration_since(observation.started)
                    .as_millis()
            });
        let (inventory_complete, completed_refs) = case
            .stream_tail
            .as_ref()
            .map(|tail| tail.completed_inventory())
            .unwrap_or((false, serde_json::json!([])));
        let cleanup_refs = case
            .stream_tail
            .as_ref()
            .map(|tail| tail.cleanup_inventory())
            .unwrap_or_else(|| serde_json::json!([]));
        Some((
            case.case.clone(),
            serde_json::json!({
                "version":2,"api":observation.scope.api,"scenario_index":observation.scope.scenario_index(),"end_reason":signal.end_reason,
                "resource_index":signal.resource_index,"event_type":signal.event_type,
                "elapsed_ms":observation.started.elapsed().as_millis(),
                "request_timeout_ms":observation.deadline.saturating_duration_since(observation.started).as_millis(),
                "inventory_complete":inventory_complete,"completed_refs":completed_refs,
                "capture_complete":inventory_complete && !case.invalidation.as_ref().is_some_and(|failure| failure.reason == "dependency_capture_incomplete"),
                "business_complete":business_complete,
                "business_completion":if business_complete { "observed" } else { "unobserved" },
                "ending":ending.filter(|_| signal.end_reason == AsyncEndReason::Resource).map(|ending| ending.report(observation.started)),
                "idle_completion":(signal.end_reason == AsyncEndReason::Idle).then(|| serde_json::json!({"quiet_ms": IDLE.as_millis()})),
                "source_stop_required":*self.quiescing.borrow(),
                "source_stop_after_ms":source_stop_after_ms,
                "cleanup_refs":cleanup_refs,
            }),
        ))
    }
}

#[cfg(test)]
mod tests;
