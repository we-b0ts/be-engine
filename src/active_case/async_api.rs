//! Async APIs close on declared completion, capture failure or the shared deadline.
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::sync::watch;
use uuid::Uuid;

use super::{ActiveCaseRegistry, DependencyDrainResult, DependencyTargets};
use crate::recorder::async_api::{AsyncEndReason, AsyncScope, AsyncSignal};
use crate::recorder::{CaseContext, RecorderEvent};

#[derive(Debug)]
pub(super) struct AsyncObservation {
    scope: AsyncScope,
    started: Instant,
    deadline: Instant,
    ended: watch::Sender<Option<AsyncSignal>>,
    stop_requested_at: Mutex<Option<SourceStopMoment>>,
    primary_complete: AtomicBool,
}

#[derive(Debug, Clone, Copy)]
struct SourceStopMoment {
    monotonic: Instant,
    wall: chrono::DateTime<chrono::Utc>,
}

impl AsyncObservation {
    fn mark_source_stop(&self) {
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
            if current.is_some() {
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

    async fn wait(&self) -> AsyncSignal {
        let mut changed = self.ended.subscribe();
        loop {
            if let Some(signal) = changed.borrow_and_update().clone() {
                return signal;
            }
            tokio::select! {
                _ = changed.changed() => {},
                _ = tokio::time::sleep_until(tokio::time::Instant::from_std(self.deadline)) => self.timeout(),
            }
        }
    }
}

impl ActiveCaseRegistry {
    pub(crate) fn select_async_response(&self, case_id: Uuid, body: Option<&serde_json::Value>) {
        let mut state = self.state.lock().expect("active case registry poisoned");
        let Some(case) = state.active.iter_mut().find(|case| case.case.id == case_id) else {
            return;
        };
        let Some(observation) = case.async_api.as_ref() else {
            return;
        };
        let (selected, signal) = observation.scope.select_response(body);
        observation.primary_complete.store(true, Ordering::Release);
        if !selected {
            case.async_api = None;
        } else if let Some(signal) = signal {
            case.accepting_dependencies = false;
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
            }));
        }
    }

    pub(crate) fn observe_async_dependency_event(
        &self,
        event: &RecorderEvent,
        targets: &DependencyTargets,
        recorded_in_case: bool,
    ) {
        if !recorded_in_case || targets.process_owned_rule.is_some() {
            return;
        }
        let mut state = self.state.lock().expect("active case registry poisoned");
        if !event.capture_complete()
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
            if !event.capture_complete() {
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
                    event_type: Some(event.kind()),
                });
                continue;
            }
            if Instant::now() >= observation.deadline {
                observation.timeout();
            } else if let Some(signal) = observation.scope.observe(event) {
                if observation.primary_complete.load(Ordering::Acquire) {
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
            observation.primary_complete.store(true, Ordering::Release);
            if observation.ended.borrow().is_some() {
                case.accepting_dependencies = false;
            }
            observation
        };
        // A fast worker may finish before the primary response. Its signal is
        // retained, while this method is called only after primary capture ends.
        let signal = observation.wait().await;
        let dependencies = {
            let mut state = self.state.lock().expect("active case registry poisoned");
            let Some(case) = state.active.iter_mut().find(|case| case.case.id == case_id) else {
                return Some(DependencyDrainResult::Drained);
            };
            case.accepting_dependencies = false;
            case.dependencies.clone()
        };
        if signal.end_reason != AsyncEndReason::Resource {
            // The old worker can still run after an error/deadline. The existing
            // supervisor stops Source normally before another Case is admitted.
            observation.mark_source_stop();
            self.begin_quiescing();
        }
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
                "policy_provenance":observation.scope.selected_provenance(),
                "resource_index":signal.resource_index,"event_type":signal.event_type,
                "elapsed_ms":observation.started.elapsed().as_millis(),
                "request_timeout_ms":observation.deadline.saturating_duration_since(observation.started).as_millis(),
                "inventory_complete":inventory_complete,"completed_refs":completed_refs,
                "capture_complete":inventory_complete && !case.invalidation.as_ref().is_some_and(|failure| failure.reason == "dependency_capture_incomplete"),
                "business_complete":signal.end_reason == AsyncEndReason::Resource,
                "business_completion":if signal.end_reason == AsyncEndReason::Resource { "observed" } else { "unobserved" },
                "source_stop_required":*self.quiescing.borrow(),
                "source_stop_after_ms":source_stop_after_ms,
                "cleanup_refs":cleanup_refs,
            }),
        ))
    }
}

#[cfg(test)]
mod tests;
