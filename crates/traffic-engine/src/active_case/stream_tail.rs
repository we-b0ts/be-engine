//! Finite dependency requests outlive primary stream closure and writer queues.

use std::collections::BTreeSet;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use uuid::Uuid;

use super::activity::{DependencyActivity, DependencyReservation};
use super::{ActiveCaseRegistry, DependencyDrainResult, DependencyTargets};
use traffic_model::recording::ProtocolRef;

const MAX_COMPLETED_REFS: usize = 100_000;

#[derive(Debug)]
pub(super) struct StreamTail {
    enabled: AtomicBool,
    activity: Arc<DependencyActivity>,
    idle: Duration,
    started: Instant,
    deadline: Instant,
    completed: Mutex<CompletedInventory>,
}

#[derive(Debug, Default)]
struct CompletedInventory {
    references: BTreeSet<ProtocolRef>,
    cleanup_refs: BTreeSet<ProtocolRef>,
    exceeded: bool,
    unsupported: bool,
}

/// Writer clones share one live request. Only protocol activity renews idle.
#[derive(Debug, Clone)]
pub(super) struct StreamTailRequest(Arc<Mutex<Option<DependencyReservation>>>);

impl StreamTailRequest {
    fn finish(&self) {
        self.0.lock().expect("stream tail request poisoned").take();
    }

    fn touch(&self) {
        if let Some(request) = self
            .0
            .lock()
            .expect("stream tail request poisoned")
            .as_ref()
        {
            request.touch();
        }
    }
}

impl StreamTail {
    pub(super) fn activity(&self) -> Arc<DependencyActivity> {
        self.activity.clone()
    }

    pub(super) fn completed_inventory(&self) -> (bool, serde_json::Value) {
        let inventory = self
            .completed
            .lock()
            .expect("stream tail inventory poisoned");
        (
            !inventory.exceeded && !inventory.unsupported,
            serde_json::to_value(&inventory.references)
                .expect("typed dependency references serialize"),
        )
    }

    pub(super) fn cleanup_inventory(&self) -> serde_json::Value {
        let inventory = self
            .completed
            .lock()
            .expect("stream tail inventory poisoned");
        serde_json::to_value(&inventory.cleanup_refs).expect("typed cleanup references serialize")
    }

    pub(super) fn is_enabled(&self) -> bool {
        self.enabled.load(Ordering::Acquire)
    }

    pub(super) fn reserve(&self) -> StreamTailRequest {
        StreamTailRequest(Arc::new(Mutex::new(Some(self.activity.reserve_request()))))
    }
}

impl DependencyTargets {
    pub(crate) fn into_process_owned(mut self, rule_name: String) -> Self {
        self.process_rule_ids = vec![rule_name.clone()];
        self.process_owned_rule = Some(rule_name);
        if !self.cases.is_empty() {
            self.cases.clear();
            self._reservations.clear();
            // Request-start classification suppresses proven process activity
            // before reservation. A request classified only now was unknown
            // while in flight and must retain that observation until completion.
        }
        self
    }

    pub(crate) fn note_stream_tail_activity(&self) {
        for request in &self.stream_tail {
            request.touch();
        }
    }
}

impl ActiveCaseRegistry {
    pub(crate) fn configure_stream_tail(
        &self,
        case_id: Uuid,
        idle: Duration,
        started: Instant,
        timeout: Duration,
    ) {
        let mut state = self.state.lock().expect("active case registry poisoned");
        if let Some(case) = state.active.iter_mut().find(|case| case.case.id == case_id) {
            case.stream_tail = Some(Arc::new(StreamTail {
                enabled: AtomicBool::new(false),
                activity: Arc::new(DependencyActivity::default()),
                idle,
                started,
                deadline: started.checked_add(timeout).unwrap_or(started),
                completed: Mutex::new(CompletedInventory::default()),
            }));
        }
    }

    pub(crate) fn enable_stream_tail(&self, case_id: Uuid) {
        let state = self.state.lock().expect("active case registry poisoned");
        if let Some(tail) = state
            .active
            .iter()
            .find(|case| case.case.id == case_id)
            .and_then(|case| case.stream_tail.as_ref())
        {
            tail.enabled.store(true, Ordering::Release);
        }
    }

    /// Only original case-owned requests may use the Source-stop lifecycle.
    pub(crate) fn source_stop_requested_for(&self, targets: &DependencyTargets) -> bool {
        let state = self.state.lock().expect("active case registry poisoned");
        !targets.cases.is_empty()
            && targets.cases.iter().all(|(target, _)| {
                state
                    .active
                    .iter()
                    .find(|case| case.case.id == target.id)
                    .and_then(|case| case.async_api.as_ref())
                    .is_some_and(|scope| scope.source_stop_requested())
            })
    }

    pub(crate) fn observe_capture_tail_event(
        &self,
        event: &traffic_protocol::capture::CaptureSnapshot,
        targets: &DependencyTargets,
    ) {
        let reference = event
            .facts()
            .semantic_required(false)
            .then(|| {
                targets
                    .capture
                    .as_ref()
                    .map(|capture| ProtocolRef::exchange("capture", capture.exchange_id()))
            })
            .flatten();
        self.observe_tail_reference(reference, targets, true, false, |_| false);
    }

    pub(crate) fn observe_tail_reference(
        &self,
        reference: Option<ProtocolRef>,
        targets: &DependencyTargets,
        recorded_in_case: bool,
        unsupported: bool,
        cleanup: impl Fn(chrono::DateTime<chrono::Utc>) -> bool,
    ) {
        if recorded_in_case {
            let state = self.state.lock().expect("active case registry poisoned");
            for (target, _) in &targets.cases {
                let Some(case) = state.active.iter().find(|case| case.case.id == target.id) else {
                    continue;
                };
                if targets.stream_tail.is_empty() && case.async_api.is_none() {
                    continue;
                }
                let Some(tail) = case.stream_tail.as_ref() else {
                    continue;
                };
                let mut completed = tail
                    .completed
                    .lock()
                    .expect("stream tail inventory poisoned");
                if let Some(reference) = &reference {
                    if completed.references.len() == MAX_COMPLETED_REFS
                        && !completed.references.contains(reference)
                    {
                        completed.exceeded = true;
                    } else {
                        completed.references.insert(reference.clone());
                        if case
                            .async_api
                            .as_ref()
                            .and_then(|scope| scope.source_stop_wall_time())
                            .is_some_and(&cleanup)
                        {
                            completed.cleanup_refs.insert(reference.clone());
                        }
                    }
                } else if unsupported {
                    completed.unsupported = true;
                }
            }
        }
        // This precedes enqueueing. Writer reservations remain held through the
        // actual append, so a zero live count cannot publish ahead of evidence.
        for request in &targets.stream_tail {
            request.finish();
        }
    }

    fn enabled_stream_tail(&self, case_id: Uuid) -> Option<Arc<StreamTail>> {
        self.state
            .lock()
            .expect("active case registry poisoned")
            .active
            .iter()
            .find(|case| case.case.id == case_id)?
            .stream_tail
            .as_ref()
            .filter(|tail| tail.enabled.load(Ordering::Acquire))
            .cloned()
    }

    pub(crate) fn stream_tail_deadline(&self, case_id: Uuid) -> Option<Instant> {
        self.enabled_stream_tail(case_id).map(|tail| tail.deadline)
    }

    /// A failed stream may release its slot only after attribution closes,
    /// business I/O and writers drain, and the complete quiet window is observed.
    pub(crate) fn failed_stream_is_drained(&self, case_id: Uuid) -> bool {
        let state = self.state.lock().expect("active case registry poisoned");
        let Some(case) = state.active.iter().find(|case| case.case.id == case_id) else {
            return false;
        };
        !state.quiescing
            && !case.recovering
            && !case.accepting_dependencies
            && case.dependencies.snapshot().0 == 0
            && case.stream_tail.as_ref().is_some_and(|tail| {
                tail.is_enabled()
                    && tail.activity.is_quiet(tail.idle)
                    && !tail
                        .completed
                        .lock()
                        .expect("stream tail inventory poisoned")
                        .exceeded
            })
    }

    pub(crate) fn stream_tail_report(
        &self,
        case_id: Uuid,
    ) -> Option<(crate::recorder::CaseContext, serde_json::Value)> {
        let state = self.state.lock().expect("active case registry poisoned");
        let case = state.active.iter().find(|case| case.case.id == case_id)?;
        let tail = case
            .stream_tail
            .as_ref()
            .filter(|tail| tail.enabled.load(Ordering::Acquire))?;
        let inventory = tail
            .completed
            .lock()
            .expect("stream tail inventory poisoned");
        Some((
            case.case.clone(),
            serde_json::json!({
                "version": 1,
                "request_timeout_ms": tail.deadline.saturating_duration_since(tail.started).as_millis(),
                "idle_ms": tail.idle.as_millis(),
                "elapsed_ms": tail.started.elapsed().as_millis(),
                "in_flight": tail.activity.snapshot().0,
                "inventory_complete": !inventory.exceeded,
                "completed_refs": inventory.references,
            }),
        ))
    }

    pub(super) async fn drain_stream_tail(
        &self,
        case_id: Uuid,
        writer_timeout: Duration,
    ) -> Option<DependencyDrainResult> {
        let tail = self.enabled_stream_tail(case_id)?;
        // A completed primary starts the observation window even if the most
        // recent dependency happened long before that response.
        tail.activity.touch();
        let (dependencies, quiet) = loop {
            let quiet = tail
                .activity
                .wait_until_quiet_until(tail.idle, tail.deadline)
                .await;
            let mut state = self.state.lock().expect("active case registry poisoned");
            if quiet && !tail.activity.is_quiet(tail.idle) {
                continue;
            }
            let Some(case) = state.active.iter_mut().find(|case| case.case.id == case_id) else {
                return Some(DependencyDrainResult::Drained);
            };
            // Admission, live request creation and this closure share one lock.
            case.accepting_dependencies = false;
            break (case.dependencies.clone(), quiet);
        };
        if !quiet {
            self.begin_quiescing();
            tracing::warn!(
                %case_id,
                in_flight = tail.activity.snapshot().0,
                request_timeout_ms = tail.deadline.saturating_duration_since(tail.started).as_millis(),
                "stream dependency observation reached its deadline; retaining live requests and quarantining case admission"
            );
            // Budget expiry is not a peer termination. Preserve the original
            // guard and attribution until already admitted business I/O ends.
            tail.activity.wait_until_idle().await;
        }
        let now = Instant::now();
        let writer_deadline = now.checked_add(writer_timeout).unwrap_or(now);
        let writers_finished = dependencies.wait_until_idle_until(writer_deadline).await;
        if !writers_finished {
            self.begin_quiescing();
            tracing::warn!(
                %case_id,
                in_flight = dependencies.snapshot().0,
                writer_timeout_ms = writer_timeout.as_millis(),
                "stream dependency writer drain exceeded its budget; retaining case ownership until evidence is written"
            );
            // Finalizing now would silently discard late events for this case.
            dependencies.wait_until_idle().await;
        }
        Some(if !quiet {
            DependencyDrainResult::ObservationTimedOut
        } else if !writers_finished {
            DependencyDrainResult::TimedOut
        } else {
            DependencyDrainResult::Drained
        })
    }
}

#[cfg(test)]
mod tests;
