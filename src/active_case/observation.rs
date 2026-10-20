//! Rule-scoped request activity, independent of writer and attribution lifetimes.

use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use uuid::Uuid;

use super::activity::{DependencyActivity, DependencyReservation};
use super::{ActiveCaseRegistry, DependencyDrainResult, DependencyTargets};
use crate::recorder::RecorderEvent;
use crate::recorder::api_origin_observation::{ApiOriginScope, DependencyRequest};

const MAX_SELECTED_REFS: usize = 100_000;

#[derive(Debug)]
pub(super) struct CaseObservation {
    scope: ApiOriginScope,
    activity: Arc<DependencyActivity>,
    idle: Duration,
    deadline: Instant,
    started: Instant,
    completed: Mutex<CompletedInventory>,
}

#[derive(Debug, Default)]
struct CompletedInventory {
    references: BTreeSet<SelectedCompletedRef>,
    exceeded: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, serde::Serialize)]
struct SelectedCompletedRef {
    protocol: &'static str,
    connection_id: Uuid,
    sequence: u64,
}

/// Clones share one request. Enqueueing or flushing evidence cannot renew idle.
#[derive(Debug, Clone)]
pub(super) struct SelectedRequest(Arc<Mutex<Option<DependencyReservation>>>);

impl SelectedRequest {
    fn finish(&self) {
        self.0.lock().expect("selected request poisoned").take();
    }
}

impl CaseObservation {
    pub(super) fn select(&self, request: &DependencyRequest<'_>) -> Option<SelectedRequest> {
        self.scope.select_request(request)?;
        Some(SelectedRequest(Arc::new(Mutex::new(Some(
            self.activity.reserve(),
        )))))
    }
}

impl DependencyTargets {
    /// Correlation metadata is not an unfinished network request.
    pub(crate) fn attribution_only(&self) -> Self {
        Self {
            cases: self.cases.clone(),
            bootstrap_open: self.bootstrap_open,
            ambiguous_active_cases: self.ambiguous_active_cases,
            _reservations: Vec::new(),
            selected: Vec::new(),
        }
    }

    pub(crate) fn complete_selected_request(&self) {
        for selected in &self.selected {
            selected.finish();
        }
    }
}

impl ActiveCaseRegistry {
    pub(crate) fn configure_observation(
        &self,
        case_id: Uuid,
        scope: ApiOriginScope,
        idle: Duration,
        started: Instant,
        timeout: Duration,
    ) {
        let mut state = self.state.lock().expect("active case registry poisoned");
        if let Some(case) = state.active.iter_mut().find(|case| case.case.id == case_id) {
            case.observation = Some(Arc::new(CaseObservation {
                scope,
                activity: Arc::new(DependencyActivity::default()),
                idle,
                deadline: started.checked_add(timeout).unwrap_or(started),
                started,
                completed: Mutex::new(CompletedInventory::default()),
            }));
        }
    }

    pub(crate) fn observe_dependency_event(
        &self,
        event: &RecorderEvent,
        targets: &DependencyTargets,
        recorded_in_case: bool,
    ) {
        if !matches!(
            event,
            RecorderEvent::MysqlExchange(_) | RecorderEvent::RedisExchange(_)
        ) {
            return;
        }
        let state = self.state.lock().expect("active case registry poisoned");
        for (target, _) in &targets.cases {
            if let Some(observation) = state
                .active
                .iter()
                .find(|case| case.case.id == target.id)
                .and_then(|case| case.observation.as_ref())
            {
                observation.scope.observe_completed(event);
                if recorded_in_case && !targets.selected.is_empty() {
                    let reference = match event {
                        RecorderEvent::MysqlExchange(exchange) => SelectedCompletedRef {
                            protocol: "mysql",
                            connection_id: exchange.connection_id,
                            sequence: exchange.query_sequence,
                        },
                        RecorderEvent::RedisExchange(exchange) => SelectedCompletedRef {
                            protocol: "redis",
                            connection_id: exchange.connection_id,
                            sequence: exchange.sequence,
                        },
                        _ => unreachable!("semantic exchanges filtered above"),
                    };
                    let mut inventory = observation
                        .completed
                        .lock()
                        .expect("observation inventory poisoned");
                    if inventory.references.len() == MAX_SELECTED_REFS
                        && !inventory.references.contains(&reference)
                    {
                        inventory.exceeded = true;
                    } else {
                        inventory.references.insert(reference);
                    }
                }
            }
        }
        targets.complete_selected_request();
    }

    /// Reacquire only the original attribution while its admission is still open.
    pub(crate) fn reacquire_targets(
        &self,
        original: &DependencyTargets,
    ) -> Option<DependencyTargets> {
        let state = self.state.lock().expect("active case registry poisoned");
        let mut reservations = Vec::new();
        let cases = state
            .active
            .iter()
            .filter(|case| {
                case.accepting_dependencies
                    && original
                        .cases
                        .iter()
                        .any(|(target, _)| target.id == case.case.id)
            })
            .map(|case| {
                reservations.push(case.dependencies.reserve());
                let reason = original
                    .cases
                    .iter()
                    .find(|(target, _)| target.id == case.case.id)
                    .unwrap()
                    .1;
                (case.case.clone(), reason)
            })
            .collect::<Vec<_>>();
        let bootstrap_open =
            original.bootstrap_open && state.bootstrap_open && state.active.is_empty();
        if bootstrap_open {
            reservations.push(state.bootstrap_dependencies.reserve());
        }
        (!cases.is_empty() || bootstrap_open).then_some(DependencyTargets {
            cases,
            bootstrap_open,
            ambiguous_active_cases: 0,
            _reservations: reservations,
            selected: Vec::new(),
        })
    }

    pub(super) async fn drain_observation(
        &self,
        case_id: Uuid,
        drain_timeout: Duration,
    ) -> Option<DependencyDrainResult> {
        let observation = {
            let state = self.state.lock().expect("active case registry poisoned");
            state
                .active
                .iter()
                .find(|case| case.case.id == case_id)?
                .observation
                .clone()?
        };
        // Idle starts no earlier than primary response completion.
        drop(observation.activity.reserve());
        let (dependencies, quiet) = loop {
            let quiet = observation
                .activity
                .wait_until_quiet_until(observation.idle, observation.deadline)
                .await;
            let mut state = self.state.lock().expect("active case registry poisoned");
            if quiet && !observation.activity.is_quiet(observation.idle) {
                continue;
            }
            let Some(case) = state.active.iter_mut().find(|case| case.case.id == case_id) else {
                return Some(DependencyDrainResult::Drained);
            };
            // Selection, reservation and closing admission share this lock.
            case.accepting_dependencies = false;
            break (case.dependencies.clone(), quiet);
        };
        let now = Instant::now();
        let drain_deadline = now.checked_add(drain_timeout).unwrap_or(now);
        if !dependencies.wait_until_idle_until(drain_deadline).await {
            // Keep Source running, but refuse another case while old I/O can leak.
            self.begin_quiescing();
            return Some(DependencyDrainResult::TimedOut);
        }
        Some(if quiet {
            DependencyDrainResult::Drained
        } else {
            self.begin_quiescing();
            DependencyDrainResult::ObservationTimedOut
        })
    }

    pub(crate) fn observation_deadline(&self, case_id: Uuid) -> Option<Instant> {
        self.state
            .lock()
            .expect("active case registry poisoned")
            .active
            .iter()
            .find(|case| case.case.id == case_id)?
            .observation
            .as_ref()
            .map(|observation| observation.deadline)
    }

    pub(crate) fn observation_report(
        &self,
        case_id: Uuid,
    ) -> Option<(crate::recorder::CaseContext, serde_json::Value)> {
        let state = self.state.lock().expect("active case registry poisoned");
        let case = state.active.iter().find(|case| case.case.id == case_id)?;
        let observation = case.observation.as_ref()?;
        let (in_flight, _) = observation.activity.snapshot();
        let inventory = observation
            .completed
            .lock()
            .expect("observation inventory poisoned");
        Some((
            case.case.clone(),
            serde_json::json!({
                "version": 1,
                "idle_ms": observation.idle.as_millis(),
                "request_timeout_ms": observation.deadline.saturating_duration_since(observation.started).as_millis(),
                "elapsed_ms": observation.started.elapsed().as_millis(),
                "selected_in_flight": in_flight,
                "rules": observation.scope.snapshot(),
                "selected_completed_refs": inventory.references,
                "inventory_complete": !inventory.exceeded,
            }),
        ))
    }
}

#[cfg(test)]
mod tests;
