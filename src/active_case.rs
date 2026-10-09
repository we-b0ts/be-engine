use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::sync::watch;
use uuid::Uuid;

use crate::recorder::{CaseContext, CaseInvalidation};

mod activity;
mod recovery;

use activity::{DependencyActivity, DependencyReservation};

#[derive(Clone)]
pub(crate) struct ActiveCaseRegistry {
    state: Arc<Mutex<ActiveCaseState>>,
    active_count: watch::Sender<usize>,
}

struct ActiveCaseState {
    active: Vec<ActiveCaseRegistration>,
    bootstrap_open: bool,
    bootstrap_sealed: bool,
    bootstrap_dependencies: Arc<DependencyActivity>,
    case_matching_ready: bool,
    quiescing: bool,
}

#[derive(Debug, Clone)]
struct ActiveCaseRegistration {
    case: CaseContext,
    invalidation: Option<CaseInvalidation>,
    accepting_dependencies: bool,
    dependencies: Arc<DependencyActivity>,
    recovering: bool,
    source_completed: bool,
}

pub(crate) struct ActiveCaseGuard {
    registry: ActiveCaseRegistry,
    case_id: Uuid,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ActiveCaseRejection {
    NotReady,
    Busy,
    Quiescing,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ActiveCaseActivationError {
    Quiescing,
    ReservationMissing,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DependencyDrainResult {
    Drained,
    TimedOut,
}

#[derive(Clone)]
pub(crate) struct DependencyTargets {
    pub(crate) cases: Vec<(CaseContext, &'static str)>,
    pub(crate) bootstrap_open: bool,
    pub(crate) ambiguous_active_cases: usize,
    _reservations: Vec<DependencyReservation>,
}

impl Drop for ActiveCaseGuard {
    fn drop(&mut self) {
        self.registry.unregister(self.case_id);
    }
}

impl ActiveCaseGuard {
    pub(crate) fn activate_dependencies(&self) -> Result<(), ActiveCaseActivationError> {
        self.registry.activate_dependencies(self.case_id)
    }
}

impl Default for ActiveCaseRegistry {
    fn default() -> Self {
        Self::new(true)
    }
}

impl ActiveCaseRegistry {
    pub(crate) fn new(case_matching_ready: bool) -> Self {
        let (active_count, _) = watch::channel(0);
        Self {
            state: Arc::new(Mutex::new(ActiveCaseState {
                active: Vec::new(),
                bootstrap_open: true,
                bootstrap_sealed: false,
                bootstrap_dependencies: Arc::new(DependencyActivity::default()),
                case_matching_ready,
                quiescing: false,
            })),
            active_count,
        }
    }

    pub(crate) fn try_reserve(
        &self,
        case: CaseContext,
    ) -> Result<ActiveCaseGuard, ActiveCaseRejection> {
        let mut state = self.state.lock().expect("active case registry poisoned");
        if state.quiescing {
            return Err(ActiveCaseRejection::Quiescing);
        }
        if !state.case_matching_ready {
            return Err(ActiveCaseRejection::NotReady);
        }
        if !state.active.is_empty() {
            return Err(ActiveCaseRejection::Busy);
        }
        state.bootstrap_open = false;
        state.active.push(ActiveCaseRegistration {
            case: case.clone(),
            invalidation: None,
            accepting_dependencies: false,
            dependencies: Arc::new(DependencyActivity::default()),
            recovering: false,
            source_completed: false,
        });
        self.active_count.send_replace(state.active.len());
        Ok(ActiveCaseGuard {
            registry: self.clone(),
            case_id: case.id,
        })
    }

    fn activate_dependencies(&self, case_id: Uuid) -> Result<(), ActiveCaseActivationError> {
        let mut state = self.state.lock().expect("active case registry poisoned");
        if state.quiescing {
            return Err(ActiveCaseActivationError::Quiescing);
        }
        let registration = state
            .active
            .iter_mut()
            .find(|registration| registration.case.id == case_id)
            .ok_or(ActiveCaseActivationError::ReservationMissing)?;
        registration.accepting_dependencies = true;
        Ok(())
    }

    fn unregister(&self, case_id: Uuid) {
        let mut state = self.state.lock().expect("active case registry poisoned");
        // A cancelled or panicked recovery cannot establish that Source has stopped.
        if state
            .active
            .iter()
            .any(|registration| registration.case.id == case_id && registration.recovering)
        {
            state.quiescing = true;
        }
        state
            .active
            .retain(|registration| registration.case.id != case_id);
        self.active_count.send_replace(state.active.len());
    }

    pub(crate) fn close_bootstrap(&self) -> bool {
        let mut state = self.state.lock().expect("active case registry poisoned");
        let was_open = state.bootstrap_open;
        state.bootstrap_open = false;
        was_open
    }

    pub(crate) fn enable_case_matching(&self) -> bool {
        let mut state = self.state.lock().expect("active case registry poisoned");
        if state.quiescing {
            return false;
        }
        state.case_matching_ready = true;
        true
    }

    pub(crate) fn begin_quiescing(&self) -> bool {
        let mut state = self.state.lock().expect("active case registry poisoned");
        let changed = !state.quiescing;
        state.quiescing = true;
        state.case_matching_ready = false;
        state.bootstrap_open = false;
        changed
    }

    pub(crate) fn is_quiescing(&self) -> bool {
        self.state
            .lock()
            .expect("active case registry poisoned")
            .quiescing
    }

    pub(crate) async fn wait_for_no_active_case(&self, timeout: Duration) -> bool {
        let mut active_count = self.active_count.subscribe();
        tokio::time::timeout(timeout, async {
            while *active_count.borrow_and_update() != 0 {
                if active_count.changed().await.is_err() {
                    return;
                }
            }
        })
        .await
        .is_ok()
    }

    pub(crate) async fn wait_for_bootstrap_dependencies(&self) {
        let dependencies = {
            let state = self.state.lock().expect("active case registry poisoned");
            state.bootstrap_dependencies.clone()
        };
        dependencies.wait_until_idle().await;
    }

    pub(crate) fn is_bootstrap_open(&self) -> bool {
        let state = self.state.lock().expect("active case registry poisoned");
        state.bootstrap_open
    }

    pub(crate) fn is_bootstrap_sealed(&self) -> bool {
        let state = self.state.lock().expect("active case registry poisoned");
        state.bootstrap_sealed
    }

    pub(crate) fn mark_bootstrap_sealed(&self) {
        let mut state = self.state.lock().expect("active case registry poisoned");
        state.bootstrap_sealed = true;
    }

    #[cfg(test)]
    pub(crate) fn case_slot_occupied(&self) -> bool {
        let state = self.state.lock().expect("active case registry poisoned");
        !state.active.is_empty()
    }

    pub(crate) fn invalidate_current_case(
        &self,
        invalidation: CaseInvalidation,
    ) -> Option<CaseContext> {
        let mut state = self.state.lock().expect("active case registry poisoned");
        let [registration] = state.active.as_mut_slice() else {
            return None;
        };
        if !registration.accepting_dependencies {
            return None;
        }
        if registration.invalidation.is_none() {
            registration.invalidation = Some(invalidation);
        }
        Some(registration.case.clone())
    }

    pub(crate) fn invalidate_case(
        &self,
        case_id: Uuid,
        invalidation: CaseInvalidation,
    ) -> Option<CaseContext> {
        let mut state = self.state.lock().expect("active case registry poisoned");
        let registration = state
            .active
            .iter_mut()
            .find(|registration| registration.case.id == case_id)?;
        if !registration.accepting_dependencies {
            return None;
        }
        if registration.invalidation.is_none() {
            registration.invalidation = Some(invalidation);
        }
        Some(registration.case.clone())
    }

    pub(crate) fn invalidation_for(&self, case_id: Uuid) -> Option<CaseInvalidation> {
        let state = self.state.lock().expect("active case registry poisoned");
        state
            .active
            .iter()
            .find(|registration| registration.case.id == case_id)
            .and_then(|registration| registration.invalidation.clone())
    }

    pub(crate) async fn drain_case_dependencies(
        &self,
        case_id: Uuid,
        post_response_window: Duration,
        timeout: Duration,
    ) -> DependencyDrainResult {
        if self.is_recovering(case_id) {
            return self
                .drain_recovering_case(case_id, post_response_window, timeout)
                .await;
        }
        if !post_response_window.is_zero() {
            tokio::time::sleep(post_response_window).await;
        }

        let started = Instant::now();
        let deadline = started.checked_add(timeout).unwrap_or(started);
        let dependencies = {
            let mut state = self.state.lock().expect("active case registry poisoned");
            let Some(registration) = state
                .active
                .iter_mut()
                .find(|registration| registration.case.id == case_id)
            else {
                return DependencyDrainResult::Drained;
            };
            registration.accepting_dependencies = false;
            registration.dependencies.clone()
        };
        if dependencies.wait_until_idle_until(deadline).await {
            DependencyDrainResult::Drained
        } else {
            DependencyDrainResult::TimedOut
        }
    }

    pub(crate) fn current_targets_for_event(&self) -> DependencyTargets {
        let state = self.state.lock().expect("active case registry poisoned");
        let active_count = state.active.len();
        let (cases, ambiguous_active_cases, mut reservations) = match state.active.as_slice() {
            [] => (Vec::new(), 0, Vec::new()),
            [registration] if registration.accepting_dependencies => (
                vec![(registration.case.clone(), "active_window")],
                0,
                vec![registration.dependencies.reserve()],
            ),
            [_] => (Vec::new(), 0, Vec::new()),
            active => (Vec::new(), active.len(), Vec::new()),
        };
        let bootstrap_open = state.bootstrap_open && active_count == 0;
        if bootstrap_open {
            reservations.push(state.bootstrap_dependencies.reserve());
        }
        DependencyTargets {
            bootstrap_open,
            cases,
            ambiguous_active_cases,
            _reservations: reservations,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn case() -> CaseContext {
        CaseContext {
            id: Uuid::new_v4(),
            rule_name: "http-rule".to_string(),
            uri_group: Some("api-user".to_string()),
        }
    }

    fn activate_case(registry: &ActiveCaseRegistry, case: CaseContext) -> ActiveCaseGuard {
        let guard = registry.try_reserve(case).unwrap();
        guard.activate_dependencies().unwrap();
        guard
    }

    #[test]
    fn first_case_closes_bootstrap_but_accepts_dependencies_only_after_activation() {
        let registry = ActiveCaseRegistry::default();

        let initial = registry.current_targets_for_event();
        assert!(initial.bootstrap_open);
        assert!(initial.cases.is_empty());

        let case = case();
        let guard = registry.try_reserve(case.clone()).unwrap();

        let reserved = registry.current_targets_for_event();
        assert!(!reserved.bootstrap_open);
        assert!(reserved.cases.is_empty());
        assert!(!registry.is_bootstrap_sealed());

        guard.activate_dependencies().unwrap();
        let active = registry.current_targets_for_event();
        assert_eq!(active.cases, vec![(case, "active_window")]);

        drop(guard);
        let after_case = registry.current_targets_for_event();
        assert!(!after_case.bootstrap_open);
        assert!(after_case.cases.is_empty());
    }

    #[test]
    fn keeps_first_invalidation_until_case_finishes() {
        let registry = ActiveCaseRegistry::default();
        let case = case();
        let guard = activate_case(&registry, case.clone());
        let first = CaseInvalidation::new("first_reason", "first message");
        let second = CaseInvalidation::new("second_reason", "second message");

        assert_eq!(
            registry.invalidate_current_case(first.clone()),
            Some(case.clone())
        );
        assert_eq!(registry.invalidate_current_case(second), Some(case.clone()));
        assert_eq!(registry.invalidation_for(case.id), Some(first));

        drop(guard);
        assert_eq!(registry.invalidation_for(case.id), None);
    }

    #[test]
    fn invalidates_only_the_requested_active_case() {
        let registry = ActiveCaseRegistry::default();
        let active = case();
        let other = case();
        let guard = activate_case(&registry, active.clone());
        let invalidation = CaseInvalidation::new("client_disconnected", "client disconnected");

        assert_eq!(
            registry.invalidate_case(other.id, invalidation.clone()),
            None
        );
        assert_eq!(registry.invalidation_for(active.id), None);
        assert_eq!(
            registry.invalidate_case(active.id, invalidation.clone()),
            Some(active.clone())
        );
        assert_eq!(registry.invalidation_for(active.id), Some(invalidation));

        drop(guard);
    }

    #[test]
    fn rejects_cases_before_ready() {
        let registry = ActiveCaseRegistry::new(false);
        let case = case();

        assert!(matches!(
            registry.try_reserve(case.clone()),
            Err(ActiveCaseRejection::NotReady)
        ));
        assert!(registry.current_targets_for_event().bootstrap_open);

        assert!(registry.close_bootstrap());
        assert!(registry.enable_case_matching());
        let guard = activate_case(&registry, case.clone());
        let active = registry.current_targets_for_event();
        assert_eq!(active.cases, vec![(case, "active_window")]);
        drop(guard);
    }

    #[tokio::test]
    async fn quiescing_rejects_new_cases_and_waits_for_active_case() {
        let registry = ActiveCaseRegistry::default();
        let guard = activate_case(&registry, case());
        assert!(registry.begin_quiescing());
        assert!(!registry.begin_quiescing());
        assert!(registry.is_quiescing());
        assert!(matches!(
            registry.try_reserve(case()),
            Err(ActiveCaseRejection::Quiescing)
        ));

        let waiting = {
            let registry = registry.clone();
            tokio::spawn(async move {
                registry
                    .wait_for_no_active_case(Duration::from_secs(1))
                    .await
            })
        };
        tokio::task::yield_now().await;
        assert!(!waiting.is_finished());
        drop(guard);
        assert!(waiting.await.unwrap());
    }

    #[tokio::test]
    async fn active_case_shutdown_drain_can_time_out() {
        let registry = ActiveCaseRegistry::default();
        let _guard = activate_case(&registry, case());
        registry.begin_quiescing();

        assert!(
            !registry
                .wait_for_no_active_case(Duration::from_millis(1))
                .await
        );
    }

    #[test]
    fn quiescing_prevents_a_reserved_case_from_becoming_active() {
        let registry = ActiveCaseRegistry::default();
        let guard = registry.try_reserve(case()).unwrap();

        assert!(registry.current_targets_for_event().cases.is_empty());
        assert!(registry.begin_quiescing());
        assert_eq!(
            guard.activate_dependencies(),
            Err(ActiveCaseActivationError::Quiescing)
        );
        assert!(registry.current_targets_for_event().cases.is_empty());
    }

    #[test]
    fn allows_only_one_active_case() {
        let registry = ActiveCaseRegistry::default();
        let first = case();
        let second = case();

        let guard = activate_case(&registry, first);
        assert!(matches!(
            registry.try_reserve(second.clone()),
            Err(ActiveCaseRejection::Busy)
        ));

        drop(guard);
        assert!(registry.try_reserve(second).is_ok());
    }

    #[test]
    fn does_not_share_ambiguous_dependencies() {
        let registry = ActiveCaseRegistry::default();
        let first = case();
        let second = case();
        {
            let mut state = registry
                .state
                .lock()
                .expect("active case registry poisoned");
            state.bootstrap_open = false;
            state.active.push(ActiveCaseRegistration {
                case: first,
                invalidation: None,
                accepting_dependencies: true,
                dependencies: Arc::new(DependencyActivity::default()),
                recovering: false,
                source_completed: false,
            });
            state.active.push(ActiveCaseRegistration {
                case: second,
                invalidation: None,
                accepting_dependencies: true,
                dependencies: Arc::new(DependencyActivity::default()),
                recovering: false,
                source_completed: false,
            });
        }

        let targets = registry.current_targets_for_event();
        assert!(targets.cases.is_empty());
        assert_eq!(targets.ambiguous_active_cases, 2);
        assert!(!targets.bootstrap_open);
    }

    #[test]
    fn can_close_bootstrap_explicitly() {
        let registry = ActiveCaseRegistry::default();

        assert!(registry.is_bootstrap_open());
        assert!(registry.close_bootstrap());
        assert!(!registry.is_bootstrap_open());
        assert!(!registry.is_bootstrap_sealed());
        registry.mark_bootstrap_sealed();
        assert!(registry.is_bootstrap_sealed());
        assert!(!registry.close_bootstrap());

        let targets = registry.current_targets_for_event();
        assert!(!targets.bootstrap_open);
        assert!(targets.cases.is_empty());
    }

    #[tokio::test]
    async fn closing_case_stops_new_dependencies_and_waits_only_for_captured_dependencies() {
        let registry = ActiveCaseRegistry::default();
        let case = case();
        let _guard = activate_case(&registry, case.clone());
        let targets = registry.current_targets_for_event();
        assert_eq!(targets.cases, vec![(case.clone(), "active_window")]);

        let closing_registry = registry.clone();
        let closing = tokio::spawn(async move {
            closing_registry
                .drain_case_dependencies(case.id, Duration::ZERO, Duration::from_secs(5))
                .await
        });
        tokio::task::yield_now().await;
        assert!(!closing.is_finished());
        assert!(registry.current_targets_for_event().cases.is_empty());

        drop(targets);
        assert_eq!(
            tokio::time::timeout(Duration::from_millis(100), closing)
                .await
                .unwrap()
                .unwrap(),
            DependencyDrainResult::Drained
        );
    }

    #[tokio::test]
    async fn post_response_window_accepts_new_dependencies_until_it_closes() {
        let registry = ActiveCaseRegistry::default();
        let case = case();
        let _guard = activate_case(&registry, case.clone());

        let closing_registry = registry.clone();
        let closing_case_id = case.id;
        let closing = tokio::spawn(async move {
            closing_registry
                .drain_case_dependencies(
                    closing_case_id,
                    Duration::from_millis(100),
                    Duration::from_secs(5),
                )
                .await
        });
        tokio::task::yield_now().await;

        let during_window = registry.current_targets_for_event();
        assert_eq!(during_window.cases, vec![(case, "active_window")]);
        drop(during_window);

        tokio::time::sleep(Duration::from_millis(120)).await;
        assert!(registry.current_targets_for_event().cases.is_empty());
        assert_eq!(closing.await.unwrap(), DependencyDrainResult::Drained);
    }

    #[tokio::test]
    async fn dependency_drain_returns_immediately_when_nothing_is_in_flight() {
        let registry = ActiveCaseRegistry::default();
        let case = case();
        let _guard = activate_case(&registry, case.clone());

        assert_eq!(
            tokio::time::timeout(
                Duration::from_millis(100),
                registry.drain_case_dependencies(case.id, Duration::ZERO, Duration::from_secs(5),),
            )
            .await
            .unwrap(),
            DependencyDrainResult::Drained
        );
    }

    #[tokio::test]
    async fn closing_bootstrap_waits_for_captured_dependencies() {
        let registry = ActiveCaseRegistry::default();
        let targets = registry.current_targets_for_event();
        assert!(targets.bootstrap_open);
        assert!(registry.close_bootstrap());

        let waiting_registry = registry.clone();
        let waiting = tokio::spawn(async move {
            waiting_registry.wait_for_bootstrap_dependencies().await;
        });
        tokio::task::yield_now().await;
        assert!(!waiting.is_finished());

        drop(targets);
        waiting.await.unwrap();
    }

    #[tokio::test]
    async fn dependency_drain_times_out_while_request_remains_in_flight() {
        let registry = ActiveCaseRegistry::default();
        let case = case();
        let _guard = activate_case(&registry, case.clone());
        let targets = registry.current_targets_for_event();

        assert_eq!(
            registry
                .drain_case_dependencies(case.id, Duration::ZERO, Duration::from_millis(20),)
                .await,
            DependencyDrainResult::TimedOut
        );
        assert!(registry.current_targets_for_event().cases.is_empty());
        drop(targets);
    }
}
