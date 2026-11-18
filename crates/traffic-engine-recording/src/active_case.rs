use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::sync::watch;
use uuid::Uuid;

use crate::recorder::{CaseContext, CaseInvalidation};

mod activity;
mod async_api;
mod client_abort;
mod correlation;
mod publication;
mod recovery;
mod shutdown;
mod socketio_close;
mod stream_tail;

use activity::{DependencyActivity, DependencyReservation};
pub use publication::CasePublication;
pub use socketio_close::{SOCKETIO_CLOSE_LIMIT, SOCKETIO_CLOSE_TAIL_TIMEOUT};
use stream_tail::{StreamTail, StreamTailRequest};

#[derive(Clone)]
pub struct ActiveCaseRegistry {
    state: Arc<Mutex<ActiveCaseState>>,
    active_count: watch::Sender<usize>,
    quiescing: watch::Sender<bool>,
    capture: Option<crate::recorder::ledger::CaptureRegistry>,
}

struct ActiveCaseState {
    active: Vec<ActiveCaseRegistration>,
    case_publications: std::collections::HashMap<Uuid, Arc<CasePublication>>,
    bootstrap_open: bool,
    bootstrap_sealed: bool,
    bootstrap_dependencies: Arc<DependencyActivity>,
    case_matching_ready: bool,
    admission_closed: bool,
    quiescing: bool,
    shutdown: Option<shutdown::ShutdownContext>,
    socketio_close_limit_case: Option<Uuid>,
}

#[derive(Debug, Clone)]
struct ActiveCaseRegistration {
    case: CaseContext,
    invalidation: Option<CaseInvalidation>,
    accepting_dependencies: bool,
    activated: bool,
    dependencies: Arc<DependencyActivity>,
    recovering: bool,
    source_completed: bool,
    stream_tail: Option<Arc<StreamTail>>,
    async_api: Option<Arc<async_api::AsyncObservation>>,
}

impl ActiveCaseRegistration {
    fn business_activity(&self) -> Arc<DependencyActivity> {
        self.stream_tail
            .as_ref()
            .map(|tail| tail.activity())
            .unwrap_or_else(|| self.dependencies.clone())
    }
}

pub struct ActiveCaseGuard {
    registry: ActiveCaseRegistry,
    case_id: Uuid,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActiveCaseRejection {
    NotReady,
    Busy,
    Quiescing,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActiveCaseActivationError {
    Quiescing,
    ReservationMissing,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DependencyDrainResult {
    Drained,
    TimedOut,
    ObservationTimedOut,
}

#[derive(Clone)]
pub struct DependencyTargets {
    pub cases: Vec<(CaseContext, &'static str)>,
    pub bootstrap_open: bool,
    pub ambiguous_active_cases: usize,
    pub process_owned_rule: Option<String>,
    pub process_rule_ids: Vec<String>,
    pub unattributed_reason: Option<&'static str>,
    pub observed_case: Option<Uuid>,
    pub shutdown_case_id: Option<Uuid>,
    pub phase: crate::dependency::observation::CapturePhase,
    pub capture: Option<crate::recorder::ledger::CaptureReservation>,
    _reservations: Vec<DependencyReservation>,
    stream_tail: Vec<StreamTailRequest>,
}

impl traffic_recorder::CaptureScope for DependencyTargets {
    fn context(&self) -> traffic_recorder::CaptureContext<'_> {
        traffic_recorder::CaptureContext {
            cases: &self.cases,
            bootstrap_open: self.bootstrap_open,
            ambiguous_active_cases: self.ambiguous_active_cases,
            process_owned_rule: self.process_owned_rule.as_deref(),
            process_rule_ids: &self.process_rule_ids,
            unattributed_reason: self.unattributed_reason,
            observed_case: self.observed_case,
            shutdown_case_id: self.shutdown_case_id,
            phase: self.phase,
            capture: self.capture.as_ref(),
        }
    }
}

impl std::fmt::Debug for DependencyTargets {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DependencyTargets")
            .field("cases", &self.cases)
            .field("capture", &self.capture)
            .finish()
    }
}

impl Drop for ActiveCaseGuard {
    fn drop(&mut self) {
        self.registry.unregister(self.case_id);
    }
}

impl ActiveCaseGuard {
    pub fn activate_dependencies(&self) -> Result<(), ActiveCaseActivationError> {
        self.registry.activate_dependencies(self.case_id)
    }
}

impl Default for ActiveCaseRegistry {
    fn default() -> Self {
        Self::new(true)
    }
}

impl ActiveCaseRegistry {
    pub fn new(case_matching_ready: bool) -> Self {
        let (active_count, _) = watch::channel(0);
        let (quiescing, _) = watch::channel(false);
        Self {
            state: Arc::new(Mutex::new(ActiveCaseState {
                active: Vec::new(),
                case_publications: std::collections::HashMap::new(),
                bootstrap_open: true,
                bootstrap_sealed: false,
                bootstrap_dependencies: Arc::new(DependencyActivity::default()),
                case_matching_ready,
                admission_closed: false,
                quiescing: false,
                shutdown: None,
                socketio_close_limit_case: None,
            })),
            active_count,
            quiescing,
            capture: None,
        }
    }

    pub fn with_capture(mut self, capture: crate::recorder::ledger::CaptureRegistry) -> Self {
        self.capture = Some(capture);
        self
    }

    pub fn try_reserve(&self, case: CaseContext) -> Result<ActiveCaseGuard, ActiveCaseRejection> {
        let mut state = self.state.lock().expect("active case registry poisoned");
        if state.quiescing || state.admission_closed {
            return Err(ActiveCaseRejection::Quiescing);
        }
        if !state.case_matching_ready {
            return Err(ActiveCaseRejection::NotReady);
        }
        if !state.active.is_empty() {
            return Err(ActiveCaseRejection::Busy);
        }
        state.bootstrap_open = false;
        if let Some(capture) = &self.capture {
            let _ = capture.input(case.id, 0, traffic_model::trace::InputKind::Request);
        }
        state.active.push(ActiveCaseRegistration {
            case: case.clone(),
            invalidation: None,
            accepting_dependencies: false,
            activated: false,
            dependencies: Arc::new(DependencyActivity::default()),
            recovering: false,
            source_completed: false,
            stream_tail: None,
            async_api: None,
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
        registration.activated = true;
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
            state.begin_shutdown();
            state.quiescing = true;
            self.quiescing.send_replace(true);
        }
        state
            .active
            .retain(|registration| registration.case.id != case_id);
        state.case_publications.remove(&case_id);
        self.active_count.send_replace(state.active.len());
    }

    pub fn close_bootstrap(&self) -> bool {
        let mut state = self.state.lock().expect("active case registry poisoned");
        let was_open = state.bootstrap_open;
        state.bootstrap_open = false;
        was_open
    }

    pub fn enable_case_matching(&self) -> bool {
        let mut state = self.state.lock().expect("active case registry poisoned");
        if state.quiescing || state.admission_closed {
            return false;
        }
        state.case_matching_ready = true;
        true
    }

    pub fn begin_quiescing(&self) -> bool {
        let mut state = self.state.lock().expect("active case registry poisoned");
        self.begin_quiescing_locked(&mut state)
    }

    /// Freeze shutdown association before a completion signal can release its Case.
    fn begin_quiescing_locked(&self, state: &mut ActiveCaseState) -> bool {
        let changed = !state.quiescing;
        state.begin_shutdown();
        state.quiescing = true;
        state.case_matching_ready = false;
        state.bootstrap_open = false;
        // Publish the actual stop boundary before waking protocol cancellation
        // observers, which need this provenance for their retained requests.
        for case in &state.active {
            if let Some(observation) = &case.async_api {
                observation.mark_source_stop();
            }
        }
        self.quiescing.send_replace(true);
        changed
    }

    /// Closed admission requires the recording supervisor to stop Source and
    /// drain evidence, including when a live dependency prevents publication.
    pub async fn wait_for_quiescing(&self) {
        let mut quiescing = self.quiescing.subscribe();
        loop {
            if *quiescing.borrow_and_update() {
                return;
            }
            if quiescing.changed().await.is_err() {
                return;
            }
        }
    }

    pub fn is_quiescing(&self) -> bool {
        self.state
            .lock()
            .expect("active case registry poisoned")
            .quiescing
    }

    pub async fn wait_for_no_active_case(&self, timeout: Duration) -> bool {
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

    pub async fn wait_for_bootstrap_dependencies(&self) {
        let dependencies = {
            let state = self.state.lock().expect("active case registry poisoned");
            state.bootstrap_dependencies.clone()
        };
        dependencies.wait_until_idle().await;
    }

    pub fn is_bootstrap_open(&self) -> bool {
        let state = self.state.lock().expect("active case registry poisoned");
        state.bootstrap_open
    }

    pub fn is_bootstrap_sealed(&self) -> bool {
        let state = self.state.lock().expect("active case registry poisoned");
        state.bootstrap_sealed
    }

    pub fn mark_bootstrap_sealed(&self) {
        let mut state = self.state.lock().expect("active case registry poisoned");
        state.bootstrap_sealed = true;
    }

    #[cfg(test)]
    pub fn case_slot_occupied(&self) -> bool {
        let state = self.state.lock().expect("active case registry poisoned");
        !state.active.is_empty()
    }

    pub fn invalidate_current_case(&self, invalidation: CaseInvalidation) -> Option<CaseContext> {
        let mut state = self.state.lock().expect("active case registry poisoned");
        let [registration] = state.active.as_mut_slice() else {
            return None;
        };
        if !registration.accepting_dependencies {
            return None;
        }
        if let Some(earlier) = &mut registration.invalidation {
            if !invalidation.can_recover_after_drain() {
                earlier.prevent_drained_case_recovery();
            }
        } else {
            registration.invalidation = Some(invalidation);
        }
        Some(registration.case.clone())
    }

    pub fn invalidate_case(
        &self,
        case_id: Uuid,
        invalidation: CaseInvalidation,
    ) -> Option<CaseContext> {
        let mut state = self.state.lock().expect("active case registry poisoned");
        let registration = state
            .active
            .iter_mut()
            .find(|registration| registration.case.id == case_id)?;
        if !registration.accepting_dependencies
            && registration.async_api.is_none()
            && !registration
                .stream_tail
                .as_ref()
                .is_some_and(|tail| tail.is_enabled())
        {
            return None;
        }
        if let Some(earlier) = &mut registration.invalidation {
            if !invalidation.can_recover_after_drain() {
                earlier.prevent_drained_case_recovery();
            }
        } else {
            registration.invalidation = Some(invalidation);
        }
        Some(registration.case.clone())
    }

    pub fn invalidation_for(&self, case_id: Uuid) -> Option<CaseInvalidation> {
        let state = self.state.lock().expect("active case registry poisoned");
        state
            .active
            .iter()
            .find(|registration| registration.case.id == case_id)
            .and_then(|registration| registration.invalidation.clone())
    }

    pub async fn drain_case_dependencies(
        &self,
        case_id: Uuid,
        _post_response_window: Duration,
        timeout: Duration,
    ) -> DependencyDrainResult {
        if self.is_recovering(case_id) {
            return self
                .drain_recovering_case(case_id, Duration::ZERO, timeout)
                .await;
        }
        if let Some(result) = self.drain_async_api(case_id, timeout).await {
            return result;
        }
        if let Some(result) = self.drain_stream_tail(case_id, timeout).await {
            return result;
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
            self.begin_quiescing();
            DependencyDrainResult::TimedOut
        }
    }

    pub fn current_targets_for_event(&self) -> DependencyTargets {
        self.targets_for_request(false, false)
    }

    #[allow(dead_code)]
    pub fn current_targets_for_request_with_tail(&self, track_tail: bool) -> DependencyTargets {
        self.targets_for_request(track_tail, true)
    }

    pub fn current_targets_for_http_request(&self, track_tail: bool) -> DependencyTargets {
        self.targets_for_request(track_tail, true)
    }

    pub fn current_targets_for_start(
        &self,
        protocol: crate::dependency::observation::ProtocolRef,
    ) -> DependencyTargets {
        let targets = self.targets_for_request(true, true);
        targets.bind_protocol(protocol);
        targets
    }

    fn targets_for_request(&self, track_tail: bool, start_capture: bool) -> DependencyTargets {
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
        let observed_case = state.active.first().map(|r| r.case.id);
        let phase = if state.quiescing || state.admission_closed {
            crate::dependency::observation::CapturePhase::Shutdown
        } else if bootstrap_open {
            crate::dependency::observation::CapturePhase::Startup
        } else {
            crate::dependency::observation::CapturePhase::Runtime
        };
        let capture = start_capture
            .then(|| {
                self.capture.as_ref().and_then(|registry| {
                    registry.begin(phase, observed_case, cases.first().map(|(case, _)| case.id))
                })
            })
            .flatten();
        if bootstrap_open {
            reservations.push(state.bootstrap_dependencies.reserve());
        }
        let stream_tail = match state.active.as_slice() {
            [case] if track_tail && case.accepting_dependencies => case
                .stream_tail
                .as_ref()
                .map(|tail| tail.reserve())
                .into_iter()
                .collect(),
            _ => Vec::new(),
        };
        DependencyTargets {
            bootstrap_open,
            cases,
            ambiguous_active_cases,
            process_owned_rule: None,
            process_rule_ids: Vec::new(),
            unattributed_reason: None,
            observed_case,
            shutdown_case_id: state.shutdown.and_then(|shutdown| shutdown.case_id),
            phase,
            capture,
            _reservations: reservations,
            stream_tail,
        }
    }
}

impl DependencyTargets {
    pub fn prepare_output(
        &self,
        output: traffic_model::trace::OutputKind,
    ) -> Option<crate::recorder::ledger::OutputReservation> {
        self.capture.as_ref()?.prepare_output(output)
    }
    pub fn transformed(&self, transformation: traffic_model::recording::Transformation) {
        if let Some(capture) = &self.capture {
            capture.transformed(transformation);
        }
    }
    pub fn record_output(&self, outcome: crate::DependencyExchangeOutcome) {
        use traffic_model::trace::OutputKind;
        if let Some(capture) = &self.capture {
            capture.output(match outcome {
                crate::DependencyExchangeOutcome::Response => OutputKind::End,
                crate::DependencyExchangeOutcome::NoResponse => OutputKind::NoResponse,
                crate::DependencyExchangeOutcome::ClientTerminated => return,
                crate::DependencyExchangeOutcome::Terminated(termination) => {
                    OutputKind::Terminated { termination }
                }
            });
        }
    }
    pub fn bind_protocol(&self, protocol: crate::dependency::observation::ProtocolRef) {
        if let Some(capture) = &self.capture {
            capture.bind_protocol(protocol);
        }
    }

    pub fn finish_capture_metadata(&self, outcome: &str) {
        if let Some(capture) = &self.capture {
            capture.finish_metadata(outcome);
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
                activated: true,
                dependencies: Arc::new(DependencyActivity::default()),
                recovering: false,
                source_completed: false,
                stream_tail: None,
                async_api: None,
            });
            state.active.push(ActiveCaseRegistration {
                case: second,
                invalidation: None,
                accepting_dependencies: true,
                activated: true,
                dependencies: Arc::new(DependencyActivity::default()),
                recovering: false,
                source_completed: false,
                stream_tail: None,
                async_api: None,
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
    async fn ordinary_case_closes_admission_without_a_post_response_sleep() {
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

        assert!(registry.current_targets_for_event().cases.is_empty());
        assert_eq!(
            tokio::time::timeout(Duration::from_millis(30), closing)
                .await
                .unwrap()
                .unwrap(),
            DependencyDrainResult::Drained
        );
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
