//! Failed-case recovery barriers for Source completion and dependency ownership.

use std::time::{Duration, Instant};

use uuid::Uuid;

use super::{ActiveCaseRegistry, DependencyDrainResult};
use crate::recorder::CaseInvalidation;

impl ActiveCaseRegistry {
    /// The caller separately proves primary application teardown. This checks
    /// the shared attribution and writer barrier under the reservation lock.
    pub fn failed_case_dependencies_drained(&self, case_id: Uuid) -> bool {
        let state = self.state.lock().expect("active case registry poisoned");
        !state.quiescing
            && state.active.iter().any(|case| {
                case.case.id == case_id
                    && !case.recovering
                    && !case.accepting_dependencies
                    && case.dependencies.snapshot().0 == 0
            })
    }

    pub fn begin_timeout_recovery(&self, case_id: Uuid, message: String) -> bool {
        let mut state = self.state.lock().expect("active case registry poisoned");
        let Some(case) = state.active.iter_mut().find(|case| case.case.id == case_id) else {
            return false;
        };
        if !case.accepting_dependencies || case.recovering {
            return false;
        }
        case.recovering = true;
        case.invalidation
            .get_or_insert_with(|| CaseInvalidation::new("upstream_response_error", message));
        true
    }

    pub fn source_request_completed(&self, case_id: Uuid) {
        let mut state = self.state.lock().expect("active case registry poisoned");
        if let Some(case) = state
            .active
            .iter_mut()
            .find(|case| case.case.id == case_id && case.recovering)
        {
            case.source_completed = true;
            // Quiet starts after Source completion, even when its last query was earlier.
            drop(case.dependencies.reserve());
        }
    }

    pub fn is_recovering(&self, case_id: Uuid) -> bool {
        self.state
            .lock()
            .expect("active case registry poisoned")
            .active
            .iter()
            .any(|case| case.case.id == case_id && case.recovering)
    }

    pub(super) async fn drain_recovering_case(
        &self,
        case_id: Uuid,
        quiet: Duration,
        timeout: Duration,
    ) -> DependencyDrainResult {
        let dependencies = {
            let state = self.state.lock().expect("active case registry poisoned");
            let Some(case) = state.active.iter().find(|case| case.case.id == case_id) else {
                return DependencyDrainResult::Drained;
            };
            case.dependencies.clone()
        };
        let deadline = Instant::now() + timeout;
        loop {
            if !dependencies.wait_until_quiet_until(quiet, deadline).await {
                self.begin_quiescing();
                return DependencyDrainResult::TimedOut;
            }
            let mut state = self.state.lock().expect("active case registry poisoned");
            // Closing admission and checking quiet share the reservation lock order.
            // A dependency arriving between the wait and this lock restarts quiet.
            if !dependencies.is_quiet(quiet) {
                continue;
            }
            if let Some(case) = state.active.iter_mut().find(|case| case.case.id == case_id) {
                case.accepting_dependencies = false;
                if case.source_completed {
                    case.recovering = false;
                }
            }
            return DependencyDrainResult::Drained;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::active_case::ActiveCaseRejection;
    use crate::recorder::CaseContext;

    fn case() -> CaseContext {
        CaseContext {
            id: Uuid::new_v4(),
            rule_name: "test".into(),
            uri_group: Some("test".into()),
        }
    }

    #[test]
    fn later_dependency_failure_revokes_recovery_without_replacing_primary_cause() {
        for by_id in [false, true] {
            let registry = ActiveCaseRegistry::default();
            let case = case();
            let guard = registry.try_reserve(case.clone()).unwrap();
            guard.activate_dependencies().unwrap();
            registry.invalidate_case(
                case.id,
                CaseInvalidation::new("interaction_client_transport_lost", "client lost")
                    .allow_drained_case_recovery(),
            );
            let failure = CaseInvalidation::new("dependency_capture_failed", "late failure");
            if by_id {
                registry.invalidate_case(case.id, failure);
            } else {
                registry.invalidate_current_case(failure);
            }
            let primary = registry.invalidation_for(case.id).unwrap();
            assert_eq!(primary.reason, "interaction_client_transport_lost");
            assert!(!primary.can_recover_after_drain());
        }
    }

    #[tokio::test]
    async fn recovery_is_idempotent_and_waits_for_real_inflight_requests() {
        let registry = ActiveCaseRegistry::default();
        let old = case();
        let guard = registry.try_reserve(old.clone()).unwrap();
        guard.activate_dependencies().unwrap();
        assert!(registry.begin_timeout_recovery(old.id, "timeout".into()));
        assert!(!registry.begin_timeout_recovery(old.id, "duplicate".into()));
        registry.source_request_completed(old.id);
        let drain_registry = registry.clone();
        let drain = tokio::spawn(async move {
            drain_registry
                .drain_case_dependencies(old.id, Duration::from_millis(40), Duration::from_secs(2))
                .await
        });
        let ownership = registry.current_targets_for_event();
        assert_eq!(ownership.cases[0].0.id, old.id);
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(!drain.is_finished());
        drop(ownership);
        let released = Instant::now();
        assert_eq!(drain.await.unwrap(), DependencyDrainResult::Drained);
        assert!(released.elapsed() < Duration::from_millis(40));
        drop(guard);
        let next = case();
        let next_guard = registry.try_reserve(next.clone()).unwrap();
        next_guard.activate_dependencies().unwrap();
        assert!(!registry.begin_timeout_recovery(old.id, "stale".into()));
        assert_eq!(registry.current_targets_for_event().cases[0].0.id, next.id);
    }

    #[test]
    fn dropping_unfinished_recovery_stops_new_case_admission() {
        let registry = ActiveCaseRegistry::default();
        let old = case();
        let guard = registry.try_reserve(old.clone()).unwrap();
        guard.activate_dependencies().unwrap();
        assert!(registry.begin_timeout_recovery(old.id, "timeout".into()));
        drop(guard);
        assert!(matches!(
            registry.try_reserve(case()),
            Err(ActiveCaseRejection::Quiescing)
        ));
    }

    #[tokio::test]
    async fn drain_timeout_cannot_release_recovery_admission() {
        let registry = ActiveCaseRegistry::default();
        let old = case();
        let guard = registry.try_reserve(old.clone()).unwrap();
        guard.activate_dependencies().unwrap();
        registry.begin_timeout_recovery(old.id, "timeout".into());
        registry.source_request_completed(old.id);
        let _ownership = registry.current_targets_for_event();
        assert_eq!(
            registry
                .drain_case_dependencies(old.id, Duration::ZERO, Duration::from_millis(10))
                .await,
            DependencyDrainResult::TimedOut
        );
        drop(guard);
        assert!(matches!(
            registry.try_reserve(case()),
            Err(ActiveCaseRejection::Quiescing)
        ));
    }
}
