//! Stop new primary admission without ending admitted case activity.

use super::{ActiveCaseRegistry, ActiveCaseState};
use crate::recorder::{CaseContext, CaseInvalidation};
use uuid::Uuid;

#[derive(Clone, Copy)]
pub(super) struct ShutdownContext {
    pub(super) case_id: Option<Uuid>,
}

impl ActiveCaseState {
    /// Freeze the actual running Case once. A prior completed Case, a reserved
    /// input or a later activation cannot acquire this teardown association.
    pub(super) fn begin_shutdown(&mut self) {
        if self.shutdown.is_none() {
            let case_id = match self.active.as_slice() {
                [case] if case.activated => Some(case.case.id),
                _ => None,
            };
            self.shutdown = Some(ShutdownContext { case_id });
        }
    }
}

pub struct ShutdownCase {
    pub case: CaseContext,
    pub failure: Option<CaseInvalidation>,
}

impl ActiveCaseRegistry {
    pub fn close_admission(&self) {
        let mut state = self.state.lock().expect("active case registry poisoned");
        state.begin_shutdown();
        state.admission_closed = true;
        state.case_matching_ready = false;
        state.bootstrap_open = false;
    }

    /// Publication already holding its commit barrier cannot be revoked by
    /// shutdown. Every other admitted case retains its first independent failure.
    pub fn invalidate_shutdown_cases(&self, failure: CaseInvalidation) -> Vec<ShutdownCase> {
        let mut state = self.state.lock().expect("active case registry poisoned");
        let mut cases = Vec::new();
        for index in 0..state.active.len() {
            let registration = &state.active[index];
            let case = registration.case.clone();
            let failure = registration
                .invalidation
                .clone()
                .unwrap_or_else(|| failure.clone());
            let publication = state.case_publications.entry(case.id).or_default();
            let invalidation = publication.invalidate_shutdown(failure);
            cases.push(ShutdownCase {
                case,
                failure: invalidation.clone(),
            });
            if let Some(invalidation) = invalidation {
                state.active[index].invalidation.get_or_insert(invalidation);
            }
        }
        cases
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::active_case::ActiveCaseRejection;
    use crate::recorder::CaseContext;
    use uuid::Uuid;

    fn case() -> CaseContext {
        CaseContext {
            id: Uuid::new_v4(),
            rule_name: "shutdown".into(),
            uri_group: None,
        }
    }

    fn shutdown_failure() -> CaseInvalidation {
        CaseInvalidation::new(
            "shutdown_case_drain_timeout",
            "shutdown truncated this case",
        )
    }

    #[test]
    fn admission_closure_keeps_reserved_activation_and_dependency_ownership() {
        let registry = ActiveCaseRegistry::default();
        let first = case();
        let guard = registry.try_reserve(first.clone()).unwrap();
        registry.close_admission();
        assert!(!registry.enable_case_matching());
        assert!(!registry.is_quiescing());
        guard.activate_dependencies().unwrap();
        assert_eq!(registry.current_targets_for_event().cases[0].0.id, first.id);
        drop(guard);
        assert!(matches!(
            registry.try_reserve(case()),
            Err(ActiveCaseRejection::Quiescing)
        ));
    }

    #[test]
    fn shutdown_association_is_the_running_case_at_the_first_boundary() {
        for failure_driven in [false, true] {
            let registry = ActiveCaseRegistry::default();
            let first = case();
            let guard = registry.try_reserve(first.clone()).unwrap();
            guard.activate_dependencies().unwrap();
            let before = registry.current_targets_for_event();
            if failure_driven {
                registry.begin_quiescing();
            } else {
                registry.close_admission();
            }
            let during = registry.current_targets_for_event();
            assert_eq!(during.cases[0].0.id, first.id);
            assert_eq!(during.shutdown_case_id, Some(first.id));
            assert_eq!(before.shutdown_case_id, None);
            drop(during);
            drop(guard);
            registry.begin_quiescing();
            registry.close_admission();
            let after = registry.current_targets_for_event();
            assert!(after.cases.is_empty());
            assert_eq!(after.shutdown_case_id, Some(first.id));
        }
    }

    #[test]
    fn completed_or_only_reserved_cases_cannot_authorize_shutdown_association() {
        for reserved in [false, true] {
            let registry = ActiveCaseRegistry::default();
            let guard = registry.try_reserve(case()).unwrap();
            if reserved {
                registry.close_admission();
                guard.activate_dependencies().unwrap();
                drop(guard);
            } else {
                guard.activate_dependencies().unwrap();
                drop(guard);
                registry.close_admission();
            }
            registry.begin_quiescing();
            assert_eq!(registry.current_targets_for_event().shutdown_case_id, None);
        }
    }

    #[tokio::test]
    async fn shutdown_invalidation_covers_closed_dependency_admission_and_preserves_first_failure()
    {
        for earlier in [
            None,
            Some(CaseInvalidation::new("original_failure", "original cause")),
        ] {
            let registry = ActiveCaseRegistry::default();
            let case = case();
            let _guard = registry.try_reserve(case.clone()).unwrap();
            if let Some(earlier) = &earlier {
                registry.state.lock().unwrap().active[0].invalidation = Some(earlier.clone());
            }
            // Shutdown must also cover a reserved case or a case writing its
            // evidence after normal dependency admission has already closed.
            let cases = registry.invalidate_shutdown_cases(shutdown_failure());
            let expected = earlier
                .as_ref()
                .map_or("shutdown_case_drain_timeout", |failure| {
                    failure.reason.as_str()
                });
            assert_eq!(cases[0].failure.as_ref().unwrap().reason, expected);
            assert_eq!(registry.invalidation_for(case.id).unwrap().reason, expected);
            let publication = registry.register_case_publication(case.id).unwrap();
            assert_eq!(
                publication
                    .begin()
                    .await
                    .invalidation
                    .as_ref()
                    .unwrap()
                    .reason,
                expected
            );
        }
    }

    #[tokio::test]
    async fn shutdown_cannot_revoke_a_case_already_committing_publication() {
        let registry = ActiveCaseRegistry::default();
        let case = case();
        let _guard = registry.try_reserve(case.clone()).unwrap();
        let publication = registry.register_case_publication(case.id).unwrap();
        let mut commit = publication.begin().await;
        assert!(
            registry.invalidate_shutdown_cases(shutdown_failure())[0]
                .failure
                .is_none()
        );
        assert!(registry.invalidation_for(case.id).is_none());
        commit.finalized = true;
        drop(commit);
        assert!(
            registry.invalidate_shutdown_cases(shutdown_failure())[0]
                .failure
                .is_none()
        );
    }
}
