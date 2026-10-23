//! Stop new primary admission without ending admitted case activity.

use super::ActiveCaseRegistry;
use crate::recorder::{CaseContext, CaseInvalidation};

pub(crate) struct ShutdownCase {
    pub(crate) case: CaseContext,
    pub(crate) failure: Option<CaseInvalidation>,
}

impl ActiveCaseRegistry {
    pub(crate) fn close_admission(&self) {
        let mut state = self.state.lock().expect("active case registry poisoned");
        state.admission_closed = true;
        state.case_matching_ready = false;
        state.bootstrap_open = false;
    }

    /// Publication already holding its commit barrier cannot be revoked by
    /// shutdown. Every other admitted case retains its first independent failure.
    pub(crate) fn invalidate_shutdown_cases(&self, failure: CaseInvalidation) -> Vec<ShutdownCase> {
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
