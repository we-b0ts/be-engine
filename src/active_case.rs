use std::sync::{Arc, Mutex};

use uuid::Uuid;

use crate::recorder::CaseContext;
use crate::recorder::http::case::CaseInvalidation;

#[derive(Clone)]
pub(crate) struct ActiveCaseRegistry {
    state: Arc<Mutex<ActiveCaseState>>,
}

struct ActiveCaseState {
    active: Vec<ActiveCaseRegistration>,
    bootstrap_open: bool,
    case_matching_ready: bool,
}

#[derive(Debug, Clone)]
struct ActiveCaseRegistration {
    case: CaseContext,
    upstream_pid: Option<u32>,
    invalidation: Option<CaseInvalidation>,
}

pub(crate) struct ActiveCaseGuard {
    registry: ActiveCaseRegistry,
    case_id: Uuid,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ActiveCaseRejection {
    NotReady,
    Busy,
}

pub(crate) struct DependencyTargets {
    pub(crate) cases: Vec<(CaseContext, &'static str)>,
    pub(crate) bootstrap_open: bool,
    pub(crate) ambiguous_active_cases: usize,
}

impl Drop for ActiveCaseGuard {
    fn drop(&mut self) {
        self.registry.unregister(self.case_id);
    }
}

impl Default for ActiveCaseRegistry {
    fn default() -> Self {
        Self::new(true)
    }
}

impl ActiveCaseRegistry {
    pub(crate) fn new(case_matching_ready: bool) -> Self {
        Self {
            state: Arc::new(Mutex::new(ActiveCaseState {
                active: Vec::new(),
                bootstrap_open: true,
                case_matching_ready,
            })),
        }
    }

    pub(crate) fn try_register(
        &self,
        case: CaseContext,
        upstream_pid: Option<u32>,
    ) -> Result<ActiveCaseGuard, ActiveCaseRejection> {
        let mut state = self.state.lock().expect("active case registry poisoned");
        if !state.case_matching_ready {
            return Err(ActiveCaseRejection::NotReady);
        }
        if !state.active.is_empty() {
            return Err(ActiveCaseRejection::Busy);
        }
        state.bootstrap_open = false;
        state.active.push(ActiveCaseRegistration {
            case: case.clone(),
            upstream_pid,
            invalidation: None,
        });
        Ok(ActiveCaseGuard {
            registry: self.clone(),
            case_id: case.id,
        })
    }

    fn unregister(&self, case_id: Uuid) {
        let mut state = self.state.lock().expect("active case registry poisoned");
        state
            .active
            .retain(|registration| registration.case.id != case_id);
    }

    pub(crate) fn close_bootstrap(&self) -> bool {
        let mut state = self.state.lock().expect("active case registry poisoned");
        let was_open = state.bootstrap_open;
        state.bootstrap_open = false;
        state.case_matching_ready = true;
        was_open
    }

    pub(crate) fn is_bootstrap_open(&self) -> bool {
        let state = self.state.lock().expect("active case registry poisoned");
        state.bootstrap_open
    }

    pub(crate) fn invalidate_current_case(
        &self,
        invalidation: CaseInvalidation,
    ) -> Option<CaseContext> {
        let mut state = self.state.lock().expect("active case registry poisoned");
        let [registration] = state.active.as_mut_slice() else {
            return None;
        };
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

    pub(crate) fn current_targets_for_event(&self, event_pid: Option<u32>) -> DependencyTargets {
        let state = self.state.lock().expect("active case registry poisoned");
        let active_count = state.active.len();
        let (cases, ambiguous_active_cases) = match state.active.as_slice() {
            [] => (Vec::new(), 0),
            [registration] => {
                let matched_by = match (registration.upstream_pid, event_pid) {
                    (Some(upstream_pid), Some(event_pid)) if upstream_pid == event_pid => "process",
                    _ => "active_window",
                };
                (vec![(registration.case.clone(), matched_by)], 0)
            }
            active => (Vec::new(), active.len()),
        };
        DependencyTargets {
            bootstrap_open: state.bootstrap_open && active_count == 0,
            cases,
            ambiguous_active_cases,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn case() -> CaseContext {
        CaseContext {
            id: Uuid::new_v4(),
            rule_name: "record-api".to_string(),
            uri_group: Some("api-user".to_string()),
        }
    }

    #[test]
    fn closes_bootstrap_on_first_case() {
        let registry = ActiveCaseRegistry::default();

        let initial = registry.current_targets_for_event(None);
        assert!(initial.bootstrap_open);
        assert!(initial.cases.is_empty());

        let case = case();
        let guard = registry.try_register(case.clone(), Some(42)).unwrap();

        let active = registry.current_targets_for_event(Some(42));
        assert!(!active.bootstrap_open);
        assert_eq!(active.cases, vec![(case, "process")]);

        drop(guard);
        let after_case = registry.current_targets_for_event(None);
        assert!(!after_case.bootstrap_open);
        assert!(after_case.cases.is_empty());
    }

    #[test]
    fn keeps_first_invalidation_until_case_finishes() {
        let registry = ActiveCaseRegistry::default();
        let case = case();
        let guard = registry.try_register(case.clone(), Some(42)).unwrap();
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
    fn rejects_cases_before_ready() {
        let registry = ActiveCaseRegistry::new(false);
        let case = case();

        assert!(matches!(
            registry.try_register(case.clone(), Some(42)),
            Err(ActiveCaseRejection::NotReady)
        ));
        assert!(registry.current_targets_for_event(None).bootstrap_open);

        assert!(registry.close_bootstrap());
        let guard = registry.try_register(case.clone(), Some(42)).unwrap();
        let active = registry.current_targets_for_event(Some(42));
        assert_eq!(active.cases, vec![(case, "process")]);
        drop(guard);
    }

    #[test]
    fn allows_only_one_active_case() {
        let registry = ActiveCaseRegistry::default();
        let first = case();
        let second = case();

        let guard = registry.try_register(first, Some(42)).unwrap();
        assert!(matches!(
            registry.try_register(second.clone(), Some(43)),
            Err(ActiveCaseRejection::Busy)
        ));

        drop(guard);
        assert!(registry.try_register(second, Some(43)).is_ok());
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
                upstream_pid: None,
                invalidation: None,
            });
            state.active.push(ActiveCaseRegistration {
                case: second,
                upstream_pid: None,
                invalidation: None,
            });
        }

        let targets = registry.current_targets_for_event(None);
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
        assert!(!registry.close_bootstrap());

        let targets = registry.current_targets_for_event(None);
        assert!(!targets.bootstrap_open);
        assert!(targets.cases.is_empty());
    }
}
