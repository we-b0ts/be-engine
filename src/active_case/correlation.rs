//! RPC correlation references never retain completed network capture.
use super::{ActiveCaseRegistry, DependencyTargets};

impl DependencyTargets {
    /// Correlation metadata is not an unfinished network request.
    pub(crate) fn attribution_only(&self) -> Self {
        Self {
            cases: self.cases.clone(),
            bootstrap_open: self.bootstrap_open,
            ambiguous_active_cases: self.ambiguous_active_cases,
            process_owned_rule: self.process_owned_rule.clone(),
            process_rule_ids: self.process_rule_ids.clone(),
            unattributed_reason: self.unattributed_reason,
            observed_case: self.observed_case,
            phase: self.phase,
            capture: None,
            _reservations: Vec::new(),
            stream_tail: Vec::new(),
        }
    }
}

impl ActiveCaseRegistry {
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
        let bootstrap_open = original.bootstrap_open
            && state.bootstrap_open
            && state.active.is_empty()
            && !state.quiescing
            && !state.admission_closed;
        let observed_case = state.active.first().map(|case| case.case.id);
        let phase = if state.quiescing || state.admission_closed {
            crate::dependency::observation::CapturePhase::Shutdown
        } else if bootstrap_open {
            crate::dependency::observation::CapturePhase::Startup
        } else {
            crate::dependency::observation::CapturePhase::Runtime
        };
        if bootstrap_open {
            reservations.push(state.bootstrap_dependencies.reserve());
        }
        (!cases.is_empty() || bootstrap_open).then_some(DependencyTargets {
            capture: self.capture.as_ref().and_then(|registry| {
                registry.begin(phase, observed_case, cases.first().map(|(case, _)| case.id))
            }),
            cases,
            bootstrap_open,
            ambiguous_active_cases: 0,
            process_owned_rule: original.process_owned_rule.clone(),
            process_rule_ids: original.process_rule_ids.clone(),
            unattributed_reason: original.unattributed_reason,
            observed_case,
            phase,
            _reservations: reservations,
            stream_tail: Vec::new(),
        })
    }

    /// A notification has its own capture lifetime. Without a proven request
    /// correlation it cannot borrow the currently active Case's ownership.
    pub(crate) fn unattributed_observation_targets(&self) -> DependencyTargets {
        let state = self.state.lock().expect("active case registry poisoned");
        let observed_case = state.active.first().map(|case| case.case.id);
        let phase = if state.quiescing || state.admission_closed {
            crate::dependency::observation::CapturePhase::Shutdown
        } else if state.bootstrap_open && state.active.is_empty() {
            crate::dependency::observation::CapturePhase::Startup
        } else {
            crate::dependency::observation::CapturePhase::Runtime
        };
        DependencyTargets {
            cases: Vec::new(),
            bootstrap_open: false,
            ambiguous_active_cases: 0,
            process_owned_rule: None,
            process_rule_ids: Vec::new(),
            unattributed_reason: None,
            observed_case,
            phase,
            capture: self
                .capture
                .as_ref()
                .and_then(|registry| registry.begin(phase, observed_case, None)),
            _reservations: Vec::new(),
            stream_tail: Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::active_case::DependencyDrainResult;
    use crate::recorder::CaseContext;
    use std::time::Duration;
    use uuid::Uuid;
    #[tokio::test]
    async fn rpc_attribution_does_not_hold_drain_and_cannot_reacquire_closed_case() {
        let registry = ActiveCaseRegistry::default();
        let case = CaseContext {
            id: Uuid::new_v4(),
            rule_name: "http".into(),
            uri_group: None,
        };
        let guard = registry.try_reserve(case.clone()).unwrap();
        guard.activate_dependencies().unwrap();
        let request = registry.current_targets_for_event();
        let reference = request.attribution_only();
        drop(request);
        assert!(registry.reacquire_targets(&reference).is_some());
        assert_eq!(
            registry
                .drain_case_dependencies(case.id, Duration::ZERO, Duration::from_millis(15))
                .await,
            DependencyDrainResult::Drained
        );
        assert!(registry.reacquire_targets(&reference).is_none());
        drop(guard);
    }
}
