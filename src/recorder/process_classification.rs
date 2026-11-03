//! Whole-task classification rejects cross-task selector overlap before ownership.
use std::collections::{BTreeMap, BTreeSet};

use crate::active_case::DependencyTargets;

/// Only a single declared task can be excluded from request-start activity.
pub(crate) fn definite_process(rules: &[String], tasks: &BTreeMap<String, String>) -> bool {
    let Some(first) = rules.first().and_then(|rule| tasks.get(rule)) else {
        return false;
    };
    rules.iter().all(|rule| tasks.get(rule) == Some(first))
}

pub(crate) fn classify(
    targets: DependencyTargets,
    rules: impl IntoIterator<Item = String>,
    tasks: &BTreeMap<String, String>,
) -> DependencyTargets {
    let rules = rules
        .into_iter()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    let Some(first) = rules.first() else {
        return targets;
    };
    let matched_tasks = rules
        .iter()
        .filter_map(|rule| tasks.get(rule))
        .collect::<BTreeSet<_>>();
    let reason = if matched_tasks.len() > 1 {
        Some("ambiguous_process_task")
    } else if rules.iter().any(|rule| !tasks.contains_key(rule)) {
        Some("process_rule_without_task_identity")
    } else {
        None
    };
    let mut targets = targets.into_process_owned(first.clone());
    targets.process_rule_ids = rules;
    targets.unattributed_reason = reason;
    targets
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::active_case::ActiveCaseRegistry;

    #[test]
    fn request_activity_is_excluded_only_for_one_complete_declared_task_identity() {
        let tasks = BTreeMap::from([
            ("a".into(), "refresh".into()),
            ("b".into(), "refresh".into()),
            ("c".into(), "cleanup".into()),
        ]);
        assert!(!definite_process(&[], &tasks));
        assert!(!definite_process(&["unknown".into()], &tasks));
        assert!(!definite_process(&["a".into(), "unknown".into()], &tasks));
        assert!(!definite_process(&["a".into(), "c".into()], &tasks));
        assert!(definite_process(&["a".into(), "b".into()], &tasks));
    }

    #[test]
    fn overlapping_selectors_from_different_tasks_are_not_resolved_by_rule_order() {
        let tasks = BTreeMap::from([
            ("rule-a".into(), "refresh".into()),
            ("rule-b".into(), "cleanup".into()),
        ]);
        for rules in [["rule-a", "rule-b"], ["rule-b", "rule-a"]] {
            let targets = classify(
                ActiveCaseRegistry::default().current_targets_for_event(),
                rules.map(str::to_owned),
                &tasks,
            );
            assert_eq!(targets.unattributed_reason, Some("ambiguous_process_task"));
            assert_eq!(targets.process_rule_ids.len(), 2);
        }
    }

    #[test]
    fn multiple_selectors_of_the_same_task_are_one_capture_owner() {
        let tasks = BTreeMap::from([
            ("rule-a".into(), "refresh".into()),
            ("rule-b".into(), "refresh".into()),
        ]);
        let targets = classify(
            ActiveCaseRegistry::default().current_targets_for_event(),
            ["rule-a".into(), "rule-b".into()],
            &tasks,
        );
        assert_eq!(targets.unattributed_reason, None);
        assert_eq!(targets.process_rule_ids.len(), 2);
    }
}
