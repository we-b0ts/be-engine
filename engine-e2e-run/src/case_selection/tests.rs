use super::*;
use crate::{
    focused_batch,
    model::{CaseStatus, RunStatus},
    store,
    support::api_directory,
    test_session,
};
use std::path::Path;

fn fixture(root: &Path) -> (RunLayout, CaseGroupInventory, ReplayIteration) {
    let (layout, mut inventory, _) = test_session::session(root);
    for group in &mut inventory.groups {
        let seed = group.cases[0].clone();
        group.cases = (0..5)
            .map(|i| {
                let mut case = seed.clone();
                case.case_id = format!("{}-{i}", seed.case_id);
                case
            })
            .collect();
    }
    (
        layout,
        inventory,
        ReplayIteration {
            workflow_id: "workflow-1".into(),
            final_round: false,
        },
    )
}

fn attempt(
    layout: &RunLayout,
    inventory: &CaseGroupInventory,
    iteration: &ReplayIteration,
) -> ActiveRunState {
    let selection = prepare(layout, inventory, Some(iteration)).unwrap();
    let mut state = ActiveRunState::new(layout.run_key.clone(), 1, inventory, &layout.active_dir);
    state.case_selection = selection;
    state.status = RunStatus::Failed;
    state.replay_finalized = true;
    state
}

fn save(layout: &RunLayout, state: &ActiveRunState) {
    for api in state.case_selection.as_ref().unwrap().groups.keys() {
        let path = layout
            .run_root
            .join("focused")
            .join(api_directory(api))
            .join("latest/state.yaml");
        store::write_yaml(&path, &focused_batch::project(state, api)).unwrap();
    }
}

fn pass(state: &mut ActiveRunState, suffix: &str) {
    for case in &mut state.cases {
        if case.case_id.ends_with(suffix) {
            case.status = CaseStatus::Passed;
            case.assertion_passed = Some(true);
            case.replay_clean = Some(true);
        }
    }
}

#[test]
fn replay_selects_every_case_even_when_previous_attempt_passed_some() {
    let root = tempfile::tempdir().unwrap();
    let (layout, inventory, mut iteration) = fixture(root.path());
    let mut first = attempt(&layout, &inventory, &iteration);
    pass(&mut first, "-0");
    save(&layout, &first);
    for final_round in [false, true] {
        iteration.final_round = final_round;
        let fresh = attempt(&layout, &inventory, &iteration);
        assert_eq!(fresh.cases.len(), 10);
        assert_eq!(diagnosis(&fresh).unwrap()["final_round"], final_round);
        assert!(
            fresh
                .case_selection
                .as_ref()
                .unwrap()
                .skipped_passed_case_ids
                .is_empty()
        );
        for group in &inventory.groups {
            validate_group(&fresh, group).unwrap();
        }
    }
    assert!(prepare(&layout, &inventory, None).unwrap().is_none());
}

#[test]
fn invalid_partitions_and_final_skips_are_rejected_and_passing_apis_never_run_empty() {
    let root = tempfile::tempdir().unwrap();
    let (layout, inventory, iteration) = fixture(root.path());
    let mut first = attempt(&layout, &inventory, &iteration);
    for suffix in ["-0", "-1", "-2", "-3", "-4"] {
        pass(&mut first, suffix);
    }
    save(&layout, &first);
    assert_eq!(attempt(&layout, &inventory, &iteration).cases.len(), 10);
    first.cases.pop();
    assert!(validate_group(&first, &inventory.groups[1]).is_err());
    let mut first = attempt(&layout, &inventory, &iteration);
    first
        .case_selection
        .as_mut()
        .unwrap()
        .skipped_passed_case_ids
        .insert("unknown".into());
    assert!(validate_group(&first, &inventory.groups[0]).is_err());
    first
        .case_selection
        .as_mut()
        .unwrap()
        .skipped_passed_case_ids
        .clear();
    let removed = first.cases.remove(0);
    first
        .case_selection
        .as_mut()
        .unwrap()
        .skipped_passed_case_ids
        .insert(removed.case_id);
    first.case_selection.as_mut().unwrap().final_round = true;
    assert!(validate_group(&first, &inventory.groups[0]).is_err());
}
