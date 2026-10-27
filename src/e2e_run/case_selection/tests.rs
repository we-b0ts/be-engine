use super::*;
use crate::e2e_run::{focused_batch, model::RunStatus, test_session};
use std::path::Path;

mod last_result;

fn fixture(root: &Path) -> (RunLayout, CaseGroupInventory, ReplayIteration) {
    let (layout, mut inventory, _) = test_session::session(root);
    std::fs::create_dir_all(root.join(".traffic-e2e")).unwrap();
    std::fs::write(
        root.join(crate::config::regression::PATH),
        "retry_failed_only: true\n",
    )
    .unwrap();
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
    inventory: &mut CaseGroupInventory,
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
fn retries_accumulate_passes_but_keep_failed_incomplete_and_unexecuted_inputs() {
    let root = tempfile::tempdir().unwrap();
    let (layout, inventory, iteration) = fixture(root.path());
    let mut first_inventory = inventory.clone();
    let mut first = attempt(&layout, &mut first_inventory, &iteration);
    assert_eq!(first.cases.len(), 10);
    pass(&mut first, "-0");
    for case in &mut first.cases {
        match case.case_id.chars().last().unwrap() {
            '1' => case.status = CaseStatus::Failed,
            '2' => case.status = CaseStatus::Incomplete,
            '3' => case.status = CaseStatus::Running,
            _ => {}
        }
    }
    save(&layout, &first);
    let mut second_inventory = inventory.clone();
    let mut second = attempt(&layout, &mut second_inventory, &iteration);
    assert_eq!(second.cases.len(), 8);
    assert!(
        second
            .cases
            .iter()
            .all(|case| !case.case_id.ends_with("-0") && case.status == CaseStatus::Pending)
    );
    pass(&mut second, "-1");
    save(&layout, &second);
    let mut third_inventory = inventory.clone();
    let third = attempt(&layout, &mut third_inventory, &iteration);
    assert_eq!(third.cases.len(), 6);
    let args = super::super::runtime::replay_case_args(&third_inventory, &third);
    assert_eq!(args.len(), 12);
    for (args, case) in args.as_chunks::<2>().0.iter().zip(&third.cases) {
        assert_eq!(args[0], "--case-id");
        assert_eq!(args[1], case.case_id.as_str());
    }
    for group in &inventory.groups {
        validate_group(&third, group).unwrap();
        let projected = focused_batch::project(&third, &group.group_id);
        validate_group(&projected, group).unwrap();
        assert_eq!(
            diagnosis(&projected).unwrap(),
            json!({
                "mode":"failed_only", "final_round":false, "available":5,
                "selected":3,"skipped_previously_passed":2,
            })
        );
    }
    let ready = json!({"session":{"selected_case_ids":third.cases.iter().map(|case| &case.case_id).collect::<Vec<_>>()}});
    super::super::runtime::validate_replay_case_selection(&ready, &third).unwrap();
    let mut restored = inventory.clone();
    restrict(&mut restored, &third).unwrap();
    assert_eq!(
        restored
            .groups
            .iter()
            .map(|group| group.cases.len())
            .sum::<usize>(),
        6
    );
}

#[test]
fn final_round_disabled_setting_new_workflow_and_changed_inventory_run_every_case() {
    let root = tempfile::tempdir().unwrap();
    let (layout, inventory, mut iteration) = fixture(root.path());
    let mut first = attempt(&layout, &mut inventory.clone(), &iteration);
    pass(&mut first, "-0");
    save(&layout, &first);
    iteration.final_round = true;
    let full = attempt(&layout, &mut inventory.clone(), &iteration);
    assert_eq!(full.cases.len(), 10);
    let args = super::super::runtime::replay_case_args(&inventory, &full);
    assert_eq!(args.len(), 4);
    assert_eq!(args[0], "--api");
    assert_eq!(diagnosis(&full).unwrap()["final_round"], true);
    iteration.final_round = false;
    iteration.workflow_id = "workflow-2".into();
    assert_eq!(
        attempt(&layout, &mut inventory.clone(), &iteration)
            .cases
            .len(),
        10
    );
    iteration.workflow_id = "workflow-1".into();
    let mut changed = inventory.clone();
    for group in &mut changed.groups {
        group.case_inventory_id = "new-inventory".into();
    }
    assert_eq!(attempt(&layout, &mut changed, &iteration).cases.len(), 10);
    changed = inventory.clone();
    changed.source_revision = "new-source".into();
    assert_eq!(attempt(&layout, &mut changed, &iteration).cases.len(), 10);
    std::fs::write(
        layout.target_root.join(crate::config::regression::PATH),
        "retry_failed_only: false\n",
    )
    .unwrap();
    assert_eq!(
        attempt(&layout, &mut inventory.clone(), &iteration)
            .cases
            .len(),
        10
    );
    assert!(
        prepare(&layout, &mut inventory.clone(), None)
            .unwrap()
            .is_none()
    );
}

#[test]
fn dirty_cases_are_retried_even_when_their_primary_responses_passed() {
    let root = tempfile::tempdir().unwrap();
    let (layout, inventory, iteration) = fixture(root.path());
    let mut first = attempt(&layout, &mut inventory.clone(), &iteration);
    pass(&mut first, "-0");
    for case in &mut first.cases {
        case.replay_clean = Some(false);
    }
    save(&layout, &first);
    assert_eq!(
        attempt(&layout, &mut inventory.clone(), &iteration)
            .cases
            .len(),
        10
    );
    for api in first.case_selection.as_ref().unwrap().groups.keys() {
        let mut legacy = focused_batch::project(&first, api);
        legacy.case_selection = None;
        store::write_yaml(
            &layout
                .run_root
                .join("focused")
                .join(api_directory(api))
                .join("latest/state.yaml"),
            &legacy,
        )
        .unwrap();
    }
    assert_eq!(
        attempt(&layout, &mut inventory.clone(), &iteration)
            .cases
            .len(),
        10
    );
}

#[test]
fn invalid_partitions_and_final_skips_are_rejected_and_passing_apis_never_run_empty() {
    let root = tempfile::tempdir().unwrap();
    let (layout, inventory, iteration) = fixture(root.path());
    let mut first = attempt(&layout, &mut inventory.clone(), &iteration);
    for suffix in ["-0", "-1", "-2", "-3", "-4"] {
        pass(&mut first, suffix);
    }
    save(&layout, &first);
    assert_eq!(
        attempt(&layout, &mut inventory.clone(), &iteration)
            .cases
            .len(),
        10
    );
    first.cases.pop();
    assert!(validate_group(&first, &inventory.groups[1]).is_err());
    let mut first = attempt(&layout, &mut inventory.clone(), &iteration);
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

#[test]
fn partial_retry_publication_keeps_recorded_progress_and_requires_full_fresh_verification() {
    use crate::e2e_run::{
        final_evidence::summarize_apis_without_aggregate, model::RunIndex, progress,
    };
    use crate::verification_progress::{VerificationStage, load};
    let root = tempfile::tempdir().unwrap();
    let (layout, inventory, mut iteration) = fixture(root.path());
    let mut index = RunIndex::empty(layout.run_key.clone(), layout.case_source.clone());
    for round in 0..3 {
        iteration.final_round = round == 2;
        let mut selected_inventory = inventory.clone();
        let mut state = attempt(&layout, &mut selected_inventory, &iteration);
        state.sequence = round + 1;
        if round == 0 {
            pass(&mut state, "-0");
        } else {
            for case in &mut state.cases {
                case.status = CaseStatus::Passed;
                case.assertion_passed = Some(true);
                case.replay_clean = Some(true);
            }
            state.status = RunStatus::Successful;
        }
        state.finished_at = Some(chrono::Utc::now());
        state.aggregate_complete = true;
        state.aggregate_clean = true;
        summarize_apis_without_aggregate(&layout, &mut state, &selected_inventory);
        for api in &mut state.apis {
            api.complete_pass = round > 0;
        }
        progress::update_focused_index(&mut index, &state, &inventory, true);
        progress::write_replay_progress(
            &layout.progress_path,
            &layout.legacy_progress_path,
            &index,
            &state,
        )
        .unwrap();
        let report = load(&layout.progress_path, VerificationStage::Progress)
            .unwrap()
            .unwrap();
        assert_eq!(report.totals.cases.executed, 10);
        assert_eq!(report.totals.cases.passed, [2, 8, 10][round as usize]);
        assert_eq!(report.totals.runs.passed, u64::from(round == 2));
        assert!(index.apis.values().all(|api| api.cases == 5));
        save(&layout, &state);
    }
}
