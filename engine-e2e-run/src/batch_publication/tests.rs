use super::*;
use crate::{
    case_group::{CanonicalCase, CanonicalCaseGroup},
    model::ApiExecution,
};
use std::path::Path;

fn fixture(root: &Path) -> (RunLayout, CaseGroupInventory) {
    let layout = RunLayout {
        target_root: root.into(),
        run_key: "run".into(),
        case_source: root.join("source"),
        progress_path: root.join("progress.yaml"),
        legacy_progress_path: root.join("legacy.yaml"),
        internal_root: root.join("internal"),
        current_path: root.join("current"),
        run_root: root.join("runtime"),
        index_path: root.join("runtime/index.yaml"),
        group_index_path: root.join("groups.json"),
        active_dir: root.join("runtime/.active"),
        latest_dir: root.join("runtime/latest"),
    };
    fs::create_dir_all(layout.latest_dir.join("reports")).unwrap();
    let inventory = CaseGroupInventory {
        case_source: layout.case_source.clone(),
        source_revision: "source".into(),
        case_inventory_id: "full-inputs".into(),
        groups: ["GET /a", "POST /b"]
            .into_iter()
            .enumerate()
            .map(|(index, api)| CanonicalCaseGroup {
                group_id: api.into(),
                method: api.split_once(' ').unwrap().0.into(),
                source_route: api.split_once(' ').unwrap().1.into(),
                pattern: None,
                case_inventory_id: format!("method-{index}"),
                cases: vec![CanonicalCase {
                    case_id: format!("case-{index}"),
                    case_dir: root.join(format!("source/case-{index}")),
                    recorded_at: None,
                }],
            })
            .collect(),
    };
    let mut state = ActiveRunState::new("run".into(), 1, &inventory, &layout.latest_dir);
    state.session_id = Some("actual-full-session".into());
    state.executed_replay_identity = Some("executed-code".into());
    state.replay_finalized = true;
    state.finished_at = Some(chrono::Utc::now());
    state.status = RunStatus::Failed;
    state.aggregate_complete = true;
    state.aggregate_clean = false;
    for (index, case) in state.cases.iter_mut().enumerate() {
        let passed = index == 0;
        case.status = if passed {
            CaseStatus::Passed
        } else {
            CaseStatus::Failed
        };
        case.assertion_passed = Some(passed);
        case.replay_clean = Some(true);
    }
    state.apis = inventory
        .groups
        .iter()
        .enumerate()
        .map(|(index, group)| ApiExecution {
            api_key: group.group_id.clone(),
            group_id: group.group_id.clone(),
            method: group.method.clone(),
            api_pattern: group.source_route.clone(),
            case_ids: vec![format!("case-{index}")],
            total: 1,
            passed: u32::from(index == 0),
            failed: u32::from(index != 0),
            incomplete: 0,
            complete_pass: index == 0,
            report_dir: layout.latest_dir.join(format!("apis/{index}")),
        })
        .collect();
    let report = serde_json::json!({"version":7,"finalized":true,"complete":true,"session_id":"actual-full-session","cases":[{"case_id":"case-0","status":"ended"},{"case_id":"case-1","status":"ended"}]});
    store::write_json(&state.replay_report, &report).unwrap();
    store::write_yaml(&layout.latest_dir.join("state.yaml"), &state).unwrap();
    let previous = layout
        .run_root
        .join("focused")
        .join(api_directory("GET /a"))
        .join("latest");
    fs::create_dir_all(&previous).unwrap();
    let mut old = state;
    old.sequence = 9;
    old.session_id = Some("older-session".into());
    store::write_yaml(&previous.join("state.yaml"), &old).unwrap();
    (layout, inventory)
}

#[test]
fn final_round_publishes_each_method_from_one_actual_session_without_upgrading_batch_failure() {
    let temp = tempfile::tempdir().unwrap();
    let (layout, inventory) = fixture(temp.path());
    let raw = fs::read(layout.latest_dir.join("reports/replay-report.json")).unwrap();
    publish(&layout, &inventory).unwrap();
    let mut selected = std::collections::BTreeSet::new();
    let mut reports = std::collections::BTreeSet::new();
    for group in &inventory.groups {
        let latest = layout
            .run_root
            .join("focused")
            .join(api_directory(&group.group_id))
            .join("latest");
        let state: ActiveRunState = store::read_yaml(&latest.join("state.yaml")).unwrap();
        assert_eq!(state.session_id.as_deref(), Some("actual-full-session"));
        assert_eq!(
            state.executed_replay_identity.as_deref(),
            Some("executed-code")
        );
        assert_eq!(state.cases.len(), 1);
        assert!(selected.insert(state.cases[0].case_id.clone()));
        reports.insert(state.replay_report);
        assert_eq!(
            state.status,
            if group.method == "GET" {
                RunStatus::Successful
            } else {
                RunStatus::Failed
            }
        );
        assert_eq!(state.sequence, if group.method == "GET" { 10 } else { 1 });
    }
    assert_eq!(reports.len(), 1); // All large report/protected payloads are archived once.
    assert_eq!(selected.len(), 2);
    assert_eq!(
        fs::read(layout.latest_dir.join("reports/replay-report.json")).unwrap(),
        raw
    );
    let actual: ActiveRunState = store::read_yaml(&layout.latest_dir.join("state.yaml")).unwrap();
    assert_eq!(actual.status, RunStatus::Failed);
    assert_eq!(
        fs::read_dir(layout.run_root.join("actual-batches"))
            .unwrap()
            .count(),
        1
    );
}

#[test]
fn a_different_report_session_cannot_replace_real_method_evidence() {
    let temp = tempfile::tempdir().unwrap();
    let (layout, inventory) = fixture(temp.path());
    store::write_json(
        &layout.latest_dir.join("reports/replay-report.json"),
        &serde_json::json!({"version":7,"finalized":true,"session_id":"foreign"}),
    )
    .unwrap();
    assert!(publish(&layout, &inventory).is_err());
    let previous = layout
        .run_root
        .join("focused")
        .join(api_directory("GET /a"))
        .join("latest/state.yaml");
    let previous: ActiveRunState = store::read_yaml(&previous).unwrap();
    assert_eq!(previous.sequence, 9);
    assert_eq!(previous.session_id.as_deref(), Some("older-session"));
}
