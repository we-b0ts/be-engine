use super::*;
use crate::case_group::{CanonicalCase, CanonicalCaseGroup};
use serde_json::{Value, json};
use std::{fs, path::PathBuf};

use crate::e2e_run::test_session::{config, session};

#[test]
fn final_evidence_retains_actual_report_failures_after_policy_changes() {
    let temp = tempfile::tempdir().unwrap();
    let config = config(temp.path());
    let (layout, inventory, mut state) = session(temp.path());
    let original_report = fs::read(&state.replay_report).unwrap();
    let original_cases = serde_json::to_value(&state.cases).unwrap();
    state
        .errors
        .push("strict replay finalize failed: actual dependency evidence was dirty".into());
    let original_errors = state.errors.clone();
    fs::write(
        &config.source_traffic_policy,
        "a later policy cannot change completed execution evidence",
    )
    .unwrap();

    build_final_evidence(&config, &layout, &inventory, &mut state).unwrap();

    assert!(state.aggregate_complete);
    assert!(!state.aggregate_clean);
    assert!(state.apis.iter().all(|api| !api.complete_pass));
    assert_eq!(serde_json::to_value(&state.cases).unwrap(), original_cases);
    assert_eq!(state.errors, original_errors);
    assert_eq!(fs::read(&state.replay_report).unwrap(), original_report);
    let aggregate: Value =
        serde_json::from_slice(&fs::read(&state.aggregate_report).unwrap()).unwrap();
    assert_eq!(
        aggregate["counts"]["events"]["http"]["unused_case_exchanges"],
        14
    );
}

#[test]
fn a_clean_final_report_does_not_promote_an_earlier_failed_case_or_remove_errors() {
    let temp = tempfile::tempdir().unwrap();
    let config = config(temp.path());
    let (layout, inventory, mut state) = session(temp.path());
    let mut actual: Value =
        serde_json::from_slice(&fs::read(&state.replay_report).unwrap()).unwrap();
    actual["unused_case_http_exchanges"] = json!([]);
    store::write_json(&state.replay_report, &actual).unwrap();
    let original_report = fs::read(&state.replay_report).unwrap();
    let original_cases = serde_json::to_value(&state.cases).unwrap();
    state
        .errors
        .push("case get-case replay evidence is dirty: earlier execution failed".into());
    let original_errors = state.errors.clone();

    build_final_evidence(&config, &layout, &inventory, &mut state).unwrap();

    assert!(state.aggregate_complete && state.aggregate_clean);
    assert!(state.apis.iter().all(|api| !api.complete_pass));
    assert_eq!(serde_json::to_value(&state.cases).unwrap(), original_cases);
    assert_eq!(state.errors, original_errors);
    assert_eq!(fs::read(&state.replay_report).unwrap(), original_report);
}

#[test]
fn assertion_report_omits_cases_without_an_assertion_result() {
    let inventory = CaseGroupInventory {
        case_source: PathBuf::from("/cases"),
        source_revision: "source".to_string(),
        case_inventory_id: "inventory".to_string(),
        groups: vec![CanonicalCaseGroup {
            group_id: "GET /api/devices".to_string(),
            method: "GET".to_string(),
            source_route: "/api/devices".to_string(),
            pattern: None,
            case_inventory_id: "inventory".to_string(),
            cases: ["passed", "failed", "pending"]
                .into_iter()
                .map(|case_id| CanonicalCase {
                    case_id: case_id.to_string(),
                    case_dir: PathBuf::from("/cases").join(case_id),
                    recorded_at: None,
                })
                .collect(),
        }],
    };
    let temp = tempfile::tempdir().unwrap();
    let mut state = ActiveRunState::new("run".to_string(), 1, &inventory, temp.path());
    let passed = state
        .cases
        .iter_mut()
        .find(|case| case.case_id == "passed")
        .unwrap();
    passed.assertion_passed = Some(true);
    passed.status = CaseStatus::Passed;
    let failed = state
        .cases
        .iter_mut()
        .find(|case| case.case_id == "failed")
        .unwrap();
    failed.assertion_passed = Some(false);
    failed.status = CaseStatus::Failed;

    let report = assertion_report(
        &state,
        true,
        state.cases.iter().map(|case| case.case_id.as_str()),
    );

    assert_eq!(report.cases.len(), 2);
    assert!(
        report
            .cases
            .iter()
            .any(|case| case.case_id == "passed" && case.passed)
    );
    assert!(
        report
            .cases
            .iter()
            .any(|case| case.case_id == "failed" && !case.passed)
    );
}
