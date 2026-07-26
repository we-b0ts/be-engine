use std::path::PathBuf;

use chrono::Utc;

use super::*;
use crate::case_group::{CanonicalCase, CanonicalCaseGroup};
use crate::e2e_run::model::{ApiExecution, CaseExecution, CaseStatus, RunStatus, STATE_VERSION};

fn state(api_passed: u32, api_failed: u32, sequence: u64) -> ActiveRunState {
    let cases = (0..api_passed)
        .map(|index| case(format!("passed-{index}"), CaseStatus::Passed))
        .chain((0..api_failed).map(|index| case(format!("failed-{index}"), CaseStatus::Failed)))
        .collect::<Vec<_>>();
    ActiveRunState {
        version: STATE_VERSION,
        run_key: "run".to_string(),
        sequence,
        status: if api_failed == 0 {
            RunStatus::Successful
        } else {
            RunStatus::Failed
        },
        started_at: Utc::now(),
        finished_at: Some(Utc::now()),
        case_source: PathBuf::from("/cases"),
        source_revision: "source".to_string(),
        case_inventory_id: "inventory".to_string(),
        recording_rule: Some("record-api".to_string()),
        replay_session: PathBuf::from("/session"),
        replay_report: PathBuf::from("/report"),
        aggregate_report: PathBuf::from("/aggregate"),
        assertions_report: PathBuf::from("/assertions"),
        session_id: Some("session".to_string()),
        replay_pid: None,
        target_started: false,
        replay_finalized: true,
        aggregate_complete: true,
        aggregate_clean: true,
        cases,
        apis: vec![ApiExecution {
            api_key: "GET /api/orders/*".to_string(),
            group_id: "GET /api/orders/*".to_string(),
            method: "GET".to_string(),
            api_pattern: "/api/orders/*".to_string(),
            case_ids: Vec::new(),
            total: api_passed + api_failed,
            passed: api_passed,
            failed: api_failed,
            incomplete: 0,
            complete_pass: api_failed == 0,
            report_dir: PathBuf::from("apis/api-0001"),
        }],
        errors: Vec::new(),
    }
}

fn case(case_id: String, status: CaseStatus) -> CaseExecution {
    CaseExecution {
        case_id,
        case_dir: PathBuf::from("/cases"),
        group_id: "GET /api/orders/*".to_string(),
        status,
        assertion_passed: Some(status == CaseStatus::Passed),
        replay_clean: Some(true),
        response_assertion: None,
    }
}

fn inventory() -> CaseGroupInventory {
    CaseGroupInventory {
        case_source: PathBuf::from("/cases"),
        source_revision: "source".to_string(),
        case_inventory_id: "inventory".to_string(),
        groups: vec![CanonicalCaseGroup {
            group_id: "GET /api/orders/*".to_string(),
            method: "GET".to_string(),
            source_route: "/api/orders/:id".to_string(),
            pattern: Some("/api/orders/*".to_string()),
            case_inventory_id: "inventory".to_string(),
            cases: (0..3)
                .map(|index| CanonicalCase {
                    case_id: format!("passed-{index}"),
                    case_dir: PathBuf::from("/cases"),
                    recorded_at: None,
                })
                .collect(),
        }],
    }
}

#[test]
fn repeated_attempts_replace_the_current_logical_run() {
    let mut index = RunIndex::empty("run".to_string(), PathBuf::from("/cases"));
    update_index(&mut index, &state(2, 1, 1));
    update_index(&mut index, &state(3, 0, 2));

    assert_eq!(index.executions, 1);
    assert_eq!(index.replayed_cases, 3);
    assert_eq!(index.passed_cases, 3);
    assert_eq!(index.passed_runs, 1);
    assert!(index.current_run.passed);
}

#[test]
fn focused_attempt_updates_the_same_current_run() {
    let mut index = RunIndex::empty("run".to_string(), PathBuf::from("/cases"));
    let completed = state(3, 0, 1);

    update_focused_index(&mut index, &completed, &inventory(), true);

    assert_eq!(index.executions, 1);
    assert_eq!(index.apis["GET /api/orders/*"].executions, 1);
    assert_eq!(build_progress(&index, &completed).status, "complete");
}

#[test]
fn published_run_progress_is_loaded_as_the_next_run_baseline() {
    let directory = tempfile::tempdir().unwrap();
    let progress_path = directory.path().join("e2e-progress.yaml");
    let completed = state(3, 0, 1);
    let mut first = RunIndex::empty("run-1".to_string(), PathBuf::from("/cases"));
    update_index(&mut first, &completed);
    store::write_yaml(&progress_path, &build_progress(&first, &completed)).unwrap();

    let second = load_progress_baseline(
        &progress_path,
        "run-2".to_string(),
        PathBuf::from("/next-cases"),
    )
    .unwrap();

    assert_eq!(second.executions, 1);
    assert_eq!(second.passed_runs, 1);
    assert_eq!(second.apis["GET /api/orders/*"].passed_cases, 3);
}

#[test]
fn human_progress_uses_e2e_pass_wording_without_verified_state() {
    let completed = state(3, 0, 1);
    let mut index = RunIndex::empty("run".to_string(), PathBuf::from("/cases"));
    update_index(&mut index, &completed);
    let yaml = serde_yaml::to_string(&build_progress(&index, &completed)).unwrap();

    assert!(yaml.contains("version: 3"));
    assert!(yaml.contains("passed: 3"));
    assert!(!yaml.contains("successful"));
    assert!(!yaml.contains("verified"));
    assert!(!yaml.contains("consecutive"));
}
