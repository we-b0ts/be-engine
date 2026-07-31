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
fn repeated_attempts_replace_the_current_logical_run_state() {
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
fn focused_attempt_updates_the_current_logical_run_state() {
    let mut index = RunIndex::empty("run".to_string(), PathBuf::from("/cases"));
    let completed = state(3, 0, 1);

    update_focused_index(&mut index, &completed, &inventory(), true);

    assert_eq!(index.executions, 1);
    assert_eq!(index.apis["GET /api/orders/*"].executions, 1);
    assert!(index.current_run.passed);
}

#[test]
fn replay_progress_counts_each_finalized_attempt_and_is_idempotent() {
    let directory = tempfile::tempdir().unwrap();
    let progress_path = directory.path().join("replay-progress.yaml");
    let legacy_path = directory.path().join("e2e-progress.yaml");
    let first = state(3, 0, 1);
    let second = state(3, 0, 2);

    write_replay_progress(&progress_path, &legacy_path, &first, ReplayRunKind::Full).unwrap();
    write_replay_progress(&progress_path, &legacy_path, &first, ReplayRunKind::Full).unwrap();
    write_replay_progress(&progress_path, &legacy_path, &second, ReplayRunKind::Full).unwrap();
    write_replay_progress(&progress_path, &legacy_path, &first, ReplayRunKind::Full).unwrap();

    let report = load(&progress_path, VerificationStage::Replay)
        .unwrap()
        .unwrap();
    assert_eq!(report.totals.runs.executed, 2);
    assert_eq!(report.totals.cases.executed, 6);
    assert_eq!(report.success_streak.runs, 2);
    assert_eq!(report.success_streak.cases, 6);
}

#[test]
fn replay_progress_does_not_recount_an_older_focused_attempt_after_a_full_run() {
    let directory = tempfile::tempdir().unwrap();
    let progress_path = directory.path().join("replay-progress.yaml");
    let legacy_path = directory.path().join("e2e-progress.yaml");
    let focused = state(3, 0, 1);
    let full = state(3, 0, 2);

    write_replay_progress(
        &progress_path,
        &legacy_path,
        &focused,
        ReplayRunKind::Focused,
    )
    .unwrap();
    write_replay_progress(&progress_path, &legacy_path, &full, ReplayRunKind::Full).unwrap();
    write_replay_progress(
        &progress_path,
        &legacy_path,
        &focused,
        ReplayRunKind::Focused,
    )
    .unwrap();

    let report = load(&progress_path, VerificationStage::Replay)
        .unwrap()
        .unwrap();
    assert_eq!(report.totals.runs.executed, 2);
    assert_eq!(report.totals.cases.executed, 6);
}

#[test]
fn migrates_legacy_e2e_progress_before_counting_the_next_attempt() {
    let directory = tempfile::tempdir().unwrap();
    let progress_path = directory.path().join("replay-progress.yaml");
    let legacy_path = directory.path().join("e2e-progress.yaml");
    std::fs::write(
        &legacy_path,
        r#"version: 3
updated_at: 2026-07-30T13:34:17Z
status: complete
run:
  key: old-run
progress:
  runs: { executed: 27, passed: 6 }
  cases: { executed: 1240, passed: 630 }
  apis: { total: 1 }
latest_run:
  number: 27
  passed: true
  cases: { executed: 100, passed: 100 }
  apis: { executed: 1, passed: 1 }
apis:
  GET /api/orders/*:
    runs: { executed: 27, passed: 6 }
    cases: { executed: 1178, passed: 625 }
"#,
    )
    .unwrap();

    write_replay_progress(
        &progress_path,
        &legacy_path,
        &state(3, 0, 1),
        ReplayRunKind::Focused,
    )
    .unwrap();

    let report = load(&progress_path, VerificationStage::Replay)
        .unwrap()
        .unwrap();
    assert_eq!(report.totals.runs.executed, 28);
    assert_eq!(report.totals.runs.passed, 7);
    assert_eq!(report.apis["GET /api/orders/*"].totals.runs.executed, 28);
    assert_eq!(report.success_streak.runs, 1);
    assert!(!legacy_path.exists());
}

#[test]
fn replay_progress_uses_passed_wording_without_verified_state() {
    let directory = tempfile::tempdir().unwrap();
    let progress_path = directory.path().join("replay-progress.yaml");
    write_replay_progress(
        &progress_path,
        &directory.path().join("e2e-progress.yaml"),
        &state(3, 0, 1),
        ReplayRunKind::Full,
    )
    .unwrap();
    let yaml = std::fs::read_to_string(progress_path).unwrap();

    assert!(yaml.contains("stage: replay"));
    assert!(yaml.contains("totals:"));
    assert!(yaml.contains("success_streak:"));
    assert!(yaml.contains("passed: 3"));
    assert!(!yaml.contains("successful"));
    assert!(!yaml.contains("verified"));
}
