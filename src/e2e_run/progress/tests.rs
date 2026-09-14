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
        replay_session: PathBuf::from("/session"),
        replay_report: PathBuf::from("/report"),
        aggregate_report: PathBuf::from("/aggregate"),
        assertions_report: PathBuf::from("/assertions"),
        session_id: Some("session".to_string()),
        replay_pid: None,
        target_started: false,
        target_container_name: None,
        target_anchor_name: None,
        target_image_id: None,
        runtime_outputs: Vec::new(),
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
        response_unavailable_reason: None,
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

fn inventory_with_friends() -> CaseGroupInventory {
    let mut inventory = inventory();
    let mut friends = inventory.groups[0].clone();
    friends.group_id = "GET /api/friends".to_string();
    friends.source_route = "/api/friends".to_string();
    friends.pattern = Some("/api/friends".to_string());
    friends.cases.truncate(1);
    inventory.groups.push(friends);
    inventory
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
fn focused_attempt_drops_obsolete_api_contributions_after_inventory_regrouping() {
    let directory = tempfile::tempdir().unwrap();
    let progress_path = directory.path().join("progress.yaml");
    let legacy_path = directory.path().join("e2e-progress.yaml");
    let mut previous = state(3, 0, 1);
    let mut obsolete = previous.apis[0].clone();
    obsolete.api_key = "GET /api/orders/1".to_string();
    obsolete.group_id = "GET /api/orders/1".to_string();
    obsolete.api_pattern = "/api/orders/1".to_string();
    obsolete.total = 1;
    obsolete.passed = 0;
    obsolete.failed = 1;
    obsolete.complete_pass = false;
    previous.apis.push(obsolete);
    previous.status = RunStatus::Failed;

    let mut index = RunIndex::empty("run".to_string(), PathBuf::from("/cases"));
    update_index(&mut index, &previous);
    assert_eq!(index.replayed_cases, 4);
    assert!(!index.current_run.passed);

    let mut focused = state(3, 0, 2);
    focused.source_revision = "source-v2".to_string();
    focused.case_inventory_id = "inventory-v2".to_string();
    index.source_revision = focused.source_revision.clone();
    index.case_inventory_id = focused.case_inventory_id.clone();
    update_focused_index(&mut index, &focused, &inventory(), true);

    assert!(!index.current_run.apis.contains_key("GET /api/orders/1"));
    assert!(!index.apis.contains_key("GET /api/orders/1"));
    assert_eq!(index.replayed_cases, 3);
    assert_eq!(index.passed_cases, 3);
    assert!(index.current_run.passed);
    write_replay_progress(&progress_path, &legacy_path, &index, &focused).unwrap();

    let report = load(&progress_path, VerificationStage::Progress)
        .unwrap()
        .unwrap();
    let latest = report.latest_run.as_ref().unwrap();
    assert!(latest.passed);
    assert_eq!(latest.scope, ["GET /api/orders/*"]);
}

#[test]
fn replay_progress_replaces_retries_of_one_recording_batch() {
    let directory = tempfile::tempdir().unwrap();
    let progress_path = directory.path().join("progress.yaml");
    let legacy_path = directory.path().join("e2e-progress.yaml");
    let first = state(3, 0, 1);
    let second = state(3, 0, 2);
    let mut index = RunIndex::empty("run".to_string(), PathBuf::from("/cases"));

    update_index(&mut index, &first);
    write_replay_progress(&progress_path, &legacy_path, &index, &first).unwrap();
    update_index(&mut index, &second);
    write_replay_progress(&progress_path, &legacy_path, &index, &second).unwrap();
    write_replay_progress(&progress_path, &legacy_path, &index, &second).unwrap();

    let report = load(&progress_path, VerificationStage::Progress)
        .unwrap()
        .unwrap();
    assert_eq!(report.totals.runs.executed, 1);
    assert_eq!(report.totals.cases.executed, 3);
    assert_eq!(report.success_streak.runs, 1);
    assert_eq!(report.success_streak.cases, 3);
}

#[test]
fn replay_progress_collapses_legacy_attempt_totals_into_one_recording_batch() {
    let directory = tempfile::tempdir().unwrap();
    let progress_path = directory.path().join("progress.yaml");
    let legacy_path = directory.path().join("e2e-progress.yaml");
    let failed = state(2, 1, 1);
    let passing = state(3, 0, 2);
    let mut report = ProgressReport::new(VerificationStage::Progress);
    let mut previous_recording = state(3, 0, 1);
    previous_recording.run_key = "previous".to_string();
    report
        .apply(legacy_attempt_observation(&previous_recording, "full").unwrap())
        .unwrap();
    report.counted_observations.clear();
    report
        .apply(legacy_attempt_observation(&failed, "full").unwrap())
        .unwrap();
    report
        .apply(legacy_attempt_observation(&passing, "full").unwrap())
        .unwrap();
    write(&progress_path, &report).unwrap();
    let mut index = RunIndex::empty("run".to_string(), PathBuf::from("/cases"));
    update_index(&mut index, &passing);

    write_replay_progress(&progress_path, &legacy_path, &index, &passing).unwrap();

    let report = load(&progress_path, VerificationStage::Progress)
        .unwrap()
        .unwrap();
    assert_eq!(report.totals.runs.executed, 2);
    assert_eq!(report.totals.runs.passed, 2);
    assert_eq!(report.totals.cases.executed, 6);
    assert_eq!(report.totals.cases.passed, 6);
    assert_eq!(report.success_streak.runs, 1);
    assert_eq!(report.success_streak.cases, 3);
    assert_eq!(report.latest_run.as_ref().unwrap().key, "run");
}

#[test]
fn replay_progress_does_not_recount_an_older_focused_attempt_after_a_full_run() {
    let directory = tempfile::tempdir().unwrap();
    let progress_path = directory.path().join("progress.yaml");
    let legacy_path = directory.path().join("e2e-progress.yaml");
    let focused = state(3, 0, 1);
    let full = state(3, 0, 2);
    let mut index = RunIndex::empty("run".to_string(), PathBuf::from("/cases"));

    update_focused_index(&mut index, &focused, &inventory(), true);
    write_replay_progress(&progress_path, &legacy_path, &index, &focused).unwrap();
    update_index(&mut index, &full);
    write_replay_progress(&progress_path, &legacy_path, &index, &full).unwrap();
    write_replay_progress(&progress_path, &legacy_path, &index, &focused).unwrap();

    let report = load(&progress_path, VerificationStage::Progress)
        .unwrap()
        .unwrap();
    assert_eq!(report.totals.runs.executed, 1);
    assert_eq!(report.totals.cases.executed, 3);
}

#[test]
fn revises_an_older_focused_attempt_after_another_api_advances() {
    let directory = tempfile::tempdir().unwrap();
    let progress_path = directory.path().join("progress.yaml");
    let legacy_path = directory.path().join("e2e-progress.yaml");
    let previous = state(2, 1, 1);
    let mut later = state(1, 0, 2);
    later.apis[0].api_key = "GET /api/friends".to_string();
    later.apis[0].group_id = "GET /api/friends".to_string();
    later.apis[0].api_pattern = "/api/friends".to_string();
    let mut index = RunIndex::empty("run".to_string(), PathBuf::from("/cases"));
    let inventory = inventory_with_friends();

    update_focused_index(&mut index, &previous, &inventory, true);
    write_replay_progress(&progress_path, &legacy_path, &index, &previous).unwrap();
    update_focused_index(&mut index, &later, &inventory, true);
    write_replay_progress(&progress_path, &legacy_path, &index, &later).unwrap();
    ensure_replay_progress_revisable(&progress_path, &index, &previous).unwrap();

    let current = state(3, 0, 1);
    update_focused_index(&mut index, &current, &inventory, true);
    revise_replay_progress(&progress_path, &index, &previous, &current).unwrap();

    let report = load(&progress_path, VerificationStage::Progress)
        .unwrap()
        .unwrap();
    assert_eq!(report.totals.runs.executed, 1);
    assert_eq!(report.totals.runs.passed, 1);
    assert_eq!(
        report.latest_run.as_ref().unwrap().scope,
        ["GET /api/friends", "GET /api/orders/*"]
    );
}

#[test]
fn migrates_legacy_e2e_progress_before_counting_the_next_attempt() {
    let directory = tempfile::tempdir().unwrap();
    let progress_path = directory.path().join("progress.yaml");
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

    let completed = state(3, 0, 1);
    let mut index = RunIndex::empty("run".to_string(), PathBuf::from("/cases"));
    update_focused_index(&mut index, &completed, &inventory(), true);
    write_replay_progress(&progress_path, &legacy_path, &index, &completed).unwrap();

    let report = load(&progress_path, VerificationStage::Progress)
        .unwrap()
        .unwrap();
    assert_eq!(report.totals.runs.executed, 28);
    assert_eq!(report.totals.runs.passed, 7);
    assert_eq!(report.apis["GET /api/orders/*"].totals.runs.executed, 28);
    assert_eq!(report.success_streak.runs, 2);
    assert!(!legacy_path.exists());
}

#[test]
fn replay_progress_uses_passed_wording_without_verified_state() {
    let directory = tempfile::tempdir().unwrap();
    let progress_path = directory.path().join("progress.yaml");
    let completed = state(3, 0, 1);
    let mut index = RunIndex::empty("run".to_string(), PathBuf::from("/cases"));
    update_index(&mut index, &completed);
    write_replay_progress(
        &progress_path,
        &directory.path().join("e2e-progress.yaml"),
        &index,
        &completed,
    )
    .unwrap();
    let yaml = std::fs::read_to_string(progress_path).unwrap();

    assert!(!yaml.contains("stage:"));
    assert!(yaml.contains("totals:"));
    assert!(yaml.contains("success_streak:"));
    assert!(yaml.contains("passed: 3"));
    assert!(!yaml.contains("successful"));
    assert!(!yaml.contains("verified"));
}
