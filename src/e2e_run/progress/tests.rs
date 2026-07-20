use std::path::PathBuf;

use chrono::Utc;

use super::*;
use crate::case_group::{CanonicalCase, CanonicalCaseGroup};
use crate::e2e_run::model::{
    ApiExecution, ApiProgress, ApiVerificationThresholds, CaseExecution, CaseStatus, RunStatus,
    STATE_VERSION,
};

fn verification(runs: u64, cases: u64) -> ApiVerificationConfig {
    ApiVerificationConfig {
        consecutive_successful_runs: runs,
        successful_cases: cases,
        overrides: BTreeMap::new(),
    }
}

fn state(api_passed: u32, api_failed: u32, status: RunStatus) -> ActiveRunState {
    let cases = (0..api_passed)
        .map(|index| CaseExecution {
            case_id: format!("passed-{index}"),
            case_dir: PathBuf::from("/cases"),
            group_id: "GET /api/orders/*".to_string(),
            status: CaseStatus::Passed,
            assertion_passed: Some(true),
            replay_clean: Some(true),
            response_assertion: None,
        })
        .chain((0..api_failed).map(|index| CaseExecution {
            case_id: format!("failed-{index}"),
            case_dir: PathBuf::from("/cases"),
            group_id: "GET /api/orders/*".to_string(),
            status: CaseStatus::Failed,
            assertion_passed: Some(false),
            replay_clean: Some(true),
            response_assertion: None,
        }))
        .collect::<Vec<_>>();
    ActiveRunState {
        version: STATE_VERSION,
        run_key: "run".to_string(),
        sequence: 1,
        status,
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
            successful: api_failed == 0,
            ensure_status: None,
            report_dir: PathBuf::from("apis/api-0001"),
        }],
        errors: Vec::new(),
    }
}

fn inventory() -> CaseGroupInventory {
    CaseGroupInventory {
        case_source: PathBuf::from("/cases"),
        source_revision: "source".to_string(),
        case_inventory_id: "inventory".to_string(),
        groups: vec![
            CanonicalCaseGroup {
                group_id: "GET /api/orders/*".to_string(),
                method: "GET".to_string(),
                source_route: "/api/orders/:id".to_string(),
                pattern: Some("/api/orders/*".to_string()),
                case_inventory_id: "inventory".to_string(),
                cases: (0..3)
                    .map(|index| CanonicalCase {
                        case_id: format!("passed-{index}"),
                        case_dir: PathBuf::from("/cases"),
                    })
                    .collect(),
            },
            CanonicalCaseGroup {
                group_id: "POST /api/payments".to_string(),
                method: "POST".to_string(),
                source_route: "/api/payments".to_string(),
                pattern: None,
                case_inventory_id: "inventory".to_string(),
                cases: vec![CanonicalCase {
                    case_id: "payment-passed".to_string(),
                    case_dir: PathBuf::from("/cases"),
                }],
            },
        ],
    }
}

fn payment_state() -> ActiveRunState {
    let mut payment = state(1, 0, RunStatus::Successful);
    payment.cases[0].case_id = "payment-passed".to_string();
    payment.cases[0].group_id = "POST /api/payments".to_string();
    payment.apis[0] = ApiExecution {
        api_key: "POST /api/payments".to_string(),
        group_id: "POST /api/payments".to_string(),
        method: "POST".to_string(),
        api_pattern: "/api/payments".to_string(),
        case_ids: vec!["payment-passed".to_string()],
        total: 1,
        passed: 1,
        failed: 0,
        incomplete: 0,
        successful: true,
        ensure_status: None,
        report_dir: PathBuf::from("apis/api-0001"),
    };
    payment
}

fn next_run_index(index: &RunIndex, state: &ActiveRunState, run_key: &str) -> RunIndex {
    let directory = tempfile::tempdir().unwrap();
    let progress_path = directory.path().join("e2e-progress.yaml");
    store::write_yaml(&progress_path, &build_progress(index, state)).unwrap();
    load_progress_baseline(
        &progress_path,
        run_key.to_string(),
        PathBuf::from("/next-cases"),
    )
    .unwrap()
}

#[test]
fn repeated_attempts_replace_the_current_run_terminal_state() {
    let mut index = RunIndex::empty("run".to_string(), PathBuf::from("/cases"));
    let first = state(2, 1, RunStatus::Failed);

    update_index(&mut index, &first, &verification(2, 6));
    assert_eq!(index.executions, 1);
    assert_eq!(index.replayed_cases, 3);
    assert_eq!(index.successful, 0);
    assert_eq!(index.passed_cases, 2);
    assert!(!index.apis["GET /api/orders/*"].verified);

    let mut second = state(3, 0, RunStatus::Successful);
    second.sequence = 2;
    update_index(&mut index, &second, &verification(2, 6));
    assert_eq!(index.executions, 1);
    assert_eq!(index.replayed_cases, 3);
    assert_eq!(index.successful, 1);
    assert_eq!(index.passed_cases, 3);
    let api = &index.apis["GET /api/orders/*"];
    assert!(!api.verified);
    assert_eq!(api.executions, 1);
    assert_eq!(api.successful, 1);
    assert_eq!(api.executed_cases, 3);
    assert_eq!(api.successful_cases, 3);
    assert_eq!(api.consecutive_successful_runs, 1);
    assert_eq!(api.consecutive_successful_cases, 3);
}

#[test]
fn successful_api_accumulates_when_another_api_fails() {
    let mut index = RunIndex::empty("run".to_string(), PathBuf::from("/cases"));
    let mut round = state(3, 0, RunStatus::Failed);
    round.cases.push(CaseExecution {
        case_id: "payment-failed".to_string(),
        case_dir: PathBuf::from("/cases"),
        group_id: "POST /api/payments".to_string(),
        status: CaseStatus::Failed,
        assertion_passed: Some(false),
        replay_clean: Some(true),
        response_assertion: None,
    });
    round.apis.push(ApiExecution {
        api_key: "POST /api/payments".to_string(),
        group_id: "POST /api/payments".to_string(),
        method: "POST".to_string(),
        api_pattern: "/api/payments".to_string(),
        case_ids: vec!["payment-failed".to_string()],
        total: 1,
        passed: 0,
        failed: 1,
        incomplete: 0,
        successful: false,
        ensure_status: None,
        report_dir: PathBuf::from("apis/api-0002"),
    });

    update_index(&mut index, &round, &verification(1, 3));

    assert!(index.apis["GET /api/orders/*"].verified);
    assert!(!index.apis["POST /api/payments"].verified);
}

#[test]
fn publishing_same_sequence_and_replaying_the_same_run_are_idempotent() {
    let mut index = RunIndex::empty("run".to_string(), PathBuf::from("/cases"));
    let completed = state(3, 0, RunStatus::Successful);
    update_index(&mut index, &completed, &verification(1, 3));
    update_index(&mut index, &completed, &verification(1, 3));
    let mut repeated = completed.clone();
    repeated.sequence = 2;
    update_index(&mut index, &repeated, &verification(1, 3));

    assert_eq!(index.executions, 1);
    assert_eq!(index.replayed_cases, 3);
    assert_eq!(index.successful, 1);
    assert_eq!(index.apis["GET /api/orders/*"].executions, 1);
    assert_eq!(
        index.apis["GET /api/orders/*"].consecutive_successful_runs,
        1
    );
}

#[test]
fn a_new_published_run_advances_verification_once() {
    let policy = verification(2, 6);
    let first = state(3, 0, RunStatus::Successful);
    let mut first_index = RunIndex::empty("run-1".to_string(), PathBuf::from("/cases"));
    update_index(&mut first_index, &first, &policy);
    assert!(!first_index.apis["GET /api/orders/*"].verified);

    let mut second = first.clone();
    second.run_key = "run-2".to_string();
    let mut second_index = next_run_index(&first_index, &first, "run-2");
    update_index(&mut second_index, &second, &policy);

    assert_eq!(second_index.executions, 2);
    assert_eq!(second_index.successful, 2);
    assert_eq!(second_index.replayed_cases, 6);
    assert_eq!(second_index.passed_cases, 6);
    assert!(second_index.apis["GET /api/orders/*"].verified);
}

#[test]
fn legacy_attempt_report_is_one_run_when_used_as_a_new_run_baseline() {
    let completed = state(31, 0, RunStatus::Successful);
    let mut report = build_progress(
        &RunIndex::empty("legacy".to_string(), PathBuf::from("/cases")),
        &completed,
    );
    report.version = 1;
    report.progress.runs = SuccessCounts {
        executed: 9,
        successful: 8,
        consecutive_successful: 8,
    };
    report.progress.cases = SuccessCounts {
        executed: 279,
        successful: 248,
        consecutive_successful: 248,
    };
    report.progress.apis = ApiCounts {
        total: 1,
        verified: 1,
    };
    report.latest_run = LatestRun {
        number: 9,
        successful: true,
        cases: LatestCounts {
            executed: 31,
            successful: 31,
        },
        apis: LatestCounts {
            executed: 1,
            successful: 1,
        },
    };
    report.apis.insert(
        "GET /api/orders/*".to_string(),
        ProgressApi {
            verified: true,
            runs: report.progress.runs,
            cases: report.progress.cases,
        },
    );
    let directory = tempfile::tempdir().unwrap();
    let progress_path = directory.path().join("e2e-progress.yaml");
    store::write_yaml(&progress_path, &report).unwrap();

    let mut index = load_progress_baseline(
        &progress_path,
        "run-2".to_string(),
        PathBuf::from("/next-cases"),
    )
    .unwrap();
    assert_eq!(index.executions, 1);
    assert_eq!(index.replayed_cases, 31);
    assert_eq!(index.apis["GET /api/orders/*"].executions, 1);
    assert!(!index.apis["GET /api/orders/*"].verified);

    let mut next = completed;
    next.run_key = "run-2".to_string();
    update_index(&mut index, &next, &verification(3, 93));
    assert_eq!(index.executions, 2);
    assert_eq!(index.replayed_cases, 62);
    assert!(!index.apis["GET /api/orders/*"].verified);
}

#[test]
fn focused_apis_contribute_to_one_logical_run() {
    let mut index = RunIndex::empty("run".to_string(), PathBuf::from("/cases"));
    let orders = state(3, 0, RunStatus::Successful);

    update_focused_index(&mut index, &orders, &inventory(), true, &verification(1, 1));

    assert_eq!(index.executions, 1);
    assert!(index.apis["GET /api/orders/*"].verified);
    assert!(!index.apis["POST /api/payments"].verified);
    assert_eq!(build_progress(&index, &orders).status, "in_progress");

    let payment = payment_state();
    update_focused_index(
        &mut index,
        &payment,
        &inventory(),
        true,
        &verification(1, 1),
    );

    assert_eq!(index.executions, 1);
    assert_eq!(index.replayed_cases, 4);
    assert_eq!(index.passed_cases, 4);
    assert!(index.apis.values().all(|api| api.verified));
    assert_eq!(build_progress(&index, &payment).status, "complete");
}

#[test]
fn focused_api_overrides_require_distinct_runs() {
    let mut policy = verification(1, 1);
    policy.overrides.insert(
        "POST /api/payments".to_string(),
        ApiVerificationThresholds {
            consecutive_successful_runs: 2,
            successful_cases: 2,
        },
    );
    let mut index = RunIndex::empty("run-1".to_string(), PathBuf::from("/cases"));
    let orders = state(3, 0, RunStatus::Successful);
    update_focused_index(&mut index, &orders, &inventory(), true, &policy);

    let mut payment = payment_state();
    update_focused_index(&mut index, &payment, &inventory(), true, &policy);

    assert!(index.apis["GET /api/orders/*"].verified);
    assert!(!index.apis["POST /api/payments"].verified);

    payment.sequence = 2;
    update_focused_index(&mut index, &payment, &inventory(), true, &policy);
    assert!(!index.apis["POST /api/payments"].verified);

    let mut next_index = next_run_index(&index, &payment, "run-2");
    payment.run_key = "run-2".to_string();
    payment.sequence = 1;
    update_focused_index(&mut next_index, &payment, &inventory(), true, &policy);
    assert!(next_index.apis["POST /api/payments"].verified);
}

#[test]
fn changed_baseline_starts_new_streaks() {
    let mut index = RunIndex::empty("run".to_string(), PathBuf::from("/cases"));
    let first = state(3, 0, RunStatus::Successful);
    update_index(&mut index, &first, &verification(2, 6));
    let mut changed = first.clone();
    changed.sequence = 2;
    changed.case_inventory_id = "changed-inventory".to_string();
    update_index(&mut index, &changed, &verification(2, 6));

    assert_eq!(index.consecutive_successful_runs, 1);
    assert_eq!(index.consecutive_successful_cases, 3);
    assert!(!index.apis["GET /api/orders/*"].verified);
}

#[test]
fn historical_apis_are_preserved_when_absent_from_the_current_inventory() {
    let first = state(3, 0, RunStatus::Successful);
    let mut first_index = RunIndex::empty("run-1".to_string(), PathBuf::from("/cases"));
    update_index(&mut first_index, &first, &verification(1, 1));

    let mut second_index = next_run_index(&first_index, &first, "run-2");
    let payment = payment_state();
    update_index(&mut second_index, &payment, &verification(1, 1));

    assert!(second_index.apis.contains_key("GET /api/orders/*"));
    assert!(second_index.apis.contains_key("POST /api/payments"));
    assert_eq!(
        build_progress(&second_index, &payment).progress.apis.total,
        2
    );
}

#[test]
fn current_run_completion_does_not_require_api_verification() {
    let mut index = RunIndex::empty("run".to_string(), PathBuf::from("/cases"));
    let completed = state(3, 0, RunStatus::Successful);
    update_index(&mut index, &completed, &verification(3, 200));

    assert!(!index.apis["GET /api/orders/*"].verified);
    assert_eq!(build_progress(&index, &completed).status, "complete");
}

#[test]
fn legacy_attempt_counts_are_collapsed_to_one_current_run() {
    let mut index = RunIndex::empty("run".to_string(), PathBuf::from("/cases"));
    index.current_run.initialized = false;
    index.inventory_complete = true;
    index.executions = 9;
    index.successful = 8;
    index.latest_status = Some(RunStatus::Successful);
    index.apis.insert(
        "GET /api/orders/*".to_string(),
        ApiProgress {
            cases: 3,
            executions: 9,
            successful: 8,
            consecutive_successful_runs: 8,
            executed_cases: 27,
            successful_cases: 24,
            consecutive_successful_cases: 24,
            verified: true,
            ..ApiProgress::default()
        },
    );

    index.normalize_legacy_progress();
    assert!(!index.apis["GET /api/orders/*"].verified);
    refresh_verification(&mut index, &verification(2, 6));

    let api = &index.apis["GET /api/orders/*"];
    assert_eq!(index.executions, 1);
    assert_eq!(index.successful, 1);
    assert_eq!(index.consecutive_successful_runs, 1);
    assert_eq!(index.consecutive_successful_cases, 3);
    assert_eq!(api.executions, 1);
    assert_eq!(api.successful, 1);
    assert_eq!(api.consecutive_successful_runs, 1);
    assert_eq!(api.consecutive_successful_cases, 3);
    assert!(!api.verified);
}

#[test]
fn human_progress_uses_only_simplified_success_counts() {
    let mut index = RunIndex::empty("run".to_string(), PathBuf::from("/cases"));
    let completed = state(3, 0, RunStatus::Successful);
    update_index(&mut index, &completed, &verification(1, 3));
    let yaml = serde_yaml::to_string(&build_progress(&index, &completed)).unwrap();

    assert!(yaml.contains("version: 2"));
    assert!(yaml.contains("consecutive_successful: 3"));
    assert!(yaml.contains("verified: true"));
    for omitted in [
        "failed:",
        "incomplete:",
        "interrupted:",
        "replayed:",
        "passed:",
        "needs_attention",
        "highlights:",
    ] {
        assert!(!yaml.contains(omitted), "{omitted} leaked into progress");
    }
}
