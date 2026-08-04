use std::collections::BTreeSet;
use std::path::PathBuf;

use chrono::Utc;

use super::{
    clear_resolved_dependency_error_messages, clear_resolved_dependency_errors,
    is_clean_case_dependency_error, is_strict_dependency_finalize_error, terminal_status,
};
use crate::e2e_run::model::{
    ActiveRunState, ApiExecution, CaseExecution, CaseStatus, RunStatus, STATE_VERSION,
};

#[test]
fn recognizes_only_the_defined_strict_dependency_finalize_failure() {
    assert!(is_strict_dependency_finalize_error(
        "strict replay finalize failed: cannot finalize replay with unmatched, unused, or unsupported exchanges; complete=true; dirty=true"
    ));
    assert!(!is_strict_dependency_finalize_error(
        "strict replay finalize failed: replay control socket disappeared"
    ));
    assert!(!is_strict_dependency_finalize_error(
        "target cleanup failed: process exited with signal 9"
    ));
}

#[test]
fn recognizes_dirty_errors_only_for_cases_that_are_now_clean() {
    let clean = BTreeSet::from(["case-clean".to_string()]);
    assert!(is_clean_case_dependency_error(
        "case case-clean replay evidence is dirty: redis unused_recorded=1",
        &clean,
    ));
    assert!(!is_clean_case_dependency_error(
        "case case-dirty replay evidence is dirty: redis unused_recorded=1",
        &clean,
    ));
    assert!(!is_clean_case_dependency_error(
        "case case-clean HTTP execution failed: connection reset",
        &clean,
    ));
}

#[test]
fn clean_dependency_view_drops_obsolete_dirty_errors_and_preserves_lifecycle_failures() {
    let clean = BTreeSet::from(["case-clean".to_string()]);
    let mut errors = vec![
        "case case-clean replay evidence is dirty: redis unused_recorded=1".to_string(),
        "strict replay finalize failed: cannot finalize replay with unmatched, unused, or unsupported exchanges; complete=true; dirty=true".to_string(),
        "strict replay finalize failed: replay control socket disappeared".to_string(),
        "target cleanup failed: process exited with signal 9".to_string(),
    ];

    clear_resolved_dependency_error_messages(&mut errors, &clean, true);

    assert_eq!(
        errors,
        [
            "strict replay finalize failed: replay control socket disappeared",
            "target cleanup failed: process exited with signal 9",
        ]
    );
}

#[test]
fn dirty_dependency_view_keeps_the_strict_finalize_failure() {
    let clean = BTreeSet::from(["case-clean".to_string()]);
    let mut errors = vec![
        "case case-clean replay evidence is dirty: redis unused_recorded=1".to_string(),
        "strict replay finalize failed: cannot finalize replay with unmatched, unused, or unsupported exchanges; complete=true; dirty=true".to_string(),
    ];

    clear_resolved_dependency_error_messages(&mut errors, &clean, false);

    assert_eq!(errors.len(), 1);
    assert!(is_strict_dependency_finalize_error(&errors[0]));
}

#[test]
fn obsolete_finalize_error_no_longer_keeps_a_clean_attempt_failed() {
    let mut state = clean_state();
    state.errors.push(
        "strict replay finalize failed: cannot finalize replay with unmatched, unused, or unsupported exchanges; complete=true; dirty=true"
            .to_string(),
    );

    clear_resolved_dependency_errors(&mut state);
    state.status = terminal_status(&state);

    assert!(state.errors.is_empty());
    assert_eq!(state.status, RunStatus::Successful);
}

#[test]
fn genuine_lifecycle_error_still_keeps_a_clean_dependency_view_failed() {
    let mut state = clean_state();
    state.errors.extend([
        "strict replay finalize failed: cannot finalize replay with unmatched, unused, or unsupported exchanges; complete=true; dirty=true"
            .to_string(),
        "target cleanup failed: process exited unexpectedly".to_string(),
    ]);

    clear_resolved_dependency_errors(&mut state);
    state.status = terminal_status(&state);

    assert_eq!(
        state.errors,
        ["target cleanup failed: process exited unexpectedly"]
    );
    assert_eq!(state.status, RunStatus::Failed);
}

fn clean_state() -> ActiveRunState {
    ActiveRunState {
        version: STATE_VERSION,
        run_key: "recording-run".to_string(),
        sequence: 6,
        status: RunStatus::Failed,
        started_at: Utc::now(),
        finished_at: Some(Utc::now()),
        case_source: PathBuf::from("/recording"),
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
        cases: vec![CaseExecution {
            case_id: "case-clean".to_string(),
            case_dir: PathBuf::from("/recording/case-clean"),
            group_id: "GET /api".to_string(),
            status: CaseStatus::Passed,
            assertion_passed: Some(true),
            replay_clean: Some(true),
            response_assertion: None,
        }],
        apis: vec![ApiExecution {
            api_key: "GET /api".to_string(),
            group_id: "GET /api".to_string(),
            method: "GET".to_string(),
            api_pattern: "/api".to_string(),
            case_ids: vec!["case-clean".to_string()],
            total: 1,
            passed: 1,
            failed: 0,
            incomplete: 0,
            complete_pass: true,
            report_dir: PathBuf::from("/api-report"),
        }],
        errors: Vec::new(),
    }
}
