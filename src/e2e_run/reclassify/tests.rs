use std::collections::BTreeSet;
use std::path::PathBuf;

use chrono::Utc;

use super::terminal_status;
use crate::e2e_run::final_evidence::{
    apply_reclassified_case_outcomes, clear_resolved_dependency_error_messages,
    clear_resolved_dependency_errors, is_clean_case_dependency_error,
    is_strict_dependency_finalize_error,
};
use crate::e2e_run::model::{
    ActiveRunState, ApiExecution, CaseExecution, CaseStatus, RunStatus, STATE_VERSION,
};
use crate::replay::BackgroundReclassification;

#[test]
fn ownership_reclassification_updates_every_method_in_the_same_session() {
    let target = tempfile::tempdir().unwrap();
    let context = crate::e2e_run::test_session::install(target.path());
    let original = std::fs::read(context.case_source.join("get-case/dependencies.jsonl")).unwrap();
    crate::e2e_run::test_session::classify_stream(target.path());
    let result =
        super::reclassify_focused_background_dependencies(context.clone(), "GET /api").unwrap();
    assert!(result.passed);
    for api in ["GET /api", "OPTIONS /api"] {
        let path = crate::e2e_run::test_session::state_path(&context, api);
        let state: ActiveRunState = crate::e2e_run::store::read_yaml(&path).unwrap();
        assert!(
            state.aggregate_clean,
            "{api} retained stale shared dependency evidence"
        );
        assert_eq!(state.status, RunStatus::Successful);
        assert_eq!(state.cases.len(), 1);
        assert_eq!(state.cases[0].group_id, api);
    }
    assert_eq!(
        original,
        std::fs::read(context.case_source.join("get-case/dependencies.jsonl")).unwrap()
    );
}

#[test]
fn shared_reclassification_accepts_a_partial_index_without_losing_recorded_coverage() {
    use crate::e2e_run::{config, store, test_session};
    use crate::verification_progress::{VerificationStage, load};
    let target = tempfile::tempdir().unwrap();
    let context = test_session::install_with_unprepared_api(target.path());
    let (_, layout) = config::resolve_layout(target.path(), &context.case_source, None).unwrap();
    let index = store::load_or_create_index(&layout, &layout.run_key, &layout.case_source).unwrap();
    let report = load(&layout.progress_path, VerificationStage::Progress)
        .unwrap()
        .unwrap();
    let before = report.counted_observations[&layout.run_key]
        .observation
        .clone();
    assert_eq!(before.apis.len(), 3);
    assert_eq!(index.current_run.api_keys.len(), 2);

    test_session::classify_stream(target.path());
    super::ensure_focused_background_reclassification_revisable(context.clone(), "GET /api")
        .unwrap();
    let result =
        super::reclassify_focused_background_dependencies(context.clone(), "GET /api").unwrap();
    assert!(result.passed);
    let report = load(&layout.progress_path, VerificationStage::Progress)
        .unwrap()
        .unwrap();
    let observation = &report.counted_observations[&layout.run_key].observation;
    assert_eq!(result.updated_apis, ["GET /api", "OPTIONS /api"]);
    assert_eq!(observation.apis.len(), 3);
    assert_eq!(
        observation.apis["GET /unprepared"],
        before.apis["GET /unprepared"]
    );
    assert!(observation.apis["GET /api"].passed);
    assert!(observation.apis["OPTIONS /api"].passed);
    assert!(!observation.finalized);
    assert_eq!(report.totals.runs.executed, 1);
    assert_eq!(report.totals.cases.executed, 3);
    assert_eq!(report.totals.cases.passed, 2);
    let finalized = std::fs::read(&layout.progress_path).unwrap();
    super::reclassify_focused_background_dependencies(context, "GET /api").unwrap();
    assert_eq!(std::fs::read(&layout.progress_path).unwrap(), finalized);
}

#[test]
fn interrupted_shared_reclassification_retries_without_recounting_the_recording() {
    use crate::e2e_run::{config, store, test_session};
    let target = tempfile::tempdir().unwrap();
    let context = test_session::install(target.path());
    test_session::classify_stream(target.path());
    let path = test_session::state_path(&context, "OPTIONS /api");
    let state: ActiveRunState = store::read_yaml(&path).unwrap();
    std::fs::remove_file(&state.assertions_report).unwrap();
    std::fs::create_dir(&state.assertions_report).unwrap();
    let (_, layout) = config::resolve_layout(target.path(), &context.case_source, None).unwrap();
    let progress = std::fs::read(&layout.progress_path).unwrap();
    assert!(
        super::reclassify_focused_background_dependencies(context.clone(), "GET /api").is_err()
    );
    assert_eq!(std::fs::read(&layout.progress_path).unwrap(), progress);
    assert!(
        layout
            .run_root
            .join("focused-reclassification.pending.yaml")
            .is_file()
    );
    std::fs::remove_dir(&state.assertions_report).unwrap();
    let result =
        super::reclassify_focused_background_dependencies(context.clone(), "GET /api").unwrap();
    assert_eq!(result.updated_apis, ["GET /api", "OPTIONS /api"]);
    assert!(result.results.iter().all(|result| result.passed));
    let index = std::fs::read(&layout.index_path).unwrap();
    let progress = std::fs::read(&layout.progress_path).unwrap();
    super::reclassify_focused_background_dependencies(context, "OPTIONS /api").unwrap();
    assert_eq!(std::fs::read(&layout.index_path).unwrap(), index);
    assert_eq!(std::fs::read(&layout.progress_path).unwrap(), progress);
    assert!(
        !layout
            .run_root
            .join("focused-reclassification.pending.yaml")
            .exists()
    );
}

#[test]
fn shared_reclassification_recovers_after_index_publication_before_progress() {
    use crate::e2e_run::{config, store, test_session};
    let target = tempfile::tempdir().unwrap();
    let context = test_session::install(target.path());
    let (_, layout) = config::resolve_layout(target.path(), &context.case_source, None).unwrap();
    let inventory =
        crate::case_group::load_case_group_inventory(&layout.group_index_path, &layout.case_source)
            .unwrap();
    let members = super::session::members(&layout, &inventory, "GET /api").unwrap();
    let index = store::load_or_create_index(&layout, &layout.run_key, &layout.case_source).unwrap();
    let revision = super::session::preflight(&layout, &members, &index).unwrap();
    let old_progress = std::fs::read(&layout.progress_path).unwrap();
    test_session::classify_stream(target.path());
    super::reclassify_focused_background_dependencies(context.clone(), "GET /api").unwrap();
    let final_index = std::fs::read(&layout.index_path).unwrap();
    let final_progress = std::fs::read(&layout.progress_path).unwrap();
    // A crash after snapshots and index commit leaves the baseline progress and checkpoint.
    std::fs::write(&layout.progress_path, old_progress).unwrap();
    super::session::begin(&layout, &revision).unwrap();
    super::reclassify_focused_background_dependencies(context, "OPTIONS /api").unwrap();
    assert_eq!(std::fs::read(&layout.index_path).unwrap(), final_index);
    assert_eq!(
        std::fs::read(&layout.progress_path).unwrap(),
        final_progress
    );
}

#[test]
fn shared_reclassification_preserves_method_response_failures_and_unrelated_attempts() {
    use crate::e2e_run::{store, test_session};
    for same_session in [true, false] {
        let target = tempfile::tempdir().unwrap();
        let context = test_session::install(target.path());
        let path = test_session::state_path(&context, "OPTIONS /api");
        let mut state: ActiveRunState = store::read_yaml(&path).unwrap();
        state.cases[0].assertion_passed = Some(false);
        if !same_session {
            state.session_id = Some("later-session".into());
            state.sequence += 1;
        }
        store::write_yaml(&path, &state).unwrap();
        let original = std::fs::read(&path).unwrap();
        test_session::classify_stream(target.path());
        let result =
            super::reclassify_focused_background_dependencies(context, "GET /api").unwrap();
        let updated: ActiveRunState = store::read_yaml(&path).unwrap();
        assert_eq!(updated.status, RunStatus::Failed);
        assert_eq!(updated.cases[0].assertion_passed, Some(false));
        if same_session {
            assert!(updated.aggregate_clean);
            assert_eq!(result.results.len(), 2);
            assert!(!result.results[1].passed);
        } else {
            assert_eq!(std::fs::read(&path).unwrap(), original);
            assert_eq!(result.results.len(), 1);
        }
    }
}

#[test]
fn shared_reclassification_rejects_active_or_inconsistent_sibling_before_writing_reports() {
    use crate::e2e_run::{store, test_session};
    for active in [true, false] {
        let target = tempfile::tempdir().unwrap();
        let context = test_session::install(target.path());
        let path = test_session::state_path(&context, "OPTIONS /api");
        let mut state: ActiveRunState = store::read_yaml(&path).unwrap();
        if active {
            std::fs::create_dir(path.parent().unwrap().parent().unwrap().join(".active")).unwrap();
        } else {
            state.case_inventory_id = "foreign-inventory".into();
            store::write_yaml(&path, &state).unwrap();
        }
        let primary: ActiveRunState =
            store::read_yaml(&test_session::state_path(&context, "GET /api")).unwrap();
        let original = std::fs::read(&primary.replay_report).unwrap();
        test_session::classify_stream(target.path());
        assert!(super::reclassify_focused_background_dependencies(context, "GET /api").is_err());
        assert_eq!(std::fs::read(&primary.replay_report).unwrap(), original);
    }
}

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

#[test]
fn final_reclassification_promotes_a_case_that_became_clean_after_case_end() {
    let mut state = clean_state();
    state.cases[0].status = CaseStatus::Failed;
    state.cases[0].replay_clean = Some(false);
    state
        .errors
        .push("case case-clean replay evidence is dirty: memcached unused_recorded=2".to_string());

    apply_reclassified_case_outcomes(&mut state, &BackgroundReclassification::default());
    clear_resolved_dependency_errors(&mut state);
    state.status = terminal_status(&state);

    assert_eq!(state.cases[0].replay_clean, Some(true));
    assert_eq!(state.cases[0].status, CaseStatus::Passed);
    assert!(state.errors.is_empty());
    assert_eq!(state.status, RunStatus::Successful);
}

#[test]
fn final_reclassification_keeps_an_unexecuted_case_pending() {
    let mut state = clean_state();
    state.cases[0].status = CaseStatus::Pending;
    state.cases[0].assertion_passed = None;
    state.cases[0].replay_clean = None;
    let reclassified = BackgroundReclassification {
        remaining_dirty_case_ids: BTreeSet::from(["case-clean".to_string()]),
        ..BackgroundReclassification::default()
    };

    apply_reclassified_case_outcomes(&mut state, &reclassified);

    assert_eq!(state.cases[0].status, CaseStatus::Pending);
    assert_eq!(state.cases[0].replay_clean, None);
}

fn clean_state() -> ActiveRunState {
    ActiveRunState {
        engine_fingerprint: None,
        version: STATE_VERSION,
        run_key: "recording-run".to_string(),
        sequence: 6,
        status: RunStatus::Failed,
        started_at: Utc::now(),
        finished_at: Some(Utc::now()),
        case_source: PathBuf::from("/recording"),
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
        cases: vec![CaseExecution {
            case_id: "case-clean".to_string(),
            case_dir: PathBuf::from("/recording/case-clean"),
            group_id: "GET /api".to_string(),
            status: CaseStatus::Passed,
            assertion_passed: Some(true),
            replay_clean: Some(true),
            response_assertion: None,
            response_unavailable_reason: None,
            execution_failure: None,
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
