use std::path::{Path, PathBuf};

use super::model::{
    RewritePhase, RewriteRecordingSettings, RewriteSliceState, RewriteState, STATE_VERSION,
};

#[cfg(test)]
pub(crate) fn install_source_snapshot(target_root: &Path) -> String {
    crate::test_support::install_source_snapshot(target_root)
}

pub(crate) fn test_state() -> RewriteState {
    crate::initialize();
    RewriteState {
        version: STATE_VERSION,
        revision: 1,
        workflow_id: "rewrite-test".to_string(),
        dependency_review: Default::default(),
        regression: None,
        recording_apis: vec!["GET /api".to_string()],
        api_inventory: Vec::new(),
        revalidation_round: None,
        pre_revalidation_review: None,
        skipped_api_statuses: Default::default(),
        source_route_bindings: std::collections::BTreeMap::new(),
        current_api_index: None,
        parked_slices: std::collections::BTreeMap::new(),
        worker_bindings: std::collections::BTreeMap::new(),
        implementers: None,
        repository_analysis: None,
        group_replay: None,
        last_group_replay: None,
        source_review_rework: std::collections::BTreeMap::new(),
        worker_event_revision: 0,
        rule_plan_event_revision: 0,
        api_catalog_initialized: false,
        api_catalog: std::collections::BTreeSet::new(),
        case_pattern_identification: None,
        case_pattern_analysis: None,
        target_quality_fingerprint: None,
        delivery_review_required: false,
        recording_run_id: "20260802000000".to_string(),
        recording_after_run_id: None,
        recording_rejection: None,
        recording_settings: RewriteRecordingSettings::default(),
        recording_request_reason: None,
        recording_input_case_source: Some(PathBuf::from("recording-input")),
        recording_input_diagnosis: None,
        recording_refresh: None,
        active_slice: RewriteSliceState {
            phase: RewritePhase::RecordingRequired,
            api: "GET /api".to_string(),
            source_route: "/api".to_string(),
            case_source: None,
            case_inventory_id: None,
            source_revision: None,
            group_id: None,
            target_fingerprint: None,
            replay_identity: None,
            attempts: Vec::new(),
            engine_retry_fingerprints: Default::default(),
            engine_retry_running: false,
            attempt_delta: None,
            active_issue: None,
            rule_plan: None,
            dependency_rule_plan: None,
            recorder_capture_plan: None,
            route: None,
            system_repair_accepted: false,
            rule_replay_pending: false,
            e2e_current: false,
        },
    }
}

pub(crate) use crate::test_support::{install_project_config, managed_test_recorder};

use crate::model::{
    RewriteApiProgress, RewriteApiStatus, RewriteIssue, RewriteIssueKind, RewriteIssueOwner,
};
use std::{fs, process::Command};
pub(crate) fn implementation_state_with_inventory(include_pending: bool) -> RewriteState {
    let mut state = test_state();
    state.phase = RewritePhase::ImplementationRequired;
    state.active_issue = Some(issue("issue-a", 1, "target-a"));
    state.api_inventory = vec![api_progress("GET /api", RewriteApiStatus::Active)];
    if include_pending {
        state
            .api_inventory
            .push(api_progress("POST /other", RewriteApiStatus::Pending));
    }
    state.current_api_index = Some(0);
    state
}

pub(crate) fn api_progress(api: &str, status: RewriteApiStatus) -> RewriteApiProgress {
    RewriteApiProgress {
        api: api.to_string(),
        source_route: Some(api.split_once(' ').unwrap().1.to_string()),
        status,
        attempts: 0,
        e2e_current: false,
        verified_target_fingerprint: None,
    }
}

pub(crate) fn configured_target() -> tempfile::TempDir {
    crate::initialize();
    let target = tempfile::tempdir().unwrap();
    fs::create_dir_all(target.path().join(".traffic-e2e")).unwrap();
    crate::workflow_test_support::install_project_config(
        target.path(),
        "master",
        crate::workflow_test_support::managed_test_recorder(),
        None,
    );
    fs::write(target.path().join("lib.rs"), "pub fn value() -> u8 { 1 }\n").unwrap();
    git_ok(target.path(), &["init", "-q", "-b", "master"]);
    git_ok(target.path(), &["config", "user.email", "test@example.com"]);
    git_ok(target.path(), &["config", "user.name", "Traffic E2E Test"]);
    git_ok(target.path(), &["add", "."]);
    git_ok(target.path(), &["commit", "-q", "-m", "baseline"]);
    git_ok(target.path(), &["switch", "-q", "-c", "feature"]);
    target
}

pub(crate) fn git_ok(repository: &Path, args: &[&str]) {
    let status = Command::new("git")
        .arg("-C")
        .arg(repository)
        .args(args)
        .status()
        .unwrap();
    assert!(status.success(), "git command failed: {args:?}");
}

pub(crate) fn issue(id: &str, attempt: u64, target_fingerprint: &str) -> RewriteIssue {
    RewriteIssue {
        id: id.to_string(),
        kind: RewriteIssueKind::Response,
        owner: RewriteIssueOwner::TargetCode,
        summary: "implementation differs".to_string(),
        pointer_pattern: None,
        representative: None,
        egress_rejections: None,
        recorder_capture_diagnosis: None,
        response_diagnosis: None,
        possible_causes: Vec::new(),
        observed_target_fingerprint: target_fingerprint.to_string(),
        attempt,
    }
}
