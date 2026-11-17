use std::path::{Path, PathBuf};

use super::model::{
    RewritePhase, RewriteRecordingSettings, RewriteSliceState, RewriteState, STATE_VERSION,
};

pub(in crate::rewrite) fn install_source_snapshot(target_root: &Path) -> String {
    crate::test_support::install_source_snapshot(target_root)
}

pub(in crate::rewrite) fn test_state() -> RewriteState {
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

pub(in crate::rewrite) use crate::test_support::{
    install_project_config, managed_test_recorder, set_managed_paths,
};
