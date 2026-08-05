use std::path::PathBuf;

use super::model::{
    RewritePhase, RewriteRecordingSettings, RewriteSliceState, RewriteState, STATE_VERSION,
};

pub(in crate::rewrite) fn test_state() -> RewriteState {
    RewriteState {
        version: STATE_VERSION,
        revision: 1,
        workflow_id: "rewrite-test".to_string(),
        recording_apis: vec!["GET /api".to_string()],
        api_inventory: Vec::new(),
        current_api_index: None,
        parked_slices: std::collections::BTreeMap::new(),
        worker_bindings: std::collections::BTreeMap::new(),
        recording_run_id: "20260802000000".to_string(),
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
            comparison_run_id: None,
            comparison_rejection: None,
            case_source: None,
            case_inventory_id: None,
            source_revision: None,
            group_id: None,
            target_fingerprint: None,
            attempts: Vec::new(),
            attempt_delta: None,
            active_issue: None,
            rule_plan: None,
            dependency_rule_plan: None,
            recorder_capture_plan: None,
            route: None,
            e2e_current: false,
            comparison_current: false,
        },
    }
}
