//! Construction of a new workflow before its first standard recording.
use super::model::{
    RewritePhase, RewriteRecordingSettings, RewriteSliceState, RewriteState, STATE_VERSION,
};
use anyhow::Result;
use std::path::Path;

pub(super) fn new_state(
    _target_root: &Path,
    api: String,
    source_route: String,
    recording_apis: Vec<String>,
) -> Result<RewriteState> {
    let recording_run_id = String::new();
    Ok(RewriteState {
        version: STATE_VERSION,
        revision: 1,
        workflow_id: format!("rewrite-{}", uuid::Uuid::new_v4().simple()),
        regression: None,
        recording_apis,
        api_inventory: Vec::new(),
        revalidation_round: None,
        skipped_api_statuses: Default::default(),
        source_route_bindings: std::collections::BTreeMap::new(),
        current_api_index: None,
        parked_slices: std::collections::BTreeMap::new(),
        worker_bindings: std::collections::BTreeMap::new(),
        source_review_rework: std::collections::BTreeMap::new(),
        worker_event_revision: 0,
        api_catalog_initialized: false,
        api_catalog: std::collections::BTreeSet::new(),
        case_pattern_identification: None,
        target_quality_fingerprint: None,
        delivery_review_required: false,
        recording_run_id,
        recording_after_run_id: None,
        recording_rejection: None,
        recording_settings: RewriteRecordingSettings::default(),
        recording_request_reason: None,
        recording_input_case_source: None,
        recording_input_diagnosis: None,
        recording_refresh: None,
        active_slice: RewriteSliceState {
            phase: RewritePhase::RecordingRequired,
            api,
            source_route,
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
    })
}
