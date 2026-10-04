//! Construction of a new workflow before its first standard recording.
use super::{
    artifacts,
    model::{
        RewritePhase, RewriteRecordingSettings, RewriteSliceState, RewriteState, STATE_VERSION,
    },
};
use crate::ManagedRecordingOperation;
use anyhow::Result;
use std::path::Path;

pub(super) fn new_state(
    target_root: &Path,
    api: String,
    source_route: String,
    recording_apis: Vec<String>,
) -> Result<RewriteState> {
    let recording_run_id =
        artifacts::allocate_run_id(target_root, ManagedRecordingOperation::Record)?;
    Ok(RewriteState {
        version: STATE_VERSION,
        revision: 1,
        workflow_id: format!("rewrite-{}", uuid::Uuid::new_v4().simple()),
        regression: None,
        recording_apis,
        api_inventory: Vec::new(),
        skipped_api_statuses: Default::default(),
        source_route_bindings: std::collections::BTreeMap::new(),
        current_api_index: None,
        parked_slices: std::collections::BTreeMap::new(),
        worker_bindings: std::collections::BTreeMap::new(),
        source_review_rework: std::collections::BTreeMap::new(),
        worker_event_revision: 0,
        process_outputs: Default::default(),
        api_catalog_initialized: false,
        api_catalog: std::collections::BTreeSet::new(),
        case_pattern_identification: None,
        target_quality_fingerprint: None,
        delivery_review_required: false,
        recording_run_id,
        require_comparison: crate::config::regression::RegressionScope::load(target_root)?
            .require_comparison,
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
            system_repair_accepted: false,
            rule_replay_pending: false,
            e2e_current: false,
            comparison_current: false,
        },
    })
}
