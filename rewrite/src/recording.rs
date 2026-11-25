//! Invalidation and refresh requirements for externally produced recording evidence.
use super::{
    inventory,
    model::{RewritePhase, RewriteRecordingReason, RewriteRecordingSettings, RewriteState},
};
use anyhow::{Result, ensure};
use std::path::Path;

pub(super) fn reset_for_fresh_recording(
    target_root: &Path,
    state: &mut RewriteState,
    settings: RewriteRecordingSettings,
    reason: RewriteRecordingReason,
) -> Result<()> {
    state.recording_after_run_id = super::recording_input::latest_existing_run_id(target_root)?
        .into_iter()
        .chain(state.recording_after_run_id.clone())
        .chain((!state.recording_run_id.is_empty()).then(|| state.recording_run_id.clone()))
        .max();
    if let Some(refresh) = state.recording_refresh.as_mut() {
        refresh.recording_run_id = None;
    }
    state.recording_input_case_source = None;
    state.recording_input_diagnosis = None;
    state.phase = RewritePhase::RecordingRequired;
    inventory::reset_for_recording(state);
    if reason == RewriteRecordingReason::SourceBaselineChanged {
        state.source_route_bindings.clear();
    }
    state.recording_run_id.clear();
    state.recording_rejection = None;
    state.recording_settings = settings;
    state.recording_request_reason = Some(reason);
    state.case_source = None;
    state.case_inventory_id = None;
    state.source_revision = None;
    state.group_id = None;
    state.target_fingerprint = None;
    state.attempts.clear();
    state.attempt_delta = None;
    state.active_issue = None;
    state.rule_replay_pending = false;
    state.rule_plan = None;
    state.dependency_rule_plan = None;
    state.recorder_capture_plan = None;
    state.route = None;
    state.e2e_current = false;
    state.bump();
    Ok(())
}

pub(super) fn begin_pending_capture_refresh(
    target_root: &Path,
    state: &mut RewriteState,
) -> Result<bool> {
    let Some(refresh) = state.recording_refresh.as_ref() else {
        return Ok(false);
    };
    if refresh.recording_run_id.is_some() {
        return Ok(false);
    }
    if state.phase == RewritePhase::RecordingRequired
        && state.recording_request_reason == Some(RewriteRecordingReason::RecorderContractChanged)
    {
        return Ok(false);
    }
    if inventory::has_runnable_work(state) {
        return Ok(false);
    }
    ensure!(
        super::fingerprint::project_config_revision(target_root)?
            == refresh.project_config_revision,
        "project config changed after scheduling the recording refresh; re-plan the affected rule"
    );
    ensure!(
        super::fingerprint::source_traffic_policy_revision(target_root)?
            == refresh.source_traffic_policy_revision,
        "source traffic policy changed after scheduling the recording refresh; re-plan the affected rule"
    );
    reset_for_fresh_recording(
        target_root,
        state,
        state.recording_settings,
        RewriteRecordingReason::RecorderContractChanged,
    )?;
    Ok(true)
}
