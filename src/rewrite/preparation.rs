use std::path::Path;

use anyhow::{Context, Result};

use super::model::{RewriteIssueKind, RewritePhase, RewriteRecordingReason, RewriteState};
use super::{artifacts, fingerprint, inventory, transition};
use crate::e2e_run::{
    focused_background_reclassification_recovery_required, latest_focused_api,
    reclassify_focused_background_dependencies,
};
use crate::{E2eRunContext, E2eRunPrepareOptions, RecordingApi, prepare_e2e_run};

pub(super) fn prepare_recording(target_root: &Path, state: &mut RewriteState) -> Result<()> {
    let (_, project) = crate::e2e_run::resolve_project(target_root)?;
    let case_source = artifacts::recording_run(target_root, &state.recording_run_id);
    let api = state.api.parse::<RecordingApi>()?;
    let config = crate::config::AppConfig::load(&project.recorder_config)?;
    let routes = config
        .http_gateway
        .source_routes
        .merged((api.method().as_str() != "MOTAN").then(|| api.to_string()))?;
    let member = crate::case_group::resolve_recording_api_seed_member(&case_source, &api, &routes)?;
    let source_revision = fingerprint::source_image_revision(target_root)?;
    let prepared = prepare_e2e_run(E2eRunPrepareOptions {
        context: E2eRunContext {
            target_root: target_root.to_path_buf(),
            case_source: case_source.clone(),
            run_key: None,
        },
        case_dir: member,
        method: api.method().to_string(),
        source_route: state.source_route.clone(),
        pattern: api.is_dynamic().then(|| api.path_pattern().to_string()),
        source_revision: source_revision.clone(),
    })?;
    state.case_source = Some(case_source);
    state.case_inventory_id = Some(prepared.group.case_inventory_id);
    state.source_revision = Some(source_revision);
    state.group_id = Some(prepared.group.group_id);
    state.bump();
    Ok(())
}

pub(super) fn restore_legacy_background_rule_recording_request(
    target_root: &Path,
    state: &mut RewriteState,
) -> Result<bool> {
    if state.phase != RewritePhase::RecordingRequired
        || state.recording_request_reason != Some(RewriteRecordingReason::RecorderContractChanged)
        || state.recording_input_case_source.is_none()
        || artifacts::standard_recording_publication(target_root, &state.recording_run_id)?
            != artifacts::RecordingPublication::Missing
    {
        return Ok(false);
    }
    let case_source = state
        .recording_input_case_source
        .clone()
        .context("legacy process-owned-rule recording request lost its prior case source")?;
    let active_api = latest_focused_api(E2eRunContext {
        target_root: target_root.to_path_buf(),
        case_source: case_source.clone(),
        run_key: None,
    })?
    .context("legacy process-owned-rule recording request has no focused attempt to restore")?;
    state.recording_run_id = recording_run_id(&case_source)?;
    state.recording_request_reason = None;
    state.recording_input_case_source = None;
    state.recording_rejection = None;
    state.recording_apis.clear();
    let apis = artifacts::standard_recording_apis(target_root, state)?;
    inventory::restore_recorded_progress(state, apis, &active_api)?;
    prepare_recording(target_root, state)?;

    let reclassification = reclassify_focused_background_dependencies(
        E2eRunContext {
            target_root: target_root.to_path_buf(),
            case_source,
            run_key: None,
        },
        &active_api,
    )?;
    transition::from_e2e_result(
        target_root,
        state,
        &reclassification.result,
        transition::AttemptTransition::RestoreReclassified,
    )?;
    Ok(true)
}

pub(super) fn restore_stale_dependency_finalize_result(
    target_root: &Path,
    state: &mut RewriteState,
) -> Result<bool> {
    if state.phase != RewritePhase::ImplementationRequired
        || state.active_issue.as_ref().map(|issue| issue.kind)
            != Some(RewriteIssueKind::TargetRuntime)
    {
        return Ok(false);
    }
    let Some(case_source) = state.case_source.clone() else {
        return Ok(false);
    };
    let Some(api) = state.group_id.clone() else {
        return Ok(false);
    };
    let context = E2eRunContext {
        target_root: target_root.to_path_buf(),
        case_source,
        run_key: None,
    };
    if !focused_background_reclassification_recovery_required(context.clone(), &api)? {
        return Ok(false);
    }
    let owner_api = state.api.clone();
    super::background_reclassification::apply(target_root, state, &owner_api)?;
    Ok(true)
}

fn recording_run_id(case_source: &Path) -> Result<String> {
    case_source
        .file_name()
        .and_then(|name| name.to_str())
        .filter(|name| name.len() == 14 && name.bytes().all(|byte| byte.is_ascii_digit()))
        .map(ToOwned::to_owned)
        .context("legacy process-owned-rule case source has no canonical recording run id")
}
