use std::path::Path;

use anyhow::Result;

use super::model::RewriteState;
use super::{artifacts, fingerprint};
use crate::{E2eRunContext, E2eRunPrepareOptions, RecordingApi, prepare_e2e_run};

pub(super) fn prepare_recording(target_root: &Path, state: &mut RewriteState) -> Result<()> {
    super::purpose::require_work_branch(target_root)?;
    crate::e2e_run::resolve_project(target_root)?;
    let case_source = artifacts::recording_run(target_root, &state.recording_run_id);
    let api = state.api.parse::<RecordingApi>()?;
    let member = crate::case_group::resolve_recording_api_seed_member(&case_source, &api)?;
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
