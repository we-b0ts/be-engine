//! A final batch is one real full-round session, never a union of API snapshots.
use std::{
    collections::BTreeSet,
    fs,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, ensure};
use serde::Serialize;
use serde_json::Value;
use uuid::Uuid;

use super::{
    E2eRunContext, config,
    model::{ActiveRunState, CaseStatus, RunStatus},
    store,
};

#[cfg(test)]
mod tests;

#[derive(Debug, Serialize)]
pub(crate) struct ActualBatchEvidence {
    pub session_id: String,
    pub report_path: PathBuf,
    pub report_sha256: String,
    pub source_inventory_id: String,
    pub recording_run_id: String,
    pub recording_run_epoch: Uuid,
    pub process_epochs: BTreeSet<Uuid>,
    pub dependency_attribution_snapshot: String,
    pub replay_identity: String,
    pub selected_case_ids: BTreeSet<String>,
    pub source_revision: String,
}

pub(super) fn validate_executed_identity(root: &Path, state: &ActiveRunState) -> Result<()> {
    let executed = state
        .executed_replay_identity
        .as_deref()
        .context("actual Replay has no frozen execution identity; execute a fresh session")?;
    ensure!(
        !executed.is_empty() && executed == crate::rewrite::batch_execution_identity(root)?,
        "Target code, startup inputs or runtime policy changed during or after the actual Replay"
    );
    Ok(())
}

fn validate_state(state: &ActiveRunState, required: &BTreeSet<String>) -> Result<()> {
    ensure!(
        state.version == super::model::STATE_VERSION,
        "unsupported actual batch state schema"
    );
    ensure!(
        state.case_selection.is_none(),
        "a selected/focused input attempt cannot certify the whole Source batch"
    );
    ensure!(
        state.status == RunStatus::Successful
            && state.finished_at.is_some()
            && state.replay_finalized
            && state.aggregate_complete
            && state.aggregate_clean
            && state.errors.is_empty()
            && !state.target_started
            && state.replay_pid.is_none(),
        "the actual complete-round Replay did not finish cleanly"
    );
    ensure!(
        state.engine_fingerprint.as_deref() == Some(crate::build_info::ENGINE_FINGERPRINT),
        "batch execution belongs to a different engine build"
    );
    let executed: BTreeSet<_> = state
        .cases
        .iter()
        .map(|case| case.case_id.clone())
        .collect();
    ensure!(
        !required.is_empty() && executed == *required && executed.len() == state.cases.len(),
        "one actual batch must execute every Source Case exactly once"
    );
    ensure!(
        state
            .cases
            .iter()
            .all(|case| case.status == CaseStatus::Passed
                && case.assertion_passed == Some(true)
                && case.replay_clean == Some(true)
                && case.execution_failure.is_none()),
        "the actual batch contains unverified input executions"
    );
    ensure!(
        !state.apis.is_empty()
            && state.apis.iter().all(|api| api.complete_pass
                && api.failed == 0
                && api.incomplete == 0
                && api.passed == api.total),
        "the actual batch contains an incomplete API verification"
    );
    Ok(())
}

pub(super) fn verify_actual_session(state: &ActiveRunState) -> Result<()> {
    let report: Value = serde_json::from_slice(&fs::read(&state.replay_report)?)?;
    let receipt =
        crate::protocols::replay::report::validation::validate_completed_receipt(&report)?;
    let actual: BTreeSet<_> = state
        .cases
        .iter()
        .map(|case| case.case_id.clone())
        .collect();
    ensure!(
        actual.len() == state.cases.len()
            && actual == receipt.required_cases
            && actual == receipt.selected_cases,
        "the actual complete-round inputs differ from the session receipt"
    );
    ensure!(
        state.session_id.as_deref() == Some(&receipt.session_id),
        "the actual execution belongs to a different Replay session"
    );
    Ok(())
}

/// Resolve only the latest full round. A stale full round cannot be repaired by
/// selecting newer focused reports, even if their aggregate API statuses pass.
pub(crate) fn completed_batch_evidence(context: E2eRunContext) -> Result<ActualBatchEvidence> {
    let (_, layout) = config::resolve_layout(
        &context.target_root,
        &context.case_source,
        context.run_key.as_deref(),
    )?;
    ensure!(
        !layout.active_dir.exists() && store::focused_active_directories(&layout)?.is_empty(),
        "finish or recover the active Replay attempt before verifying its batch"
    );
    let state_path = layout.latest_dir.join("state.yaml");
    let state: ActiveRunState = store::read_yaml(&state_path)
        .context("no completed full-round execution exists; run one fresh whole-batch Replay")?;
    ensure!(
        state.case_source == layout.case_source && state.run_key == layout.run_key,
        "the latest full-round execution belongs to a different Source selection"
    );
    let inventory = crate::case_group::load_complete_case_group_inventory(
        &layout.group_index_path,
        &layout.case_source,
    )?;
    ensure!(
        state.source_revision == inventory.source_revision
            && state.case_inventory_id == inventory.case_inventory_id,
        "the actual complete-round execution does not match the current canonical Source inventory"
    );
    ensure!(
        state.source_revision
            == crate::source_snapshot::source_image_revision(&layout.target_root)?,
        "the actual batch belongs to a different Source image revision"
    );
    validate_executed_identity(&layout.target_root, &state)?;

    let (root, manifest) = crate::dependency_index::recording::manifest(&layout.case_source)?;
    crate::dependency_index::recording::authenticate(&root)?;
    ensure!(
        manifest.capture_complete && manifest.inputs.iter().all(|input| input.complete),
        "a complete Source recording is required for final batch verification"
    );
    let required: BTreeSet<_> = manifest
        .inputs
        .iter()
        .map(|input| input.case_id.to_string())
        .collect();
    ensure!(
        required.len() == manifest.inputs.len(),
        "Source batch has duplicate input identities"
    );
    validate_state(&state, &required)?;
    let manifest_bytes = fs::read(root.join(crate::dependency::observation::MANIFEST_FILE))?;
    let source_inventory_id = crate::policy_evidence::digest(&manifest_bytes);
    let report_bytes =
        fs::read(&state.replay_report).context("the actual batch Replay report is unavailable")?;
    let report: Value = serde_json::from_slice(&report_bytes)?;
    let receipt =
        crate::protocols::replay::report::validation::validate_completed_receipt(&report)?;
    let session = state
        .session_id
        .as_deref()
        .context("actual batch has no session identity")?;
    ensure!(
        receipt.session_id == session && report["session_id"].as_str() == Some(session),
        "actual execution and dependency reconciliation refer to different sessions"
    );
    ensure!(
        receipt.selected_cases == required && receipt.required_cases == required,
        "the actual session receipt does not cover the whole Source batch"
    );
    ensure!(
        receipt.source_inventory_id == source_inventory_id
            && receipt.recording_run_id == manifest.run_id
            && receipt.recording_run_epoch == manifest.run_epoch,
        "the actual session receipt belongs to a different immutable Source recording"
    );
    let process_epochs: BTreeSet<_> = manifest.process_epochs.iter().copied().collect();
    ensure!(
        process_epochs.len() == manifest.process_epochs.len()
            && receipt
                .process_epochs
                .iter()
                .copied()
                .collect::<BTreeSet<_>>()
                == process_epochs,
        "the actual session receipt belongs to different Source process lifetimes"
    );
    let snapshot = crate::rewrite::dependency_attribution_identity_for_source(
        &layout.target_root,
        &layout.case_source,
        &manifest.run_id,
    )?;
    ensure!(
        receipt.dependency_attribution_snapshot.as_deref() == Some(&snapshot)
            && report["dependency_attribution_snapshot"].as_str() == Some(&snapshot),
        "the actual session did not execute the current frozen dependency owners"
    );
    // Authenticate once more at this cold verification boundary; a concurrent
    // Source replacement cannot yield a receipt for a mixture of manifests.
    ensure!(
        fs::read(root.join(crate::dependency::observation::MANIFEST_FILE))? == manifest_bytes,
        "Source manifest changed during batch verification"
    );
    Ok(ActualBatchEvidence {
        session_id: session.into(),
        report_path: state.replay_report,
        report_sha256: crate::policy_evidence::digest(&report_bytes),
        source_inventory_id,
        recording_run_id: manifest.run_id,
        recording_run_epoch: manifest.run_epoch,
        process_epochs,
        dependency_attribution_snapshot: snapshot,
        replay_identity: state
            .executed_replay_identity
            .context("frozen Replay identity absent")?,
        selected_case_ids: required,
        source_revision: state.source_revision,
    })
}
