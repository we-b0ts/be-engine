//! Certify one actual workflow session without claiming whole-Source consumption.
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, ensure};
use serde::Serialize;
use serde_json::Value;
use uuid::Uuid;

use super::{E2eRunContext, batch_evidence, model::ActiveRunState, run_config, store, support};
use crate::dependency_index::FileStamp;

#[cfg(test)]
mod tests;
mod validation;

#[derive(Debug, Serialize)]
pub struct WorkflowBatchEvidence {
    pub workflow_id: String,
    pub session_id: String,
    pub sequence: u64,
    pub report_path: PathBuf,
    pub report_sha256: String,
    pub source_inventory_id: String,
    pub recording_run_id: String,
    pub recording_run_epoch: Uuid,
    pub process_epochs: BTreeSet<Uuid>,
    pub dependency_attribution_snapshot: String,
    pub replay_identity: String,
    pub engine_fingerprint: String,
    pub selected_case_ids: BTreeSet<String>,
    pub method_apis: BTreeSet<String>,
    pub source_revision: String,
    pub projection_sha256: BTreeMap<PathBuf, String>,
}

/// Read with a stable native-file identity at this cold acceptance boundary.
fn artifact(path: &Path, hashes: &mut BTreeMap<PathBuf, String>) -> Result<Vec<u8>> {
    let before = FileStamp::read_native(path)?;
    let bytes = fs::read(path)?;
    ensure!(
        before == FileStamp::read_native(path)?,
        "workflow artifact changed while being verified: {}",
        path.display()
    );
    let digest = crate::policy_evidence::digest(&bytes);
    if let Some(previous) = hashes.insert(path.to_owned(), digest.clone()) {
        ensure!(
            previous == digest,
            "workflow artifact changed during verification"
        );
    }
    Ok(bytes)
}

/// Only projections from the same fresh `run_e2e_apis` final session may pay
/// workflow contracts. Historical passing methods cannot be combined here.
pub fn completed_workflow_evidence(
    context: E2eRunContext,
    methods: &BTreeSet<String>,
) -> Result<WorkflowBatchEvidence> {
    ensure!(!methods.is_empty(), "workflow has no executable methods");
    let (config, layout) = run_config::resolve_layout(
        &context.target_root,
        &context.case_source,
        context.run_key.as_deref(),
    )?;
    ensure!(
        !layout.active_dir.exists() && store::focused_active_directories(&layout)?.is_empty(),
        "finish active Replay before certifying workflow contracts"
    );
    let inventory = crate::case_group::load_case_group_inventory(
        &layout.group_index_path,
        &layout.case_source,
    )?;
    ensure!(
        inventory.source_revision
            == crate::source_snapshot::source_image_revision(&layout.target_root)?,
        "workflow belongs to a different Source image revision"
    );
    let (recording, manifest) = crate::dependency_index::recording::manifest(&layout.case_source)?;
    crate::dependency_index::recording::authenticate(&recording)?;
    validation::complete_source(&manifest)?;
    let all_inputs: BTreeSet<_> = manifest
        .inputs
        .iter()
        .map(|i| i.case_id.to_string())
        .collect();
    let selectors = methods
        .iter()
        .map(|method| method.parse::<crate::RecordingApi>())
        .collect::<Result<Vec<_>>>()?;
    let required: BTreeSet<_> =
        crate::case_group::resolve_recording_api_case_ids(&layout.case_source, &selectors)?
            .into_iter()
            .collect();
    ensure!(
        required.is_subset(&all_inputs),
        "workflow Cases are absent from the sealed manifest"
    );
    let manifest_path = recording.join(crate::dependency::observation::MANIFEST_FILE);
    let manifest_bytes = fs::read(&manifest_path)?;
    let source_inventory_id = crate::policy_evidence::digest(&manifest_bytes);
    let snapshot = crate::coordination::dependency_attribution_identity_for_source(
        &layout.target_root,
        &layout.case_source,
        &manifest.run_id,
    )?;
    let policy = crate::policy::runtime::validate_replay_policy(&config.replay_policy)?;
    let mut projection_sha256 = BTreeMap::new();
    let mut states = Vec::new();
    let mut selected_case_ids = BTreeSet::new();
    let mut common_report = None::<Vec<u8>>;
    for method in methods {
        let group = inventory
            .groups
            .iter()
            .find(|group| &group.group_id == method)
            .with_context(|| format!("workflow method {method:?} has no canonical Source group"))?;
        let latest = layout
            .run_root
            .join("focused")
            .join(support::api_directory(method))
            .join("latest");
        let state: ActiveRunState = serde_yaml::from_slice(&artifact(
            &latest.join("state.yaml"),
            &mut projection_sha256,
        )?)
        .with_context(|| format!("no actual final evidence for workflow method {method:?}"))?;
        validation::projection(&state, group, &inventory, &layout)?;
        batch_evidence::validate_executed_identity(&layout.target_root, &state)?;
        ensure!(
            state.replay_report == latest.join("reports/replay-report.json"),
            "workflow report escaped its focused published snapshot"
        );
        let bytes = artifact(&state.replay_report, &mut projection_sha256)?;
        if let Some(common) = &common_report {
            ensure!(
                *common == bytes,
                "workflow methods do not reference the same actual session report"
            );
        } else {
            common_report = Some(bytes);
        }
        validation::response_and_stop(
            &state,
            &latest,
            &policy.fingerprint,
            &mut projection_sha256,
        )?;
        ensure!(
            state
                .cases
                .iter()
                .all(|case| selected_case_ids.insert(case.case_id.clone())),
            "workflow method projections overlap input identities"
        );
        states.push(state);
    }
    ensure!(
        selected_case_ids == required,
        "workflow method projections omit Cases from the complete Source method scope"
    );
    validation::one_session(&states)?;
    let state = &states[0];
    let report_bytes = common_report.context("workflow report absent")?;
    let report: Value = serde_json::from_slice(&report_bytes)?;
    validation::session_report(
        &report,
        state,
        &selected_case_ids,
        &all_inputs,
        &manifest,
        &source_inventory_id,
        &snapshot,
        &policy.fingerprint,
    )?;
    let aggregate = crate::protocols::replay::report::aggregate::aggregate_runner_replay_report(
        &layout.case_source,
        &state.replay_report,
        state
            .replay_report
            .parent()
            .context("workflow report parent absent")?,
        &crate::protocols::replay::report::aggregate::ReplayAggregateOptions {
            case_ids: selected_case_ids.clone(),
            session_ids: BTreeSet::from([state
                .session_id
                .clone()
                .context("workflow session absent")?]),
        },
    )?;
    ensure!(
        aggregate.is_complete() && !aggregate.is_dirty(),
        "actual workflow session has incomplete or dirty API contracts"
    );
    if let Some(witnesses) = report.get("policy_witnesses") {
        let witnesses: crate::policy_evidence::WitnessManifest =
            serde_json::from_value(witnesses.clone())?;
        for path in witnesses.artifact_paths(&state.replay_report)? {
            artifact(&path, &mut projection_sha256)?;
        }
    }
    ensure!(
        fs::read(manifest_path)? == manifest_bytes,
        "Source manifest changed during workflow verification"
    );
    for (path, digest) in &projection_sha256 {
        ensure!(
            crate::policy_evidence::digest(&fs::read(path)?) == *digest,
            "workflow artifact changed during certification"
        );
    }
    Ok(WorkflowBatchEvidence {
        workflow_id: state
            .case_selection
            .as_ref()
            .context("workflow selection absent")?
            .completed_workflow()?
            .into(),
        session_id: state
            .session_id
            .clone()
            .context("workflow session absent")?,
        sequence: state.sequence,
        report_path: state.replay_report.clone(),
        report_sha256: crate::policy_evidence::digest(&report_bytes),
        source_inventory_id,
        recording_run_id: manifest.run_id,
        recording_run_epoch: manifest.run_epoch,
        process_epochs: manifest.process_epochs.into_iter().collect(),
        dependency_attribution_snapshot: snapshot,
        replay_identity: state
            .executed_replay_identity
            .clone()
            .context("workflow execution identity absent")?,
        engine_fingerprint: crate::build_info::ENGINE_FINGERPRINT.into(),
        selected_case_ids,
        method_apis: methods.clone(),
        source_revision: state.source_revision.clone(),
        projection_sha256,
    })
}
