//! A dirty actual batch can authorize a repair plan, never a passing receipt.
use super::{
    E2eRunContext, batch_evidence, config,
    model::{ActiveRunState, CaseStatus, STATE_VERSION},
    store,
};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::PathBuf,
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct BatchRuleEvidence {
    pub session_id: String,
    pub sequence: u64,
    pub recording_run_id: String,
    pub source_revision: String,
    pub source_inventory_id: String,
    pub dependency_attribution_snapshot: String,
    pub execution_identity: String,
    pub engine_fingerprint: String,
    pub case_inventory_id: String,
    pub case_source: PathBuf,
    pub report: PathBuf,
    pub report_sha256: String,
    pub assertions: PathBuf,
    pub aggregate: PathBuf,
    pub runner_state: PathBuf,
    pub cases: BTreeMap<String, PathBuf>,
}

/// Require genuine complete execution and current immutable inputs; failure of
/// comparison is deliberately allowed, since that is what a repair addresses.
pub(crate) fn batch_rule_evidence(context: E2eRunContext) -> Result<BatchRuleEvidence> {
    let (_, layout) = config::resolve_layout(
        &context.target_root,
        &context.case_source,
        context.run_key.as_deref(),
    )?;
    ensure!(
        !layout.active_dir.exists() && store::focused_active_directories(&layout)?.is_empty(),
        "finish active Replay before planning a whole-batch rule"
    );
    let runner_state = layout.latest_dir.join("state.yaml");
    let state: ActiveRunState =
        store::read_yaml(&runner_state).context("no actual full-round evidence exists")?;
    ensure!(
        state.version == STATE_VERSION
            && state.case_selection.is_none()
            && state.finished_at.is_some()
            && state.replay_finalized
            && !state.target_started
            && state.replay_pid.is_none(),
        "batch rule evidence requires a finalized actual full-round execution"
    );
    ensure!(
        state.case_source == layout.case_source && state.run_key == layout.run_key,
        "actual batch belongs to a different Source selection"
    );
    ensure!(
        state.engine_fingerprint.as_deref() == Some(crate::build_info::ENGINE_FINGERPRINT),
        "actual batch uses a different engine build"
    );
    batch_evidence::validate_executed_identity(&layout.target_root, &state)?;
    let inventory = crate::case_group::load_complete_case_group_inventory(
        &layout.group_index_path,
        &layout.case_source,
    )?;
    ensure!(
        state.source_revision == inventory.source_revision
            && state.case_inventory_id == inventory.case_inventory_id
            && state.source_revision
                == crate::source_snapshot::source_image_revision(&layout.target_root)?,
        "actual batch prepared Source identity changed"
    );
    let (recording, manifest) = crate::dependency_index::recording::manifest(&layout.case_source)?;
    crate::dependency_index::recording::authenticate(&recording)?;
    ensure!(
        manifest.capture_complete
            && !manifest.coverage.inventory_gaps
            && manifest.inputs.iter().all(|input| input.complete),
        "batch planning requires a sealed complete Source recording"
    );
    let cases = manifest
        .inputs
        .iter()
        .map(|input| (input.case_id.to_string(), recording.join(&input.path)))
        .collect::<BTreeMap<_, _>>();
    let required = cases.keys().cloned().collect::<BTreeSet<_>>();
    let executed = state
        .cases
        .iter()
        .map(|case| case.case_id.clone())
        .collect::<BTreeSet<_>>();
    ensure!(
        !required.is_empty()
            && cases.len() == manifest.inputs.len()
            && executed == required
            && state.cases.len() == required.len()
            && state.cases.iter().all(|case| matches!(
                case.status,
                CaseStatus::Passed | CaseStatus::Failed
            ) && case.assertion_passed.is_some()
                && case.replay_clean.is_some()),
        "batch rule evidence must execute every Source input exactly once; incomplete attempts cannot authorize batch plans"
    );
    ensure!(
        state.replay_report == layout.latest_dir.join("reports/replay-report.json")
            && state.assertions_report == layout.latest_dir.join("reports/assertions.json")
            && state.aggregate_report == layout.latest_dir.join("reports/aggregate.json"),
        "actual batch evidence escaped its published snapshot"
    );
    let report_bytes = fs::read(&state.replay_report)?;
    let report: Value = serde_json::from_slice(&report_bytes)?;
    let session_id = state
        .session_id
        .clone()
        .context("actual batch has no session identity")?;
    let source_inventory_id = crate::policy_evidence::digest(&fs::read(
        recording.join(crate::dependency::observation::MANIFEST_FILE),
    )?);
    let snapshot = crate::rewrite::dependency_attribution_identity_for_source(
        &layout.target_root,
        &layout.case_source,
        &manifest.run_id,
    )?;
    let receipt = &report["batch_reconciliation"];
    let selected: BTreeSet<String> = serde_json::from_value(receipt["selected_cases"].clone())?;
    let recorded: BTreeSet<String> = serde_json::from_value(receipt["required_cases"].clone())?;
    ensure!(
        receipt["schema"] == "dependency-reconciliation/v3"
            && receipt["source_capture_complete"] == true
            && receipt["execution_complete"] == true
            && report["version"] == 7
            && report["finalized"] == true
            && report["session_id"].as_str() == Some(&session_id)
            && receipt["session_id"].as_str() == Some(&session_id)
            && receipt["complete_source_scope"] == true
            && selected == required
            && recorded == required,
        "batch report does not describe this complete actual session"
    );
    ensure!(
        receipt["source_inventory_id"].as_str() == Some(&source_inventory_id)
            && receipt["recording_run_id"].as_str() == Some(&manifest.run_id)
            && receipt["recording_run_epoch"] == serde_json::to_value(manifest.run_epoch)?
            && serde_json::from_value::<BTreeSet<uuid::Uuid>>(receipt["process_epochs"].clone())?
                == manifest.process_epochs.iter().copied().collect()
            && receipt["dependency_attribution_snapshot"].as_str() == Some(&snapshot)
            && report["dependency_attribution_snapshot"].as_str() == Some(&snapshot),
        "actual batch Source or frozen attribution identity changed"
    );
    for artifact in [
        &state.replay_report,
        &state.assertions_report,
        &state.aggregate_report,
        &runner_state,
    ] {
        crate::dependency_index::FileStamp::read_native(artifact)?;
    }
    Ok(BatchRuleEvidence {
        session_id,
        sequence: state.sequence,
        recording_run_id: manifest.run_id,
        source_revision: state.source_revision,
        source_inventory_id,
        dependency_attribution_snapshot: snapshot,
        execution_identity: state
            .executed_replay_identity
            .context("actual execution identity absent")?,
        engine_fingerprint: crate::build_info::ENGINE_FINGERPRINT.into(),
        case_inventory_id: state.case_inventory_id,
        case_source: state.case_source,
        report: state.replay_report,
        report_sha256: crate::policy_evidence::digest(&report_bytes),
        assertions: state.assertions_report,
        aggregate: state.aggregate_report,
        runner_state,
        cases,
    })
}
