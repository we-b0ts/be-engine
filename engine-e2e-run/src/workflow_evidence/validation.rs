//! Validate focused projections against their original, complete actual session.
use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, ensure};
use serde_json::Value;

use super::artifact;
use crate::{
    case_group::{CanonicalCaseGroup, CaseGroupInventory},
    case_selection,
    dependency::observation::{RecordingManifest, SemanticInventory},
    model::{ActiveRunState, AssertionReport, CaseStatus, RunLayout, RunStatus},
};

pub(super) fn complete_source(manifest: &RecordingManifest) -> Result<()> {
    ensure!(
        manifest.sealed
            && crate::dependency_index::recording::supported_recording_schema(&manifest.schema)
            && manifest.capture_complete
            && !manifest.coverage.inventory_gaps
            && manifest.coverage.capture_failures == 0
            && manifest.coverage.pending.is_empty()
            && !manifest.inputs.is_empty()
            && manifest.inputs.iter().all(|input| input.complete),
        "workflow acceptance requires a sealed complete Source recording, including unselected inputs"
    );
    ensure!(
        manifest
            .inputs
            .iter()
            .map(|i| i.case_id)
            .collect::<BTreeSet<_>>()
            .len()
            == manifest.inputs.len(),
        "Source recording repeats input identities"
    );
    ensure!(
        manifest
            .process_epochs
            .iter()
            .collect::<BTreeSet<_>>()
            .len()
            == manifest.process_epochs.len(),
        "Source recording repeats process lifetimes"
    );
    Ok(())
}

pub(super) fn projection(
    state: &ActiveRunState,
    group: &CanonicalCaseGroup,
    inventory: &CaseGroupInventory,
    layout: &RunLayout,
) -> Result<()> {
    ensure!(
        state.version == crate::model::STATE_VERSION
            && state.status == RunStatus::Successful
            && state.finished_at.is_some()
            && state.replay_finalized
            && state.aggregate_complete
            && state.aggregate_clean
            && state.errors.is_empty()
            && !state.target_started
            && state.replay_pid.is_none()
            && state.target_container_name.is_none()
            && state.target_anchor_name.is_none(),
        "workflow method has no clean finished actual execution with stopped Target"
    );
    ensure!(
        state.engine_fingerprint.as_deref() == Some(crate::build_info::ENGINE_FINGERPRINT),
        "workflow method belongs to a different engine build"
    );
    state
        .case_selection
        .as_ref()
        .context("workflow method has no final session selection")?
        .completed_workflow()?;
    ensure!(
        state.case_source == layout.case_source
            && state.run_key == layout.run_key
            && state.source_revision == inventory.source_revision
            && state.case_inventory_id == inventory.case_inventory_id,
        "workflow method has a different canonical Source identity"
    );
    case_selection::validate_group(state, group)?;
    ensure!(
        state.cases.len() == group.cases.len()
            && state.cases.iter().all(|case| {
                case.group_id == group.group_id
                    && case.status == CaseStatus::Passed
                    && case.assertion_passed == Some(true)
                    && case.replay_clean == Some(true)
                    && case.execution_failure.is_none()
                    && group.cases.iter().any(|input| {
                        input.case_id == case.case_id && input.case_dir == case.case_dir
                    })
            }),
        "workflow method did not freshly execute every canonical Case cleanly"
    );
    let api = state
        .apis
        .first()
        .context("workflow method summary absent")?;
    let ids = state
        .cases
        .iter()
        .map(|case| case.case_id.as_str())
        .collect::<BTreeSet<_>>();
    ensure!(
        state.apis.len() == 1
            && api.group_id == group.group_id
            && api.complete_pass
            && api.failed == 0
            && api.incomplete == 0
            && api.passed == api.total
            && api.total as usize == ids.len()
            && api.case_ids.len() == ids.len()
            && api
                .case_ids
                .iter()
                .map(String::as_str)
                .collect::<BTreeSet<_>>()
                == ids,
        "workflow method summary does not cover its actual Case executions"
    );
    Ok(())
}

pub(super) fn one_session(states: &[ActiveRunState]) -> Result<()> {
    let first = states.first().context("workflow session has no methods")?;
    let workflow = first
        .case_selection
        .as_ref()
        .context("workflow selection absent")?
        .completed_workflow()?;
    ensure!(
        first.session_id.as_deref().is_some_and(|id| !id.is_empty())
            && first
                .executed_replay_identity
                .as_deref()
                .is_some_and(|id| !id.is_empty()),
        "workflow session has no actual execution identity"
    );
    for state in states {
        ensure!(
            state.session_id == first.session_id
                && state.sequence == first.sequence
                && state.executed_replay_identity == first.executed_replay_identity
                && state.source_revision == first.source_revision
                && state.case_inventory_id == first.case_inventory_id
                && state.started_at == first.started_at
                && state.finished_at == first.finished_at
                && state
                    .case_selection
                    .as_ref()
                    .context("workflow selection absent")?
                    .completed_workflow()?
                    == workflow,
            "workflow methods are not projections of one actual final session"
        );
    }
    Ok(())
}

fn ids(value: &Value, field: &str) -> Result<BTreeSet<String>> {
    let values = value[field]
        .as_array()
        .with_context(|| format!("workflow report lacks {field}"))?;
    let ids = values
        .iter()
        .map(|value| {
            value
                .as_str()
                .map(ToOwned::to_owned)
                .context("workflow report contains an invalid Case identity")
        })
        .collect::<Result<BTreeSet<_>>>()?;
    ensure!(
        ids.len() == values.len(),
        "workflow report repeats a Case identity"
    );
    Ok(ids)
}

#[allow(clippy::too_many_arguments)]
pub(super) fn session_report(
    report: &Value,
    state: &ActiveRunState,
    selected: &BTreeSet<String>,
    all_inputs: &BTreeSet<String>,
    manifest: &RecordingManifest,
    inventory_id: &str,
    snapshot: &str,
    policy: &str,
) -> Result<()> {
    let receipt = &report["batch_reconciliation"];
    let session = state
        .session_id
        .as_deref()
        .context("workflow session absent")?;
    ensure!(
        report["version"] == 7
            && report["session_id"].as_str() == Some(session)
            && report["finalized"] == true
            && report["complete"] == true
            && report["finalized_at"].is_string()
            && report["active_case_id"].is_null()
            && receipt["schema"] == "dependency-reconciliation/v3"
            && receipt["session_id"].as_str() == Some(session)
            && receipt["execution_complete"] == true
            && receipt["source_capture_complete"] == true,
        "workflow actual session is not finalized and complete"
    );
    let cases = report["cases"]
        .as_array()
        .context("workflow report has no actual Cases")?;
    let executed = cases
        .iter()
        .map(|case| {
            ensure!(
                case["status"] == "ended",
                "workflow report contains an unfinished Case"
            );
            case["case_id"]
                .as_str()
                .map(ToOwned::to_owned)
                .context("workflow Case identity absent")
        })
        .collect::<Result<BTreeSet<_>>>()?;
    ensure!(
        !selected.is_empty()
            && executed.len() == cases.len()
            && executed == *selected
            && ids(report, "selected_case_ids")? == *selected
            && ids(receipt, "selected_cases")? == *selected
            && ids(receipt, "required_cases")? == *all_inputs
            && receipt["complete_source_scope"] == Value::Bool(selected == all_inputs),
        "workflow session does not execute its exact complete method scope"
    );
    ensure!(
        receipt["source_inventory_id"].as_str() == Some(inventory_id)
            && receipt["recording_run_id"].as_str() == Some(&manifest.run_id)
            && receipt["recording_run_epoch"] == serde_json::to_value(manifest.run_epoch)?
            && serde_json::from_value::<Vec<uuid::Uuid>>(receipt["process_epochs"].clone())?
                == manifest.process_epochs
            && receipt["dependency_attribution_snapshot"].as_str() == Some(snapshot)
            && report["dependency_attribution_snapshot"].as_str() == Some(snapshot),
        "workflow session has a different immutable Source or frozen ownership identity"
    );
    let source: SemanticInventory = serde_json::from_value(receipt["source_inventory"].clone())?;
    ensure!(
        source.unattributed_dependencies == 0
            && source
                .unsupported_by_scope
                .iter()
                .filter(|(scope, _)| selected.contains(*scope))
                .all(|(_, protocols)| protocols.values().all(|n| *n == 0))
            && source.by_owner_kind.values().sum::<u64>() == source.total_mandatory,
        "workflow Source contains ownerless or unsupported traffic"
    );
    ensure!(
        report["replay_policy"]["fingerprint"].as_str() == Some(policy)
            && report["replay_policy"]["expected_response"] == "assertions_only",
        "workflow actual session used a different runtime policy"
    );
    ensure!(
        report["dependency_hypothesis_coverage_error"].is_null()
            && report["target_observation_coverage_error"].is_null()
            && report
                .get("dependency_pre_matches")
                .is_none_or(|value| value.as_array().is_some_and(Vec::is_empty))
            && receipt["provisional_hypotheses_used"] == false,
        "workflow depends on provisional or incomplete Target observations"
    );
    if let Some(journal) = report
        .get("dependency_hypothesis_journal")
        .filter(|v| v.is_object())
    {
        ensure!(
            journal["complete"] == true
                && journal["error"].is_null()
                && journal["enqueued"].as_u64().is_some()
                && journal["enqueued"] == journal["durable"],
            "workflow hypothesis journal is incomplete"
        );
    }
    if let Some(witnesses) = report.get("policy_witnesses").filter(|v| v.is_object()) {
        ensure!(
            witnesses["complete"] == true && witnesses["omitted"] == 0,
            "workflow protected Target evidence is incomplete"
        );
    }
    // Startup and process consumption deliberately remain WholeSource obligations.
    Ok(())
}

pub(super) fn response_and_stop(
    state: &ActiveRunState,
    latest: &Path,
    policy: &str,
    hashes: &mut BTreeMap<PathBuf, String>,
) -> Result<()> {
    ensure!(
        state.assertions_report.starts_with(latest) && state.aggregate_report.starts_with(latest),
        "workflow response evidence escaped its published snapshot"
    );
    let assertions: AssertionReport =
        serde_json::from_slice(&artifact(&state.assertions_report, hashes)?)?;
    let expected: BTreeSet<_> = state
        .cases
        .iter()
        .map(|case| case.case_id.as_str())
        .collect();
    ensure!(
        assertions.version == crate::model::ASSERTION_REPORT_VERSION
            && assertions.assertion_mode == "runner_owned"
            && assertions.expected_response == "assertions_only"
            && assertions.source_revision == state.source_revision
            && assertions.case_source == state.case_source.to_string_lossy()
            && assertions.case_inventory_id == state.case_inventory_id
            && assertions.policy_fingerprint.as_deref() == Some(policy)
            && assertions.cases.len() == expected.len()
            && assertions
                .cases
                .iter()
                .map(|case| case.case_id.as_str())
                .collect::<BTreeSet<_>>()
                == expected
            && assertions.cases.iter().all(|case| case.passed),
        "workflow runner response assertions do not cover all actual inputs"
    );
    for case in &state.cases {
        let summary = case
            .response_assertion
            .as_ref()
            .context("workflow response detail absent")?;
        let projected = assertions
            .cases
            .iter()
            .find(|item| item.case_id == case.case_id)
            .and_then(|item| item.response.as_ref())
            .context("workflow assertion detail absent")?;
        ensure!(
            serde_json::to_value(projected)? == serde_json::to_value(summary)?
                && summary.passed
                && summary.difference_count == 0
                && summary.policy_fingerprint == policy
                && summary.detail_report.starts_with(latest)
                && summary.actual_response.starts_with(latest)
                && summary.request == case.case_dir.join("request.json")
                && summary.expected_response == crate::source_response::path(&case.case_dir),
            "workflow response detail differs from its runner projection"
        );
        let detail_bytes = artifact(&summary.detail_report, hashes)?;
        ensure!(
            crate::verification_progress::fingerprint(&detail_bytes) == summary.detail_fingerprint,
            "workflow response assertion detail changed"
        );
        let detail: Value = serde_json::from_slice(&detail_bytes)?;
        let actual = artifact(&summary.actual_response, hashes)?;
        let expected_response = artifact(&summary.expected_response, hashes)?;
        artifact(&summary.request, hashes)?;
        ensure!(
            detail["passed"] == true
                && detail["case_id"].as_str() == Some(&case.case_id)
                && detail["differences"].as_array().is_some_and(Vec::is_empty)
                && detail["policy_fingerprint"].as_str() == Some(policy)
                && detail["request_path"].as_str() == summary.request.to_str()
                && detail["expected_response_path"].as_str() == summary.expected_response.to_str()
                && detail["expected_response_fingerprint"].as_str()
                    == Some(&crate::verification_progress::fingerprint(
                        &expected_response
                    ))
                && detail["actual_response_path"].as_str() == summary.actual_response.to_str()
                && detail["actual_response_fingerprint"].as_str()
                    == Some(&crate::verification_progress::fingerprint(&actual)),
            "workflow primary response was not independently verified"
        );
    }
    let aggregate: Value = serde_json::from_slice(&artifact(&state.aggregate_report, hashes)?)?;
    ensure!(
        aggregate["complete"] == true
            && aggregate["dirty"] == false
            && ids(&aggregate, "selected_case_ids")?
                == expected.into_iter().map(ToOwned::to_owned).collect()
            && aggregate["selected_session_ids"] == serde_json::json!([state.session_id]),
        "workflow method aggregate is not a clean projection of the actual session"
    );
    let stop: Value =
        serde_json::from_slice(&artifact(&latest.join("reports/target-stop.json"), hashes)?)?;
    ensure!(
        stop["status"] == "stopped"
            && stop["exit_code"] == 0
            && stop["removed"] == true
            && stop["container_name"]
                .as_str()
                .is_some_and(|name| !name.is_empty()),
        "workflow Target has no genuine clean stop evidence"
    );
    Ok(())
}
