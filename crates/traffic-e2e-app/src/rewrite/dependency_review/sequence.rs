//! Missing strict predecessors open one ownership question on finalized evidence.
use super::{
    model::{ClaimStatus, ForeignUnusedClaim},
    source, verification,
};
use crate::rewrite::{inventory, model::RewriteState};
use anyhow::{Context, Result};
use std::{collections::BTreeSet, path::Path};

pub(in crate::rewrite) fn register(
    root: &Path,
    state: &mut RewriteState,
    results: &[crate::E2eApiRunResult],
) -> Result<()> {
    for result in results
        .iter()
        .filter(|result| !result.passed && result.gates.replay == crate::E2eReplayGate::Complete)
    {
        let selected = inventory::scoped(state, Some(&result.api.parse()?))?;
        let context = crate::E2eRunContext {
            target_root: root.into(),
            case_source: selected
                .case_source
                .clone()
                .context("sequence review Source absent")?,
            run_key: None,
        };
        let evidence = crate::e2e_run::resolve_e2e_response_rule_evidence(
            context,
            selected
                .group_id
                .as_deref()
                .context("sequence review API group absent")?,
        )?;
        let report: serde_json::Value = serde_json::from_slice(&std::fs::read(evidence.replay)?)?;
        if report["dependency_sequence_missing"]
            .as_array()
            .is_none_or(Vec::is_empty)
        {
            continue;
        }
        let source = source::load(&selected)?;
        let actual = verification::claim_actual(root, &selected, &source)?;
        let missing = actual.missing_sequences(&source);
        let source_revision = selected
            .source_revision
            .as_deref()
            .context("sequence review Source revision absent")?;
        for exchange in missing {
            let ids = BTreeSet::from([exchange]);
            // A proved or rejected answer remains valid for this Source and
            // API. Another Target retry cannot repeatedly dispatch the analyst.
            if state.dependency_review.claims.values().any(|claim| {
                claim.method_api == result.api
                    && claim.recording_run_id == state.recording_run_id
                    && claim.source_revision == source_revision
                    && claim.source_inventory_id == source.identity
                    && claim.source_exchange_ids == ids
            }) {
                continue;
            }
            let reason = "The next recorded dependency request did not arrive within the bounded sequence wait. Review its Source ownership before classifying the missing request as a Target implementation defect.".to_owned();
            let id = source::digest(&serde_json::to_vec(&(
                "missing-sequence-ownership/v1",
                &state.workflow_id,
                &result.api,
                &state.recording_run_id,
                &source.identity,
                source_revision,
                exchange,
            ))?);
            state.dependency_review.claims.insert(
                id.clone(),
                ForeignUnusedClaim {
                    id,
                    api: crate::rewrite::api_selector::public_api(&result.api).into(),
                    method_api: result.api.clone(),
                    recording_run_id: state.recording_run_id.clone(),
                    source_revision: source_revision.into(),
                    source_inventory_id: source.identity.clone(),
                    attempt: actual.attempt,
                    execution_identity: actual.execution_identity.clone(),
                    report_sha256: actual.report_sha256.clone(),
                    source_exchange_ids: ids,
                    exclusion: None,
                    reason,
                    status: ClaimStatus::Pending,
                    rejection: None,
                },
            );
            state.dependency_review.revision += 1;
            state.bump();
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn failed_result(executed: usize) -> crate::E2eApiRunResult {
        serde_json::from_value(serde_json::json!({
            "run_key":"runtime-failure", "api":"GET /api/health", "attempt":1,
            "status":"interrupted", "passed":false,
            "gates":{"responses":"incomplete", "replay":"incomplete", "dependencies":"unknown"},
            "diagnosis":{
                "counts":{"selected":20, "executed":executed, "response_passed":0,
                    "response_nonpassing":0, "response_incomplete":20},
                "response_differences":{"total_differences":0, "indexed_differences":0,
                    "omitted_differences":0, "failure_clusters":[], "omitted_failure_clusters":0},
                "representative":null
            },
            "progress":".traffic-e2e/progress.yaml"
        }))
        .unwrap()
    }

    #[test]
    fn unfinalized_runtime_failures_keep_their_original_recovery_path() {
        let root = tempfile::tempdir().unwrap();
        let mut state = crate::rewrite::test_state();
        state.case_source = None;
        state.group_id = None;
        for executed in [0, 1] {
            register(root.path(), &mut state, &[failed_result(executed)]).unwrap();
        }
        assert!(state.dependency_review.claims.is_empty());
        assert_eq!(state.dependency_review.revision, 0);
    }

    #[test]
    fn finalized_failures_still_require_authenticated_source_evidence() {
        let root = tempfile::tempdir().unwrap();
        let mut state = crate::rewrite::test_state();
        state.case_source = None;
        let mut result = failed_result(20);
        result.gates.replay = crate::E2eReplayGate::Complete;
        assert!(register(root.path(), &mut state, &[result]).is_err());
        assert!(state.dependency_review.claims.is_empty());
    }
}
