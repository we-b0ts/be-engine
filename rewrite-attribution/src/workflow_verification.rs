//! One actual final session pays the current workflow's API contracts only.
use super::{
    model::{
        BatchAcceptanceReceipt, ClaimStatus, WorkflowAcceptanceReceipt, WorkflowArtifactIdentity,
        WorkflowCompletionScope,
    },
    rules, source,
};
use anyhow::{Context, Result, ensure};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::Path,
};
use traffic_rewrite_model::rewrite::{
    model::{RewriteApiStatus, RewriteState},
    verification_obligations::{self, VerificationScope},
};

pub fn methods(state: &RewriteState) -> BTreeSet<String> {
    state
        .api_inventory
        .iter()
        .filter(|item| item.status != RewriteApiStatus::Skipped)
        .map(|item| item.api.clone())
        .collect()
}

/// Recapture can replace the current inventory while retaining method requirements.
pub fn required_scope_methods(_root: &Path, state: &RewriteState) -> Result<BTreeSet<String>> {
    Ok(state
        .dependency_review
        .required_method_apis
        .iter()
        .cloned()
        .chain(state.api_inventory.iter().map(|item| item.api.clone()))
        .filter(|method| !traffic_rewrite_model::rewrite::inventory::is_skipped(state, method))
        .collect())
}

fn scope_selected(scope: &VerificationScope, methods: &BTreeSet<String>) -> bool {
    methods
        .iter()
        .any(|api| verification_obligations::scope_matches_api(scope, api))
}

fn ownership_pending(state: &RewriteState, methods: &BTreeSet<String>) -> bool {
    state.case_source.is_none()
        || state.dependency_review.recording_run_id.as_deref() != Some(&state.recording_run_id)
        || !state
            .dependency_review
            .unresolved_source_exchange_ids
            .is_empty()
        || state.dependency_review.claims.values().any(|claim| {
            claim.recording_run_id == state.recording_run_id
                && matches!(claim.status, ClaimStatus::Pending | ClaimStatus::Unresolved)
        })
        || state
            .dependency_review
            .investigations
            .values()
            .any(|request| {
                request.recording_run_id == state.recording_run_id
                    && methods.contains(&request.method_api)
                    && matches!(
                        request.status,
                        ClaimStatus::Pending | ClaimStatus::Unresolved
                    )
            })
}

fn apis_complete(state: &RewriteState) -> bool {
    state.api_inventory.iter().all(|item| {
        item.status == RewriteApiStatus::Skipped
            || item.status == RewriteApiStatus::Complete && item.e2e_current
    })
}

pub fn pending(state: &RewriteState) -> bool {
    let methods = methods(state);
    methods.is_empty()
        || !apis_complete(state)
        || state.dependency_review.workflow_receipt.is_none()
        || ownership_pending(state, &methods)
        || state
            .dependency_review
            .obligations
            .values()
            .any(|obligation| obligation.pending() && scope_selected(&obligation.scope, &methods))
}

pub fn current(
    root: &Path,
    state: &RewriteState,
    read: super::snapshot::SnapshotReader,
) -> Result<bool> {
    let Some(receipt) = &state.dependency_review.workflow_receipt else {
        return Ok(false);
    };
    let Some(review) = &state.pre_revalidation_review else {
        return Ok(false);
    };
    let actual = &receipt.actual;
    let methods = methods(state);
    if methods.is_empty()
        || required_scope_methods(root, state)? != methods
        || !apis_complete(state)
        || receipt.completion_scope != WorkflowCompletionScope::WorkflowContracts
        || receipt.workflow_id != state.workflow_id
        || receipt.review_context != review.context
        || receipt.review_receipt_identity != review.receipt_identity
        || actual.covered_method_apis != methods
        || actual.selected_case_ids.is_empty()
        || actual.session_id.is_empty()
        || actual.report_sha256.is_empty()
        || actual.engine_fingerprint != traffic_engine::build_info::ENGINE_FINGERPRINT
        || actual.recording_run_id != state.recording_run_id
        || Some(actual.source_revision.as_str()) != state.source_revision.as_deref()
        || state.case_source.is_none()
        || actual.source_inventory_id != source::inventory_identity(state)?
        || actual.replay_identity != traffic_engine::execution_identity::replay_identity(root)?
        || actual.attribution_snapshot
            != super::snapshot::identity(read, root, &state.recording_run_id)?
        || receipt.policy_fingerprint != rules::load(root)?.fingerprints.full
        || traffic_engine::dependency_index::FileStamp::read_native(&actual.report_path)
            .ok()
            .as_ref()
            != Some(&actual.report_stamp)
    {
        return Ok(false);
    }
    if !matches!(
        traffic_rewrite_runtime::traffic_operation::state(root)?,
        traffic_rewrite_runtime::traffic_operation::TrafficOperationState::Absent
    ) {
        return Ok(false);
    }
    if receipt.projections.is_empty()
        || receipt.projections.iter().any(|(path, identity)| {
            identity.sha256.is_empty()
                || traffic_engine::dependency_index::FileStamp::read_native(path)
                    .ok()
                    .as_ref()
                    != Some(&identity.stamp)
        })
    {
        return Ok(false);
    }
    Ok(true)
}

pub fn accept(
    root: &Path,
    state: &mut RewriteState,
    read: super::snapshot::SnapshotReader,
    completion_current: fn(&Path, &RewriteState) -> bool,
) -> Result<Vec<String>> {
    let methods = methods(state);
    ensure!(
        required_scope_methods(root, state)? == methods,
        "current recording inventory omits selected required workflow methods; restore their complete Source inputs or explicitly adjust only/skip"
    );
    ensure!(
        !methods.is_empty(),
        "workflow final verification requires a nonempty API method scope"
    );
    ensure!(
        !ownership_pending(state, &methods),
        "workflow ownership or owned-request investigation remains unresolved"
    );
    ensure!(
        completion_current(root, state),
        "workflow completion requires the final admitted candidate's complete actual revalidation"
    );
    let evidence = traffic_engine::e2e_run::completed_workflow_evidence(
        traffic_engine::E2eRunContext {
            target_root: root.into(),
            case_source: state.case_source.clone().context("Source absent")?,
            run_key: None,
        },
        &methods,
    )?;
    ensure!(
        evidence.workflow_id == state.workflow_id
            && evidence.method_apis == methods
            && evidence.recording_run_id == state.recording_run_id
            && Some(evidence.source_revision.as_str()) == state.source_revision.as_deref()
            && evidence.engine_fingerprint == traffic_engine::build_info::ENGINE_FINGERPRINT
            && evidence.source_inventory_id == source::inventory_identity(state)?
            && evidence.replay_identity
                == traffic_engine::execution_identity::replay_identity(root)?
            && evidence.dependency_attribution_snapshot
                == super::snapshot::identity(read, root, &state.recording_run_id)?,
        "workflow actual evidence belongs to different inputs, methods or execution"
    );
    let source = source::load(state)?;
    let mut completed = Vec::new();
    for (id, obligation) in &state.dependency_review.obligations {
        if obligation.pending() && scope_selected(&obligation.scope, &methods) {
            super::batch_verification::validate_api_scope(
                root,
                state,
                &source,
                &evidence.selected_case_ids,
                &evidence.recording_run_id,
                obligation,
            )?;
            completed.push(id.clone());
        }
    }
    let review = state
        .pre_revalidation_review
        .as_ref()
        .context("final candidate review absent")?;
    let stamp = traffic_engine::dependency_index::FileStamp::read_native(&evidence.report_path)?;
    ensure!(
        source::digest(&fs::read(&evidence.report_path)?) == evidence.report_sha256
            && traffic_engine::dependency_index::FileStamp::read_native(&evidence.report_path)?
                == stamp,
        "workflow actual report changed during acceptance"
    );
    let receipt = WorkflowAcceptanceReceipt {
        completion_scope: WorkflowCompletionScope::WorkflowContracts,
        workflow_id: state.workflow_id.clone(),
        policy_fingerprint: rules::load(root)?.fingerprints.full,
        review_context: review.context.clone(),
        review_receipt_identity: review.receipt_identity.clone(),
        projections: evidence
            .projection_sha256
            .into_iter()
            .map(|(path, sha256)| {
                let stamp = traffic_engine::dependency_index::FileStamp::read_native(&path)?;
                ensure!(
                    source::digest(&fs::read(&path)?) == sha256
                        && traffic_engine::dependency_index::FileStamp::read_native(&path)?
                            == stamp,
                    "workflow method projection changed during acceptance"
                );
                Ok((path, WorkflowArtifactIdentity { sha256, stamp }))
            })
            .collect::<Result<BTreeMap<_, _>>>()?,
        actual: BatchAcceptanceReceipt {
            engine_fingerprint: evidence.engine_fingerprint,
            recording_run_id: evidence.recording_run_id,
            source_revision: evidence.source_revision,
            source_inventory_id: evidence.source_inventory_id,
            replay_identity: evidence.replay_identity,
            attribution_snapshot: evidence.dependency_attribution_snapshot,
            session_id: evidence.session_id.clone(),
            report_path: evidence.report_path,
            report_sha256: evidence.report_sha256,
            report_stamp: stamp,
            selected_case_ids: evidence.selected_case_ids,
            covered_method_apis: methods,
        },
    };
    for id in &completed {
        state
            .dependency_review
            .obligations
            .get_mut(id)
            .expect("validated workflow API obligation")
            .completed_by_session = Some(evidence.session_id.clone());
    }
    state.dependency_review.workflow_receipt = Some(receipt);
    state.dependency_review.workflow_failure = None;
    state.dependency_review.revision += 1;
    Ok(completed)
}
