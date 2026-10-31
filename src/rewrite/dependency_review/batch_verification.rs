//! A single actual complete-round receipt closes run-owned obligations.
use super::{
    model::{BatchAcceptanceReceipt, ClaimStatus},
    rules, source,
};
use crate::{
    dependency::attribution::DependencyOwner,
    rewrite::{
        model::RewriteState,
        verification_obligations::{ScopeObligation, VerificationRequirement, VerificationScope},
    },
};
use anyhow::{Context, Result, ensure};
use std::{collections::BTreeSet, path::Path};

pub(super) fn required_methods(state: &RewriteState) -> BTreeSet<String> {
    state
        .dependency_review
        .required_method_apis
        .iter()
        .cloned()
        .chain(state.api_inventory.iter().map(|item| item.api.clone()))
        .filter(|api| !crate::rewrite::regression_scope::is_skipped(state, api))
        .collect()
}

pub(super) fn covers_method(source: &source::SourceSnapshot, method_api: &str) -> Result<bool> {
    let Some((method, pattern)) = method_api.split_once(' ') else {
        return Ok(false);
    };
    if source.apis.values().any(|api| api == method_api) {
        return Ok(true);
    }
    for (id, api) in &source.apis {
        if !api
            .split_once(' ')
            .is_some_and(|(actual, _)| actual == method)
        {
            continue;
        }
        let directory = source
            .inputs
            .get(id)
            .context("Source input directory absent")?;
        let request: serde_json::Value =
            serde_json::from_slice(&source.read_input(&directory.join("request.json"))?)?;
        if request["uri"]
            .as_str()
            .and_then(|uri| uri.parse::<hyper::Uri>().ok())
            .is_some_and(|uri| crate::path_pattern::matches_path_pattern(pattern, uri.path()))
        {
            return Ok(true);
        }
    }
    Ok(false)
}

pub(in crate::rewrite) fn current(root: &Path, state: &RewriteState) -> Result<bool> {
    let Some(receipt) = &state.dependency_review.batch_receipt else {
        return Ok(false);
    };
    if receipt.engine_fingerprint != crate::build_info::ENGINE_FINGERPRINT
        || receipt.recording_run_id != state.recording_run_id
        || Some(receipt.source_revision.as_str()) != state.source_revision.as_deref()
        || state.case_source.is_none()
        || receipt.source_inventory_id != source::inventory_identity(state)?
        || receipt.replay_identity != crate::rewrite::fingerprint::replay_identity(root)?
        || receipt.attribution_snapshot
            != crate::rewrite::dependency_attribution_snapshot(root, &state.recording_run_id)?
        || crate::dependency_index::FileStamp::read_native(&receipt.report_path)
            .ok()
            .as_ref()
            != Some(&receipt.report_stamp)
    {
        return Ok(false);
    }
    Ok(required_methods(state).is_subset(&receipt.covered_method_apis))
}

fn validate_scope(
    root: &Path,
    state: &RewriteState,
    source: &source::SourceSnapshot,
    evidence: &crate::e2e_run::ActualBatchEvidence,
    obligation: &ScopeObligation,
) -> Result<()> {
    ensure!(
        Some(obligation.source_revision.as_str()) == state.source_revision.as_deref(),
        "origin proof belongs to another Source image revision"
    );
    if obligation.requirement == VerificationRequirement::Capture {
        ensure!(
            evidence.recording_run_id != obligation.baseline_recording_run_id,
            "capture obligation requires genuinely new Source evidence for its origin"
        );
    }
    let active = rules::fingerprints(&rules::load(root)?)?;
    let has_owner = source.exchanges.iter().any(|(id, event)| {
        if !event.capture.semantic_required || !event.complete {
            return false;
        }
        let owner = state
            .dependency_review
            .decisions
            .get(id)
            .filter(|decision| rules::current(decision, &active))
            .map(|decision| &decision.owner)
            .unwrap_or(&event.capture.attribution);
        match (&obligation.scope, owner) {
            (
                VerificationScope::Process {
                    source_task,
                    process_epoch,
                },
                DependencyOwner::Process {
                    source_task: actual,
                    process_epoch: epoch,
                    ..
                },
            ) => {
                actual == source_task
                    && evidence.process_epochs.contains(epoch)
                    && (obligation.requirement == VerificationRequirement::Capture
                        || epoch == process_epoch)
            }
            (
                VerificationScope::Startup {
                    initialization_unit,
                    process_epoch,
                },
                DependencyOwner::Startup {
                    initialization_unit: actual,
                    process_epoch: epoch,
                },
            ) => {
                actual == initialization_unit
                    && evidence.process_epochs.contains(epoch)
                    && (obligation.requirement == VerificationRequirement::Capture
                        || epoch == process_epoch)
            }
            _ => false,
        }
    });
    if let VerificationScope::Api {
        api,
        method,
        scenario,
    } = &obligation.scope
    {
        let method = method
            .as_ref()
            .context("origin obligation requires a concrete method contract")?;
        let method_api = format!("{method} {api}");
        let selected = source
            .apis
            .iter()
            .filter(|(_, actual)| **actual == method_api)
            .map(|(id, _)| *id)
            .collect::<BTreeSet<_>>();
        ensure!(
            !selected.is_empty()
                && selected
                    .iter()
                    .all(|id| evidence.selected_case_ids.contains(&id.to_string())),
            "actual full batch omits the required origin method inputs"
        );
        if let Some(index) = scenario {
            let policy = rules::load(root)?;
            let rule = policy
                .async_api
                .get(&method_api)
                .and_then(|rules| rules.get(*index))
                .context("origin async scenario is no longer effective; obtain new Source proof")?;
            let mut matched = false;
            for id in selected {
                let directory = source.inputs.get(&id).context("origin input absent")?;
                let request: serde_json::Value =
                    serde_json::from_slice(&source.read_input(&directory.join("request.json"))?)?;
                let response: serde_json::Value = serde_json::from_slice(
                    &source.read_input(&directory.join("expected-response.json"))?,
                )?;
                matched |= crate::policy::async_api_matches(
                    &method_api,
                    rule,
                    method,
                    request["uri"].as_str().context("origin URI absent")?,
                    crate::replay::native_source_request_body(&request).as_ref(),
                ) && crate::policy::async_response_matches(
                    rule,
                    crate::replay::native_source_request_body(&response).as_ref(),
                );
            }
            ensure!(
                matched,
                "current Source has no input selecting the required original async scenario"
            );
        }
    } else {
        ensure!(
            has_owner,
            "the actual effective Source scope contains no complete occurrence of this process task or initialization unit"
        );
    }
    Ok(())
}

pub(super) fn verify(root: &Path, state: &mut RewriteState, id: &str) -> Result<String> {
    let context = crate::E2eRunContext {
        target_root: root.into(),
        case_source: state.case_source.clone().context("Source absent")?,
        run_key: None,
    };
    let evidence = crate::e2e_run::completed_batch_evidence(context)?;
    let source = source::load(state)?;
    ensure!(
        source.identity == evidence.source_inventory_id,
        "batch evidence Source inventory changed"
    );
    let obligation = state
        .dependency_review
        .obligations
        .get(id)
        .context("verification obligation absent")?;
    ensure!(
        obligation.pending(),
        "verification obligation is already completed or retired"
    );
    validate_scope(root, state, &source, &evidence, obligation)?;
    state
        .dependency_review
        .obligations
        .get_mut(id)
        .expect("validated obligation")
        .completed_by_session = Some(evidence.session_id.clone());
    Ok(evidence.session_id)
}

pub(super) fn accept(root: &Path, state: &mut RewriteState) -> Result<Vec<String>> {
    let evidence = crate::e2e_run::completed_batch_evidence(crate::E2eRunContext {
        target_root: root.into(),
        case_source: state.case_source.clone().context("Source absent")?,
        run_key: None,
    })?;
    let source = source::load(state)?;
    ensure!(
        source.identity == evidence.source_inventory_id,
        "batch evidence Source inventory changed"
    );
    let methods = required_methods(state);
    for method in &methods {
        ensure!(
            covers_method(&source, method)?,
            "the current sealed Source run omits required workflow method API {method}; a full round cannot be assembled from historical API attempts"
        );
    }
    ensure!(
        state.dependency_review.recording_run_id.as_deref()
            == Some(state.recording_run_id.as_str())
            && state
                .dependency_review
                .unresolved_source_exchange_ids
                .is_empty()
            && !state
                .dependency_review
                .claims
                .values()
                .any(|claim| claim.recording_run_id == state.recording_run_id
                    && matches!(claim.status, ClaimStatus::Pending | ClaimStatus::Unresolved))
            && !state
                .dependency_review
                .investigations
                .values()
                .any(|request| request.recording_run_id == state.recording_run_id
                    && matches!(
                        request.status,
                        ClaimStatus::Pending | ClaimStatus::Unresolved
                    )),
        "independent Source attribution work remains unresolved"
    );
    let mut completed = Vec::new();
    for (id, obligation) in &state.dependency_review.obligations {
        if obligation.pending() {
            validate_scope(root, state, &source, &evidence, obligation)?;
            completed.push(id.clone());
        }
    }
    let stamp = crate::dependency_index::FileStamp::read_native(&evidence.report_path)?;
    let receipt = BatchAcceptanceReceipt {
        engine_fingerprint: crate::build_info::ENGINE_FINGERPRINT.into(),
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
    };
    for id in &completed {
        state
            .dependency_review
            .obligations
            .get_mut(id)
            .expect("validated obligation")
            .completed_by_session = Some(evidence.session_id.clone());
    }
    state.dependency_review.batch_receipt = Some(receipt);
    state.dependency_review.revision += 1;
    Ok(completed)
}
