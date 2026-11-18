//! Engine-issued acceptance reuses real execution without inventing consumption.
use anyhow::{Context, Result, ensure};
use std::{collections::BTreeSet, path::Path};

use super::{model::AcceptanceReceipt, source};
use crate::dependency::attribution::DependencyOwner;
use crate::model::{RewriteApiStatus, RewritePhase, RewriteState};

use traffic_rewrite_evidence::attribution_attempt::ActualAttempt;
pub use traffic_rewrite_evidence::attribution_attempt::claim_actual;

pub fn actual(
    root: &Path,
    state: &RewriteState,
    source: &source::SourceSnapshot,
) -> Result<ActualAttempt> {
    ensure!(
        state
            .attempts
            .last()
            .is_some_and(|attempt| attempt.engine_fingerprint.as_deref()
                == Some(crate::build_info::ENGINE_FINGERPRINT)),
        "attribution acceptance requires an actual attempt from the current engine build"
    );
    ensure!(
        state.attempts.last().is_some_and(dependency_only),
        "unused attribution acceptance requires passing responses and complete actual Replay with dependency-only failures"
    );
    claim_actual(root, state, source)
}

pub use traffic_rewrite_evidence::attribution_projection::filter_cases;

fn foreign_owner(source: &source::SourceSnapshot, owner: &DependencyOwner, api: &str) -> bool {
    match owner {
        DependencyOwner::Case { origin_case_id, .. } => {
            source.apis.get(origin_case_id).is_some_and(|owner| {
                crate::api_selector::public_api(owner) != crate::api_selector::public_api(api)
            })
        }
        DependencyOwner::Process { .. } | DependencyOwner::Startup { .. } => true,
        DependencyOwner::Shutdown { .. } | DependencyOwner::Unattributed { .. } => false,
    }
}

pub fn reconcile(
    root: &Path,
    state: &mut RewriteState,
    source: &source::SourceSnapshot,
) -> Result<Vec<String>> {
    let active_rules = super::rules::fingerprints(&super::rules::load(root)?)?;
    let mut accepted = Vec::new();
    let apis = state
        .dependency_review
        .claims
        .values()
        .filter(|claim| claim.recording_run_id == state.recording_run_id)
        .map(|claim| claim.method_api.clone())
        .collect::<BTreeSet<_>>();
    for api in apis {
        if crate::verification_obligations::blocks_api(&state.dependency_review.obligations, &api) {
            continue;
        }
        let selected = crate::inventory::scoped(state, Some(&api.parse()?))?;
        if selected.rule_replay_pending || selected.rule_plan.is_some() {
            continue;
        }
        let Ok(mut actual) = actual(root, &selected, source) else {
            continue;
        };
        if actual.unused.is_empty() {
            continue;
        }
        let mut proof_ids = BTreeSet::new();
        let fully_proved = actual.unused.iter().all(|id| {
            state
                .dependency_review
                .decisions
                .get(id)
                .is_some_and(|decision| {
                    super::rules::current(decision, &active_rules)
                        && foreign_owner(source, &decision.owner, &api)
                        && {
                            proof_ids.insert(decision.proof_id.clone());
                            true
                        }
                })
        });
        if !fully_proved {
            continue;
        }
        if !actual.without_unused_is_clean(source)? {
            continue;
        }
        let receipt = AcceptanceReceipt {
            engine_fingerprint: crate::build_info::ENGINE_FINGERPRINT.into(),
            verdict: "ai-verified".into(),
            api: crate::api_selector::public_api(&api).into(),
            method_api: api.clone(),
            recording_run_id: state.recording_run_id.clone(),
            source_revision: selected
                .source_revision
                .clone()
                .context("Source revision absent")?,
            source_inventory_id: source.identity.clone(),
            attempt: actual.attempt,
            session_id: actual.session_id,
            report_sha256: actual.report_sha256,
            execution_identity: actual.execution_identity,
            proof_ids,
            excluded_unused: actual.unused,
            batch_verified: false,
        };
        crate::inventory::with_slice_mut(state, &api, |slice| {
            slice.phase = RewritePhase::SliceComplete;
            slice.e2e_current = true;
            slice.active_issue = None;
            slice.target_fingerprint = Some(crate::fingerprint::repository_fingerprint(root)?);
            Ok(())
        })?;
        state
            .dependency_review
            .receipts
            .insert(api.clone(), receipt);
        let active = state.api == api;
        if let Some(item) = state.api_inventory.iter_mut().find(|item| item.api == api) {
            item.e2e_current = true;
            if !active {
                item.status = RewriteApiStatus::Complete;
            }
            item.verified_target_fingerprint =
                Some(crate::fingerprint::repository_fingerprint(root)?);
        }
        accepted.push(api);
    }
    Ok(accepted)
}

pub fn receipt_current(root: &Path, state: &RewriteState, api: &str) -> Result<bool> {
    let Some(receipt) = state.dependency_review.receipts.get(api) else {
        return Ok(false);
    };
    if receipt.engine_fingerprint != crate::build_info::ENGINE_FINGERPRINT
        || receipt.recording_run_id != state.recording_run_id
        || Some(receipt.source_revision.as_str()) != state.source_revision.as_deref()
        || receipt.source_inventory_id != source::inventory_identity(state)?
        || receipt.execution_identity != crate::fingerprint::replay_identity(root)?
        || crate::verification_obligations::blocks_api(&state.dependency_review.obligations, api)
    {
        return Ok(false);
    }
    if state
        .attempts
        .last()
        .is_none_or(|attempt| attempt.attempt != receipt.attempt)
    {
        return Ok(false);
    }
    let active_rules = super::rules::fingerprints(&super::rules::load(root)?)?;
    Ok(receipt.excluded_unused.iter().all(|id| {
        state
            .dependency_review
            .decisions
            .get(id)
            .is_some_and(|decision| {
                receipt.proof_ids.contains(&decision.proof_id)
                    && super::rules::current(decision, &active_rules)
            })
    }))
}

pub fn invalidate_receipts(root: &Path, state: &mut RewriteState) -> Result<()> {
    let active_rules = super::rules::fingerprints(&super::rules::load(root)?)?;
    let inventory_id = state
        .case_source
        .as_ref()
        .map(|_| source::inventory_identity(state))
        .transpose()?;
    let stale = state
        .dependency_review
        .receipts
        .iter()
        .filter(|(_, receipt)| {
            Some(receipt.source_inventory_id.as_str()) != inventory_id.as_deref()
                || receipt.excluded_unused.iter().any(|id| {
                    state
                        .dependency_review
                        .decisions
                        .get(id)
                        .is_none_or(|decision| {
                            !receipt.proof_ids.contains(&decision.proof_id)
                                || !super::rules::current(decision, &active_rules)
                        })
                })
        })
        .map(|(api, _)| api.clone())
        .collect::<Vec<_>>();
    for api in stale {
        state.dependency_review.receipts.remove(&api);
        crate::inventory::with_slice_mut(state, &api, |slice| {
            slice.phase = RewritePhase::ApiPending;
            slice.e2e_current = false;
            Ok(())
        })?;
        if let Some(item) = state.api_inventory.iter_mut().find(|item| item.api == api) {
            item.status = RewriteApiStatus::Pending;
            item.e2e_current = false;
            item.verified_target_fingerprint = None;
        }
    }
    Ok(())
}

pub fn dependency_only(attempt: &crate::model::RewriteAttemptSummary) -> bool {
    attempt.gates.responses == crate::E2eResponseGate::Passed
        && attempt.gates.replay == crate::E2eReplayGate::Complete
        && attempt.gates.dependencies == crate::E2eDependencyGate::Dirty
        && attempt.counts.selected > 0
        && attempt.counts.executed == attempt.counts.selected
        && attempt.counts.response_passed == attempt.counts.executed
        && attempt.counts.response_nonpassing == 0
        && attempt.counts.response_incomplete == 0
}
