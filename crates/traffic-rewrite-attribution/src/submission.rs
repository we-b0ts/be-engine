//! Source-backed ownership submission applied within the caller's workflow transaction.
use crate::{
    decisions,
    model::{AttributionReviewContext, AttributionSubmission, ClaimStatus, RewriteState},
    rules, source,
    validation::validate_proposal,
};
use anyhow::{Context, Result, ensure};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
};
use traffic_engine::dependency::attribution::DependencyOwner;
use traffic_rewrite_model::rewrite::verification_obligations::ScopeObligation;
use uuid::Uuid;

pub struct AppliedAttribution {
    pub revision: u64,
    pub moved_case_scopes: BTreeMap<String, BTreeSet<Uuid>>,
    pub changed_scopes: BTreeSet<String>,
}

/// The caller locks the workflow and persists the state after admission succeeds.
pub fn apply(
    root: &Path,
    state: &mut RewriteState,
    original: &source::SourceSnapshot,
    context: &AttributionReviewContext,
    input: &AttributionSubmission,
) -> Result<AppliedAttribution> {
    ensure!(
        input.assignment_id == context.assignment_id
            && input.expected_revision == context.revision
            && input.recording_run_id == context.recording_run_id
            && input.source_revision == context.source_revision
            && input.source_inventory_id == context.source_inventory_id,
        "attribution assignment or evidence revision is stale"
    );
    let next_revision = context
        .revision
        .checked_add(1)
        .context("attribution revision exhausted")?;
    let mut touched = BTreeSet::new();
    let mut moved_case_scopes = std::collections::BTreeMap::new();
    let mut changed_scopes = BTreeSet::new();
    for original_proposal in &input.decisions {
        let mut proposal = original_proposal.clone();
        let rule_bindings = rules::bind(root, state, original, &mut proposal)?;
        validate_proposal(state, original, &proposal)?;
        ensure!(
            proposal
                .source_exchange_ids
                .iter()
                .all(|id| touched.insert(*id)),
            "overlapping attribution decisions in one submission"
        );
        let proof_id = source::digest(&serde_json::to_vec(&(
            &input.source_inventory_id,
            &proposal,
        ))?);
        crate::impact::observe(
            state,
            original,
            &proposal,
            &mut moved_case_scopes,
            &mut changed_scopes,
        );
        let group = std::sync::Arc::new(decisions::DecisionGroup {
            template: decisions::DecisionTemplate {
                owner: proposal.owner.clone(),
                proof_id: proof_id.clone(),
                proof_revision: next_revision,
                proof: proposal.proof.clone(),
                rule_bindings,
            },
            exchange_ids: proposal.source_exchange_ids.iter().copied().collect(),
        });
        state
            .dependency_review
            .decisions
            .insert_group(group.clone())?;
        state.dependency_review.decision_history.record(
            group,
            &state.workflow_id,
            &state.recording_run_id,
            &original.identity,
        );
        {
            let requirement = proposal
                .impact
                .requirement()
                .unwrap_or(crate::verification_obligations::VerificationRequirement::Replay);
            let id = source::digest(&serde_json::to_vec(&(
                &proof_id,
                &proposal.obligation_scope,
                requirement,
            ))?);
            state.dependency_review.obligations.insert(
                id.clone(),
                ScopeObligation {
                    id,
                    scope: proposal.obligation_scope.clone(),
                    requirement,
                    source_revision: input.source_revision.clone(),
                    baseline_recording_run_id: state.recording_run_id.clone(),
                    proof_id: proof_id.clone(),
                    reason: proposal.missing_evidence.clone().unwrap_or_else(|| {
                        "ownership changes Replay admission for the original owner".into()
                    }),
                    completed_by_session: None,
                    retired_reason: None,
                },
            );
        }
    }
    for id in &input.unresolved_claim_ids {
        state
            .dependency_review
            .claims
            .get_mut(id)
            .context("unknown unresolved claim")?
            .status = ClaimStatus::Unresolved;
    }
    for rejection in &input.claim_rejections {
        rejection.proof.validate(&input.source_revision)?;
        ensure!(
            !rejection.reason.trim().is_empty() && rejection.reason.len() <= 4096,
            "claim rejection requires a bounded Source-backed reason"
        );
        let claim = state
            .dependency_review
            .claims
            .get_mut(&rejection.claim_id)
            .context("unknown rejected claim")?;
        ensure!(
            claim.recording_run_id == state.recording_run_id
                && claim.source_inventory_id == original.identity,
            "claim rejection belongs to another Source inventory"
        );
        claim.status = ClaimStatus::Rejected;
        claim.rejection = Some(rejection.clone());
    }
    ensure!(
        input.investigation_resolutions.is_empty(),
        "missing or unmatched traffic has an API owner; submit its implementer diagnosis with dependency-attribution resolve"
    );
    for claim in state.dependency_review.claims.values_mut() {
        if claim.status != ClaimStatus::Rejected
            && claim.recording_run_id == state.recording_run_id
            && claim
                .source_exchange_ids
                .iter()
                .all(|id| state.dependency_review.decisions.contains_key(id))
        {
            claim.status = ClaimStatus::Proved;
        }
    }
    state.dependency_review.revision = next_revision;
    state.dependency_review.recording_run_id = Some(state.recording_run_id.clone());
    state.dependency_review.source_inventory_id = Some(original.identity.clone());
    state.dependency_review.unresolved_source_exchange_ids = original
        .exchanges
        .iter()
        .filter(|(id, event)| {
            event.capture.semantic_required
                && matches!(
                    event.capture.attribution,
                    DependencyOwner::Unattributed { .. }
                )
                && !state.dependency_review.decisions.contains_key(id)
                && !original.case_defaults.contains_key(id)
        })
        .map(|(id, _)| *id)
        .collect();
    Ok(AppliedAttribution {
        revision: next_revision,
        moved_case_scopes,
        changed_scopes,
    })
}
