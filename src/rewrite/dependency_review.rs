//! Independent Source attribution and API-scoped verification obligations.
mod analysis;
mod batch;
mod batch_verification;
mod case_defaults;
mod decisions;
mod investigations;
mod model;
mod ownership_impact;
mod projection;
mod queries;
mod rules;
mod snapshot;
mod source;
mod target_query;
#[cfg(test)]
mod tests;
mod verification;
mod workflow_verification;

use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::Path,
};

use super::{
    model::RewriteState,
    store::RewriteStore,
    verification_obligations::{ScopeObligation, VerificationScope},
};
#[cfg(test)]
use crate::dependency::attribution::AttributionDecision;
use crate::dependency::attribution::DependencyOwner;
pub(super) use analysis::required_action;
pub use batch::{dependency_attribution_batch_information, retry_dependency_batch};
pub(super) use batch::{required_action as batch_action, run as run_batch};
pub(super) use batch_verification::current as batch_current;
pub use investigations::{
    InvestigationOutcome, InvestigationResolution, TargetInvestigation,
    TargetInvestigationResolutionSubmission, TargetInvestigationSubmission,
    investigate_unmatched_dependency, resolve_target_investigation,
};
pub(super) use model::ReviewLedger;
pub use model::{
    AttributionCommandOptions, AttributionReviewContext, AttributionRuleBinding,
    AttributionSubmission, ClaimRejection, ForeignUnusedClaim, ForeignUnusedSubmission,
    ProposedAttribution,
};
use model::{ClaimStatus, SCHEMA};
pub use projection::dependency_attribution_api_information;
pub use projection::dependency_attribution_hypotheses;
pub(super) use projection::information as api_information;
pub use queries::{dependency_attribution_candidates, dependency_attribution_rules};
pub use target_query::dependency_attribution_target;
pub(super) use workflow_verification::{current as workflow_current, pending as workflow_pending};

fn open(root: &Path) -> Result<(std::path::PathBuf, RewriteStore)> {
    let (root, _) = crate::e2e_run::resolve_project(root)?;
    let store = RewriteStore::new(&root)?;
    Ok((root, store))
}

pub(super) fn refresh_receipts(root: &Path, state: &mut RewriteState) -> Result<()> {
    if !state.dependency_review.decisions.is_empty() {
        let active = rules::fingerprints(&rules::load(root)?)?;
        let inventory = state
            .case_source
            .as_ref()
            .map(|_| source::inventory_identity(state))
            .transpose()?;
        let inventory_changed =
            state.dependency_review.source_inventory_id.as_deref() != inventory.as_deref();
        let source_revision = state.source_revision.clone();
        let expired = state.dependency_review.decisions.retain_groups(|decision| {
            !inventory_changed
                && rules::current(decision, &active)
                && Some(decision.proof.source_revision.as_str()) == source_revision.as_deref()
        });
        if !expired.is_empty() {
            let expired_proofs = expired
                .iter()
                .filter(|group| !rules::current(&group.template, &active))
                .map(|group| group.template.proof_id.clone())
                .collect::<BTreeSet<_>>();
            for obligation in
                state
                    .dependency_review
                    .obligations
                    .values_mut()
                    .filter(|obligation| {
                        obligation.pending() && expired_proofs.contains(&obligation.proof_id)
                    })
            {
                obligation.retired_reason=Some("ownership proof lost its effective rule binding; original Source ownership is restored and must still reconcile".into());
            }
            for claim in state.dependency_review.claims.values_mut() {
                if claim.recording_run_id == state.recording_run_id
                    && claim
                        .source_exchange_ids
                        .iter()
                        .any(|id| expired.iter().any(|group| group.contains(id)))
                {
                    claim.status = ClaimStatus::Pending;
                }
            }
            // Immutable history is retained; an expired rule restores original capture ownership.
            state.dependency_review.recording_run_id = None;
            state.dependency_review.revision += 1;
        }
    }
    investigations::refresh(state);
    analysis::refresh_inventory(root, state)?;
    if !state.dependency_review.receipts.is_empty() {
        verification::invalidate_receipts(root, state)?;
    }
    Ok(())
}

pub fn dependency_attribution_context(
    context: super::RewriteContext,
) -> Result<AttributionReviewContext> {
    let (root, store) = open(&context.target_root)?;
    let state = store
        .load()?
        .context("rewrite workflow has not been initialized")?;
    let policy = rules::load(&root)?;
    let mut context = if state.dependency_review.claims.values().any(|claim| {
        claim.recording_run_id == state.recording_run_id
            && matches!(claim.status, ClaimStatus::Pending | ClaimStatus::Unresolved)
    }) {
        let source = source::load(&state)?;
        let mut context = context_for(&root, &state, &source)?;
        context.task_groups = rules::claim_groups(&policy, &source, &context.claims)?;
        context
    } else {
        let (identity, ids) = analysis::review_inventory(&root, &state)?;
        let mut context = context_from_inventory(&root, &state, &identity, ids.into_owned())?;
        context.task_groups = rules::empty_claim_groups(&policy)?;
        context
    };
    context.effective_policy_fingerprint = policy.fingerprints.full.clone();
    context.rule_groups = rules::groups(&policy)?;
    let apis = context
        .claims
        .iter()
        .map(|claim| claim.api.clone())
        .collect::<BTreeSet<_>>();
    context.evidence_commands = apis
        .into_iter()
        .map(|api| {
            super::action::command(
                &root,
                vec![
                    "dependency-attribution".into(),
                    "show".into(),
                    "--api".into(),
                    api,
                ],
                vec![],
            )
        })
        .collect();
    context.evidence_commands.push(super::action::command(
        &root,
        vec!["dependency-attribution".into(), "rules".into()],
        vec![],
    ));
    Ok(context)
}

fn context_for(
    root: &Path,
    state: &RewriteState,
    source: &source::SourceSnapshot,
) -> Result<AttributionReviewContext> {
    let active_rules = rules::fingerprints(&rules::load(root)?)?;
    let decisions = state
        .dependency_review
        .decisions
        .iter()
        .filter(|(_, decision)| rules::current(decision, &active_rules))
        .collect::<BTreeMap<_, _>>();
    let unattributed_exchange_ids = source
        .exchanges
        .iter()
        .filter(|(id, event)| {
            event.capture.semantic_required
                && matches!(
                    event.capture.attribution,
                    DependencyOwner::Unattributed { .. }
                )
                && !decisions.contains_key(id)
                && !source.case_defaults.contains_key(id)
        })
        .map(|(id, _)| *id)
        .collect();
    context_from_inventory(root, state, &source.identity, unattributed_exchange_ids)
}

fn context_from_inventory(
    root: &Path,
    state: &RewriteState,
    identity: &str,
    unattributed_exchange_ids: BTreeSet<uuid::Uuid>,
) -> Result<AttributionReviewContext> {
    let source_revision = state
        .source_revision
        .clone()
        .context("Source revision absent")?;
    let claims = state
        .dependency_review
        .claims
        .values()
        .filter(|claim| {
            claim.recording_run_id == state.recording_run_id
                && matches!(claim.status, ClaimStatus::Pending | ClaimStatus::Unresolved)
        })
        .cloned()
        .collect();
    let assignment_id = assignment_id(state)?;
    Ok(AttributionReviewContext {
        schema: SCHEMA,
        work_type: "dependency_attribution",
        workflow_id: state.workflow_id.clone(),
        recording_run_id: state.recording_run_id.clone(),
        source_revision,
        source_inventory_id: identity.into(),
        revision: state.dependency_review.revision,
        assignment_id,
        claims,
        task_groups: BTreeMap::new(),
        evidence_commands: vec![],
        effective_policy_fingerprint: String::new(),
        rule_groups: vec![],
        rule_planning: crate::rewrite::unified_rule::attribution::information(root, state)?,
        unattributed_exchange_ids,
        obligations: state
            .dependency_review
            .obligations
            .values()
            .filter(|o| o.pending())
            .cloned()
            .collect(),
        next_step: "Resolve every ownerless Source occurrence through supported process-task or async-origin API rules and independent positive proof before formal Replay. Reject mistaken ownership returns with Source proof. Missing traffic remains with its reporting API implementer; no ownership result proves consumption.",
    })
}

pub fn claim_foreign_unused(options: AttributionCommandOptions) -> Result<Value> {
    let (root, store) = open(&options.target_root)?;
    let input: ForeignUnusedSubmission = serde_json::from_slice(&fs::read(&options.file)?)?;
    ensure!(
        input.schema == SCHEMA,
        "unsupported foreign-unused claim schema"
    );
    let _lock = store.lock()?;
    let mut state = store
        .load()?
        .context("rewrite workflow has not been initialized")?;
    let api = super::inventory::api_for_rule_evidence_id(&root, &state, &input.evidence_id)?;
    ensure!(
        super::api_selector::public_api(&api) == input.api,
        "claim evidence belongs to another canonical API"
    );
    super::worker::ensure_api_confirmed(&state, &api, "submitting an unused ownership claim")?;
    let selected = super::inventory::scoped(&state, Some(&api.parse()?))?;
    let original = source::load(&state)?;
    let actual = verification::claim_actual(&root, &selected, &original)?;
    let source_revision = selected
        .source_revision
        .as_deref()
        .context("Source revision absent")?;
    if let Some(proof) = &input.exclusion {
        proof.validate(source_revision)?;
    }
    let reason = if input.reason.trim().is_empty() {
        input
            .exclusion
            .as_ref()
            .map(|proof| proof.exclusive_scope.clone())
            .unwrap_or_default()
    } else {
        input.reason.clone()
    };
    ensure!(
        !reason.trim().is_empty() && reason.len() <= 4096,
        "ownership return requires concrete unused occurrences and a bounded reason, not an exclusion proof"
    );
    ensure!(
        !input.source_exchange_ids.is_empty()
            && input.source_exchange_ids.is_subset(&actual.unused),
        "claim must select actual unused occurrences from this exact finalized attempt"
    );
    let id = source::digest(&serde_json::to_vec(&(
        &state.workflow_id,
        &api,
        actual.attempt,
        &input.source_exchange_ids,
        &reason,
        &input.exclusion,
    ))?);
    if !state.dependency_review.claims.contains_key(&id) {
        state.dependency_review.claims.insert(
            id.clone(),
            ForeignUnusedClaim {
                id: id.clone(),
                api: input.api,
                method_api: api,
                recording_run_id: state.recording_run_id.clone(),
                source_revision: source_revision.into(),
                source_inventory_id: original.identity,
                attempt: actual.attempt,
                execution_identity: actual.execution_identity,
                report_sha256: actual.report_sha256,
                source_exchange_ids: input.source_exchange_ids,
                exclusion: input.exclusion,
                reason,
                status: ClaimStatus::Pending,
                rejection: None,
            },
        );
        state.dependency_review.revision += 1;
        state.bump();
        store.save(&state)?;
    }
    Ok(
        json!({"schema":SCHEMA,"claim_id":id,"status":"attribution_pending","accepted":false,
        "owner":"repository_analyst","next_command":super::action::command(&root,vec!["dependency-attribution".into(),"context".into()],vec![])}),
    )
}

pub fn apply_dependency_attribution(options: AttributionCommandOptions) -> Result<Value> {
    let (root, store) = open(&options.target_root)?;
    let input: AttributionSubmission = serde_json::from_slice(&fs::read(&options.file)?)?;
    ensure!(
        input.schema == SCHEMA,
        "unsupported attribution submission schema"
    );
    let _lock = store.lock()?;
    let mut state = store
        .load()?
        .context("rewrite workflow has not been initialized")?;
    let original = source::load(&state)?;
    let context = context_for(&root, &state, &original)?;
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
    for original_proposal in &input.decisions {
        let mut proposal = original_proposal.clone();
        let rule_bindings = rules::bind(&root, &state, &original, &mut proposal)?;
        validate_proposal(&state, &original, &proposal)?;
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
        ownership_impact::observe(&state, &original, &proposal, &mut moved_case_scopes);
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
                .unwrap_or(super::verification_obligations::VerificationRequirement::Replay);
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
    ownership_impact::invalidate(
        &root,
        &mut state,
        &original,
        moved_case_scopes,
        next_revision,
    )?;
    verification::invalidate_receipts(&root, &mut state)?;
    let accepted = verification::reconcile(&root, &mut state, &original)?;
    state.bump();
    store.save(&state)?;
    let pending = required_action(&root, &state);
    Ok(
        json!({"schema":SCHEMA,"revision":next_revision,"accepted_apis":accepted,
        "pending_obligations":state.dependency_review.obligations.values().filter(|o|o.pending()).collect::<Vec<_>>(),
        "ownership_complete":pending.is_none(),"unattributed_remaining":state.dependency_review.unresolved_source_exchange_ids.len(),
        "next_action":pending,"batch_verified":false,"next_command":super::action::next_command(&root)}),
    )
}

fn validate_proposal(
    state: &RewriteState,
    source: &source::SourceSnapshot,
    proposal: &ProposedAttribution,
) -> Result<()> {
    ensure!(
        !proposal.source_task.trim().is_empty() && proposal.source_task.len() <= 128,
        "attribution requires an actual bounded Source task/entrypoint"
    );
    proposal.proof.validate(
        state
            .source_revision
            .as_deref()
            .context("Source revision absent")?,
    )?;
    proposal.owner.validate()?;
    ensure!(
        !matches!(proposal.owner, DependencyOwner::Unattributed { .. }),
        "unresolved ownership is not a proven decision"
    );
    ensure!(
        !proposal.source_exchange_ids.is_empty(),
        "attribution proof requires original Source occurrences"
    );
    for id in &proposal.source_exchange_ids {
        let event = source
            .exchanges
            .get(id)
            .context("attribution occurrence is absent from original Source inventory")?;
        ensure!(
            event.complete,
            "attribution cannot exempt incomplete original capture"
        );
        ensure!(
            proposal
                .claim_ids
                .iter()
                .all(|claim| state.dependency_review.claims.contains_key(claim)),
            "unknown attribution claim"
        );
    }
    for claim_id in &proposal.claim_ids {
        let claim = &state.dependency_review.claims[claim_id];
        ensure!(
            claim.recording_run_id == state.recording_run_id
                && claim.source_inventory_id == source.identity,
            "attribution claim belongs to changed Source inventory"
        );
        ensure!(
            !claim
                .source_exchange_ids
                .is_disjoint(&proposal.source_exchange_ids),
            "attribution proof does not cover the claimed occurrences"
        );
    }
    let scope_valid = match (&proposal.owner, &proposal.obligation_scope) {
        (DependencyOwner::Case { origin_case_id, .. }, scope @ VerificationScope::Api { .. }) => {
            source
                .apis
                .get(origin_case_id)
                .is_some_and(|api| super::verification_obligations::scope_matches_api(scope, api))
        }
        (
            DependencyOwner::Process {
                process_epoch,
                source_task,
                ..
            },
            VerificationScope::Process {
                process_epoch: epoch,
                source_task: task,
            },
        ) => process_epoch == epoch && source_task == task && source.epochs.contains(epoch),
        (
            DependencyOwner::Startup {
                process_epoch,
                initialization_unit,
            },
            VerificationScope::Startup {
                process_epoch: epoch,
                initialization_unit: unit,
            },
        ) => process_epoch == epoch && initialization_unit == unit && source.epochs.contains(epoch),
        _ => false,
    };
    ensure!(
        scope_valid,
        "verification obligation must belong to the actual proven origin scope"
    );
    if proposal.impact == super::verification_obligations::VerificationImpact::MissingCapture {
        ensure!(
            proposal
                .missing_evidence
                .as_ref()
                .is_some_and(|reason| !reason.trim().is_empty()),
            "capture obligation requires concrete missing evidence"
        );
    }
    Ok(())
}

#[cfg(test)]
pub(crate) fn dependency_attribution_overlay(
    root: &Path,
    recording_run: &str,
) -> Result<Vec<AttributionDecision>> {
    snapshot::overlay(root, recording_run)
}

pub(crate) fn dependency_attribution_identity(root: &Path, recording_run: &str) -> Result<String> {
    snapshot::identity(root, recording_run)
}

pub(crate) fn dependency_attribution_identity_for_source(
    root: &Path,
    source: &Path,
    recording_run: &str,
) -> Result<String> {
    snapshot::identity_for_source(root, source, recording_run)
}

pub(crate) fn freeze_dependency_attribution(
    target: Option<&Path>,
    source: &Path,
    recording_run: &str,
) -> Result<(BTreeMap<uuid::Uuid, DependencyOwner>, String)> {
    snapshot::frozen(target, source, recording_run)
}

pub(super) fn batch_pending(state: &RewriteState) -> bool {
    state.case_source.is_some() && state.dependency_review.batch_receipt.is_none()
        || (state.case_source.is_some()
            && state.dependency_review.recording_run_id.as_deref()
                != Some(state.recording_run_id.as_str()))
        || state.dependency_review.claims.values().any(|claim| {
            claim.recording_run_id == state.recording_run_id
                && matches!(claim.status, ClaimStatus::Pending | ClaimStatus::Unresolved)
        })
        || state
            .dependency_review
            .obligations
            .values()
            .any(|o| o.pending())
        || !state
            .dependency_review
            .unresolved_source_exchange_ids
            .is_empty()
        || state
            .dependency_review
            .investigations
            .values()
            .any(|request| {
                request.recording_run_id == state.recording_run_id
                    && matches!(
                        request.status,
                        ClaimStatus::Pending | ClaimStatus::Unresolved
                    )
            })
}

fn assignment_id(state: &RewriteState) -> Result<String> {
    Ok(source::digest(&serde_json::to_vec(&(
        &state.workflow_id,
        &state.recording_run_id,
        &state.source_revision,
        state.dependency_review.revision,
    ))?))
}

pub fn verify_dependency_obligation(context: super::RewriteContext, id: &str) -> Result<Value> {
    let (root, store) = open(&context.target_root)?;
    let _lock = store.lock()?;
    let mut state = store.load()?.context("rewrite workflow absent")?;
    let session = verification::verify_obligation(&root, &mut state, id)?;
    // This explicit verification command can retain a stronger WholeSource
    // receipt only when its independent strict full-session validator passes.
    // Workflow finalization never calls this path for run-owned obligations.
    let _ = batch_verification::accept(&root, &mut state);
    state.dependency_review.revision += 1;
    state.bump();
    store.save(&state)?;
    Ok(json!({"obligation_id":id,"verified_by_session":session,"batch_verified":false}))
}

pub(super) fn verify_completed_api_obligations(
    root: &Path,
    state: &mut RewriteState,
    results: &[crate::E2eApiRunResult],
) {
    let ids = state
        .dependency_review
        .obligations
        .iter()
        .filter(|(_, obligation)| {
            obligation.pending()
                && results.iter().any(|result| {
                    result.passed
                        && super::verification_obligations::scope_matches_api(
                            &obligation.scope,
                            &result.api,
                        )
                })
        })
        .map(|(id, _)| id.clone())
        .collect::<Vec<_>>();
    for id in ids {
        if verification::verify_obligation(root, state, &id).is_ok() {
            state.dependency_review.revision += 1;
        }
    }
}

pub fn dependency_attribution_source_information(
    context: super::RewriteContext,
    id: &str,
) -> Result<Value> {
    let (root, store) = open(&context.target_root)?;
    let state = store.load()?.context("rewrite workflow absent")?;
    let id = id.parse::<uuid::Uuid>()?;
    let information = source::information(&state, id)?;
    let event = &information.exchange;
    let metadata = &event.selector;
    Ok(
        json!({"schema":SCHEMA,"recording_run_id":state.recording_run_id,"source_inventory_id":information.identity,
        "source_exchange_id":id,"capture":event.capture,"capture_complete":event.complete,
        "effective_attribution":state.dependency_review.decisions.get(&id).map(|decision|decision.decision(id)),
        "default_case_attribution":information.case_default,
        "request_shape":{"event_type":metadata["event_type"],"operation":metadata["command"].as_str().or_else(||metadata["method"].as_str()),
            "endpoint":{"host":metadata["target_host"],"port":metadata["target_port"]},
            "args_count":metadata["args"].as_array().map(Vec::len),"params_count":metadata["params"].as_array().map(Vec::len),
            "sql_digest":metadata["sql"].as_str().map(|sql|source::digest(sql.as_bytes()))},
        "does_not_prove":"A captured physical occurrence is not caller tracing, successful Target matching or actual consumption.",
        "next_command":super::action::command(&root,vec!["dependency-attribution".into(),"context".into()],vec![])}),
    )
}
