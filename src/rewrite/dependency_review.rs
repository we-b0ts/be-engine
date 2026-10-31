//! Independent Source attribution and API-scoped verification obligations.
mod batch;
mod batch_verification;
mod investigations;
mod model;
mod ownership_impact;
mod projection;
mod queries;
mod rules;
mod source;
mod target_query;
#[cfg(test)]
mod tests;
mod verification;

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
use crate::dependency::attribution::{AttributionDecision, DependencyOwner};
pub use batch::{dependency_attribution_batch_information, retry_dependency_batch};
pub(super) use batch::{required_action as batch_action, run as run_batch};
pub(super) use batch_verification::current as batch_current;
pub use investigations::{
    InvestigationOutcome, InvestigationResolution, TargetInvestigation,
    TargetInvestigationSubmission, investigate_unmatched_dependency,
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
        let expired = state
            .dependency_review
            .decisions
            .iter()
            .filter(|(_, decision)| {
                inventory_changed
                    || !rules::current(decision, &active)
                    || Some(decision.proof.source_revision.as_str())
                        != state.source_revision.as_deref()
            })
            .map(|(id, _)| *id)
            .collect::<BTreeSet<_>>();
        if !expired.is_empty() {
            let expired_proofs = expired
                .iter()
                .filter_map(|id| state.dependency_review.decisions.get(id))
                .filter(|decision| !rules::current(decision, &active))
                .map(|decision| decision.proof_id.clone())
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
            state
                .dependency_review
                .decisions
                .retain(|id, _| !expired.contains(id));
            for claim in state.dependency_review.claims.values_mut() {
                if claim.recording_run_id == state.recording_run_id
                    && !claim.source_exchange_ids.is_disjoint(&expired)
                {
                    claim.status = ClaimStatus::Pending;
                }
            }
            // Immutable history is retained; an expired rule restores original capture ownership.
            state.dependency_review.recording_run_id = None;
            state.dependency_review.revision += 1;
        }
    }
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
    let source = source::load(&state)?;
    let policy = rules::load(&root)?;
    let mut context = context_for(&root, &state, &source)?;
    context.task_groups = rules::claim_groups(&policy, &source, &context.claims)?;
    context.effective_policy_fingerprint = policy.fingerprints.full.clone();
    context.rule_groups = rules::groups(&policy)?;
    let apis = context
        .claims
        .iter()
        .map(|claim| claim.api.clone())
        .chain(
            context
                .investigations
                .iter()
                .map(|request| request.api.clone()),
        )
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
        .collect::<Vec<_>>();
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
        })
        .map(|(id, _)| *id)
        .collect();
    let assignment_id = assignment_id(state)?;
    let owners = decisions
        .iter()
        .map(|(id, decision)| (**id, decision.owner.clone()))
        .collect::<BTreeMap<_, _>>();
    let investigations = state
        .dependency_review
        .investigations
        .values()
        .filter(|request| {
            request.recording_run_id == state.recording_run_id
                && matches!(
                    request.status,
                    ClaimStatus::Pending | ClaimStatus::Unresolved
                )
        })
        .cloned()
        .map(|mut request| {
            request.candidate_discovery = request
                .target_observations
                .iter()
                .map(|(id, observation)| {
                    (
                        id.clone(),
                        queries::candidate_page(
                            root,
                            state,
                            source,
                            (&request.id, id),
                            observation,
                            &owners,
                            0,
                        ),
                    )
                })
                .collect();
            request
        })
        .collect();
    Ok(AttributionReviewContext {
        schema: SCHEMA,
        work_type: "dependency_attribution",
        workflow_id: state.workflow_id.clone(),
        recording_run_id: state.recording_run_id.clone(),
        source_revision,
        source_inventory_id: source.identity.clone(),
        revision: state.dependency_review.revision,
        assignment_id,
        claims,
        investigations,
        task_groups: BTreeMap::new(),
        evidence_commands: vec![],
        effective_policy_fingerprint: String::new(),
        rule_groups: vec![],
        unattributed_exchange_ids,
        obligations: state
            .dependency_review
            .obligations
            .values()
            .filter(|o| o.pending())
            .cloned()
            .collect(),
        next_step: "Analyze actual Source tasks and indirect callers read-only. Submit independent positive owner proofs; claim exclusion alone never removes a consumption obligation.",
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
    let actual = verification::actual(&root, &selected, &original)?;
    input.exclusion.validate(
        selected
            .source_revision
            .as_deref()
            .context("Source revision absent")?,
    )?;
    ensure!(
        !input.source_exchange_ids.is_empty()
            && input.source_exchange_ids.is_subset(&actual.unused),
        "claim must select actual unused occurrences from this exact finalized attempt"
    );
    ensure!(
        input.source_exchange_ids.iter().all(|id| original
            .exchanges
            .get(id)
            .is_some_and(|event| event.complete)),
        "claim cannot exempt incomplete Source capture"
    );
    let id = source::digest(&serde_json::to_vec(&(
        &state.workflow_id,
        &api,
        actual.attempt,
        &input.source_exchange_ids,
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
                source_revision: input.exclusion.source_revision.clone(),
                source_inventory_id: original.identity,
                attempt: actual.attempt,
                execution_identity: actual.execution_identity,
                report_sha256: actual.report_sha256,
                source_exchange_ids: input.source_exchange_ids,
                exclusion: input.exclusion,
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
        for id in &proposal.source_exchange_ids {
            let decision = AttributionDecision {
                exchange_id: *id,
                owner: proposal.owner.clone(),
                proof_id: proof_id.clone(),
                proof_revision: next_revision,
                proof: proposal.proof.clone(),
                rule_bindings: rule_bindings.clone(),
            };
            state
                .dependency_review
                .decision_history
                .push(decision.clone());
            state.dependency_review.decisions.insert(*id, decision);
        }
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
    for resolution in &input.investigation_resolutions {
        investigations::apply_resolution(&mut state, resolution)?;
    }
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
    Ok(
        json!({"schema":SCHEMA,"revision":next_revision,"accepted_apis":accepted,
        "pending_obligations":state.dependency_review.obligations.values().filter(|o|o.pending()).collect::<Vec<_>>(),
        "batch_verified":false,"next_command":super::action::next_command(&root)}),
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

pub(crate) fn dependency_attribution_overlay(
    root: &Path,
    recording_run: &str,
) -> Result<Vec<AttributionDecision>> {
    let Some(state) = RewriteStore::new(root)?.load_snapshot()? else {
        return Ok(vec![]);
    };
    if state.recording_run_id != recording_run {
        return Ok(vec![]);
    }
    if state.dependency_review.recording_run_id.as_deref() != Some(recording_run) {
        return Ok(vec![]);
    }
    ensure!(
        state.dependency_review.source_inventory_id.as_deref()
            == Some(source::inventory_identity(&state)?.as_str()),
        "attribution overlay belongs to a changed sealed Source inventory; obtain fresh independent proof"
    );
    let active = rules::fingerprints(&rules::load(root)?)?;
    Ok(state
        .dependency_review
        .decisions
        .values()
        .filter(|decision| {
            Some(decision.proof.source_revision.as_str()) == state.source_revision.as_deref()
                && rules::current(decision, &active)
        })
        .cloned()
        .collect())
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

pub(super) fn required_action(
    root: &Path,
    state: &RewriteState,
) -> Option<super::model::RewriteAction> {
    let initial = state.case_source.is_some()
        && state.dependency_review.recording_run_id.as_deref()
            != Some(state.recording_run_id.as_str());
    let count = state
        .dependency_review
        .claims
        .values()
        .filter(|claim| {
            claim.recording_run_id == state.recording_run_id && claim.status == ClaimStatus::Pending
        })
        .count();
    let unmatched = state
        .dependency_review
        .investigations
        .values()
        .filter(|request| {
            request.recording_run_id == state.recording_run_id
                && request.status == ClaimStatus::Pending
        })
        .count();
    let final_unresolved = batch::apis_ready(state)
        && !state
            .dependency_review
            .unresolved_source_exchange_ids
            .is_empty();
    (count > 0 || unmatched > 0 || initial || final_unresolved).then(||super::model::RewriteAction::DependencyAttributionRequired {
        summary:if initial {"review new recording attribution once before Replay; retain unresolved scopes without blocking unrelated API diagnosis".into()} else {format!("independently prove Source ownership for {count} unused dependency claims; current API implementation may continue")},
        assignment_id:assignment_id(state).expect("serializable attribution assignment"),dispatch_generation:state.dependency_review.revision,
        claim_kinds:BTreeMap::from([("foreign_unused".into(),count),("target_request_investigation".into(),unmatched)]),
        context:super::action::command(root,vec!["dependency-attribution".into(),"context".into()],vec![]),
        apply:super::action::command(root,vec!["dependency-attribution".into(),"apply".into(),"--file".into(),"<attribution.json>".into()],vec![]),
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
    let inventory = source::load(&state)?;
    let id = id.parse::<uuid::Uuid>()?;
    let event = inventory
        .exchanges
        .get(&id)
        .context("Source exchange is outside this immutable recording")?;
    let metadata = &event.selector;
    Ok(
        json!({"schema":SCHEMA,"recording_run_id":state.recording_run_id,"source_inventory_id":inventory.identity,
        "source_exchange_id":id,"capture":event.capture,"capture_complete":event.complete,
        "effective_attribution":state.dependency_review.decisions.get(&id),
        "request_shape":{"event_type":metadata["event_type"],"operation":metadata["command"].as_str().or_else(||metadata["method"].as_str()),
            "endpoint":{"host":metadata["target_host"],"port":metadata["target_port"]},
            "args_count":metadata["args"].as_array().map(Vec::len),"params_count":metadata["params"].as_array().map(Vec::len),
            "sql_digest":metadata["sql"].as_str().map(|sql|source::digest(sql.as_bytes()))},
        "does_not_prove":"A captured physical occurrence is not caller tracing, successful Target matching or actual consumption.",
        "next_command":super::action::command(&root,vec!["dependency-attribution".into(),"context".into()],vec![])}),
    )
}
