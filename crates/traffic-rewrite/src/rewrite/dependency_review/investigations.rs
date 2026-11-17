//! API-owned missing/unmatched requests, independent of analyst ownership work.
mod resolution;
use super::{
    model::{AttributionCommandOptions, ClaimStatus, SCHEMA},
    source,
};
use crate::rewrite::verification_obligations::{
    ScopeObligation, VerificationRequirement, VerificationScope,
};
use crate::{
    dependency::attribution::AttributionProof,
    policy::Surface,
    policy_evidence::{TargetRole, WitnessManifest},
};
use anyhow::{Context, Result, ensure};
pub use resolution::{TargetInvestigationResolutionSubmission, resolve_target_investigation};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TargetInvestigationSubmission {
    pub schema: String,
    pub api: String,
    pub evidence_id: String,
    pub target_observation_ids: BTreeSet<String>,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TargetInvestigation {
    pub id: String,
    pub kind: String,
    pub api: String,
    pub method_api: String,
    pub recording_run_id: String,
    pub source_revision: String,
    pub source_inventory_id: String,
    pub attempt: u64,
    pub session_id: String,
    pub report_sha256: String,
    pub target_observations: BTreeMap<String, Value>,
    #[serde(skip)]
    pub candidate_discovery: BTreeMap<String, Value>,
    pub reason: String,
    pub status: ClaimStatus,
    pub resolution: Option<InvestigationOutcome>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InvestigationOutcome {
    ValueRule,
    TargetImplementation,
    CrossScope,
    MissingCapture,
    Unresolved,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InvestigationResolution {
    pub investigation_id: String,
    pub outcome: InvestigationOutcome,
    pub source_task: String,
    pub proof: AttributionProof,
    pub origin_scope: VerificationScope,
    pub reason: String,
}

pub fn investigate_unmatched_dependency(options: AttributionCommandOptions) -> Result<Value> {
    let (root, store) = super::open(&options.target_root)?;
    let input: TargetInvestigationSubmission = serde_json::from_slice(&fs::read(options.file)?)?;
    ensure!(
        input.schema == SCHEMA && !input.target_observation_ids.is_empty(),
        "investigation requires current schema and actual Target observation IDs"
    );
    ensure!(
        !input.reason.trim().is_empty() && input.reason.len() <= 4096,
        "investigation requires a bounded factual reason"
    );
    let _lock = store.lock()?;
    let mut state = store.load()?.context("rewrite workflow absent")?;
    let api =
        crate::rewrite::inventory::api_for_rule_evidence_id(&root, &state, &input.evidence_id)?;
    ensure!(
        crate::rewrite::api_selector::public_api(&api) == input.api,
        "investigation evidence belongs to another canonical API"
    );
    crate::rewrite::worker::ensure_api_confirmed(
        &state,
        &api,
        "submitting a Target-request investigation",
    )?;
    let selected = crate::rewrite::inventory::scoped(&state, Some(&api.parse()?))?;
    let original = source::load(&state)?;
    let attempt = selected
        .attempts
        .last()
        .context("investigation has no real execution")?
        .attempt;
    let context = crate::E2eRunContext {
        target_root: root.clone(),
        case_source: selected.case_source.clone().context("Source absent")?,
        run_key: None,
    };
    let group = selected.group_id.as_deref().context("API group absent")?;
    let summary = crate::e2e_run::finalized_focused_attempt_summary(context.clone(), group)?;
    ensure!(summary.attempt == attempt, "investigation attempt changed");
    let evidence = crate::e2e_run::resolve_e2e_response_rule_evidence(context, group)?;
    let bytes = fs::read(&evidence.replay)?;
    let report: Value = serde_json::from_slice(&bytes)?;
    let unmatched_ids = unmatched_observations(&report, &summary.selected_case_ids);
    ensure!(
        input.target_observation_ids.is_subset(&unmatched_ids),
        "investigation must select exact unmatched requests from the current actual report"
    );
    let manifest: WitnessManifest = serde_json::from_value(report["policy_witnesses"].clone())?;
    ensure!(
        manifest.complete && manifest.sealed,
        "independent Target observation coverage must be sealed and complete"
    );
    let _private = crate::policy_evidence::verify(&evidence.replay, &manifest)?;
    let graph = manifest
        .graph()
        .context("independent Target request graph absent")?;
    let mut observations = BTreeMap::new();
    for target in graph
        .targets
        .iter()
        .filter(|target| input.target_observation_ids.contains(&target.id))
    {
        ensure!(
            target.metadata.role == TargetRole::IndependentTargetObservation
                && target.metadata.surface == Surface::DependencyRequest
                && summary.selected_case_ids.contains(&target.metadata.case_id),
            "Target observation is not an independent request in this exact API attempt"
        );
        observations.insert(
            target.id.clone(),
            json!({"case_id":target.metadata.case_id,"resource":target.metadata.resource,
            "operation":target.metadata.operation,"clocks":target.metadata.clocks}),
        );
    }
    ensure!(
        observations.len() == input.target_observation_ids.len(),
        "investigation references an absent Target observation"
    );
    let id = source::digest(&serde_json::to_vec(&(
        &state.workflow_id,
        &api,
        attempt,
        &input.target_observation_ids,
    ))?);
    if !state.dependency_review.investigations.contains_key(&id) {
        state.dependency_review.investigations.insert(
            id.clone(),
            TargetInvestigation {
                id: id.clone(),
                kind: "target_request_investigation".into(),
                api: input.api.clone(),
                method_api: api,
                recording_run_id: state.recording_run_id.clone(),
                source_revision: selected
                    .source_revision
                    .clone()
                    .context("Source revision absent")?,
                source_inventory_id: original.identity,
                attempt,
                session_id: report["session_id"]
                    .as_str()
                    .context("actual session absent")?
                    .into(),
                report_sha256: source::digest(&bytes),
                target_observations: observations,
                candidate_discovery: BTreeMap::new(),
                reason: input.reason,
                status: ClaimStatus::Pending,
                resolution: None,
            },
        );
        state.dependency_review.revision += 1;
        state.bump();
        store.save(&state)?;
    }
    Ok(
        json!({"schema":SCHEMA,"investigation_id":id,"status":"implementation_diagnosis_required","owner":"api_implementer","accepted":false,
        "does_not_prove":"Missing traffic has the reporting API's owner. Unmatched evidence does not establish async behavior or a recording omission.",
        "next_command":crate::rewrite::action::command(&root,vec!["dependency-attribution".into(),"show".into(),"--api".into(),input.api],vec![])}),
    )
}

pub(super) fn unmatched_observations(report: &Value, cases: &BTreeSet<String>) -> BTreeSet<String> {
    let mut ids = BTreeSet::new();
    for events in [
        report["unmatched_queries"].as_array(),
        report["unmatched_http_requests"].as_array(),
        report["redis"]["unmatched"].as_array(),
        report["memcached"]["unmatched"].as_array(),
        report["motan"]["unmatched"].as_array(),
        report["kafka"]["unmatched"].as_array(),
    ]
    .into_iter()
    .flatten()
    {
        for event in events.iter().filter(|event| {
            event["case_id"]
                .as_str()
                .is_some_and(|case| cases.contains(case))
        }) {
            if let Some(id) = event["target_observation_id"].as_str() {
                ids.insert(id.into());
            }
        }
    }
    ids
}

pub(super) fn refresh(state: &mut crate::rewrite::model::RewriteState) {
    let attempts = std::iter::once(&state.active_slice)
        .chain(state.parked_slices.values())
        .filter_map(|slice| {
            slice
                .attempts
                .last()
                .map(|attempt| (slice.api.clone(), attempt.attempt))
        })
        .collect::<BTreeMap<_, _>>();
    for request in state
        .dependency_review
        .investigations
        .values_mut()
        .filter(|request| {
            request.recording_run_id == state.recording_run_id
                && matches!(
                    request.status,
                    ClaimStatus::Pending | ClaimStatus::Unresolved
                )
        })
    {
        if attempts
            .get(&request.method_api)
            .is_some_and(|attempt| *attempt > request.attempt)
        {
            // Preserve the old observations and conclusion without transferring
            // them to a different execution or inventing a passing verdict.
            request.status = ClaimStatus::Superseded;
        }
    }
}

pub(super) fn apply_resolution(
    state: &mut crate::rewrite::model::RewriteState,
    resolution: &InvestigationResolution,
) -> Result<()> {
    let request = state
        .dependency_review
        .investigations
        .get(&resolution.investigation_id)
        .context("unknown Target investigation")?
        .clone();
    ensure!(
        request.recording_run_id == state.recording_run_id,
        "Target investigation belongs to another recording"
    );
    resolution.proof.validate(
        state
            .source_revision
            .as_deref()
            .context("Source revision absent")?,
    )?;
    ensure!(
        !resolution.source_task.trim().is_empty() && !resolution.reason.trim().is_empty(),
        "resolution requires an actual Source entrypoint and a factual result"
    );
    let requirement = match resolution.outcome {
        InvestigationOutcome::MissingCapture => Some(VerificationRequirement::Capture),
        InvestigationOutcome::CrossScope => Some(VerificationRequirement::Replay),
        _ => None,
    };
    if let Some(requirement) = requirement {
        let proof_id = source::digest(&serde_json::to_vec(resolution)?);
        let id = source::digest(&serde_json::to_vec(&(
            &proof_id,
            &resolution.origin_scope,
            requirement,
        ))?);
        state.dependency_review.obligations.insert(
            id.clone(),
            ScopeObligation {
                id,
                scope: resolution.origin_scope.clone(),
                requirement,
                source_revision: resolution.proof.source_revision.clone(),
                baseline_recording_run_id: state.recording_run_id.clone(),
                proof_id,
                reason: resolution.reason.clone(),
                completed_by_session: None,
                retired_reason: None,
            },
        );
    }
    let request = state
        .dependency_review
        .investigations
        .get_mut(&resolution.investigation_id)
        .expect("known investigation");
    request.status = if matches!(resolution.outcome, InvestigationOutcome::Unresolved) {
        ClaimStatus::Unresolved
    } else {
        ClaimStatus::Proved
    };
    request.resolution = Some(resolution.outcome);
    Ok(())
}

pub(super) fn for_api(
    root: &std::path::Path,
    state: &crate::rewrite::model::RewriteState,
    api: &str,
) -> Result<Vec<Value>> {
    let requests = state
        .dependency_review
        .investigations
        .values()
        .filter(|request| {
            request.method_api == api && request.recording_run_id == state.recording_run_id
        })
        .collect::<Vec<_>>();
    if requests.is_empty() {
        return Ok(vec![]);
    }
    let source = source::load(state)?;
    let active = super::rules::fingerprints(&super::rules::load(root)?)?;
    let owners = state
        .dependency_review
        .decisions
        .iter()
        .filter(|(_, decision)| super::rules::current(decision, &active))
        .map(|(id, decision)| (*id, decision.owner.clone()))
        .collect();
    Ok(requests.into_iter().map(|request| {
        let discovery = request.target_observations.iter().map(|(id, observation)|
            (id.clone(), super::queries::candidate_page(root, state, &source, (&request.id, id), observation, &owners, 0)))
            .collect::<BTreeMap<_,_>>();
        json!({"investigation":request,"owner":"api_implementer","candidate_discovery":discovery,
            "expected_revision":state.dependency_review.revision,
            "resolve_command":crate::rewrite::action::command(root,vec!["dependency-attribution".into(),"resolve".into(),"--file".into(),"<implementer-diagnosis.json>".into()],vec![]),
            "required_diagnosis":"Trace the reporting API's async lifecycle, cache and real dependency client. Publish its async API rule if scope is wrong; otherwise prove the exact capture omission and interception/response-rewrite change. Do not send owned missing traffic to the repository analyst."})
    }).collect())
}
