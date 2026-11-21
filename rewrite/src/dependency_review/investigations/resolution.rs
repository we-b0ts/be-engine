//! Coordinator publication of the existing API implementer's Source diagnosis.
use super::{InvestigationOutcome, InvestigationResolution};
use crate::dependency_review::{AttributionCommandOptions, SCHEMA, source};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::fs;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TargetInvestigationResolutionSubmission {
    pub schema: String,
    pub evidence_id: String,
    pub expected_revision: u64,
    pub resolution: InvestigationResolution,
}

pub fn resolve_target_investigation(options: AttributionCommandOptions) -> Result<Value> {
    let (root, store) = super::super::open(&options.target_root)?;
    let input: TargetInvestigationResolutionSubmission =
        serde_json::from_slice(&fs::read(options.file)?)?;
    ensure!(
        input.schema == SCHEMA,
        "unsupported investigation resolution schema"
    );
    let _lock = store.lock()?;
    let mut state = store.load()?.context("rewrite workflow absent")?;
    ensure!(
        input.expected_revision == state.dependency_review.revision,
        "investigation revision changed; obtain the current API investigation before resolving it"
    );
    let api = crate::inventory::api_for_rule_evidence_id(&root, &state, &input.evidence_id)?;
    crate::worker::ensure_api_confirmed(
        &state,
        &api,
        "submitting the API implementer's missing-traffic diagnosis",
    )?;
    let request = state
        .dependency_review
        .investigations
        .get(&input.resolution.investigation_id)
        .context("unknown Target investigation")?;
    ensure!(
        request.method_api == api
            && request.recording_run_id == state.recording_run_id
            && request.source_inventory_id == source::inventory_identity(&state)?
            && Some(request.source_revision.as_str()) == state.source_revision.as_deref(),
        "investigation does not belong to this API and current Source inventory"
    );
    let selected = crate::inventory::scoped(&state, Some(&api.parse()?))?;
    ensure!(
        selected
            .attempts
            .last()
            .is_some_and(|attempt| attempt.attempt == request.attempt),
        "investigation belongs to a superseded API attempt"
    );
    let evidence = crate::e2e_run::resolve_e2e_response_rule_evidence(
        crate::E2eRunContext {
            target_root: root.clone(),
            case_source: selected.case_source.clone().context("Source absent")?,
            run_key: None,
        },
        selected.group_id.as_deref().context("API group absent")?,
    )?;
    ensure!(
        source::digest(&fs::read(evidence.replay)?) == request.report_sha256,
        "investigation report changed since the actual Target observation"
    );
    if matches!(
        input.resolution.outcome,
        InvestigationOutcome::CrossScope | InvestigationOutcome::MissingCapture
    ) {
        ensure!(
            crate::verification_obligations::scope_matches_api(
                &input.resolution.origin_scope,
                &api
            ),
            "missing traffic is owned by its reporting API; another owner requires a separate concrete Source ownership return"
        );
    }
    if matches!(input.resolution.outcome, InvestigationOutcome::CrossScope) {
        ensure!(
            super::super::rules::load(&root)?
                .async_api
                .get(&api)
                .is_some_and(|rules| !rules.is_empty()),
            "publish the reporting API's supported async_api lifecycle rule before resolving an asynchronous scope gap"
        );
    }
    super::apply_resolution(&mut state, &input.resolution)?;
    state.dependency_review.revision += 1;
    state.bump();
    store.save(&state)?;
    Ok(
        json!({"schema":SCHEMA,"investigation_id":input.resolution.investigation_id,
        "owner":"api_implementer","outcome":input.resolution.outcome,"accepted":false,
        "next_command":crate::action::next_command(&root)}),
    )
}
