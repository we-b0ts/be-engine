//! Paginated offline investigation over authenticated Source/Target metadata.
use super::{model::SCHEMA, source::SourceSnapshot};
use crate::{
    dependency::attribution::DependencyOwner,
    rewrite::{RewriteContext, model::RewriteState},
};
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use std::{collections::BTreeMap, path::Path};
use uuid::Uuid;

pub fn dependency_attribution_candidates(
    context: RewriteContext,
    investigation: &str,
    target: &str,
    revision: u64,
    offset: usize,
) -> Result<Value> {
    let (root, store) = super::open(&context.target_root)?;
    let state = store.load()?.context("rewrite workflow absent")?;
    ensure!(
        state.dependency_review.revision == revision,
        "attribution revision changed; obtain fresh context before continuing pagination"
    );
    let source = super::source::load(&state)?;
    let request = state
        .dependency_review
        .investigations
        .get(investigation)
        .context("investigation absent")?;
    ensure!(
        request.recording_run_id == state.recording_run_id
            && Some(request.source_revision.as_str()) == state.source_revision.as_deref()
            && request.source_inventory_id == source.identity,
        "investigation belongs to another authenticated Source revision or recording inventory"
    );
    let observation = request
        .target_observations
        .get(target)
        .context("Target observation is outside this authenticated investigation")?;
    let active = super::rules::fingerprints(&super::rules::load(&root)?)?;
    let owners = state
        .dependency_review
        .decisions
        .iter()
        .filter(|(_, decision)| super::rules::current(decision, &active))
        .map(|(id, decision)| (*id, decision.owner.clone()))
        .collect();
    Ok(candidate_page(
        &root,
        &state,
        &source,
        (investigation, target),
        observation,
        &owners,
        offset,
    ))
}

pub(super) fn candidate_page(
    root: &Path,
    state: &RewriteState,
    source: &SourceSnapshot,
    request: (&str, &str),
    observation: &Value,
    owners: &BTreeMap<Uuid, DependencyOwner>,
    offset: usize,
) -> Value {
    let (investigation, target) = request;
    let mut page = source.discovery.discover(observation, owners, offset, 20);
    page["schema"] = json!(SCHEMA);
    page["investigation_id"] = json!(investigation);
    page["target_observation_id"] = json!(target);
    page["recording_run_id"] = json!(state.recording_run_id);
    page["source_inventory_id"] = json!(source.identity);
    page["source_revision"] = json!(state.source_revision);
    page["proof_revision"] = json!(state.dependency_review.revision);
    page["next_command"] = page["next_offset"]
        .as_u64()
        .map(|next| {
            json!(crate::rewrite::action::command(
                root,
                vec![
                    "dependency-attribution".into(),
                    "candidates".into(),
                    "--investigation".into(),
                    investigation.into(),
                    "--target-observation".into(),
                    target.into(),
                    "--revision".into(),
                    state.dependency_review.revision.to_string(),
                    "--offset".into(),
                    next.to_string()
                ],
                vec![]
            ))
        })
        .unwrap_or(Value::Null);
    page
}

pub fn dependency_attribution_rules(context: RewriteContext) -> Result<Value> {
    let (root, store) = super::open(&context.target_root)?;
    let state = store.load()?.context("rewrite workflow absent")?;
    let policy = super::rules::load(&root)?;
    Ok(
        json!({"schema":SCHEMA,"policy_fingerprint":policy.fingerprints.full,"source_revision":state.source_revision,
        "rule_groups":super::rules::groups(&policy)?,"binding_contract":"Bind all selector rule IDs of one process task, or the actual origin API end-only lifecycle rule. Names alone are not proofs.",
        "plan_command":crate::rewrite::action::command(&root,vec!["rule".into(),"plan".into(),"--file".into(),"<proposal.json>".into(),"--evidence".into(),"<current-evidence-id>".into()],vec![]),
        "apply_contract":"Apply the planned rule first; then obtain fresh attribution context and submit its effective policy fingerprint and complete rule group."}),
    )
}
