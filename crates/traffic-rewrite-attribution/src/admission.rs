//! Sealed Source admission inventory and rule-bound unresolved ownership reads.
use super::source;
use anyhow::{Context, Result};
use std::{
    borrow::Cow,
    collections::{BTreeMap, BTreeSet},
    path::Path,
};
use traffic_engine::{attribution_review, dependency::attribution::DependencyOwner};
use traffic_rewrite_model::rewrite::model::RewriteState;
use uuid::Uuid;

type CaseDefaults = BTreeMap<Uuid, DependencyOwner>;

pub fn refresh_inventory(root: &Path, state: &mut RewriteState) -> Result<()> {
    let Some(source_path) = &state.case_source else {
        return Ok(());
    };
    let Ok((identity, _)) = source::inventory(state) else {
        // The action owner surfaces malformed/missing inventory as an input
        // requirement; unrelated read-only diagnostics remain available.
        return Ok(());
    };
    let defaults = super::case_defaults::load(source_path, Some(root))?;
    let default_identity = defaults_identity(&defaults)?;
    if cache_current(state, &identity, &default_identity) && decisions_current(root, state)? {
        return Ok(());
    }
    let unresolved = unresolved(root, state, &identity, &defaults)?;
    // Admission is mechanical. A changed default must restore previously
    // removed IDs instead of trusting an old empty ownership review.
    state.dependency_review.recording_run_id = Some(state.recording_run_id.clone());
    state.dependency_review.source_inventory_id = Some(identity);
    state.dependency_review.case_defaults_identity = Some(default_identity);
    state.dependency_review.unresolved_source_exchange_ids = unresolved;
    Ok(())
}

fn defaults_identity(defaults: &CaseDefaults) -> Result<String> {
    Ok(traffic_engine::policy_evidence::digest(
        &serde_json::to_vec(&("dependency-attribution-admission/v2", defaults))?,
    ))
}

fn cache_current(state: &RewriteState, inventory: &str, defaults: &str) -> bool {
    state.dependency_review.recording_run_id.as_deref() == Some(state.recording_run_id.as_str())
        && state.dependency_review.source_inventory_id.as_deref() == Some(inventory)
        && state.dependency_review.case_defaults_identity.as_deref() == Some(defaults)
}

fn decisions_current(root: &Path, state: &RewriteState) -> Result<bool> {
    if state.dependency_review.decisions.is_empty() {
        return Ok(true);
    }
    let active = super::rules::fingerprints(&super::rules::load(root)?)?;
    Ok(state
        .dependency_review
        .decisions
        .templates()
        .all(|decision| {
            super::rules::current(decision, &active)
                && Some(decision.proof.source_revision.as_str()) == state.source_revision.as_deref()
        }))
}

fn unresolved(
    root: &Path,
    state: &RewriteState,
    inventory: &str,
    defaults: &CaseDefaults,
) -> Result<BTreeSet<Uuid>> {
    let source_path = state
        .case_source
        .as_ref()
        .expect("Source inventory present");
    let mut proved = BTreeSet::new();
    if state.dependency_review.source_inventory_id.as_deref() == Some(inventory)
        && !state.dependency_review.decisions.is_empty()
    {
        let active = super::rules::fingerprints(&super::rules::load(root)?)?;
        proved.extend(
            state
                .dependency_review
                .decisions
                .iter()
                .filter(|(_, decision)| {
                    super::rules::current(*decision, &active)
                        && Some(decision.proof.source_revision.as_str())
                            == state.source_revision.as_deref()
                })
                .map(|(id, _)| *id),
        );
    }
    let admission = attribution_review::admission(source_path)?;
    Ok(admission
        .captured
        .into_iter()
        .filter(|id| {
            !defaults.contains_key(id)
                && !proved.contains(id)
                && !admission.optional_controls.contains(id)
        })
        .collect())
}

/// The same sealed admission inventory serves status and read-only context.
/// It does not establish rule coverage or authorize an ownership decision.
pub fn review_inventory<'a>(
    root: &Path,
    state: &'a RewriteState,
) -> Result<(String, Cow<'a, BTreeSet<Uuid>>)> {
    let source_path = state
        .case_source
        .as_deref()
        .context("workflow has no Source recording")?;
    let (identity, captured) = source::inventory(state)?;
    if captured == 0 {
        return Ok((identity, Cow::Owned(BTreeSet::new())));
    }
    let defaults = super::case_defaults::load(source_path, Some(root))?;
    if cache_current(state, &identity, &defaults_identity(&defaults)?)
        && decisions_current(root, state)?
    {
        return Ok((
            identity,
            Cow::Borrowed(&state.dependency_review.unresolved_source_exchange_ids),
        ));
    }
    let ids = unresolved(root, state, &identity, &defaults)?;
    Ok((identity, Cow::Owned(ids)))
}
