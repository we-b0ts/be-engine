//! Ownership questions select analyst work; already owned failures do not.
use super::{model::ClaimStatus, source};
use crate::dependency::{attribution::DependencyOwner, observation::CaptureMetadata};
use crate::rewrite::model::{RewriteAction, RewriteInputRequiredReason, RewriteState};
use anyhow::{Context, Result};
use std::{
    borrow::Cow,
    collections::{BTreeMap, BTreeSet},
    path::Path,
};
use uuid::Uuid;

type CaseDefaults = BTreeMap<Uuid, DependencyOwner>;

pub(super) fn refresh_inventory(root: &Path, state: &mut RewriteState) -> Result<()> {
    let Some(source_path) = &state.case_source else {
        return Ok(());
    };
    let Ok((identity, _)) = source::inventory(state) else {
        // The action owner surfaces malformed/missing inventory as an input
        // requirement; unrelated read-only diagnostics remain available.
        return Ok(());
    };
    let defaults = super::scope_defaults::load(source_path, Some(root))?;
    let default_identity = defaults.identity()?;
    if cache_current(state, &identity, &default_identity) && decisions_current(root, state)? {
        return Ok(());
    }
    let unresolved = unresolved(root, state, &identity, &defaults.owners)?;
    // Admission is mechanical. A changed default must restore previously
    // removed IDs instead of trusting an old empty ownership review.
    state.dependency_review.recording_run_id = Some(state.recording_run_id.clone());
    state.dependency_review.source_inventory_id = Some(identity);
    state.dependency_review.case_defaults_identity = Some(default_identity);
    state.dependency_review.unresolved_source_exchange_ids = unresolved;
    Ok(())
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
    let (recording, manifest) = crate::dependency_index::recording::manifest(source_path)?;
    if manifest.semantic_inventory.unattributed_dependencies == 0
        && !defaults
            .values()
            .any(|owner| matches!(owner, DependencyOwner::Unattributed { .. }))
    {
        return Ok(BTreeSet::new());
    }
    crate::dependency_index::recording::authenticate(&recording)?;
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
    let mut input = crate::dependency_index::RecordStream::open(
        &recording.join("indexes/unattributed-scope.json"),
    )?;
    let mut unresolved = defaults
        .iter()
        .filter_map(|(id, owner)| {
            (matches!(owner, DependencyOwner::Unattributed { .. }) && !proved.contains(id))
                .then_some(*id)
        })
        .collect::<BTreeSet<_>>();
    while let Some((_, bytes)) = input.next()? {
        if bytes.iter().all(u8::is_ascii_whitespace) {
            continue;
        }
        let event: serde_json::Value = serde_json::from_slice(bytes)?;
        let capture: CaptureMetadata = serde_json::from_value(event["capture"].clone())?;
        if capture.semantic_required
            && matches!(capture.attribution, DependencyOwner::Unattributed { .. })
            && !defaults
                .get(&capture.exchange_id)
                .is_some_and(|owner| !matches!(owner, DependencyOwner::Unattributed { .. }))
            && !proved.contains(&capture.exchange_id)
        {
            unresolved.insert(capture.exchange_id);
        }
    }
    Ok(unresolved)
}

fn ownerless(root: &Path, state: &RewriteState) -> Result<u64> {
    if state.case_source.is_none() {
        return Ok(0);
    }
    Ok(review_inventory(root, state)?.1.len() as u64)
}

/// The same sealed admission inventory serves status and read-only context.
/// It does not establish rule coverage or authorize an ownership decision.
pub(super) fn review_inventory<'a>(
    root: &Path,
    state: &'a RewriteState,
) -> Result<(String, Cow<'a, BTreeSet<Uuid>>)> {
    let source_path = state
        .case_source
        .as_deref()
        .context("workflow has no Source recording")?;
    let (identity, _) = source::inventory(state)?;
    let defaults = super::scope_defaults::load(source_path, Some(root))?;
    if cache_current(state, &identity, &defaults.identity()?) && decisions_current(root, state)? {
        return Ok((
            identity,
            Cow::Borrowed(&state.dependency_review.unresolved_source_exchange_ids),
        ));
    }
    let ids = unresolved(root, state, &identity, &defaults.owners)?;
    Ok((identity, Cow::Owned(ids)))
}

pub(in crate::rewrite) fn required_action(
    root: &Path,
    state: &RewriteState,
) -> Option<RewriteAction> {
    let unowned = match ownerless(root, state) {
        Ok(count) => count,
        Err(error) => {
            return Some(RewriteAction::InputRequired {
                reason: RewriteInputRequiredReason::RecordingEvidenceRequired,
                summary: format!("cannot establish Source dependency ownership: {error:#}"),
                required: vec!["provide the current sealed dependency inventory".into()],
                recording_input_diagnosis: None,
            });
        }
    };
    let disputed = state
        .dependency_review
        .claims
        .values()
        .filter(|claim| {
            claim.recording_run_id == state.recording_run_id
                && matches!(claim.status, ClaimStatus::Pending | ClaimStatus::Unresolved)
        })
        .count();
    (unowned > 0 || disputed > 0).then(|| RewriteAction::DependencyAttributionRequired {
        summary: format!(
            "resolve {unowned} ownerless Source dependencies and {disputed} ownership returns through the repository analyst before formal Replay; apply supported owner rules or reject mistaken returns"
        ),
        assignment_id: super::assignment_id(state).expect("serializable attribution assignment"),
        dispatch_generation: state.dependency_review.revision,
        claim_kinds: BTreeMap::from([
            ("unattributed_source".into(), usize::try_from(unowned).unwrap_or(usize::MAX)),
            ("foreign_unused".into(), disputed),
        ]),
        context: crate::rewrite::action::command(root, vec!["dependency-attribution".into(), "context".into()], vec![]),
        apply: crate::rewrite::action::command(root, vec!["dependency-attribution".into(), "apply".into(), "--file".into(), "<attribution.json>".into()], vec![]),
    })
}
