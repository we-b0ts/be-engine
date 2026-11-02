//! Ownership questions select analyst work; already owned failures do not.
use super::{model::ClaimStatus, source};
use crate::rewrite::model::{RewriteAction, RewriteInputRequiredReason, RewriteState};
use anyhow::Result;
use std::{collections::BTreeMap, path::Path};

pub(super) fn refresh_inventory(root: &Path, state: &mut RewriteState) -> Result<()> {
    if state.case_source.is_none() {
        return Ok(());
    }
    let Ok((identity, unattributed)) = source::inventory(state) else {
        // The action owner surfaces malformed/missing inventory as an input
        // requirement; unrelated read-only diagnostics remain available.
        return Ok(());
    };
    let defaults = super::case_defaults::load(state.case_source.as_ref().unwrap(), Some(root))?;
    state
        .dependency_review
        .unresolved_source_exchange_ids
        .retain(|id| !defaults.contains_key(id));
    if unattributed == defaults.len() as u64 {
        // Inventory admission is mechanical, not a claim that the repository was
        // analyzed or that any dependency was consumed successfully.
        state.dependency_review.recording_run_id = Some(state.recording_run_id.clone());
        state.dependency_review.source_inventory_id = Some(identity);
        state
            .dependency_review
            .unresolved_source_exchange_ids
            .clear();
    }
    Ok(())
}

fn ownerless(root: &Path, state: &RewriteState) -> Result<u64> {
    if state.case_source.is_none() {
        return Ok(0);
    }
    let (identity, captured) = source::inventory(state)?;
    if captured == 0 {
        return Ok(0);
    }
    let defaults = super::case_defaults::load(state.case_source.as_ref().unwrap(), Some(root))?;
    let captured = captured.saturating_sub(defaults.len() as u64);
    if !state.dependency_review.decisions.is_empty() {
        let active = super::rules::fingerprints(&super::rules::load(root)?)?;
        if state
            .dependency_review
            .decisions
            .templates()
            .any(|decision| {
                !super::rules::current(decision, &active)
                    || Some(decision.proof.source_revision.as_str())
                        != state.source_revision.as_deref()
            })
        {
            // A read-only caller may hold a pre-refresh state. Never let cached
            // unresolved IDs authorize Replay after the rules lost their proof.
            return Ok(captured);
        }
    }
    if state.dependency_review.recording_run_id.as_deref() == Some(&state.recording_run_id)
        && state.dependency_review.source_inventory_id.as_deref() == Some(&identity)
    {
        Ok(state
            .dependency_review
            .unresolved_source_exchange_ids
            .iter()
            .filter(|id| !defaults.contains_key(id))
            .count() as u64)
    } else {
        Ok(captured)
    }
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
