//! Explicit API verification is separate from acceptance of the final full sweep.
use super::*;
use crate::model::{RewriteApiProgress, RewritePhase};

fn queued_success(state: &RewriteState, item: &RewriteApiProgress) -> bool {
    item.status == RewriteApiStatus::Active
        && item.api == state.api
        && state.phase == RewritePhase::ApiPending
        && state.attempts.is_empty()
        && item.verified_target_fingerprint.is_some()
}

pub(super) fn eligible(state: &RewriteState, item: &RewriteApiProgress) -> bool {
    matches!(
        item.status,
        RewriteApiStatus::Complete | RewriteApiStatus::RevalidationPending
    ) || queued_success(state, item)
}

pub(super) fn request(state: &mut RewriteState, requested: &[String]) -> Result<()> {
    ensure!(
        !requested.is_empty(),
        "focused verification requires an API"
    );
    ensure!(
        available(state),
        "focused verification must wait for unfinished implementations, repairs, initial API attempts, active issues, replay completion and pending plans"
    );
    for api in requested {
        ensure!(
            state
                .api_inventory
                .iter()
                .any(|item| item.api == *api && eligible(state, item)),
            "API {api} is not a prior success eligible for focused verification"
        );
    }
    // Retire only scheduling/admission of the idle final sweep. Its failed
    // capture, original receipts and all verification obligations remain intact.
    for item in &mut state.api_inventory {
        if item.status == RewriteApiStatus::Active {
            item.status = RewriteApiStatus::RevalidationPending;
        }
        if requested.contains(&item.api) {
            item.status = RewriteApiStatus::Pending;
            item.e2e_current = false;
            state.parked_slices.remove(&item.api);
        }
    }
    state.revalidation_round = None;
    state.pre_revalidation_review = None;
    let first = state
        .api_inventory
        .iter()
        .position(|item| requested.contains(&item.api))
        .context("focused verification lost its API inventory")?;
    inventory::resume_at(state, first)?;
    state.bump();
    Ok(())
}

pub(super) fn available(state: &RewriteState) -> bool {
    !state.api_inventory.is_empty()
        && state
            .api_inventory
            .iter()
            .all(|item| item.status == RewriteApiStatus::Skipped || eligible(state, item))
        && !crate::transition::replay_completion_pending(state)
        && state.active_issue.is_none()
        && state.group_replay.is_none()
        && state.source_review_rework.is_empty()
        && !crate::rule_plans::pending(state)
}

#[cfg(test)]
mod tests;
