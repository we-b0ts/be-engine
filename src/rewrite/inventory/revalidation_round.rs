//! Durable membership of one complete revalidation sweep, independent of evidence freshness.
use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use super::{RewriteApiStatus, RewritePhase, RewriteState};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(in crate::rewrite) struct RevalidationRound {
    remaining: BTreeSet<String>,
}

pub(in crate::rewrite) fn ready(state: &RewriteState) -> bool {
    !state.api_inventory.is_empty()
        && state.source_review_rework.is_empty()
        && state.api_inventory.iter().all(|item| match item.status {
            RewriteApiStatus::Complete
            | RewriteApiStatus::Skipped
            | RewriteApiStatus::RevalidationPending
            | RewriteApiStatus::SystemRepairRequired => true,
            RewriteApiStatus::Active if item.api == state.api => matches!(
                state.phase,
                RewritePhase::SliceComplete | RewritePhase::SystemRepairRequired
            ),
            _ => false,
        })
}

pub(in crate::rewrite) fn contains(state: &RewriteState, api: &str) -> bool {
    state
        .revalidation_round
        .as_ref()
        .is_some_and(|round| round.remaining.contains(api))
}

pub(in crate::rewrite) fn next(state: &RewriteState) -> Option<&str> {
    let can_begin = state.revalidation_round.is_none() && ready(state);
    state.api_inventory.iter().find_map(|item| {
        let eligible = if state.revalidation_round.is_some() {
            contains(state, &item.api) && item.status != RewriteApiStatus::Skipped
        } else {
            can_begin && item.status == RewriteApiStatus::RevalidationPending
        };
        eligible.then_some(item.api.as_str())
    })
}

pub(in crate::rewrite) fn begin(state: &mut RewriteState) -> bool {
    if state.revalidation_round.is_some() || !ready(state) {
        return false;
    }
    let remaining: BTreeSet<_> = state
        .api_inventory
        .iter()
        .filter(|item| item.status == RewriteApiStatus::RevalidationPending)
        .map(|item| item.api.clone())
        .collect();
    if remaining.is_empty() {
        return false;
    }
    state.revalidation_round = Some(RevalidationRound { remaining });
    state.bump();
    true
}

/// A terminal failure consumes membership too; repairs wait until the sweep drains.
pub(in crate::rewrite) fn finish(state: &mut RewriteState, api: &str) {
    if let Some(round) = state.revalidation_round.as_mut() {
        round.remaining.remove(api);
        if round.remaining.is_empty() {
            state.revalidation_round = None;
        }
    }
}

pub(in crate::rewrite) fn reconcile_skips(state: &mut RewriteState) {
    let skipped = state
        .api_inventory
        .iter()
        .filter(|item| item.status == RewriteApiStatus::Skipped)
        .map(|item| item.api.clone())
        .collect::<Vec<_>>();
    for api in skipped {
        finish(state, &api);
    }
}

#[cfg(test)]
mod tests;
