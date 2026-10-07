//! Worker route selection is separate from method-specific recording contracts.
use anyhow::{Context, Result, ensure};

use super::{
    RewriteContext,
    model::{RewriteApiStatus, RewriteState},
    store::RewriteStore,
};
use crate::RecordingApi;

pub use crate::recording_api::RecordingApiScope as RewriteApiSelector;

pub(super) fn route(api: &str) -> &str {
    api.split_once(' ').map_or(api, |(_, path)| path)
}

pub(super) fn public_api(api: &str) -> &str {
    crate::recording_api::identity(api)
}

pub(super) fn members(state: &RewriteState, selector: &RewriteApiSelector) -> Vec<String> {
    state
        .api_inventory
        .iter()
        .filter(|item| match selector {
            RewriteApiSelector::Route(path) => {
                !item.api.starts_with("MOTAN ") && route(&item.api) == path
            }
            RewriteApiSelector::Motan(api) => item.api == api.to_string(),
        })
        .map(|item| item.api.clone())
        .collect()
}

pub(super) fn select(state: &RewriteState, selector: &RewriteApiSelector) -> Result<RecordingApi> {
    if let RewriteApiSelector::Motan(api) = selector {
        return Ok(api.clone());
    }
    let candidates = members(state, selector);
    ensure!(
        !candidates.is_empty(),
        "recorded API inventory does not contain {selector:?}"
    );
    let selected = candidates
        .iter()
        .min_by_key(|api| {
            let item = state
                .api_inventory
                .iter()
                .find(|item| &item.api == *api)
                .unwrap();
            let priority = match item.status {
                RewriteApiStatus::Active if !super::regression_scope::is_skipped(state, api) => 0,
                RewriteApiStatus::ImplementationRequired => 1,
                RewriteApiStatus::Pending | RewriteApiStatus::RevalidationPending => 2,
                RewriteApiStatus::SystemRepairRequired => 3,
                _ => 4,
            };
            (priority, *api)
        })
        .unwrap();
    selected.parse()
}

/// HTTP workers always own the canonical route, independent of method progress.
pub(super) fn work_scope(_state: &RewriteState, api: &str) -> super::RewriteWorkScope {
    super::RewriteWorkScope::Api {
        api: public_api(api).into(),
    }
}

pub(super) fn scoped(state: &RewriteState, api: &str) -> Result<RewriteState> {
    // Method keys are internal ledger references, never public selectors.
    if api.contains(' ') {
        return super::inventory::scoped(state, Some(&api.parse()?));
    }
    if state.api_inventory.is_empty() && public_api(&state.api) == api {
        return Ok(state.clone());
    }
    let selector = api.parse::<RewriteApiSelector>()?;
    let selected = if matches!(selector, RewriteApiSelector::Route(_)) {
        let mut candidates = members(state, &selector);
        candidates.sort();
        candidates
            .iter()
            .find(|api| {
                let slice = if state.api == **api {
                    Some(&state.active_slice)
                } else {
                    state.parked_slices.get(*api)
                };
                slice.is_some_and(|slice| {
                    slice.active_issue.is_some()
                        && slice.phase == super::RewritePhase::ImplementationRequired
                })
            })
            .map(|api| api.parse())
            .transpose()?
            .unwrap_or(select(state, &selector)?)
    } else {
        select(state, &selector)?
    };
    super::inventory::scoped(state, Some(&selected))
}

pub(super) fn canonical_scope(
    state: &RewriteState,
    scope: &super::RewriteWorkScope,
) -> super::RewriteWorkScope {
    match scope {
        super::RewriteWorkScope::Api { api } => work_scope(state, api),
        _ => scope.clone(),
    }
}

pub fn status_rewrite_for_selector(
    context: RewriteContext,
    selector: &RewriteApiSelector,
) -> Result<super::RewriteStatusReport> {
    if let RewriteApiSelector::Motan(api) = selector {
        return super::status_rewrite_for_api(context, Some(api));
    }
    let state = RewriteStore::new(&context.target_root)?.load()?.context(
        "route selection requires a recorded API inventory; start with next without --api",
    )?;
    let selected = select(&state, selector)?;
    super::status_rewrite_for_api(context, Some(&selected))
}

#[cfg(test)]
mod tests;
