//! Worker route selection is separate from method-specific recording contracts.
use std::{fmt, str::FromStr};

use anyhow::{Context, Result, ensure};

use super::{
    RewriteContext,
    model::{RewriteApiStatus, RewriteState},
    store::RewriteStore,
};
use crate::RecordingApi;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RewriteApiSelector {
    Route(String),
    Method(RecordingApi),
}

impl FromStr for RewriteApiSelector {
    type Err = anyhow::Error;
    fn from_str(value: &str) -> Result<Self> {
        ensure!(
            !value.split(' ').next().unwrap_or("").contains('|'),
            "select a route or one METHOD API; combined method selectors are not supported"
        );
        if value.starts_with('/') {
            // Reuse the recording path grammar without inventing a wildcard method.
            let api = format!("GET {value}").parse::<RecordingApi>()?;
            Ok(Self::Route(api.path_pattern().into()))
        } else {
            Ok(Self::Method(value.parse()?))
        }
    }
}

impl fmt::Display for RewriteApiSelector {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Route(route) => formatter.write_str(route),
            Self::Method(api) => api.fmt(formatter),
        }
    }
}

impl From<RecordingApi> for RewriteApiSelector {
    fn from(api: RecordingApi) -> Self {
        Self::Method(api)
    }
}

pub(super) fn route(api: &str) -> &str {
    api.split_once(' ').map_or(api, |(_, path)| path)
}

pub(super) fn members(state: &RewriteState, selector: &RewriteApiSelector) -> Vec<String> {
    state
        .api_inventory
        .iter()
        .filter(|item| match selector {
            RewriteApiSelector::Route(path) => {
                !item.api.starts_with("MOTAN ") && route(&item.api) == path
            }
            RewriteApiSelector::Method(api) => item.api == api.to_string(),
        })
        .map(|item| item.api.clone())
        .collect()
}

pub(super) fn select(state: &RewriteState, selector: &RewriteApiSelector) -> Result<RecordingApi> {
    if let RewriteApiSelector::Method(api) = selector {
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

/// Existing method-owned tasks retain their identity and receipts. New work uses
/// one path-owned worker; no implicit transfer between historical workers.
pub(super) fn work_scope(state: &RewriteState, api: &str) -> super::RewriteWorkScope {
    let path = route(api);
    if api.starts_with("MOTAN ") || !state.route_worker_scopes && api.contains(' ') {
        return super::RewriteWorkScope::Api { api: api.into() };
    }
    let legacy = state
        .worker_bindings
        .keys()
        .find(|key| key.contains(' ') && route(key) == path);
    super::RewriteWorkScope::Api {
        api: match legacy {
            Some(key) if !api.contains(' ') => key.as_str(),
            Some(_) => api,
            None => path,
        }
        .into(),
    }
}

pub(super) fn scoped(state: &RewriteState, api: &str) -> Result<RewriteState> {
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
    if let RewriteApiSelector::Method(api) = selector {
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
