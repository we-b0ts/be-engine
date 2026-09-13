//! Validate and retain source-route bindings across recording batches.
use anyhow::{Context, Result, ensure};

use crate::RecordingApi;
use crate::rewrite::model::{RewritePhase, RewriteState};

/// Recorded dynamic APIs are already canonicalized by a confirmed case pattern.
/// Use that pattern as the route specification when no more specific historical
/// source-route binding exists, so verification does not ask for the same route
/// analysis a second time.
pub(super) fn adopt_recorded_patterns(state: &mut RewriteState) -> bool {
    retain_bindings(state);
    let bindings = state.source_route_bindings.clone();
    let mut changed = false;
    for item in &mut state.api_inventory {
        if item.source_route.is_some() {
            continue;
        }
        let Ok(api) = item.api.parse::<RecordingApi>() else {
            continue;
        };
        if !api.is_dynamic() {
            continue;
        }
        item.source_route = Some(
            bindings
                .get(&item.api)
                .cloned()
                .unwrap_or_else(|| api.path_pattern().to_string()),
        );
        changed = true;
    }
    if !changed {
        return false;
    }

    let routes = state
        .api_inventory
        .iter()
        .filter_map(|item| {
            item.source_route
                .as_ref()
                .map(|route| (item.api.clone(), route.clone()))
        })
        .collect::<std::collections::BTreeMap<_, _>>();
    if state.source_route.is_empty()
        && let Some(route) = routes.get(&state.api)
    {
        state.source_route = route.clone();
    }
    for slice in state.parked_slices.values_mut() {
        if slice.source_route.is_empty()
            && let Some(route) = routes.get(&slice.api)
        {
            slice.source_route = route.clone();
        }
    }
    retain_bindings(state);
    true
}

pub(in crate::rewrite) fn validate_source_route(api: &RecordingApi, route: &str) -> Result<()> {
    crate::rewrite::validate_single_line("source route", route)?;
    if api.is_dynamic() {
        crate::case_group::validate_pattern_against_source_route(api.path_pattern(), route)
    } else {
        ensure!(
            route == api.path_pattern(),
            "static API {api} requires its canonical source route {:?}",
            api.path_pattern()
        );
        Ok(())
    }
}

/// Preserve valid bindings from legacy state before resetting its batch inventory.
/// Exact method/pattern keys prevent reuse for newly introduced or changed APIs.
pub(super) fn retain_bindings(state: &mut RewriteState) {
    let valid = |api: &str, route: &str| {
        api.parse::<RecordingApi>()
            .is_ok_and(|api| api.is_dynamic() && validate_source_route(&api, route).is_ok())
    };
    state
        .source_route_bindings
        .retain(|api, route| valid(api, route));
    for item in &state.api_inventory {
        if let Some(route) = &item.source_route
            && valid(&item.api, route)
        {
            state
                .source_route_bindings
                .insert(item.api.clone(), route.clone());
        }
    }
    if valid(&state.api, &state.source_route) {
        let api = state.api.clone();
        let route = state.source_route.clone();
        state.source_route_bindings.insert(api, route);
    }
}

pub(in crate::rewrite) fn bind_options(
    state: &mut RewriteState,
    requested_api: Option<&RecordingApi>,
    requested_source_route: Option<&str>,
) -> Result<bool> {
    if let Some(api) = requested_api {
        ensure!(
            state.api == api.to_string(),
            "active rewrite API is {}; refusing a different --api",
            state.api
        );
    }
    let Some(route) = requested_source_route else {
        return Ok(false);
    };
    ensure!(
        !state.api.is_empty(),
        "--source-route requires an active API"
    );
    let api = state.api.parse::<RecordingApi>()?;
    validate_source_route(&api, route)?;
    if state.source_route == route {
        return Ok(false);
    }
    ensure!(
        api.is_dynamic(),
        "static API {} already has a canonical source route",
        state.api
    );
    if !state.source_route.is_empty() {
        // Older engines persisted the binding before grouping validated it.
        // A recorded-pattern fallback may be refined to the complete source
        // registration route. Otherwise only an invalid route with no
        // verification history can be corrected.
        let pattern_fallback = state.source_route == api.path_pattern();
        ensure!(
            (pattern_fallback || validate_source_route(&api, &state.source_route).is_err())
                && state.phase == RewritePhase::ApiPending
                && state.group_id.is_none()
                && state.attempts.is_empty()
                && !state.e2e_current
                && !state.comparison_current,
            "active rewrite source route is {:?}; refusing a different --source-route unless it is a recorded-pattern fallback or invalid binding with no group or verification history",
            state.source_route
        );
    }
    let index = state
        .current_api_index
        .context("active API has no inventory index")?;
    let current = state
        .api_inventory
        .get(index)
        .context("active API inventory index is invalid")?;
    ensure!(
        current.api == state.api,
        "active API inventory does not match"
    );
    ensure!(
        current.attempts == 0
            && !current.e2e_current
            && !current.comparison_current
            && current.verified_target_fingerprint.is_none(),
        "cannot replace a source route with inventory verification history"
    );
    state.api_inventory[index].source_route = Some(route.to_string());
    state.source_route = route.to_string();
    state
        .source_route_bindings
        .insert(api.to_string(), route.to_string());
    state.bump();
    Ok(true)
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod recording_tests;
