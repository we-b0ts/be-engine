//! Validate source-route bindings before persistence and repair unused invalid bindings.
use anyhow::{Context, Result, ensure};

use crate::RecordingApi;
use crate::rewrite::model::{RewritePhase, RewriteState};

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
        // Only an invalid route with no verification history can be corrected.
        ensure!(
            validate_source_route(&api, &state.source_route).is_err()
                && state.phase == RewritePhase::ApiPending
                && state.group_id.is_none()
                && state.attempts.is_empty()
                && !state.e2e_current
                && !state.comparison_current,
            "active rewrite source route is {:?}; refusing a different --source-route unless the existing binding is invalid and has no group or verification history",
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
    state.bump();
    Ok(true)
}

#[cfg(test)]
mod tests;
