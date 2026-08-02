use anyhow::{Context, Result, ensure};

use super::model::{
    RewriteApiInventoryView, RewriteApiProgress, RewriteApiStatus, RewritePhase, RewriteState,
};
use crate::RecordingApi;

pub(super) fn initialize_legacy(state: &mut RewriteState) -> bool {
    let mut changed = false;
    if state.recording_apis.is_empty() && !state.api.is_empty() {
        state.recording_apis.push(state.api.clone());
        changed = true;
    }
    if state.api_inventory.is_empty() && !state.api.is_empty() {
        let complete = state.phase == RewritePhase::SliceComplete;
        state.api_inventory.push(RewriteApiProgress {
            api: state.api.clone(),
            source_route: Some(state.source_route.clone()),
            status: if complete {
                RewriteApiStatus::Complete
            } else {
                RewriteApiStatus::Active
            },
            attempts: state.attempts.len(),
            e2e_current: state.e2e_current,
            comparison_current: state.comparison_current,
        });
        state.current_api_index = (!complete).then_some(0);
        changed = true;
    }
    changed
}

pub(super) fn recording_scope(state: &RewriteState) -> Vec<String> {
    if state.recording_apis.is_empty() && !state.api.is_empty() {
        vec![state.api.clone()]
    } else {
        state.recording_apis.clone()
    }
}

pub(super) fn install(state: &mut RewriteState, apis: Vec<String>) -> Result<()> {
    ensure!(
        !apis.is_empty(),
        "standard recording contains no API inventory"
    );
    state.api_inventory = apis
        .into_iter()
        .enumerate()
        .map(|(index, api)| {
            let parsed = api.parse::<RecordingApi>()?;
            let source_route = if parsed.is_dynamic() {
                (state.api == api && !state.source_route.is_empty())
                    .then(|| state.source_route.clone())
            } else {
                Some(parsed.path_pattern().to_string())
            };
            Ok(RewriteApiProgress {
                api,
                source_route,
                status: if index == 0 {
                    RewriteApiStatus::Active
                } else {
                    RewriteApiStatus::Pending
                },
                attempts: 0,
                e2e_current: false,
                comparison_current: false,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    state.current_api_index = Some(0);
    load_current(state)?;
    Ok(())
}

pub(super) fn bind_options(
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
    super::validate_single_line("source route", route)?;
    ensure!(
        !state.api.is_empty(),
        "--source-route requires an active API"
    );
    if state.source_route.is_empty() {
        let api = state.api.parse::<RecordingApi>()?;
        ensure!(
            api.is_dynamic(),
            "static API {} already has a canonical source route",
            state.api
        );
        state.source_route = route.to_string();
        let index = state
            .current_api_index
            .context("active API has no inventory index")?;
        state.api_inventory[index].source_route = Some(route.to_string());
        state.bump();
        return Ok(true);
    }
    ensure!(
        state.source_route == route,
        "active rewrite source route is {:?}; refusing a different --source-route",
        state.source_route
    );
    Ok(false)
}

pub(super) fn current_requires_source_route(state: &RewriteState) -> bool {
    !state.api.is_empty()
        && state.source_route.is_empty()
        && state
            .api
            .parse::<RecordingApi>()
            .is_ok_and(|api| api.is_dynamic())
}

pub(super) fn complete_current_and_advance(state: &mut RewriteState) -> Result<bool> {
    let index = state
        .current_api_index
        .context("completed API has no inventory index")?;
    let current = state
        .api_inventory
        .get_mut(index)
        .context("completed API inventory index is invalid")?;
    current.status = RewriteApiStatus::Complete;
    current.attempts = state.attempts.len();
    current.e2e_current = state.e2e_current;
    current.comparison_current = state.comparison_current;

    let next = state
        .api_inventory
        .iter()
        .position(|item| item.status == RewriteApiStatus::Pending);
    let Some(next) = next else {
        state.current_api_index = None;
        return Ok(false);
    };
    state.api_inventory[next].status = RewriteApiStatus::Active;
    state.current_api_index = Some(next);
    clear_active_evidence(state);
    load_current(state)?;
    state.phase = RewritePhase::ApiPending;
    Ok(true)
}

pub(super) fn reset_for_recording(state: &mut RewriteState) {
    state.api_inventory.clear();
    state.current_api_index = None;
    if state.recording_apis.len() == 1 {
        state.api = state.recording_apis[0].clone();
        if let Ok(api) = state.api.parse::<RecordingApi>() {
            state.source_route = if api.is_dynamic() {
                String::new()
            } else {
                api.path_pattern().to_string()
            };
        }
    } else {
        state.api.clear();
        state.source_route.clear();
    }
}

pub(super) fn view(state: &RewriteState) -> RewriteApiInventoryView {
    let mut items = state.api_inventory.clone();
    if let Some(index) = state.current_api_index
        && let Some(current) = items.get_mut(index)
    {
        current.source_route = (!state.source_route.is_empty()).then(|| state.source_route.clone());
        current.attempts = state.attempts.len();
        current.e2e_current = state.e2e_current;
        current.comparison_current = state.comparison_current;
    }
    RewriteApiInventoryView {
        total: items.len(),
        completed: items
            .iter()
            .filter(|item| item.status == RewriteApiStatus::Complete)
            .count(),
        current_index: state.current_api_index,
        current_api: state
            .current_api_index
            .and_then(|index| items.get(index))
            .map(|item| item.api.clone()),
        items,
    }
}

fn load_current(state: &mut RewriteState) -> Result<()> {
    let index = state
        .current_api_index
        .context("rewrite API inventory has no active index")?;
    let current = state
        .api_inventory
        .get(index)
        .context("rewrite API inventory index is invalid")?;
    state.api = current.api.clone();
    state.source_route = current.source_route.clone().unwrap_or_default();
    Ok(())
}

fn clear_active_evidence(state: &mut RewriteState) {
    state.comparison_run_id = None;
    state.comparison_rejection = None;
    state.case_source = None;
    state.case_inventory_id = None;
    state.source_revision = None;
    state.group_id = None;
    state.target_fingerprint = None;
    state.attempts.clear();
    state.attempt_delta = None;
    state.active_issue = None;
    state.rule_plan = None;
    state.dependency_rule_plan = None;
    state.route = None;
    state.e2e_current = false;
    state.comparison_current = false;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn advances_across_recorded_apis_without_replacing_the_standard_run() {
        let mut state = crate::rewrite::test_state();
        let run_id = state.recording_run_id.clone();
        install(
            &mut state,
            vec!["GET /a".to_string(), "POST /b".to_string()],
        )
        .unwrap();
        state.e2e_current = true;
        state.comparison_current = true;

        assert!(complete_current_and_advance(&mut state).unwrap());
        assert_eq!(state.api, "POST /b");
        assert_eq!(state.phase, RewritePhase::ApiPending);
        assert_eq!(state.recording_run_id, run_id);
        let inventory = view(&state);
        assert_eq!(inventory.total, 2);
        assert_eq!(inventory.completed, 1);
        assert_eq!(inventory.current_index, Some(1));
        assert_eq!(inventory.current_api.as_deref(), Some("POST /b"));
        assert_eq!(inventory.items[0].status, RewriteApiStatus::Complete);
        assert_eq!(inventory.items[1].status, RewriteApiStatus::Active);
    }
}
