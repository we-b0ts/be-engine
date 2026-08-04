use anyhow::{Context, Result, ensure};

use super::model::{
    RewriteApiInventoryDetails, RewriteApiInventoryView, RewriteApiProgress, RewriteApiStatus,
    RewritePhase, RewriteSliceState, RewriteState,
};
use crate::RecordingApi;

const MAX_CONCURRENT_AI_WORK_ITEMS: usize = 32;

pub(super) fn initialize_legacy(state: &mut RewriteState) -> bool {
    let mut changed = false;
    if state.api_inventory.is_empty() && !state.api.is_empty() {
        if state.recording_apis.is_empty() {
            state.recording_apis.push(state.api.clone());
        }
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
            verified_target_fingerprint: state.target_fingerprint.clone(),
        });
        state.current_api_index = (!complete).then_some(0);
        changed = true;
    }
    if explicit_recording_scope_conflicts_with_inventory(state) {
        state.recording_apis.clear();
        changed = true;
    }
    changed
}

fn explicit_recording_scope_conflicts_with_inventory(state: &RewriteState) -> bool {
    !state.recording_apis.is_empty()
        && !state.api_inventory.is_empty()
        && (state.recording_apis.len() != state.api_inventory.len()
            || state
                .recording_apis
                .iter()
                .any(|api| !state.api_inventory.iter().any(|item| item.api == *api)))
}

pub(super) fn recording_scope(state: &RewriteState) -> Vec<String> {
    if state.recording_apis.is_empty() && state.api_inventory.is_empty() && !state.api.is_empty() {
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
                verified_target_fingerprint: None,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let installed_apis = state
        .api_inventory
        .iter()
        .map(|item| item.api.clone())
        .collect::<Vec<_>>();
    state
        .worker_bindings
        .retain(|api, _| installed_apis.contains(api));
    state.parked_slices.clear();
    state.current_api_index = Some(0);
    load_pending(state, 0)?;
    Ok(())
}

pub(super) fn activate_requested(
    state: &mut RewriteState,
    requested_api: Option<&RecordingApi>,
) -> Result<bool> {
    let Some(requested_api) = requested_api else {
        return Ok(false);
    };
    let requested = requested_api.to_string();
    if state.api == requested {
        return Ok(false);
    }
    ensure!(
        matches!(
            state.phase,
            RewritePhase::ApiPending | RewritePhase::ImplementationRequired
        ),
        "API {} is currently in {:?}; wait for its deterministic traffic operation before selecting {requested}",
        state.api,
        state.phase
    );
    let requested_index = state
        .api_inventory
        .iter()
        .position(|item| item.api == requested)
        .with_context(|| format!("recorded API inventory does not contain {requested:?}"))?;
    ensure!(
        matches!(
            state.api_inventory[requested_index].status,
            RewriteApiStatus::Pending | RewriteApiStatus::ImplementationRequired
        ),
        "API {requested} is not available for concurrent AI work"
    );
    if state.api_inventory[requested_index].status == RewriteApiStatus::Pending {
        let retained_work_items = state.parked_slices.len()
            + usize::from(state.phase == RewritePhase::ImplementationRequired);
        ensure!(
            retained_work_items < MAX_CONCURRENT_AI_WORK_ITEMS,
            "concurrent AI work item limit of {MAX_CONCURRENT_AI_WORK_ITEMS} was reached"
        );
    }

    if state.phase == RewritePhase::ImplementationRequired {
        super::worker::ensure_current_confirmed(state)?;
        park_current_implementation(state)?;
    } else {
        let current_index = state
            .current_api_index
            .context("active API has no inventory index")?;
        state.api_inventory[current_index].status = RewriteApiStatus::Pending;
    }
    state.current_api_index = Some(requested_index);
    state.api_inventory[requested_index].status = RewriteApiStatus::Active;
    state.active_slice = match state.parked_slices.remove(&requested) {
        Some(slice) => slice,
        None => pending_slice(&state.api_inventory[requested_index])?,
    };
    state.bump();
    Ok(true)
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

pub(super) fn scoped(
    state: &RewriteState,
    requested_api: Option<&RecordingApi>,
) -> Result<RewriteState> {
    let Some(requested_api) = requested_api else {
        return Ok(state.clone());
    };
    let requested = requested_api.to_string();
    if state.api == requested {
        return Ok(state.clone());
    }
    let index = state
        .api_inventory
        .iter()
        .position(|item| item.api == requested)
        .with_context(|| format!("recorded API inventory does not contain {requested:?}"))?;
    let item = &state.api_inventory[index];
    let slice = match state.parked_slices.get(&requested).cloned() {
        Some(slice) => slice,
        None if item.status == RewriteApiStatus::Pending => pending_slice(item)?,
        None if item.status == RewriteApiStatus::Complete => completed_slice(item)?,
        None => anyhow::bail!("API {requested} has no concurrent AI work state"),
    };
    let mut scoped = state.clone();
    scoped.active_slice = slice;
    scoped.current_api_index = Some(index);
    Ok(scoped)
}

pub(super) fn api_for_evidence_query(
    target_root: &std::path::Path,
    state: &RewriteState,
    query_id: &str,
) -> Option<String> {
    slices(state).find_map(|slice| {
        super::evidence::commands(target_root, &slice)
            .iter()
            .any(|command| command.query_id == query_id)
            .then(|| slice.api.clone())
    })
}

pub(super) fn api_for_evidence_id(
    target_root: &std::path::Path,
    state: &RewriteState,
    evidence_id: &str,
) -> Option<String> {
    slices(state).find_map(|slice| {
        super::evidence::commands(target_root, &slice)
            .into_iter()
            .any(|command| {
                super::evidence::query(target_root, &slice, &command.query_id)
                    .is_ok_and(|report| report.evidence_id == evidence_id)
            })
            .then(|| slice.api.clone())
    })
}

pub(super) fn api_for_rule_plan(state: &RewriteState, plan_id: &str) -> Option<String> {
    slices(state).find_map(|slice| {
        slice
            .rule_plan
            .as_ref()
            .is_some_and(|plan| plan.id == plan_id)
            .then(|| slice.api.clone())
    })
}

pub(super) fn api_for_dependency_rule_plan(state: &RewriteState, plan_id: &str) -> Option<String> {
    slices(state).find_map(|slice| {
        slice
            .dependency_rule_plan
            .as_ref()
            .is_some_and(|plan| plan.id == plan_id)
            .then(|| slice.api.clone())
    })
}

pub(super) fn api_for_repair(state: &RewriteState, repair_id: &str) -> Option<String> {
    slices(state).find_map(|slice| {
        slice
            .route
            .as_ref()
            .and_then(|route| route.repair_id.as_deref())
            .is_some_and(|candidate| candidate == repair_id)
            .then(|| slice.api.clone())
    })
}

pub(super) fn with_slice_mut<T>(
    state: &mut RewriteState,
    api: &str,
    operation: impl FnOnce(&mut RewriteState) -> Result<T>,
) -> Result<T> {
    if state.api == api {
        return operation(state);
    }
    let slice = state
        .parked_slices
        .remove(api)
        .with_context(|| format!("API {api} has no concurrent AI work state"))?;
    let active = std::mem::replace(&mut state.active_slice, slice);
    let current_index = state.current_api_index;
    state.current_api_index = state.api_inventory.iter().position(|item| item.api == api);
    let result = operation(state);
    let updated = std::mem::replace(&mut state.active_slice, active);
    state.current_api_index = current_index;
    state.parked_slices.insert(api.to_string(), updated);
    result
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
    let attempts = state.attempts.len();
    let e2e_current = state.e2e_current;
    let comparison_current = state.comparison_current;
    let target_fingerprint = state.target_fingerprint.clone();
    let current = state
        .api_inventory
        .get_mut(index)
        .context("completed API inventory index is invalid")?;
    current.status = RewriteApiStatus::Complete;
    current.attempts = attempts;
    current.e2e_current = e2e_current;
    current.comparison_current = comparison_current;
    current.verified_target_fingerprint = target_fingerprint;

    let next = state
        .api_inventory
        .iter()
        .position(|item| item.status == RewriteApiStatus::Pending);
    let next = next.or_else(|| {
        state
            .api_inventory
            .iter()
            .position(|item| item.status == RewriteApiStatus::ImplementationRequired)
    });
    let Some(next) = next else {
        state.current_api_index = None;
        return Ok(false);
    };
    state.api_inventory[next].status = RewriteApiStatus::Active;
    state.current_api_index = Some(next);
    let api = state.api_inventory[next].api.clone();
    if let Some(slice) = state.parked_slices.remove(&api) {
        state.active_slice = slice;
    } else {
        state.active_slice = pending_slice(&state.api_inventory[next])?;
    }
    Ok(true)
}

pub(super) fn reset_for_recording(state: &mut RewriteState) {
    state.api_inventory.clear();
    state.current_api_index = None;
    state.parked_slices.clear();
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

pub(super) fn invalidate_completed_for_target_change(
    state: &mut RewriteState,
    target_fingerprint: &str,
) -> Result<bool> {
    let mut changed = false;
    for item in &mut state.api_inventory {
        if item.status == RewriteApiStatus::Complete
            && item.verified_target_fingerprint.as_deref() != Some(target_fingerprint)
        {
            item.status = RewriteApiStatus::Pending;
            item.e2e_current = false;
            item.comparison_current = false;
            item.verified_target_fingerprint = None;
            changed = true;
        }
    }
    if changed && state.phase == RewritePhase::SliceComplete {
        let next = state
            .api_inventory
            .iter()
            .position(|item| item.status == RewriteApiStatus::Pending)
            .context("invalidated API inventory has no pending slice")?;
        state.api_inventory[next].status = RewriteApiStatus::Active;
        state.current_api_index = Some(next);
        load_pending(state, next)?;
    }
    if changed {
        state.bump();
    }
    Ok(changed)
}

pub(super) fn restore_recorded_progress(
    state: &mut RewriteState,
    apis: Vec<String>,
    active_api: &str,
) -> Result<()> {
    install(state, apis)?;
    let active = state
        .api_inventory
        .iter()
        .position(|item| item.api == active_api)
        .with_context(|| format!("recorded API inventory does not contain {active_api:?}"))?;
    for (index, item) in state.api_inventory.iter_mut().enumerate() {
        item.status = match index.cmp(&active) {
            std::cmp::Ordering::Less => RewriteApiStatus::Complete,
            std::cmp::Ordering::Equal => RewriteApiStatus::Active,
            std::cmp::Ordering::Greater => RewriteApiStatus::Pending,
        };
    }
    state.current_api_index = Some(active);
    load_pending(state, active)
}

pub(super) fn view(state: &RewriteState) -> RewriteApiInventoryView {
    RewriteApiInventoryView {
        total: state.api_inventory.len(),
        completed: state
            .api_inventory
            .iter()
            .filter(|item| item.status == RewriteApiStatus::Complete)
            .count(),
        pending: state
            .api_inventory
            .iter()
            .filter(|item| item.status == RewriteApiStatus::Pending)
            .count(),
        implementation_required: state
            .api_inventory
            .iter()
            .filter(|item| item.status == RewriteApiStatus::ImplementationRequired)
            .count(),
        current_index: state.current_api_index,
        current_api: state
            .current_api_index
            .and_then(|index| state.api_inventory.get(index))
            .map(|item| item.api.clone()),
    }
}

pub(super) fn details(state: &RewriteState) -> RewriteApiInventoryDetails {
    let mut items = state.api_inventory.clone();
    if let Some(index) = state.current_api_index
        && let Some(current) = items.get_mut(index)
    {
        current.source_route = (!state.source_route.is_empty()).then(|| state.source_route.clone());
        current.attempts = state.attempts.len();
        current.e2e_current = state.e2e_current;
        current.comparison_current = state.comparison_current;
    }
    RewriteApiInventoryDetails {
        summary: view(state),
        items,
    }
}

fn load_pending(state: &mut RewriteState, index: usize) -> Result<()> {
    let current = state
        .api_inventory
        .get(index)
        .context("rewrite API inventory index is invalid")?;
    state.active_slice = pending_slice(current)?;
    Ok(())
}

fn pending_slice(current: &RewriteApiProgress) -> Result<RewriteSliceState> {
    let api = current.api.parse::<RecordingApi>()?;
    Ok(RewriteSliceState::pending(
        current.api.clone(),
        current.source_route.clone().unwrap_or_else(|| {
            if api.is_dynamic() {
                String::new()
            } else {
                api.path_pattern().to_string()
            }
        }),
    ))
}

fn completed_slice(current: &RewriteApiProgress) -> Result<RewriteSliceState> {
    let mut slice = pending_slice(current)?;
    slice.phase = RewritePhase::SliceComplete;
    slice.target_fingerprint = current.verified_target_fingerprint.clone();
    slice.e2e_current = current.e2e_current;
    slice.comparison_current = current.comparison_current;
    Ok(slice)
}

fn park_current_implementation(state: &mut RewriteState) -> Result<()> {
    ensure!(
        state.phase == RewritePhase::ImplementationRequired,
        "only an implementation issue can be parked for concurrent AI work"
    );
    let index = state
        .current_api_index
        .context("active API has no inventory index")?;
    let attempts = state.attempts.len();
    let e2e_current = state.e2e_current;
    let comparison_current = state.comparison_current;
    let current = state
        .api_inventory
        .get_mut(index)
        .context("active API inventory index is invalid")?;
    current.status = RewriteApiStatus::ImplementationRequired;
    current.attempts = attempts;
    current.e2e_current = e2e_current;
    current.comparison_current = comparison_current;
    state
        .parked_slices
        .insert(state.api.clone(), state.active_slice.clone());
    Ok(())
}

fn slices(state: &RewriteState) -> impl Iterator<Item = RewriteState> + '_ {
    std::iter::once(state.clone()).chain(state.parked_slices.values().cloned().map(|slice| {
        let mut scoped = state.clone();
        scoped.active_slice = slice;
        scoped
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn modern_all_configured_inventory_keeps_its_omitted_recording_scope() {
        let mut state = crate::rewrite::test_state();
        install(
            &mut state,
            vec!["GET /a".to_string(), "POST /b".to_string()],
        )
        .unwrap();
        state.recording_apis.clear();

        assert!(!initialize_legacy(&mut state));
        assert!(state.recording_apis.is_empty());
        assert_eq!(
            crate::rewrite::action::workflow_view(&state).scope,
            "all_configured_apis"
        );
    }

    #[test]
    fn stale_single_api_scope_is_cleared_from_a_multi_api_inventory() {
        let mut state = crate::rewrite::test_state();
        install(
            &mut state,
            vec!["GET /a".to_string(), "POST /b".to_string()],
        )
        .unwrap();
        state.recording_apis = vec!["GET /a".to_string()];

        assert!(initialize_legacy(&mut state));
        assert!(state.recording_apis.is_empty());
        assert_eq!(
            crate::rewrite::action::workflow_view(&state).scope,
            "all_configured_apis"
        );
    }

    #[test]
    fn explicit_single_api_scope_remains_bound_to_its_inventory() {
        let mut state = crate::rewrite::test_state();
        install(&mut state, vec!["GET /a".to_string()]).unwrap();
        state.recording_apis = vec!["GET /a".to_string()];

        assert!(!initialize_legacy(&mut state));
        assert_eq!(state.recording_apis, ["GET /a"]);
        assert_eq!(
            crate::rewrite::action::workflow_view(&state).scope,
            "GET /a"
        );
    }

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
        assert_eq!(inventory.pending, 0);
        assert_eq!(inventory.implementation_required, 0);
        assert_eq!(inventory.current_index, Some(1));
        assert_eq!(inventory.current_api.as_deref(), Some("POST /b"));
        let serialized = serde_json::to_value(&inventory).unwrap();
        assert!(serialized.get("items").is_none());

        let details = details(&state);
        assert_eq!(details.items[0].status, RewriteApiStatus::Complete);
        assert_eq!(details.items[1].status, RewriteApiStatus::Active);
    }

    #[test]
    fn implementation_issue_can_be_parked_while_another_api_becomes_active() {
        let mut state = crate::rewrite::test_state();
        install(
            &mut state,
            vec!["GET /a".to_string(), "POST /b".to_string()],
        )
        .unwrap();
        state.phase = RewritePhase::ImplementationRequired;
        state.target_fingerprint = Some("target-a".to_string());
        state.active_issue = Some(test_issue("issue-a", "target-a"));

        let api_b = "POST /b".parse::<RecordingApi>().unwrap();
        let error = activate_requested(&mut state, Some(&api_b)).unwrap_err();
        assert!(error.to_string().contains("subagent dispatch is confirmed"));
        super::super::worker::confirm_current_for_test(&mut state);

        assert!(activate_requested(&mut state, Some(&api_b)).unwrap());
        assert_eq!(state.api, "POST /b");
        assert_eq!(state.phase, RewritePhase::ApiPending);
        assert_eq!(
            state.api_inventory[0].status,
            RewriteApiStatus::ImplementationRequired
        );
        assert_eq!(state.api_inventory[1].status, RewriteApiStatus::Active);
        assert_eq!(view(&state).implementation_required, 1);

        let api_a = "GET /a".parse::<RecordingApi>().unwrap();
        let scoped = scoped(&state, Some(&api_a)).unwrap();
        assert_eq!(scoped.api, "GET /a");
        assert_eq!(scoped.phase, RewritePhase::ImplementationRequired);
        assert_eq!(scoped.target_fingerprint.as_deref(), Some("target-a"));

        state.phase = RewritePhase::ImplementationRequired;
        state.target_fingerprint = Some("target-b".to_string());
        state.active_issue = Some(test_issue("issue-b", "target-b"));
        super::super::worker::confirm_current_for_test(&mut state);
        assert!(activate_requested(&mut state, Some(&api_a)).unwrap());
        assert_eq!(state.api, "GET /a");
        assert_eq!(state.target_fingerprint.as_deref(), Some("target-a"));
        assert_eq!(
            state.parked_slices["POST /b"].target_fingerprint.as_deref(),
            Some("target-b")
        );
    }

    fn test_issue(id: &str, target_fingerprint: &str) -> crate::rewrite::model::RewriteIssue {
        crate::rewrite::model::RewriteIssue {
            id: id.to_string(),
            kind: crate::rewrite::model::RewriteIssueKind::Response,
            owner: crate::rewrite::model::RewriteIssueOwner::TargetCode,
            summary: "implementation differs".to_string(),
            pointer_pattern: None,
            representative: None,
            possible_causes: Vec::new(),
            observed_target_fingerprint: target_fingerprint.to_string(),
            attempt: 1,
            comparison_observation: None,
        }
    }

    #[test]
    fn status_can_scope_an_untouched_pending_or_completed_api() {
        let mut state = crate::rewrite::test_state();
        install(
            &mut state,
            vec!["GET /a".to_string(), "POST /b".to_string()],
        )
        .unwrap();
        let api_b = "POST /b".parse::<RecordingApi>().unwrap();

        let pending = scoped(&state, Some(&api_b)).unwrap();
        assert_eq!(pending.api, "POST /b");
        assert_eq!(pending.phase, RewritePhase::ApiPending);

        state.api_inventory[1].status = RewriteApiStatus::Complete;
        state.api_inventory[1].e2e_current = true;
        state.api_inventory[1].comparison_current = true;
        state.api_inventory[1].verified_target_fingerprint = Some("target-b".to_string());
        let complete = scoped(&state, Some(&api_b)).unwrap();
        assert_eq!(complete.phase, RewritePhase::SliceComplete);
        assert_eq!(complete.target_fingerprint.as_deref(), Some("target-b"));
        assert!(complete.e2e_current);
        assert!(complete.comparison_current);
        assert!(
            !super::super::action::for_state(std::path::Path::new("/target"), &complete)
                .terminal_allowed
        );
    }

    #[test]
    fn completed_slice_is_requeued_when_the_target_revision_changes() {
        let mut state = crate::rewrite::test_state();
        install(
            &mut state,
            vec!["GET /a".to_string(), "POST /b".to_string()],
        )
        .unwrap();
        state.target_fingerprint = Some("target-r0".to_string());
        state.e2e_current = true;
        state.comparison_current = true;
        state.phase = RewritePhase::ImplementationRequired;
        state.active_issue = Some(test_issue("issue-a", "target-r0"));
        super::super::worker::confirm_current_for_test(&mut state);
        assert!(complete_current_and_advance(&mut state).unwrap());
        assert_eq!(state.api_inventory[0].status, RewriteApiStatus::Complete);
        assert!(state.worker_bindings.contains_key("GET /a"));

        assert!(invalidate_completed_for_target_change(&mut state, "target-r1").unwrap());
        assert_eq!(state.api_inventory[0].status, RewriteApiStatus::Pending);
        assert!(!state.api_inventory[0].e2e_current);
        assert!(!state.api_inventory[0].comparison_current);
        assert!(state.api_inventory[0].verified_target_fingerprint.is_none());
        assert!(state.worker_bindings.contains_key("GET /a"));

        let api_a = "GET /a".parse::<RecordingApi>().unwrap();
        assert!(activate_requested(&mut state, Some(&api_a)).unwrap());
        state.phase = RewritePhase::ImplementationRequired;
        state.active_issue = Some(test_issue("issue-a-later", "target-r1"));
        assert_eq!(
            super::super::worker::dispatch_view(&state, None).state,
            crate::rewrite::model::RewriteWorkerDispatchState::ResumeRequired
        );
    }
}
