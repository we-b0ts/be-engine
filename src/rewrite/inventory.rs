use anyhow::{Context, Result, ensure};

use super::model::{
    RewriteApiProgress, RewriteApiStatus, RewritePhase, RewriteSliceState, RewriteState,
};
use crate::RecordingApi;

pub(super) mod revalidation_round;
mod selection;
pub(super) use selection::{activate_requested, can_switch_api};
mod source_route;
pub(super) use source_route::{bind_options, validate_source_route};
mod views;
pub(super) use views::{details, view};

pub(super) const RECORDED_API_INVENTORY_SCOPE: &str = "recorded_api_inventory";

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
            verified_target_fingerprint: state.target_fingerprint.clone(),
        });
        state.current_api_index = (!complete).then_some(0);
        changed = true;
    }
    if explicit_recording_scope_conflicts_with_inventory(state) {
        state.recording_apis.clear();
        changed = true;
    }
    changed |= source_route::adopt_recorded_patterns(state);
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

/// Install a completed recording's canonical API inventory. The returned flag
/// reports whether at least one dynamic API uses its confirmed recorded pattern
/// because no more specific historical source route is available.
pub(super) fn install(state: &mut RewriteState, apis: Vec<String>) -> Result<bool> {
    ensure!(
        !apis.is_empty(),
        "standard recording contains no API inventory"
    );
    for api in &apis {
        api.parse::<RecordingApi>()?;
    }
    state
        .dependency_review
        .required_method_apis
        .extend(apis.iter().cloned());
    source_route::retain_bindings(state);
    state.skipped_api_statuses.clear();
    state.revalidation_round = None;
    state.pre_revalidation_review = None;
    state.api_inventory = apis
        .into_iter()
        .enumerate()
        .map(|(index, api)| {
            let parsed = api.parse::<RecordingApi>()?;
            let source_route = if parsed.is_dynamic() {
                state.source_route_bindings.get(&api).cloned()
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
                verified_target_fingerprint: None,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    source_route::adopt_recorded_patterns(state);
    let uses_recorded_patterns = state.api_inventory.iter().any(|item| {
        item.api.parse::<RecordingApi>().is_ok_and(|api| {
            api.is_dynamic() && item.source_route.as_deref() == Some(api.path_pattern())
        })
    });
    let installed_apis = state
        .api_inventory
        .iter()
        .map(|item| item.api.clone())
        .collect::<Vec<_>>();
    state.worker_bindings.retain(|api, binding| {
        installed_apis.contains(api) || binding.first_bound_at.is_some() || binding.expert.is_some()
    });
    state.parked_slices.clear();
    state.current_api_index = Some(0);
    load_pending(state, 0)?;
    Ok(uses_recorded_patterns)
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
        None if matches!(
            item.status,
            RewriteApiStatus::Pending | RewriteApiStatus::RevalidationPending
        ) =>
        {
            pending_slice(item)?
        }
        None if item.status == RewriteApiStatus::Complete => completed_slice(item)?,
        None => anyhow::bail!("API {requested} has no concurrent AI work state"),
    };
    let mut scoped = state.clone();
    if matches!(
        state.phase,
        RewritePhase::ImplementationRequired | RewritePhase::SystemRepairRequired
    ) {
        scoped
            .parked_slices
            .insert(state.api.clone(), state.active_slice.clone());
    }
    scoped.parked_slices.remove(&requested);
    scoped.active_slice = slice;
    scoped.current_api_index = Some(index);
    Ok(scoped)
}

pub(super) fn api_for_evidence_query(state: &RewriteState, query_id: &str) -> Option<String> {
    slices(state).find_map(|slice| {
        super::evidence::accepts_query(&slice, query_id).then(|| slice.api.clone())
    })
}

pub(super) fn api_for_evidence_id(
    target_root: &std::path::Path,
    state: &RewriteState,
    evidence_id: &str,
) -> Option<String> {
    slices(state).find_map(|slice| {
        super::evidence::report_for_id(target_root, &slice, evidence_id)
            .is_some()
            .then(|| slice.api.clone())
    })
}

pub(super) fn api_for_rule_evidence_id(
    target_root: &std::path::Path,
    state: &RewriteState,
    evidence_id: &str,
) -> Result<String> {
    if let Some(slice) = slices(state)
        .find(|slice| super::evidence::current_overview_matches(target_root, slice, evidence_id))
    {
        if let Some(detail) = super::evidence::commands(target_root, &slice)
            .into_iter()
            .find(|command| command.query_id.ends_with("unified-rule-candidates"))
        {
            anyhow::bail!(
                "current issue overview is not planning evidence; execute the returned detail command {}, then use that response's applicable planner and evidence_id. No new Replay or dispatch is required for this evidence-type correction",
                serde_json::to_string(&detail.command)?
            );
        }
        anyhow::bail!(
            "current issue overview is not planning evidence; follow its returned issue queries and actions before proposing a traffic rule"
        );
    }
    api_for_evidence_id(target_root, state, evidence_id)
        .context("rule evidence is stale or belongs to no concurrent API work item")
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

pub(super) fn api_for_recorder_capture_plan(state: &RewriteState, plan_id: &str) -> Option<String> {
    slices(state).find_map(|slice| {
        slice
            .recorder_capture_plan
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
    let target_fingerprint = state.target_fingerprint.clone();
    let current = state
        .api_inventory
        .get_mut(index)
        .context("completed API inventory index is invalid")?;
    current.status = RewriteApiStatus::Complete;
    current.attempts = attempts;
    current.e2e_current = e2e_current;
    current.verified_target_fingerprint = target_fingerprint;
    let mut completed = state.active_slice.clone();
    completed.phase = RewritePhase::SliceComplete;
    state.parked_slices.insert(state.api.clone(), completed);
    let api = state.api.clone();
    revalidation_round::finish(state, &api);

    let next = revalidation_round::next(state)
        .and_then(|api| state.api_inventory.iter().position(|item| item.api == api));
    let next = next.or_else(|| {
        state
            .api_inventory
            .iter()
            .position(|item| item.status == RewriteApiStatus::Pending)
    });
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
    revalidation_round::begin(state);
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

pub(super) fn mark_awaiting_recording_refresh(state: &mut RewriteState, api: &str) -> Result<bool> {
    let index = state
        .api_inventory
        .iter()
        .position(|item| item.api == api)
        .with_context(|| format!("recorded API inventory does not contain {api:?}"))?;
    let active_attempts = (state.api == api).then(|| state.attempts.len());
    let item = &mut state.api_inventory[index];
    item.status = RewriteApiStatus::AwaitingRecordingRefresh;
    if let Some(attempts) = active_attempts {
        item.attempts = attempts;
    }
    item.e2e_current = false;
    item.verified_target_fingerprint = None;

    if state.current_api_index == Some(index) {
        state
            .parked_slices
            .insert(api.to_string(), state.active_slice.clone());
        let next = next_runnable_index(state);
        if let Some(next) = next {
            state.api_inventory[next].status = RewriteApiStatus::Active;
            state.current_api_index = Some(next);
            let next_api = state.api_inventory[next].api.clone();
            state.active_slice = match state.parked_slices.remove(&next_api) {
                Some(slice) => slice,
                None => pending_slice(&state.api_inventory[next])?,
            };
        } else {
            state.current_api_index = None;
        }
    }
    state.bump();
    Ok(has_runnable_work(state))
}

pub(super) fn has_runnable_work(state: &RewriteState) -> bool {
    revalidation_round::next(state).is_some()
        || state.api_inventory.iter().any(|item| {
            matches!(
                item.status,
                RewriteApiStatus::Active
                    | RewriteApiStatus::Pending
                    | RewriteApiStatus::ImplementationRequired
            )
        })
}

pub(super) fn rebase_target_fingerprint(state: &mut RewriteState, previous: &str, current: &str) {
    for item in &mut state.api_inventory {
        if item.verified_target_fingerprint.as_deref() == Some(previous) {
            item.verified_target_fingerprint = Some(current.to_string());
        }
    }
    rebase_slice_fingerprint(&mut state.active_slice, previous, current);
    for slice in state.parked_slices.values_mut() {
        rebase_slice_fingerprint(slice, previous, current);
    }
}

fn rebase_slice_fingerprint(slice: &mut RewriteSliceState, previous: &str, current: &str) {
    if slice.target_fingerprint.as_deref() == Some(previous) {
        slice.target_fingerprint = Some(current.to_string());
    }
}

pub(super) fn next_runnable_index(state: &RewriteState) -> Option<usize> {
    revalidation_round::next(state)
        .and_then(|api| state.api_inventory.iter().position(|item| item.api == api))
        .or_else(|| {
            state
                .api_inventory
                .iter()
                .position(|item| item.status == RewriteApiStatus::Pending)
        })
        .or_else(|| {
            state
                .api_inventory
                .iter()
                .position(|item| item.status == RewriteApiStatus::ImplementationRequired)
        })
}

pub(super) fn reset_for_recording(state: &mut RewriteState) {
    source_route::retain_bindings(state);
    state.api_inventory.clear();
    state.revalidation_round = None;
    state.pre_revalidation_review = None;
    state.skipped_api_statuses.clear();
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
    super::group_replay::refresh(state);
}

pub(super) fn defer_completed_for_target_change(
    state: &mut RewriteState,
    target_fingerprint: &str,
) -> Result<bool> {
    let mut changed = false;
    for item in &mut state.api_inventory {
        if item.status == RewriteApiStatus::Complete
            && item.verified_target_fingerprint.as_deref() != Some(target_fingerprint)
        {
            state.parked_slices.remove(&item.api);
            item.status = RewriteApiStatus::RevalidationPending;
            item.e2e_current = false;
            changed = true;
        }
    }
    if changed {
        state.bump();
    }
    Ok(changed)
}

pub(super) fn next_pending_api_for_concurrent_work(state: &RewriteState) -> Option<&str> {
    state
        .api_inventory
        .iter()
        .find(|item| item.status == RewriteApiStatus::Pending)
        .map(|item| item.api.as_str())
}

pub(super) fn unattempted_apis(state: &RewriteState) -> impl Iterator<Item = &str> {
    let active = (state.phase == RewritePhase::ApiPending && state.attempts.is_empty())
        .then_some(state.api.as_str());
    let pending = state
        .api_inventory
        .iter()
        .filter(|item| item.status == RewriteApiStatus::Pending && item.attempts == 0)
        .map(|item| item.api.as_str());
    active
        .into_iter()
        .chain(pending)
        .filter(|api| !super::regression_scope::is_skipped(state, api))
}

fn load_pending(state: &mut RewriteState, index: usize) -> Result<()> {
    let current = state
        .api_inventory
        .get(index)
        .context("rewrite API inventory index is invalid")?;
    state.active_slice = pending_slice(current)?;
    Ok(())
}

pub(super) fn resume_at(state: &mut RewriteState, index: usize) -> Result<()> {
    if state.api_inventory[index].status == RewriteApiStatus::RevalidationPending {
        revalidation_round::begin(state);
        ensure!(
            revalidation_round::contains(state, &state.api_inventory[index].api),
            "API must wait for all implementation acceptances before revalidation"
        );
    }
    let item = &state.api_inventory[index];
    state.active_slice = match state.parked_slices.remove(&item.api) {
        Some(slice) => slice,
        None => pending_slice(item)?,
    };
    state.api_inventory[index].status = RewriteApiStatus::Active;
    state.current_api_index = Some(index);
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

pub(super) fn completed_slice(current: &RewriteApiProgress) -> Result<RewriteSliceState> {
    let mut slice = pending_slice(current)?;
    slice.phase = RewritePhase::SliceComplete;
    slice.target_fingerprint = current.verified_target_fingerprint.clone();
    slice.e2e_current = current.e2e_current;
    Ok(slice)
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
    fn modern_recorded_inventory_keeps_its_omitted_recording_scope() {
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
            RECORDED_API_INVENTORY_SCOPE
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
            RECORDED_API_INVENTORY_SCOPE
        );
    }

    #[test]
    fn explicit_single_api_scope_remains_bound_to_its_inventory() {
        let mut state = crate::rewrite::test_state();
        install(&mut state, vec!["GET /a".to_string()]).unwrap();
        state.recording_apis = vec!["GET /a".to_string()];

        assert!(!initialize_legacy(&mut state));
        assert_eq!(state.recording_apis, ["GET /a"]);
        assert_eq!(crate::rewrite::action::workflow_view(&state).scope, "/a");
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
        assert_eq!(inventory.current_api.as_deref(), Some("/b"));
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
            egress_rejections: None,
            recorder_capture_diagnosis: None,
            response_diagnosis: None,
            possible_causes: Vec::new(),
            observed_target_fingerprint: target_fingerprint.to_string(),
            attempt: 1,
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
        state.api_inventory[1].verified_target_fingerprint = Some("target-b".to_string());
        let complete = scoped(&state, Some(&api_b)).unwrap();
        assert_eq!(complete.phase, RewritePhase::SliceComplete);
        assert_eq!(complete.target_fingerprint.as_deref(), Some("target-b"));
        assert!(complete.e2e_current);
        assert!(
            !super::super::action::for_state(std::path::Path::new("/target"), &complete)
                .terminal_allowed
        );
    }

    #[test]
    fn completed_slice_is_deferred_until_normal_work_drains() {
        let mut state = crate::rewrite::test_state();
        install(
            &mut state,
            vec!["GET /a".to_string(), "POST /b".to_string()],
        )
        .unwrap();
        state.target_fingerprint = Some("target-r0".to_string());
        state.e2e_current = true;
        state.phase = RewritePhase::ImplementationRequired;
        state.active_issue = Some(test_issue("issue-a", "target-r0"));
        super::super::worker::confirm_current_for_test(&mut state);
        assert!(complete_current_and_advance(&mut state).unwrap());
        assert_eq!(state.api_inventory[0].status, RewriteApiStatus::Complete);
        assert!(state.worker_bindings.contains_key("/a"));

        assert!(defer_completed_for_target_change(&mut state, "target-r1").unwrap());
        assert_eq!(
            state.api_inventory[0].status,
            RewriteApiStatus::RevalidationPending
        );
        assert!(!state.api_inventory[0].e2e_current);
        assert_eq!(
            state.api_inventory[0]
                .verified_target_fingerprint
                .as_deref(),
            Some("target-r0")
        );
        assert!(state.worker_bindings.contains_key("/a"));

        state.target_fingerprint = Some("target-r1".to_string());
        state.e2e_current = true;
        assert!(complete_current_and_advance(&mut state).unwrap());
        assert_eq!(state.api, "GET /a");
        assert_eq!(state.phase, RewritePhase::ApiPending);
        assert_eq!(state.api_inventory[0].status, RewriteApiStatus::Active);
        assert_eq!(view(&state).revalidation_pending, 0);
    }

    #[test]
    fn terminal_target_change_defers_without_implicitly_starting_a_round() {
        let mut state = crate::rewrite::test_state();
        install(
            &mut state,
            vec!["GET /a".to_string(), "POST /b".to_string()],
        )
        .unwrap();
        for item in &mut state.api_inventory {
            item.status = RewriteApiStatus::Complete;
            item.e2e_current = true;
            item.verified_target_fingerprint = Some("target-r0".to_string());
        }
        state.phase = RewritePhase::SliceComplete;
        state.current_api_index = None;

        assert!(defer_completed_for_target_change(&mut state, "target-r1").unwrap());

        assert_eq!(state.phase, RewritePhase::SliceComplete);
        assert_eq!(state.current_api_index, None);
        assert_eq!(
            state.api_inventory[0].status,
            RewriteApiStatus::RevalidationPending
        );
        assert_eq!(
            state.api_inventory[1].status,
            RewriteApiStatus::RevalidationPending
        );
        assert_eq!(view(&state).revalidation_pending, 2);
    }

    #[test]
    fn capture_refresh_waiter_is_parked_while_the_next_api_advances() {
        let mut state = crate::rewrite::test_state();
        install(
            &mut state,
            vec!["GET /a".to_string(), "POST /b".to_string()],
        )
        .unwrap();
        state.phase = RewritePhase::AwaitingRecordingRefresh;

        assert!(mark_awaiting_recording_refresh(&mut state, "GET /a").unwrap());
        assert_eq!(state.api, "POST /b");
        assert_eq!(state.phase, RewritePhase::ApiPending);
        assert_eq!(
            state.api_inventory[0].status,
            RewriteApiStatus::AwaitingRecordingRefresh
        );
        assert_eq!(state.api_inventory[1].status, RewriteApiStatus::Active);
        assert_eq!(view(&state).awaiting_recording_refresh, 1);

        state.phase = RewritePhase::AwaitingRecordingRefresh;
        assert!(!mark_awaiting_recording_refresh(&mut state, "POST /b").unwrap());
        assert!(state.current_api_index.is_none());
        assert_eq!(view(&state).awaiting_recording_refresh, 2);
    }

    #[test]
    fn coordinator_config_change_rebases_only_matching_target_fingerprints() {
        let mut state = crate::rewrite::test_state();
        install(
            &mut state,
            vec!["GET /a".to_string(), "POST /b".to_string()],
        )
        .unwrap();
        state.api_inventory[0].status = RewriteApiStatus::Complete;
        state.api_inventory[0].verified_target_fingerprint = Some("before".to_string());
        state.api_inventory[1].verified_target_fingerprint = Some("unrelated".to_string());
        state.target_fingerprint = Some("before".to_string());

        rebase_target_fingerprint(&mut state, "before", "after");

        assert_eq!(
            state.api_inventory[0]
                .verified_target_fingerprint
                .as_deref(),
            Some("after")
        );
        assert_eq!(
            state.api_inventory[1]
                .verified_target_fingerprint
                .as_deref(),
            Some("unrelated")
        );
        assert_eq!(state.target_fingerprint.as_deref(), Some("after"));
    }
}
