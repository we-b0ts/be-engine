//! Read-only projection of coordinator work, including one explicit idle wait.
use std::collections::BTreeMap;
use std::path::Path;

use anyhow::Result;
use serde::Serialize;

use super::model::{RewriteAction, RewriteApiStatus, RewritePhase, RewriteState};
use super::worker::{model::RewriteWorkerCoverageState as Coverage, runtime, scheduler};

#[derive(Debug, Clone, Default, Serialize)]
pub struct RewriteCoordinationDetails {
    pub ready: BTreeMap<String, usize>,
    pub waiting: BTreeMap<String, usize>,
    pub completed: usize,
}

impl RewriteCoordinationDetails {
    pub(super) fn pending(&self) -> usize {
        self.ready.values().sum()
    }
}

/// One global projection, independent of the action selected for scoped inspection.
pub(super) fn status_details(
    target_root: &Path,
    state: &RewriteState,
) -> Result<RewriteCoordinationDetails> {
    let busy = resources_busy(target_root)?;
    let base = super::action::status_base(target_root, state)?;
    let execution = super::execution::status_action(target_root)?;
    let failed = matches!(execution, Some(RewriteAction::ExecutionFailed { .. }));
    let selected = if state.revalidation_round.is_none()
        && let Some(expert) = super::expert::required_action(target_root, state, None)
    {
        expert
    } else if busy || failed {
        super::worker::scheduler::global_action(target_root, state, true)
            .or(execution.clone())
            .unwrap_or_else(|| base.clone())
    } else {
        super::action::select_action(target_root, state, base.clone())
    };
    let mut result = projected_details(target_root, state, &base, &selected, busy || failed);
    if matches!(execution, Some(RewriteAction::RecoveryRequired { .. }))
        || matches!(
            super::store::RewriteStore::new(target_root)?.lock_state()?,
            super::store::RewriteLockState::Stale
        )
        || matches!(
            super::traffic_operation::state(target_root)?,
            super::traffic_operation::TrafficOperationState::Stale(_)
        )
    {
        result.ready.remove("wait");
        add(&mut result.ready, "recover_workflow", 1);
    }
    Ok(result)
}

pub(super) fn resources_busy(target_root: &Path) -> Result<bool> {
    Ok(!matches!(
        super::traffic_operation::state(target_root)?,
        super::traffic_operation::TrafficOperationState::Absent
    ) || !matches!(
        super::store::RewriteStore::new(target_root)?.lock_state()?,
        super::store::RewriteLockState::Absent
    ) || super::execution::owned_by_other_process(target_root)?)
}

fn add(counts: &mut BTreeMap<String, usize>, name: &str, count: usize) {
    if count > 0 {
        *counts.entry(name.to_string()).or_default() += count;
    }
}

fn replace_one(counts: &mut BTreeMap<String, usize>, previous: &str, next: &str) {
    remove_one(counts, previous);
    add(counts, next, 1);
}

fn remove_one(counts: &mut BTreeMap<String, usize>, previous: &str) {
    if let Some(value) = counts.get_mut(previous) {
        *value -= 1;
        if *value == 0 {
            counts.remove(previous);
        }
    }
}

pub(super) fn details(
    state: &RewriteState,
    action: &RewriteAction,
    busy: bool,
) -> RewriteCoordinationDetails {
    let mut result = RewriteCoordinationDetails::default();
    let first_pass_ready =
        super::inventory::can_switch_api(state) && super::inventory::has_unattempted_api(state);
    let (dispatch, reports, close) = super::expert::counts(state);
    add(&mut result.ready, "dispatch_expert", dispatch);
    add(&mut result.waiting, "expert_report", reports);
    add(&mut result.ready, "close_expert", close);
    for scope in runtime::scopes(state) {
        if state.revalidation_round.is_some() {
            add(&mut result.waiting, "revalidation_round", 1);
            continue;
        }
        match runtime::coverage(state, &scope) {
            Coverage::DispatchRequired => add(&mut result.ready, "dispatch_worker", 1),
            Coverage::ResumeRequired => add(&mut result.ready, "resume_worker", 1),
            Coverage::StatusRequired => add(&mut result.ready, "check_worker_status", 1),
            Coverage::Running => add(&mut result.waiting, "worker_handoff", 1),
            Coverage::IntegrationRequired if !busy && !first_pass_ready => {
                add(&mut result.ready, "integrate_handoff", 1)
            }
            Coverage::IntegrationRequired => add(&mut result.waiting, "integration_resource", 1),
            Coverage::VerificationRequired
                if !busy && !first_pass_ready && super::inventory::can_switch_api(state) =>
            {
                add(&mut result.ready, "verify_handoff", 1)
            }
            Coverage::VerificationRequired => add(&mut result.waiting, "verification_resource", 1),
        }
    }
    let mut unverified = state
        .api_inventory
        .iter()
        .filter(|item| item.status == RewriteApiStatus::Pending)
        .map(|item| super::api_selector::public_api(&item.api))
        .collect::<std::collections::BTreeSet<_>>();
    if !state.api.is_empty()
        && (state.phase == RewritePhase::ApiPending
            || state.system_repair_accepted
            || super::rule_replay::pending(&state.active_slice))
    {
        unverified.insert(super::api_selector::public_api(&state.api));
    }
    unverified.extend(
        state
            .parked_slices
            .values()
            .filter(|slice| {
                (slice.system_repair_accepted || super::rule_replay::pending(slice))
                    && !super::regression_scope::is_skipped(state, &slice.api)
            })
            .map(|slice| super::api_selector::public_api(&slice.api)),
    );
    let unverified = unverified.len();
    if !busy && super::inventory::can_switch_api(state) {
        add(&mut result.ready, "verify_api", unverified);
    } else {
        add(&mut result.waiting, "replay_resource", unverified);
    }
    add(
        &mut result.waiting,
        "final_revalidation",
        state
            .api_inventory
            .iter()
            .filter(|item| item.status == RewriteApiStatus::RevalidationPending)
            .map(|item| super::api_selector::public_api(&item.api))
            .collect::<std::collections::BTreeSet<_>>()
            .len(),
    );
    result.completed = super::inventory::view(state).completed;
    match action {
        RewriteAction::SystemRepairRequired { acceptance, .. } => {
            if acceptance.is_some() && !busy {
                add(&mut result.ready, "verify_system_repair", 1);
            } else {
                add(&mut result.waiting, "system_repair", 1);
            }
        }

        RewriteAction::WaitRequired { .. }
        | RewriteAction::Blocked { .. }
        | RewriteAction::WorkerEventsRequired { .. }
        | RewriteAction::RecordingInProgress { .. }
        | RewriteAction::RecordingRefreshPending { .. }
        | RewriteAction::Complete { .. }
        | RewriteAction::ExecutionFailed { .. } => {}
        RewriteAction::InputRequired {
            reason: super::model::RewriteInputRequiredReason::WorkflowNotInitialized,
            ..
        } => {}
        RewriteAction::ImplementationRequired { .. }
        | RewriteAction::ExpertRequired { .. }
        | RewriteAction::WorkerStatusRequired { .. }
        | RewriteAction::IntegrationRequired { .. } => {}
        RewriteAction::AdvanceRequired { .. }
            if result.ready.contains_key("verify_api")
                || result.ready.contains_key("verify_handoff") => {}
        RewriteAction::TargetQualityRequired { .. }
        | RewriteAction::SourceReviewRequired { .. }
            if !busy =>
        {
            let previous = if state.system_repair_accepted || super::rule_replay::any_ready(state) {
                "verify_api"
            } else {
                "verify_handoff"
            };
            replace_one(&mut result.ready, previous, "target_quality")
        }
        RewriteAction::PlanApplyRequired { .. } if !busy => {
            replace_one(&mut result.ready, "integrate_handoff", "apply_plan")
        }
        _ if busy => add(&mut result.waiting, "workflow_resource", 1),
        _ => add(&mut result.ready, "advance_workflow", 1),
    }
    result
}

pub(super) fn projected_details(
    target_root: &Path,
    state: &RewriteState,
    base: &RewriteAction,
    selected: &RewriteAction,
    busy: bool,
) -> RewriteCoordinationDetails {
    let mut result = details(state, base, busy);
    // Count parked repair acceptances as well as the active one. A repair is
    // actionable only after its observed external revision has changed.
    result.ready.remove("verify_system_repair");
    result.waiting.remove("system_repair");
    for api in super::scheduling::repair_apis(state) {
        let ready = !busy
            && super::inventory::can_switch_api(state)
            && api
                .parse()
                .ok()
                .and_then(|api| super::inventory::scoped(state, Some(&api)).ok())
                .is_some_and(|scoped| {
                    super::repair::pending_command(target_root, &scoped).is_some()
                });
        if ready {
            add(&mut result.ready, "verify_system_repair", 1);
        } else {
            add(&mut result.waiting, "system_repair", 1);
        }
    }
    if super::review::is_rework_wait(base) {
        for key in [
            "verify_handoff",
            "verify_api",
            "verify_system_repair",
            "target_quality",
        ] {
            if let Some(count) = result.ready.remove(key) {
                add(&mut result.waiting, "source_review_rework", count);
            }
        }
    }
    if matches!(selected, RewriteAction::Blocked { .. }) {
        result.ready.clear();
    } else if !busy
        && super::scheduling::round_action(target_root, state).is_some()
        && matches!(selected, RewriteAction::AdvanceRequired { .. })
    {
        for key in [
            "dispatch_worker",
            "resume_worker",
            "check_worker_status",
            "integrate_handoff",
            "verify_handoff",
            "verify_api",
            "verify_system_repair",
        ] {
            if let Some(count) = result.ready.remove(key) {
                add(&mut result.waiting, "revalidation_round", count);
            }
        }
        if let Some(api) = super::scheduling::revalidation_api(state)
            && state.api_inventory.iter().any(|item| {
                item.status == RewriteApiStatus::RevalidationPending
                    && super::api_selector::public_api(&item.api)
                        == super::api_selector::public_api(api)
            })
        {
            remove_one(&mut result.waiting, "final_revalidation");
        }
        result.ready.clear();
        add(&mut result.ready, "revalidate_api", 1);
    } else if !busy
        && result.ready.is_empty()
        && matches!(selected, RewriteAction::AdvanceRequired { .. })
    {
        if super::scheduling::revalidation_api(state).is_some() {
            remove_one(&mut result.waiting, "final_revalidation");
            add(&mut result.ready, "revalidate_api", 1);
        } else {
            add(&mut result.ready, "advance_workflow", 1);
        }
    } else if result.ready.is_empty()
        && !matches!(selected, RewriteAction::ExecutionFailed { .. })
        && (busy || !matches!(selected, RewriteAction::Complete { .. }))
    {
        add(&mut result.ready, "wait", 1);
    }
    result
}

pub(super) fn pending(state: &RewriteState, action: &RewriteAction, busy: bool) -> usize {
    details(state, action, busy).pending()
}

pub(super) fn busy_workers(
    target_root: &Path,
    state: &RewriteState,
    api: Option<&crate::RecordingApi>,
) -> Result<Option<super::model::RewriteActionEnvelope>> {
    if state.revalidation_round.is_some() {
        return Ok(None);
    }
    let selected = if let Some(api) = api {
        let scope = super::api_selector::work_scope(state, &api.to_string());
        runtime::scopes(state)
            .contains(&scope)
            .then_some(scope)
            .and_then(|scope| {
                matches!(
                    runtime::coverage(state, &scope),
                    Coverage::DispatchRequired
                        | Coverage::ResumeRequired
                        | Coverage::StatusRequired
                )
                .then(|| scheduler::scope_action(target_root, state, &scope))
            })
    } else {
        scheduler::global_action(target_root, state, true)
    };
    Ok(selected.map(|action| {
        let mut envelope = super::action::envelope(target_root, state, action);
        envelope.pending =
            projected_details(target_root, state, &envelope.action, &envelope.action, true)
                .pending();
        envelope
    }))
}

pub(super) fn initial_details(pending: usize) -> RewriteCoordinationDetails {
    single_ready("initialize_workflow", pending)
}

pub(super) fn single_ready(kind: &str, pending: usize) -> RewriteCoordinationDetails {
    let mut result = RewriteCoordinationDetails::default();
    add(&mut result.ready, kind, pending);
    result
}

#[cfg(test)]
mod tests;
