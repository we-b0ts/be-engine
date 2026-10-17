use std::path::Path;

use anyhow::Result;

use crate::RecordingApi;

use super::model::{
    ACTION_SCHEMA_VERSION, RewriteAction, RewriteActionEnvelope, RewriteAdvanceKind,
    RewriteCommandSpec, RewriteFocusedE2eExecution, RewriteFocusedE2eExecutionMode,
    RewriteInputRequiredReason, RewritePhase, RewriteState, RewriteWorkflowView,
};
use super::{
    case_patterns, inventory, progress_publication, recorder_capture, recording_action, repair,
    target_quality, worker,
};

pub(super) fn for_state(target_root: &Path, state: &RewriteState) -> RewriteActionEnvelope {
    if state.revalidation_round.is_some() {
        let mut projected = state.clone();
        if super::review::pre_revalidation::reconcile(target_root, &mut projected).unwrap_or(false)
        {
            return for_state(target_root, &projected);
        }
    }
    let base = super::review::pre_revalidation::required_action(target_root, state)
        .ok()
        .flatten()
        .unwrap_or_else(|| state_action(target_root, state));
    let selected = select_action(target_root, state, base);
    envelope(target_root, state, selected)
}

pub(super) fn for_status(
    target_root: &Path,
    state: &RewriteState,
) -> Result<RewriteActionEnvelope> {
    let base = status_base(target_root, state)?;
    let selected = select_action(target_root, state, base.clone());
    let pending =
        super::coordination::projected_details(target_root, state, &base, &selected, false)
            .pending();
    let mut result = envelope(target_root, state, selected);
    result.pending = pending;
    Ok(result)
}

/// Native workflow gate, before choosing among worker actions. Counts consume this
/// same gate regardless of which API's action the caller wants to inspect.
pub(super) fn status_base(target_root: &Path, state: &RewriteState) -> Result<RewriteAction> {
    if state.revalidation_round.is_some() {
        let mut projected = state.clone();
        if super::review::pre_revalidation::reconcile(target_root, &mut projected)? {
            return status_base(target_root, &projected);
        }
    }
    if state.case_pattern_identification.is_some()
        || super::transition::replay_completion_pending(state)
    {
        return Ok(state_action(target_root, state));
    }
    for api in super::scheduling::repair_apis(state) {
        let scoped = inventory::scoped(state, Some(&api.parse()?))?;
        repair::acceptance_ready(target_root, &scoped)?;
    }
    let recording_status = recording_action::status_action(target_root, state)?;
    if let Some(review) = super::review::pre_revalidation::required_action(target_root, state)? {
        return Ok(review);
    }
    if let Some(review) = super::review::required_action(target_root, state)? {
        return Ok(review);
    }
    let target_change = target_quality::status_action(target_root, state)?;
    let reclassification = if target_change.is_none() {
        super::background_reclassification::required_action(target_root, state)?
    } else {
        None
    };
    Ok(match state.phase {
        RewritePhase::RecordingRequired if recording_status.is_some() => {
            recording_status.expect("recording status was checked")
        }
        _ if target_change.is_some() => target_change.expect("target change was checked"),
        _ if reclassification.is_some() => reclassification.expect("reclassification was checked"),
        _ => state_action(target_root, state),
    })
}

pub(super) fn select_action(
    target_root: &Path,
    state: &RewriteState,
    base: RewriteAction,
) -> RewriteAction {
    if matches!(base, RewriteAction::PreRevalidationReviewRequired { .. }) {
        return base;
    }
    if state.revalidation_round.is_some() {
        let mut projected = state.clone();
        if super::review::pre_revalidation::reconcile(target_root, &mut projected).unwrap_or(false)
        {
            return select_action(target_root, &projected, base);
        }
    }
    if matches!(&base, RewriteAction::WaitRequired { resource, .. }
        if resource == "pre_revalidation_candidate")
    {
        return base;
    }
    if matches!(
        base,
        RewriteAction::AdvanceRequired {
            kind: RewriteAdvanceKind::ReclassifyDependencies,
            ..
        }
    ) {
        return base;
    }
    if !matches!(
        base,
        RewriteAction::SourceReviewRequired { .. } | RewriteAction::TargetQualityRequired { .. }
    ) && let Some(round) = super::scheduling::round_action(target_root, state)
    {
        return round;
    }
    if let Some(expert) = super::expert::required_action(target_root, state, None) {
        return expert;
    }
    if matches!(
        base,
        RewriteAction::SystemRepairRequired {
            acceptance: Some(_),
            ..
        }
    ) {
        return base;
    }
    if !matches!(
        base,
        RewriteAction::PlanApplyRequired { .. }
            | RewriteAction::TargetQualityRequired { .. }
            | RewriteAction::SourceReviewRequired { .. }
    ) && !super::review::is_rework_wait(&base)
        && let Some(repair) = super::scheduling::repair_action(target_root, state)
    {
        return repair;
    }
    if let Some(selected) = global_worker_action(target_root, state, &base) {
        return selected;
    }
    if matches!(base, RewriteAction::ImplementationRequired { .. }) {
        return worker::state_action(target_root, state);
    }
    if matches!(
        base,
        RewriteAction::SystemRepairRequired {
            acceptance: None,
            ..
        } | RewriteAction::Complete { .. }
    ) && let Some(idle) = super::scheduling::idle_action(target_root, state)
    {
        return idle;
    }
    base
}

fn global_worker_action(
    target_root: &Path,
    state: &RewriteState,
    base: &RewriteAction,
) -> Option<RewriteAction> {
    if state.case_pattern_identification.is_some()
        || super::transition::replay_completion_pending(state)
        || matches!(base, RewriteAction::PlanApplyRequired { .. })
    {
        return None;
    }
    let selected = worker::scheduler::global_action(target_root, state, false)?;
    if matches!(selected, RewriteAction::AdvanceRequired { .. })
        && (matches!(
            base,
            RewriteAction::TargetQualityRequired { .. }
                | RewriteAction::SourceReviewRequired { .. }
        ) || super::review::is_rework_wait(base))
    {
        return None;
    }
    Some(selected)
}

pub(super) fn for_scoped_status(
    target_root: &Path,
    state: &RewriteState,
) -> Result<RewriteActionEnvelope> {
    if state.revalidation_round.is_some() {
        let mut projected = state.clone();
        if super::review::pre_revalidation::reconcile(target_root, &mut projected)? {
            return for_scoped_status(target_root, &projected);
        }
    }
    if let Some(review) = super::review::pre_revalidation::required_action(target_root, state)? {
        return Ok(envelope(target_root, state, review));
    }
    if let Some(refresh) = super::background_reclassification::required_action(target_root, state)?
    {
        if let Some(review) = super::review::required_action(target_root, state)? {
            return Ok(envelope(target_root, state, review));
        }
        if let Some(quality) = target_quality::status_action(target_root, state)? {
            return Ok(envelope(target_root, state, quality));
        }
        return Ok(envelope(target_root, state, refresh));
    }
    let method_scope = super::RewriteWorkScope::Api {
        api: state.api.clone(),
    };
    if state.phase == RewritePhase::ImplementationRequired
        && !super::replay_admission::admitted(state, &method_scope)
        && let Some(scope) = worker::runtime::scopes(state)
            .into_iter()
            .find(|scope| match scope {
                super::RewriteWorkScope::Api { api } => {
                    api == &super::api_selector::work_scope(state, &state.api).binding_key()
                }
            })
        && state.rule_plan.is_none()
        && state.dependency_rule_plan.is_none()
        && state.recorder_capture_plan.is_none()
    {
        if worker::runtime::acceptance_ready(state, &scope) {
            if let Some(action) = super::review::required_action(target_root, state)? {
                return Ok(envelope(target_root, state, action));
            }
            if let Some(action) = target_quality::status_action(target_root, state)? {
                return Ok(envelope(target_root, state, action));
            }
        }
        return Ok(envelope(
            target_root,
            state,
            worker::scheduler::scope_action(target_root, state, &scope),
        ));
    }
    Ok(envelope(
        target_root,
        state,
        // Scoped next uses this action to decide whether it may advance. Include
        // publication and executor state just as the global status projection does.
        status_base(target_root, state)?,
    ))
}

pub(super) fn wait_envelope(
    target_root: &Path,
    state: &RewriteState,
    requested_api: Option<String>,
    active: &super::traffic_operation::TrafficOperationMarker,
) -> RewriteActionEnvelope {
    envelope(
        target_root,
        state,
        super::traffic_operation::wait_action(target_root, requested_api, active),
    )
}

pub(super) fn api_selection_wait_envelope(
    target_root: &Path,
    state: &RewriteState,
    requested_api: String,
) -> RewriteActionEnvelope {
    let requested_api = super::api_selector::public_api(&requested_api).to_string();
    let blocking_api = super::api_selector::public_api(&state.api);
    envelope(
        target_root,
        state,
        RewriteAction::WaitRequired {
            execution_mode: None,
            summary: format!(
                "wait for API {}; its {:?} transition must finish before selecting {}",
                blocking_api, state.phase, requested_api
            ),
            resource: "rewrite_api_transition".to_string(),
            requested_api: Some(requested_api),
            blocking_api: (!state.api.is_empty()).then(|| blocking_api.to_string()),
            active_operation: None,
            retry_after_seconds: 5,
            status: status_command_for_api(
                target_root,
                (!state.api.is_empty()).then_some(blocking_api),
            ),
        },
    )
}

pub(super) fn coordinator_wait_envelope(
    target_root: &Path,
    state: &RewriteState,
    requested_api: Option<String>,
) -> RewriteActionEnvelope {
    let status_api = requested_api
        .as_deref()
        .or((!state.api.is_empty()).then_some(state.api.as_str()))
        .map(super::api_selector::public_api);
    let status = status_command_for_api(target_root, status_api);
    envelope(
        target_root,
        state,
        RewriteAction::WaitRequired {
            execution_mode: None,
            summary: "wait for the live rewrite coordinator transition".to_string(),
            resource: "rewrite_coordinator".to_string(),
            requested_api: requested_api.map(|api| super::api_selector::public_api(&api).into()),
            blocking_api: (!state.api.is_empty())
                .then(|| super::api_selector::public_api(&state.api).into()),
            active_operation: None,
            retry_after_seconds: 5,
            status,
        },
    )
}

pub(super) fn uninitialized_coordinator_wait_envelope(
    target_root: &Path,
    requested_api: Option<String>,
) -> RewriteActionEnvelope {
    let status = status_command_for_api(target_root, requested_api.as_deref());
    RewriteActionEnvelope {
        schema_version: ACTION_SCHEMA_VERSION,
        pending: 1,
        workflow: None,
        api_inventory: None,
        latest_focused_e2e: None,
        terminal_allowed: false,
        action: RewriteAction::WaitRequired {
            execution_mode: None,
            summary: "wait for the live rewrite coordinator initialization".to_string(),
            resource: "rewrite_coordinator".to_string(),
            requested_api,
            blocking_api: None,
            active_operation: None,
            retry_after_seconds: 5,
            status,
        },
    }
}

pub(super) fn envelope(
    target_root: &Path,
    state: &RewriteState,
    action: RewriteAction,
) -> RewriteActionEnvelope {
    let workflow = Some(workflow_view(state));
    let busy = matches!(
        action,
        RewriteAction::WaitRequired { .. } | RewriteAction::ExecutionFailed { .. }
    );
    RewriteActionEnvelope {
        schema_version: ACTION_SCHEMA_VERSION,
        pending: super::coordination::projected_details(
            target_root,
            state,
            &state_action(target_root, state),
            &action,
            busy,
        )
        .pending(),
        workflow,
        api_inventory: Some(inventory::view(state)),
        latest_focused_e2e: latest_focused_e2e(state),
        terminal_allowed: super::expert::counts(state).2 == 0
            && super::review::admission_current(target_root, state)
            && super::review::pre_revalidation::completion_current(target_root, state)
            && progress_publication::state(target_root, state)
                == Some(progress_publication::PublicationState::Published),
        action,
    }
}

pub(super) fn state_action(target_root: &Path, state: &RewriteState) -> RewriteAction {
    let selected_api = super::api_selector::work_scope(state, &state.api).binding_key();
    let display_api = super::api_selector::public_api(&state.api);
    if let Some(action) = case_patterns::state_action(target_root, state) {
        return action;
    }
    if super::transition::replay_completion_pending(state) {
        return advance_required(
            target_root,
            Some(&selected_api),
            format!(
                "finish Replay validation for {} in this recording batch",
                display_api
            ),
        );
    }
    match progress_publication::state(target_root, state) {
        Some(progress_publication::PublicationState::SynchronizationRequired) => {
            return advance_required(
                target_root,
                (!state.api.is_empty()).then_some(selected_api.as_str()),
                "synchronize the final verification progress snapshot from the runner-owned ledger"
                    .to_string(),
            );
        }
        Some(progress_publication::PublicationState::CommitRequired(required)) => {
            return RewriteAction::InputRequired {
                reason: RewriteInputRequiredReason::VerificationProgressCommitRequired,
                summary: "commit every listed coordinator-managed final delivery file".to_string(),
                required,
                recording_input_diagnosis: None,
            };
        }
        Some(progress_publication::PublicationState::Published) | None => {}
    }
    if super::rule_replay::pending(&state.active_slice) {
        return replay_advance(
            target_root,
            &selected_api,
            "verification rule applied; replay the same API and immutable cases".into(),
        );
    }
    if super::engine_retry::pending(state, &state.active_slice) {
        return replay_advance(
            target_root,
            &selected_api,
            "engine build changed or the failed attempt has no build identity; retry the same API and immutable cases once with this engine build".into(),
        );
    }
    if state.system_repair_accepted {
        return replay_advance(
            target_root,
            &selected_api,
            "system repair accepted; replay the same API and immutable cases".into(),
        );
    }
    if state.phase == RewritePhase::SystemRepairRequired
        && state
            .route
            .as_ref()
            .is_some_and(|route| route.repair_id.is_none())
    {
        return advance_required(
            target_root,
            Some(&selected_api),
            "initialize coordinator-issued acceptance for the pending legacy system repair"
                .to_string(),
        );
    }
    if state.phase == RewritePhase::ApiPending && inventory::current_requires_source_route(state) {
        return RewriteAction::InputRequired {
            reason: RewriteInputRequiredReason::SourceRouteRequired,
            summary: format!(
                "dynamic API {} requires a route confirmed from source registration",
                display_api
            ),
            required: vec!["--source-route <confirmed-source-route>".to_string()],
            recording_input_diagnosis: None,
        };
    }
    if state.phase == RewritePhase::ImplementationRequired {
        if let Some(action) = super::plan_recovery::required_action(target_root, state) {
            return action;
        }
        if let Some(action) = recorder_capture::pending_plan_action(target_root, state) {
            return action;
        }
        if let Some(plan) = &state.rule_plan {
            return RewriteAction::PlanApplyRequired {
                summary: if plan.unified.is_some() {
                    "apply the unchanged pending unified rule plan"
                } else {
                    "recover the retired pending rule plan after active traffic finishes"
                }
                .into(),
                command: if plan.unified.is_some() {
                    rule_apply_command(target_root, &plan.id)
                } else {
                    dependency_rule_apply_command(target_root, &plan.id)
                },
            };
        }
        if let Some(plan) = &state.dependency_rule_plan {
            return RewriteAction::PlanApplyRequired {
                summary: "recover the retired dependency rule plan after active traffic finishes"
                    .into(),
                command: dependency_rule_apply_command(target_root, &plan.id),
            };
        }
    }
    match state.phase {
        RewritePhase::RecordingRequired => RewriteAction::InputRequired {
            reason: super::model::RewriteInputRequiredReason::RecordingEvidenceRequired,
            summary: format!(
                "{}; place a completed external recording under the conventional recording directory, then run next",
                recording_summary(state)
            ),
            required: vec![
                target_root
                    .join(crate::repository::LOCAL_ARTIFACTS_ROOT)
                    .join("recordings")
                    .display()
                    .to_string(),
            ],
            recording_input_diagnosis: state.recording_input_diagnosis.clone(),
        },
        RewritePhase::ApiPending => replay_advance(
            target_root,
            &selected_api,
            format!("continue with the next recorded API {display_api}"),
        ),
        RewritePhase::ImplementationRequired => {
            worker::implementation_action(target_root, state, None)
        }
        RewritePhase::AwaitingRecordingRefresh => {
            recorder_capture::pending_refresh_action(target_root, state)
        }
        RewritePhase::SystemRepairRequired => RewriteAction::SystemRepairRequired {
            work_scope: super::api_selector::work_scope(state, &state.api),
            issue: state
                .active_issue
                .clone()
                .expect("system repair phase requires an issue"),
            route: state.route.clone(),
            acceptance: repair::pending_command(target_root, state),
        },
        RewritePhase::SliceComplete => RewriteAction::Complete {
            summary: if super::regression_scope::has_skips(state)
                && state.api_inventory.iter().all(|item| item.status.is_done())
            {
                let summary = inventory::view(state);
                format!(
                    "regression scope complete: {} API(s) verified, {} skipped by {}",
                    summary.completed,
                    summary.skipped,
                    super::regression_scope::PATH
                )
            } else if state
                .api_inventory
                .iter()
                .all(|item| item.status == super::model::RewriteApiStatus::Complete)
            {
                format!(
                    "all {} API(s) in the current recording have current evidence",
                    inventory::view(state).total,
                )
            } else {
                format!(
                    "{} satisfies this recording batch's validation requirements; other recorded APIs still require work",
                    display_api
                )
            },
            e2e_current: state.e2e_current,
        },
    }
}

fn advance_required(target_root: &Path, api: Option<&str>, summary: String) -> RewriteAction {
    RewriteAction::AdvanceRequired {
        summary,
        command: next_command(target_root),
        api: api
            .filter(|api| !api.is_empty())
            .map(|api| super::api_selector::public_api(api).to_string()),
        kind: RewriteAdvanceKind::Workflow,
    }
}

pub(super) fn replay_advance(target_root: &Path, api: &str, summary: String) -> RewriteAction {
    let mut action = advance_required(target_root, Some(api), summary);
    if let RewriteAction::AdvanceRequired { kind, .. } = &mut action {
        *kind = RewriteAdvanceKind::Replay;
    }
    action
}

pub(super) fn advance_envelope(
    target_root: &Path,
    state: &RewriteState,
    summary: String,
) -> RewriteActionEnvelope {
    envelope(
        target_root,
        state,
        replay_advance(
            target_root,
            &super::api_selector::work_scope(state, &state.api).binding_key(),
            summary,
        ),
    )
}

fn recording_summary(state: &RewriteState) -> String {
    if let Some(reason) = &state.recording_rejection {
        format!(
            "previous standard recording was rejected ({reason}); generate a replacement for {}",
            workflow_scope(state)
        )
    } else {
        match state.recording_request_reason {
            Some(reason) => format!(
                "fresh standard recording requested ({reason}) for {}",
                workflow_scope(state)
            ),
            None => format!(
                "generate one finalized standard recording for {}",
                workflow_scope(state)
            ),
        }
    }
}

pub(super) fn input_required(target_root: &Path) -> RewriteActionEnvelope {
    RewriteActionEnvelope {
        schema_version: ACTION_SCHEMA_VERSION,
        pending: 1,
        workflow: None,
        api_inventory: None,
        latest_focused_e2e: None,
        action: advance_required(
            target_root,
            None,
            "initialize the rewrite workflow from the existing target project".into(),
        ),
        terminal_allowed: false,
    }
}

pub(super) fn source_route_required(
    _target_root: &Path,
    api: &RecordingApi,
) -> RewriteActionEnvelope {
    RewriteActionEnvelope {
        schema_version: ACTION_SCHEMA_VERSION,
        pending: 1,
        workflow: None,
        api_inventory: None,
        latest_focused_e2e: None,
        action: RewriteAction::InputRequired {
            reason: RewriteInputRequiredReason::SourceRouteRequired,
            summary: format!(
                "dynamic API {api} requires a route confirmed from source registration"
            ),
            required: vec!["--source-route <confirmed-source-route>".to_string()],
            recording_input_diagnosis: None,
        },
        terminal_allowed: false,
    }
}

pub(super) fn recovery_required(target_root: &Path) -> RewriteActionEnvelope {
    RewriteActionEnvelope {
        schema_version: ACTION_SCHEMA_VERSION,
        pending: 1,
        workflow: None,
        api_inventory: None,
        latest_focused_e2e: None,
        action: RewriteAction::RecoveryRequired {
            summary: "rewrite workflow is locked; execute the recovery command before retrying"
                .to_string(),
            command: recover_command(target_root),
        },
        terminal_allowed: false,
    }
}

pub(super) fn latest_focused_e2e(state: &RewriteState) -> Option<RewriteFocusedE2eExecution> {
    let current = state.attempts.last()?;
    let case_source = state.case_source.clone()?;
    let previous_attempt = state
        .attempts
        .iter()
        .rev()
        .nth(1)
        .map(|attempt| attempt.attempt)
        .or_else(|| {
            current
                .attempt
                .checked_sub(1)
                .filter(|attempt| *attempt > 0)
        });
    Some(RewriteFocusedE2eExecution {
        execution_mode: if previous_attempt.is_some() {
            RewriteFocusedE2eExecutionMode::ReusedStandardCases
        } else {
            RewriteFocusedE2eExecutionMode::FreshStandardCases
        },
        recording_run_id: state.recording_run_id.clone(),
        case_source,
        case_inventory_id: state.case_inventory_id.clone(),
        previous_attempt,
        current_attempt: current.attempt,
        passed: current.passed,
    })
}

pub(super) fn workflow_view(state: &RewriteState) -> RewriteWorkflowView {
    RewriteWorkflowView {
        id: state.workflow_id.clone(),
        revision: state.revision,
        phase: state.phase,
        scope: workflow_scope(state),
        recording_run_id: state.recording_run_id.clone(),
        work_scope: (!state.api.is_empty())
            .then(|| super::api_selector::work_scope(state, &state.api)),
    }
}

fn workflow_scope(state: &RewriteState) -> String {
    let scope = inventory::recording_scope(state);
    if scope.is_empty() {
        inventory::RECORDED_API_INVENTORY_SCOPE.to_string()
    } else {
        scope
            .iter()
            .map(|api| super::api_selector::public_api(api))
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>()
            .join(", ")
    }
}

pub(super) fn command(
    target_root: &Path,
    arguments: Vec<String>,
    required_env_names: Vec<String>,
) -> RewriteCommandSpec {
    let mut argv = Vec::with_capacity(arguments.len() + 3);
    argv.extend([
        "backend-rewrite".to_string(),
        "--target-root".to_string(),
        target_root.to_string_lossy().into_owned(),
    ]);
    argv.extend(arguments);
    RewriteCommandSpec {
        cwd: target_root.to_path_buf(),
        argv,
        required_env_names,
    }
}

pub(super) fn next_command(target_root: &Path) -> RewriteCommandSpec {
    command(target_root, vec!["next".to_string()], Vec::new())
}

pub(super) fn status_command(target_root: &Path) -> RewriteCommandSpec {
    command(target_root, vec!["status".to_string()], Vec::new())
}

pub(super) fn status_command_for_api(target_root: &Path, api: Option<&str>) -> RewriteCommandSpec {
    let mut arguments = vec!["status".to_string()];
    if let Some(api) = api {
        arguments.extend([
            "--api".to_string(),
            super::api_selector::public_api(api).to_string(),
        ]);
    }
    command(target_root, arguments, Vec::new())
}

pub(super) fn rule_apply_command(target_root: &Path, plan_id: &str) -> RewriteCommandSpec {
    command(
        target_root,
        vec!["rule".to_string(), "apply".to_string(), plan_id.to_string()],
        Vec::new(),
    )
}

pub(super) fn dependency_rule_apply_command(
    target_root: &Path,
    plan_id: &str,
) -> RewriteCommandSpec {
    command(
        target_root,
        vec![
            "rule".to_string(),
            "recover".to_string(),
            plan_id.to_string(),
        ],
        Vec::new(),
    )
}

pub(super) fn repair_verify_command(target_root: &Path, repair_id: &str) -> RewriteCommandSpec {
    command(
        target_root,
        vec![
            "repair".to_string(),
            "verify".to_string(),
            repair_id.to_string(),
        ],
        Vec::new(),
    )
}

pub(super) fn recover_command(target_root: &Path) -> RewriteCommandSpec {
    command(target_root, vec!["recover".to_string()], Vec::new())
}

#[cfg(test)]
#[path = "action_tests.rs"]
mod tests;
