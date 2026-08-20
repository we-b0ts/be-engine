use std::path::Path;

use anyhow::Result;

use crate::RecordingApi;

use super::model::{
    ACTION_SCHEMA_VERSION, RewriteAction, RewriteActionEnvelope, RewriteCommandSpec,
    RewriteFocusedE2eExecution, RewriteFocusedE2eExecutionMode, RewriteInputRequiredReason,
    RewritePhase, RewriteRecordingInputMode, RewriteState, RewriteWorkflowView,
};
use super::{
    inventory, process_outputs, progress_publication, recorder_capture, recording,
    recording_action, repair, target_quality, worker,
};

pub(super) fn for_state(target_root: &Path, state: &RewriteState) -> RewriteActionEnvelope {
    envelope(target_root, state, state_action(target_root, state))
}

pub(super) fn for_status(
    target_root: &Path,
    state: &RewriteState,
) -> Result<RewriteActionEnvelope> {
    let recording_status = recording_action::status_action(target_root, state)?;
    let target_change = target_quality::status_action(target_root, state)?;
    let action = match state.phase {
        RewritePhase::RecordingRequired | RewritePhase::ComparisonRecordingRequired
            if recording_status.is_some() =>
        {
            recording_status.expect("recording status was checked")
        }
        _ if target_change.is_some() => target_change.expect("target change was checked"),
        _ => state_action(target_root, state),
    };
    Ok(envelope(target_root, state, action))
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
    envelope(
        target_root,
        state,
        RewriteAction::WaitRequired {
            summary: format!(
                "wait for API {}; its {:?} transition must finish before selecting {}",
                state.api, state.phase, requested_api
            ),
            resource: "rewrite_api_transition".to_string(),
            requested_api: Some(requested_api),
            blocking_api: (!state.api.is_empty()).then(|| state.api.clone()),
            active_operation: None,
            retry_after_seconds: 5,
            status: status_command_for_api(
                target_root,
                (!state.api.is_empty()).then_some(state.api.as_str()),
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
        .or((!state.api.is_empty()).then_some(state.api.as_str()));
    let status = status_command_for_api(target_root, status_api);
    envelope(
        target_root,
        state,
        RewriteAction::WaitRequired {
            summary: "wait for the live rewrite coordinator transition".to_string(),
            resource: "rewrite_coordinator".to_string(),
            requested_api,
            blocking_api: (!state.api.is_empty()).then(|| state.api.clone()),
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
        workflow: None,
        api_inventory: None,
        process_output_inventory: None,
        latest_focused_e2e: None,
        terminal_allowed: false,
        action: RewriteAction::WaitRequired {
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
    RewriteActionEnvelope {
        schema_version: ACTION_SCHEMA_VERSION,
        workflow,
        api_inventory: Some(inventory::view(state)),
        process_output_inventory: Some(process_outputs::view(state)),
        latest_focused_e2e: latest_focused_e2e(state),
        terminal_allowed: progress_publication::state(target_root, state)
            == Some(progress_publication::PublicationState::Published),
        action,
    }
}

fn state_action(target_root: &Path, state: &RewriteState) -> RewriteAction {
    match progress_publication::state(target_root, state) {
        Some(progress_publication::PublicationState::SynchronizationRequired) => {
            return advance_required(
                target_root,
                Some(&state.api),
                "synchronize the final verification progress snapshot from the runner-owned ledger"
                    .to_string(),
            );
        }
        Some(progress_publication::PublicationState::CommitRequired) => {
            return RewriteAction::InputRequired {
                reason: RewriteInputRequiredReason::VerificationProgressCommitRequired,
                summary: "commit the coordinator-generated final verification progress snapshot"
                    .to_string(),
                required: progress_publication::public_paths()
                    .into_iter()
                    .map(str::to_string)
                    .collect(),
            };
        }
        Some(progress_publication::PublicationState::Published) | None => {}
    }
    if process_outputs::active_scope(state).is_some() {
        return worker::state_action(target_root, state);
    }
    if state.phase == RewritePhase::SystemRepairRequired
        && state
            .route
            .as_ref()
            .is_some_and(|route| route.repair_id.is_none())
    {
        return advance_required(
            target_root,
            Some(&state.api),
            "initialize coordinator-issued acceptance for the pending legacy system repair"
                .to_string(),
        );
    }
    if state.phase == RewritePhase::ApiPending && inventory::current_requires_source_route(state) {
        return RewriteAction::InputRequired {
            reason: RewriteInputRequiredReason::SourceRouteRequired,
            summary: format!(
                "dynamic API {} requires a route confirmed from source registration",
                state.api
            ),
            required: vec!["--source-route <confirmed-source-route>".to_string()],
        };
    }
    if state.phase == RewritePhase::ImplementationRequired {
        if let Some(action) = recorder_capture::pending_plan_action(target_root, state) {
            return action;
        }
        if let Some(plan) = &state.rule_plan {
            return RewriteAction::PlanApplyRequired {
                summary: "apply the unchanged pending verification-rule plan".to_string(),
                command: rule_apply_command(target_root, &plan.id),
            };
        }
        if let Some(plan) = &state.dependency_rule_plan {
            return RewriteAction::PlanApplyRequired {
                summary: if plan.reused_existing {
                    format!(
                        "confirm reused process-owned dependency rule {} and reclassify the current attempt",
                        plan.effective_name.as_deref().unwrap_or(&plan.name)
                    )
                } else {
                    "apply the unchanged pending process-owned dependency plan and reclassify the current attempt"
                        .to_string()
                },
                command: dependency_rule_apply_command(target_root, &plan.id),
            };
        }
    }
    match state.phase {
        RewritePhase::RecordingRequired => RewriteAction::RecordingRequired {
            summary: recording_summary(state),
            run_id: state.recording_run_id.clone(),
            input_mode: if recording::standard_recording_input_source(state).is_some() {
                RewriteRecordingInputMode::ReusedAtomicRecording
            } else {
                RewriteRecordingInputMode::ExternalLiveTraffic
            },
            recording_input_diagnosis: if recording::standard_recording_input_source(state)
                .is_none()
                && !recording::requires_external_live_traffic(state)
            {
                state.recording_input_diagnosis.clone()
            } else {
                None
            },
            command: recording_action::command(target_root, state, false),
        },
        RewritePhase::ApiPending => advance_required(
            target_root,
            Some(&state.api),
            format!("continue with the next recorded API {}", state.api),
        ),
        RewritePhase::ImplementationRequired => worker::state_action(target_root, state),
        RewritePhase::AwaitingRecordingRefresh => {
            recorder_capture::pending_refresh_action(target_root, state)
        }
        RewritePhase::ComparisonRecordingRequired => RewriteAction::ComparisonRecordingRequired {
            summary: state.comparison_rejection.as_ref().map_or_else(
                || format!("generate fresh comparison evidence for {}", state.api),
                |reason| {
                    format!(
                        "previous comparison recording was rejected ({reason}); generate fresh comparison evidence for {}",
                        state.api
                    )
                },
            ),
            run_id: state
                .comparison_run_id
                .clone()
                .expect("comparison recording phase requires a run id"),
            command: recording_action::command(target_root, state, true),
        },
        RewritePhase::SystemRepairRequired => RewriteAction::SystemRepairRequired {
            issue: state
                .active_issue
                .clone()
                .expect("system repair phase requires an issue"),
            route: state.route.clone(),
            acceptance: repair::pending_command(target_root, state),
        },
        RewritePhase::SliceComplete => {
            if let Some(id) = process_outputs::next_eligible_id(state) {
                return RewriteAction::AdvanceRequired {
                    summary: format!(
                        "all API work items were traversed; verify process output {id}"
                    ),
                    command: next_command_for_process_output(target_root, id),
                };
            }
            RewriteAction::Complete {
            summary: if state
                .api_inventory
                .iter()
                .all(|item| item.status == super::model::RewriteApiStatus::Complete)
            {
                format!(
                    "all {} recorded API slice(s) and {} process output(s) have current evidence",
                    state.api_inventory.len(),
                    state.process_outputs.inventory.len()
                )
            } else {
                format!(
                    "{} has current E2E and comparison evidence; other recorded APIs still require work",
                    state.api
                )
            },
            e2e_current: state.e2e_current,
            comparison_current: state.comparison_current,
            }
        }
    }
}

fn advance_required(target_root: &Path, api: Option<&str>, summary: String) -> RewriteAction {
    advance_required_with_command(summary, next_command_with_optional_api(target_root, api))
}

fn advance_required_with_command(summary: String, command: RewriteCommandSpec) -> RewriteAction {
    RewriteAction::AdvanceRequired { summary, command }
}

pub(super) fn advance_envelope(
    target_root: &Path,
    state: &RewriteState,
    summary: String,
) -> RewriteActionEnvelope {
    envelope(
        target_root,
        state,
        advance_required(target_root, Some(&state.api), summary),
    )
}

fn recording_summary(state: &RewriteState) -> String {
    let summary = if let Some(reason) = &state.recording_rejection {
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
    };
    if recording::requires_external_live_traffic(state) {
        format!("{summary}; the request reason requires fresh external live traffic")
    } else if recording::standard_recording_input_source(state).is_none() {
        format!(
            "{summary}; no exact-scope atomic historical input is reusable, capture fresh external live traffic"
        )
    } else {
        summary
    }
}

pub(super) fn input_required(_target_root: &Path) -> RewriteActionEnvelope {
    RewriteActionEnvelope {
        schema_version: ACTION_SCHEMA_VERSION,
        workflow: None,
        api_inventory: None,
        process_output_inventory: None,
        latest_focused_e2e: None,
        action: RewriteAction::InputRequired {
            reason: RewriteInputRequiredReason::WorkflowNotInitialized,
            summary: "start the rewrite workflow for every API observed through recorder configuration, or optionally select one API".to_string(),
            required: vec!["run `backend-rewrite next`; optional: --api 'METHOD /path-or-pattern'".to_string()],
        },
        terminal_allowed: false,
    }
}

pub(super) fn source_route_required(
    _target_root: &Path,
    api: &RecordingApi,
) -> RewriteActionEnvelope {
    RewriteActionEnvelope {
        schema_version: ACTION_SCHEMA_VERSION,
        workflow: None,
        api_inventory: None,
        process_output_inventory: None,
        latest_focused_e2e: None,
        action: RewriteAction::InputRequired {
            reason: RewriteInputRequiredReason::SourceRouteRequired,
            summary: format!(
                "dynamic API {api} requires a route confirmed from source registration"
            ),
            required: vec!["--source-route <confirmed-source-route>".to_string()],
        },
        terminal_allowed: false,
    }
}

pub(super) fn recovery_required(target_root: &Path) -> RewriteActionEnvelope {
    RewriteActionEnvelope {
        schema_version: ACTION_SCHEMA_VERSION,
        workflow: None,
        api_inventory: None,
        process_output_inventory: None,
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
        work_scope: process_outputs::selected_scope(state).or_else(|| {
            (!state.api.is_empty()).then(|| super::process_output_model::RewriteWorkScope::Api {
                api: state.api.clone(),
            })
        }),
    }
}

fn workflow_scope(state: &RewriteState) -> String {
    let scope = inventory::recording_scope(state);
    if scope.is_empty() {
        inventory::RECORDED_API_INVENTORY_SCOPE.to_string()
    } else {
        scope.join(", ")
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

pub(super) fn next_command_for_api(target_root: &Path, api: &str) -> RewriteCommandSpec {
    next_command_with_optional_api(target_root, Some(api))
}

pub(super) fn next_command_for_process_output(target_root: &Path, id: &str) -> RewriteCommandSpec {
    command(
        target_root,
        vec![
            "next".to_string(),
            "--process-output".to_string(),
            id.to_string(),
        ],
        Vec::new(),
    )
}

fn next_command_with_optional_api(target_root: &Path, api: Option<&str>) -> RewriteCommandSpec {
    let mut arguments = vec!["next".to_string()];
    if let Some(api) = api.filter(|api| !api.is_empty()) {
        arguments.extend(["--api".to_string(), api.to_string()]);
    }
    command(target_root, arguments, Vec::new())
}

pub(super) fn status_command(target_root: &Path) -> RewriteCommandSpec {
    command(target_root, vec!["status".to_string()], Vec::new())
}

pub(super) fn status_command_for_api(target_root: &Path, api: Option<&str>) -> RewriteCommandSpec {
    let mut arguments = vec!["status".to_string()];
    if let Some(api) = api {
        arguments.extend(["--api".to_string(), api.to_string()]);
    }
    command(target_root, arguments, Vec::new())
}

pub(super) fn status_command_for_process_output(
    target_root: &Path,
    id: &str,
) -> RewriteCommandSpec {
    command(
        target_root,
        vec![
            "status".to_string(),
            "--process-output".to_string(),
            id.to_string(),
        ],
        Vec::new(),
    )
}

pub(super) fn retarget_wait_status_for_process_output(
    envelope: &mut RewriteActionEnvelope,
    target_root: &Path,
    id: &str,
) {
    if let RewriteAction::WaitRequired { status, .. } = &mut envelope.action {
        *status = status_command_for_process_output(target_root, id);
    }
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
            "dependency-rule".to_string(),
            "apply".to_string(),
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
