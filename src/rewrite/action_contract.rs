use serde::{Serialize, Serializer};

use super::model::{
    RewriteAction, RewriteCommandSpec, RewriteInputRequiredReason, RewriteIssue, RewriteIssueKind,
    RewriteIssueOwner, RewriteRecordingInputDiagnosis, RewriteRouteRecord,
    RewriteWorkerDispatchView,
};

impl Serialize for RewriteAction {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Self::ExpertRequired { summary, expert, commands, execution_mode } => RewriteActionView {
                kind: "expert_required",
                summary,
                details: RewriteExpertDetails { expert, execution_mode: *execution_mode },
                commands,
            }.serialize(serializer),
            Self::Blocked { summary, system_repair_apis,  resume } => RewriteActionView {
                kind: "blocked",
                summary,
                details: serde_json::json!({
                    "reason": "system_repair_required",
                    "system_repair_apis": system_repair_apis,
                        }),
                commands: serde_json::json!({"resume": resume}),
            }.serialize(serializer),
            Self::WorkerEventsRequired { summary, inventory, status } => RewriteActionView {
                kind: "worker_events_required",
                summary,
                details: RewriteNoDetails {},
                commands: serde_json::json!({"inventory": inventory, "status": status}),
            }.serialize(serializer),
            Self::PurposeRequired { summary, pr_base, replay, record } => RewriteActionView {
                kind: "purpose_required", summary,
                details: serde_json::json!({"pr_base":pr_base, "user_approval_required":true,
                    "runtime_query_scope":"current_coordinator_session", "required_active_agent_count":0,
                    "choices":["replay_existing_recording", "record_new_traffic"]}),
                commands: serde_json::json!({"replay":replay, "record":record}),
            }.serialize(serializer),
            Self::InputRequired {
                reason,
                summary,
                required,
                recording_input_diagnosis,
            } => RewriteActionView {
                kind: "input_required",
                summary,
                details: RewriteInputRequiredDetails { reason, required, recording_input_diagnosis: recording_input_diagnosis.as_ref() },
                commands: RewriteNoCommands {},
            }
            .serialize(serializer),
            Self::RecoveryRequired { summary, command } => RewriteActionView {
                kind: "recovery_required",
                summary,
                details: RewriteNoDetails {},
                commands: RewriteRecoveryCommands { recover: command },
            }
            .serialize(serializer),
            Self::WaitRequired {
                summary,
                execution_mode,
                resource,
                requested_api,
                blocking_api,
                active_operation,
                retry_after_seconds,
                status,
            } => RewriteActionView {
                kind: "wait_required",
                summary,
                details: RewriteWaitRequiredDetails {
                    execution_mode: *execution_mode,
                    reason: "resource_busy",
                    resource,
                    requested_api: requested_api.as_deref(),
                    blocking_api: blocking_api.as_deref(),
                    active_operation: active_operation.as_ref(),
                    retry_after_seconds: *retry_after_seconds,
                },
                commands: serde_json::json!({"wait": super::waiting::command(status, *retry_after_seconds)}),
            }
            .serialize(serializer),
            Self::RecordingInProgress {
                summary,
                run_id,
                progress,
                status_poll_after_seconds,
                status,
            } => RewriteActionView {
                kind: "recording_in_progress",
                summary,
                details: RewriteRecordingInProgressDetails {
                    run_id,
                    progress,
                    status_poll_after_seconds: *status_poll_after_seconds,
                },
                commands: serde_json::json!({"wait": super::waiting::command(status, *status_poll_after_seconds)}),
            }
            .serialize(serializer),
            Self::CasePatternIdentificationRequired {
                summary,
                batch_id,
                recording_run_id,
                candidates,
                command,
            } => RewriteActionView {
                kind: "case_pattern_identification_required",
                summary,
                details: RewriteCasePatternIdentificationDetails {
                    batch_id,
                    recording_run_id,
                    candidates,
                    pattern_input: RewriteCasePatternInput {
                        environment_variable: "BACKEND_REWRITE_SOURCE_ROUTES_JSON",
                        format: "JSON array of confirmed METHOD path-or-pattern registrations",
                        empty_array_meaning: "no new registrations; every candidate must already be covered",
                        rules: [
                            "replace only variable whole path segments with *",
                            "use ** only as the final segment for a source-defined catch-all tail",
                            "include static routes explicitly and preserve each Source HTTP method",
                        ],
                    },
                },
                commands: RewriteApplyCommands { apply: command },
            }
            .serialize(serializer),
            Self::ImplementationRequired {
                summary,
                execution_mode,
                issue,
                worker,
                confirm_worker,
                report_worker,
                acceptance,
            } => RewriteActionView {
                kind: "implementation_required",
                summary,
                details: RewriteImplementationDetails {
                    execution_mode: *execution_mode,
                    issue: RewriteIssueDetails::from(issue),
                    work_scope: &worker.work_scope,
                    worker,
                },
                commands: RewriteImplementationCommands {
                    confirm_worker: confirm_worker.as_ref(),
                    report_worker,
                    acceptance,
                },
            }
            .serialize(serializer),
            Self::WorkerStatusRequired {
                summary,
                execution_mode,
                worker,
                report_worker,
            } => RewriteActionView {
                kind: "worker_status_required",
                summary,
                details: RewriteWorkerCoordinationDetails {
                    execution_mode: *execution_mode,
                    worker,
                    handoff_id: None,
                },
                commands: RewriteWorkerCoordinationCommands {
                    report_worker,
                },
            }
            .serialize(serializer),
            Self::IntegrationRequired {
                summary,
                worker,
                handoff_id,
                report_worker,
            } => RewriteActionView {
                kind: "integration_required",
                summary,
                details: RewriteWorkerCoordinationDetails {
                    execution_mode: None,
                    worker,
                    handoff_id: Some(handoff_id),
                },
                commands: RewriteWorkerCoordinationCommands {
                    report_worker,
                },
            }
            .serialize(serializer),
            Self::ExecutionFailed {
                summary,
                operation_id,
                retry,
                status,
            } => RewriteActionView {
                kind: "execution_failed",
                summary,
                details: serde_json::json!({"operation_id": operation_id}),
                commands: serde_json::json!({"retry": retry, "status": status}),
            }
            .serialize(serializer),
            Self::SourceReviewRequired { summary, check, show, rework, accept } => RewriteActionView {
                kind: "source_review_required", summary,
                details: serde_json::json!({"check_owner": "code-integrator", "coordinator_action": "accept_receipt"}),
                commands: serde_json::json!({"check": check, "show": show, "rework": rework, "accept": accept}),
            }.serialize(serializer),
            Self::TargetQualityRequired {
                summary,
                gate_id,
                target_fingerprint,
                gates,
                command,
            } => RewriteActionView {
                kind: "target_quality_required",
                summary,
                details: RewriteTargetQualityDetails {
                    gate_id,
                    target_fingerprint,
                    gates,
                },
                commands: RewriteExecuteCommands { execute: command },
            }
            .serialize(serializer),
            Self::PlanApplyRequired { summary, command } => RewriteActionView {
                kind: "plan_apply_required",
                summary,
                details: RewriteNoDetails {},
                commands: RewriteApplyCommands { apply: command },
            }
            .serialize(serializer),
            Self::AdvanceRequired { summary, command, api, kind } => RewriteActionView {
                kind: "advance_required",
                summary,
                details: serde_json::json!({"operation": kind, "api": api.as_deref().map(super::api_selector::public_api)}),
                commands: RewriteAdvanceCommands { advance: command },
            }
            .serialize(serializer),
            Self::SystemRepairRequired {
                work_scope,
                issue,
                route,
                acceptance,
            } => RewriteActionView {
                kind: "system_repair_required",
                summary: if acceptance.is_some() {
                    "verify the available system repair through commands.acceptance, then follow the returned action"
                } else {
                    "wait for the required system revision to change; global status continues other ready work"
                },
                details: RewriteSystemRepairDetails {
                    work_scope,
                    acceptance_ready: acceptance.is_some(),
                    issue: RewriteIssueDetails::from(issue),
                    route: route.as_ref(),
                },
                commands: RewriteAcceptanceCommands {
                    acceptance: acceptance.as_ref(),
                },
            }
            .serialize(serializer),
            Self::RecordingRefreshPending {
                summary,
                plan_ids,
                resource_identities,
                status,
            } => RewriteActionView {
                kind: "recording_refresh_pending",
                summary,
                details: RewriteRecordingRefreshPendingDetails {
                    plan_ids,
                    resource_identities,
                },
                commands: serde_json::json!({"wait": super::waiting::command(status, 30)}),
            }
            .serialize(serializer),
            Self::Complete {
                summary,
                e2e_current,
            } => RewriteActionView {
                kind: "complete",
                summary,
                details: RewriteCompleteDetails {
                    e2e_current: *e2e_current,
                },
                commands: RewriteNoCommands {},
            }
            .serialize(serializer),
        }
    }
}

#[derive(Serialize)]
struct RewriteActionView<'a, D, C> {
    kind: &'static str,
    summary: &'a str,
    details: D,
    commands: C,
}

#[derive(Serialize)]
struct RewriteNoDetails {}

#[derive(Serialize)]
struct RewriteNoCommands {}

#[derive(Serialize)]
struct RewriteInputRequiredDetails<'a> {
    reason: &'a RewriteInputRequiredReason,
    required: &'a [String],
    #[serde(skip_serializing_if = "Option::is_none")]
    recording_input_diagnosis: Option<&'a RewriteRecordingInputDiagnosis>,
}

#[derive(Serialize)]
struct RewriteRecordingInProgressDetails<'a> {
    run_id: &'a str,
    progress: &'a super::model::RewriteRecordingProgress,
    status_poll_after_seconds: u64,
}

#[derive(Serialize)]
struct RewriteCasePatternIdentificationDetails<'a> {
    batch_id: &'a str,
    recording_run_id: &'a str,
    candidates: &'a [String],
    pattern_input: RewriteCasePatternInput<'a>,
}

#[derive(Serialize)]
struct RewriteCasePatternInput<'a> {
    environment_variable: &'a str,
    format: &'a str,
    empty_array_meaning: &'a str,
    rules: [&'a str; 3],
}

#[derive(Serialize)]
struct RewriteRecordingRefreshPendingDetails<'a> {
    plan_ids: &'a [String],
    resource_identities: &'a [String],
}

#[derive(Serialize)]
struct RewriteWaitRequiredDetails<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    execution_mode: Option<super::model::RewriteExecutionMode>,
    reason: &'static str,
    resource: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    requested_api: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    blocking_api: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    active_operation: Option<&'a super::model::RewriteTrafficOperationView>,
    retry_after_seconds: u64,
}

#[derive(Serialize)]
struct RewriteIssueDetails<'a> {
    issue_id: &'a str,
    issue_kind: &'a RewriteIssueKind,
    owner: &'a RewriteIssueOwner,
    observed_target_fingerprint: &'a str,
    attempt: u64,
}

#[derive(Serialize)]
struct RewriteImplementationDetails<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    execution_mode: Option<super::model::RewriteExecutionMode>,
    #[serde(flatten)]
    issue: RewriteIssueDetails<'a>,
    work_scope: &'a super::work_scope::RewriteWorkScope,
    worker: &'a RewriteWorkerDispatchView,
}

#[derive(Serialize)]
struct RewriteTargetQualityDetails<'a> {
    gate_id: &'a str,
    target_fingerprint: &'a str,
    gates: &'a [String],
}

impl<'a> From<&'a RewriteIssue> for RewriteIssueDetails<'a> {
    fn from(issue: &'a RewriteIssue) -> Self {
        Self {
            issue_id: &issue.id,
            issue_kind: &issue.kind,
            owner: &issue.owner,
            observed_target_fingerprint: &issue.observed_target_fingerprint,
            attempt: issue.attempt,
        }
    }
}

#[derive(Serialize)]
struct RewriteSystemRepairDetails<'a> {
    work_scope: &'a super::RewriteWorkScope,
    acceptance_ready: bool,
    #[serde(flatten)]
    issue: RewriteIssueDetails<'a>,
    #[serde(skip_serializing_if = "Option::is_none")]
    route: Option<&'a RewriteRouteRecord>,
}

#[derive(Serialize)]
struct RewriteCompleteDetails {
    e2e_current: bool,
}

#[derive(Serialize)]
struct RewriteRecoveryCommands<'a> {
    recover: &'a RewriteCommandSpec,
}

#[derive(Serialize)]
struct RewriteExecuteCommands<'a> {
    execute: &'a RewriteCommandSpec,
}

#[derive(Serialize)]
struct RewriteImplementationCommands<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    confirm_worker: Option<&'a RewriteCommandSpec>,
    report_worker: &'a RewriteCommandSpec,
    acceptance: &'a RewriteCommandSpec,
}

#[derive(Serialize)]
struct RewriteWorkerCoordinationDetails<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    execution_mode: Option<super::model::RewriteExecutionMode>,
    worker: &'a RewriteWorkerDispatchView,
    #[serde(skip_serializing_if = "Option::is_none")]
    handoff_id: Option<&'a str>,
}

#[derive(Serialize)]
struct RewriteExpertDetails<'a> {
    #[serde(flatten)]
    expert: &'a super::expert::model::RewriteExpertView,
    #[serde(skip_serializing_if = "Option::is_none")]
    execution_mode: Option<super::model::RewriteExecutionMode>,
}

#[derive(Serialize)]
struct RewriteWorkerCoordinationCommands<'a> {
    report_worker: &'a RewriteCommandSpec,
}

#[derive(Serialize)]
struct RewriteApplyCommands<'a> {
    apply: &'a RewriteCommandSpec,
}

#[derive(Serialize)]
struct RewriteAdvanceCommands<'a> {
    advance: &'a RewriteCommandSpec,
}

#[derive(Serialize)]
struct RewriteAcceptanceCommands<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    acceptance: Option<&'a RewriteCommandSpec>,
}

/// Scheduling responses retain identity; inventory owns the expanded workflow view.
pub(super) fn compact_workflow<S>(
    workflow: &Option<super::model::RewriteWorkflowView>,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    #[derive(Serialize)]
    struct Identity<'a> {
        id: &'a str,
        revision: u64,
    }
    workflow
        .as_ref()
        .map(|value| Identity {
            id: &value.id,
            revision: value.revision,
        })
        .serialize(serializer)
}
