use serde::{Serialize, Serializer};

use super::model::{
    RewriteAction, RewriteCommandSpec, RewriteInputRequiredReason, RewriteIssue, RewriteIssueKind,
    RewriteIssueOwner, RewriteRecordingInputDiagnosis, RewriteRecordingInputMode,
    RewriteRouteRecord, RewriteWorkerDispatchView,
};

impl Serialize for RewriteAction {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Self::InputRequired {
                reason,
                summary,
                required,
            } => RewriteActionView {
                kind: "input_required",
                summary,
                details: RewriteInputRequiredDetails { reason, required },
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
                    reason: "resource_busy",
                    resource,
                    requested_api: requested_api.as_deref(),
                    blocking_api: blocking_api.as_deref(),
                    active_operation: active_operation.as_ref(),
                    retry_after_seconds: *retry_after_seconds,
                },
                commands: RewriteStatusCommands { status },
            }
            .serialize(serializer),
            Self::RecordingRequired {
                summary,
                run_id,
                input_mode,
                recording_input_diagnosis,
                command,
            } => RewriteActionView {
                kind: "recording_required",
                summary,
                details: RewriteRecordingRequiredDetails {
                    run_id,
                    input_mode,
                    recording_input_diagnosis: recording_input_diagnosis.as_ref(),
                },
                commands: RewriteRecordingCommands { execute: command },
            }
            .serialize(serializer),
            Self::RecordingInProgress {
                summary,
                run_id,
                status_poll_after_seconds,
                status,
            } => RewriteActionView {
                kind: "recording_in_progress",
                summary,
                details: RewriteRecordingInProgressDetails {
                    run_id,
                    status_poll_after_seconds: *status_poll_after_seconds,
                },
                commands: RewriteStatusCommands { status },
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
                        environment_variable: "BACKEND_REWRITE_CASE_PATH_PATTERNS_JSON",
                        format: "JSON array of path patterns",
                        empty_array_meaning: "every candidate is a static path",
                        rules: [
                            "replace only variable whole path segments with *",
                            "use ** only as the final segment for a source-defined catch-all tail",
                            "omit static paths from the array",
                        ],
                    },
                },
                commands: RewriteApplyCommands { apply: command },
            }
            .serialize(serializer),
            Self::ImplementationRequired {
                summary,
                issue,
                worker,
                confirm_worker,
                report_worker,
                evidence,
                acceptance,
            } => RewriteActionView {
                kind: "implementation_required",
                summary,
                details: RewriteImplementationDetails {
                    issue: RewriteIssueDetails::from(issue),
                    work_scope: &worker.work_scope,
                    worker,
                },
                commands: RewriteImplementationCommands {
                    confirm_worker: confirm_worker.as_ref(),
                    report_worker,
                    evidence,
                    acceptance,
                },
            }
            .serialize(serializer),
            Self::WorkerStatusRequired {
                summary,
                worker,
                report_worker,
                evidence,
            } => RewriteActionView {
                kind: "worker_status_required",
                summary,
                details: RewriteWorkerCoordinationDetails {
                    worker,
                    handoff_id: None,
                },
                commands: RewriteWorkerCoordinationCommands {
                    report_worker,
                    evidence,
                },
            }
            .serialize(serializer),
            Self::IntegrationRequired {
                summary,
                worker,
                handoff_id,
                report_worker,
                evidence,
            } => RewriteActionView {
                kind: "integration_required",
                summary,
                details: RewriteWorkerCoordinationDetails {
                    worker,
                    handoff_id: Some(handoff_id),
                },
                commands: RewriteWorkerCoordinationCommands {
                    report_worker,
                    evidence,
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
                commands: RewriteRecordingCommands { execute: command },
            }
            .serialize(serializer),
            Self::PlanApplyRequired { summary, command } => RewriteActionView {
                kind: "plan_apply_required",
                summary,
                details: RewriteNoDetails {},
                commands: RewriteApplyCommands { apply: command },
            }
            .serialize(serializer),
            Self::AdvanceRequired { summary, command } => RewriteActionView {
                kind: "advance_required",
                summary,
                details: RewriteNoDetails {},
                commands: RewriteAdvanceCommands { advance: command },
            }
            .serialize(serializer),
            Self::ComparisonRecordingRequired {
                summary,
                run_id,
                command,
            } => RewriteActionView {
                kind: "comparison_recording_required",
                summary,
                details: RewriteRecordingRunDetails { run_id },
                commands: RewriteRecordingCommands { execute: command },
            }
            .serialize(serializer),
            Self::SystemRepairRequired {
                work_scope,
                issue,
                route,
                evidence,
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
                    evidence,
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
                commands: RewriteStatusCommands { status },
            }
            .serialize(serializer),
            Self::Complete {
                summary,
                e2e_current,
                comparison_current,
            } => RewriteActionView {
                kind: "complete",
                summary,
                details: RewriteCompleteDetails {
                    e2e_current: *e2e_current,
                    comparison_current: *comparison_current,
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
}

#[derive(Serialize)]
struct RewriteRecordingRequiredDetails<'a> {
    run_id: &'a str,
    input_mode: &'a RewriteRecordingInputMode,
    #[serde(skip_serializing_if = "Option::is_none")]
    recording_input_diagnosis: Option<&'a RewriteRecordingInputDiagnosis>,
}

#[derive(Serialize)]
struct RewriteRecordingRunDetails<'a> {
    run_id: &'a str,
}

#[derive(Serialize)]
struct RewriteRecordingInProgressDetails<'a> {
    run_id: &'a str,
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
    #[serde(flatten)]
    issue: RewriteIssueDetails<'a>,
    work_scope: &'a super::process_output_model::RewriteWorkScope,
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
    comparison_current: bool,
}

#[derive(Serialize)]
struct RewriteRecoveryCommands<'a> {
    recover: &'a RewriteCommandSpec,
}

#[derive(Serialize)]
struct RewriteRecordingCommands<'a> {
    execute: &'a RewriteCommandSpec,
}

#[derive(Serialize)]
struct RewriteStatusCommands<'a> {
    status: &'a RewriteCommandSpec,
}

#[derive(Serialize)]
struct RewriteImplementationCommands<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    confirm_worker: Option<&'a RewriteCommandSpec>,
    report_worker: &'a RewriteCommandSpec,
    evidence: &'a RewriteCommandSpec,
    acceptance: &'a RewriteCommandSpec,
}

#[derive(Serialize)]
struct RewriteWorkerCoordinationDetails<'a> {
    worker: &'a RewriteWorkerDispatchView,
    #[serde(skip_serializing_if = "Option::is_none")]
    handoff_id: Option<&'a str>,
}

#[derive(Serialize)]
struct RewriteWorkerCoordinationCommands<'a> {
    report_worker: &'a RewriteCommandSpec,
    evidence: &'a RewriteCommandSpec,
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
    evidence: &'a RewriteCommandSpec,
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
