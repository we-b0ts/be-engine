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
            Self::BatchDiagnosisRequired{summary,evidence,inspect,retry} => RewriteActionView {
                kind:"batch_diagnosis_required",summary,details:evidence,
                commands:serde_json::json!({"inspect":inspect,"retry_after_repair":retry}),
            }.serialize(serializer),
            Self::DependencyAttributionRequired { summary, context, apply,assignment_id,dispatch_generation,claim_kinds } => RewriteActionView {
                kind:"dependency_attribution_required", summary,
                details:serde_json::json!({"work_type":"dependency_attribution","owner":"repository_analyst",
                    "assignment_id":assignment_id,"dispatch_generation":dispatch_generation,"claim_kinds":claim_kinds,"read_only_analysis":true}),
                commands:serde_json::json!({"context":context,"apply":apply}),
            }.serialize(serializer),
            Self::RepositoryAnalysisRequired { summary, analysis, context, apply } => RewriteActionView {
                kind: "repository_analysis_required", summary,
                details: analysis,
                commands: serde_json::json!({"context": context, "apply": apply}),
            }.serialize(serializer),
            Self::ImplementerDispatchRequired { summary, dispatch, confirm, report } => RewriteActionView {
                kind: "implementer_dispatch_required", summary,
                details: dispatch,
                commands: serde_json::json!({"confirm": confirm, "report": report}),
            }.serialize(serializer),
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
                report_rework,
            } => RewriteActionView {
                kind: "integration_required",
                summary,
                details: RewriteWorkerCoordinationDetails {
                    execution_mode: None,
                    worker,
                    handoff_id: Some(handoff_id),
                },
                commands: serde_json::json!({"report_worker": report_worker, "report_rework": report_rework}),
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
            Self::PreRevalidationReviewRequired { summary, quality_check, quality_paths, check, accept } => RewriteActionView {
                kind: "pre_revalidation_review_required", summary,
                details: serde_json::json!({"check_owner": "code-integrator", "coordinator_action": "publish_candidate_and_accept_receipt", "stage": "pre_revalidation", "quality_check": quality_check, "quality_paths": quality_paths}),
                commands: serde_json::json!({"check": check, "accept": accept}),
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
pub struct RewriteActionView<'a, D, C> {
    pub kind: &'static str,
    pub summary: &'a str,
    pub details: D,
    pub commands: C,
}

#[derive(Serialize)]
pub struct RewriteNoDetails {}

#[derive(Serialize)]
pub struct RewriteNoCommands {}

#[derive(Serialize)]
pub struct RewriteInputRequiredDetails<'a> {
    pub reason: &'a RewriteInputRequiredReason,
    pub required: &'a [String],
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recording_input_diagnosis: Option<&'a RewriteRecordingInputDiagnosis>,
}

#[derive(Serialize)]
pub struct RewriteRecordingInProgressDetails<'a> {
    pub run_id: &'a str,
    pub progress: &'a super::model::RewriteRecordingProgress,
    pub status_poll_after_seconds: u64,
}

#[derive(Serialize)]
pub struct RewriteRecordingRefreshPendingDetails<'a> {
    pub plan_ids: &'a [String],
    pub resource_identities: &'a [String],
}

#[derive(Serialize)]
pub struct RewriteWaitRequiredDetails<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub execution_mode: Option<super::model::RewriteExecutionMode>,
    pub reason: &'static str,
    pub resource: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub requested_api: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub blocking_api: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub active_operation: Option<&'a super::model::RewriteTrafficOperationView>,
    pub retry_after_seconds: u64,
}

#[derive(Serialize)]
pub struct RewriteIssueDetails<'a> {
    pub issue_id: &'a str,
    pub issue_kind: &'a RewriteIssueKind,
    pub owner: &'a RewriteIssueOwner,
    pub observed_target_fingerprint: &'a str,
    pub attempt: u64,
}

#[derive(Serialize)]
pub struct RewriteImplementationDetails<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub execution_mode: Option<super::model::RewriteExecutionMode>,
    #[serde(flatten)]
    pub issue: RewriteIssueDetails<'a>,
    pub work_scope: &'a super::work_scope::RewriteWorkScope,
    pub worker: &'a RewriteWorkerDispatchView,
}

#[derive(Serialize)]
pub struct RewriteTargetQualityDetails<'a> {
    pub gate_id: &'a str,
    pub target_fingerprint: &'a str,
    pub gates: &'a [String],
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
pub struct RewriteSystemRepairDetails<'a> {
    pub work_scope: &'a super::RewriteWorkScope,
    pub acceptance_ready: bool,
    #[serde(flatten)]
    pub issue: RewriteIssueDetails<'a>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub route: Option<&'a RewriteRouteRecord>,
}

#[derive(Serialize)]
pub struct RewriteCompleteDetails {
    pub e2e_current: bool,
}

#[derive(Serialize)]
pub struct RewriteRecoveryCommands<'a> {
    pub recover: &'a RewriteCommandSpec,
}

#[derive(Serialize)]
pub struct RewriteExecuteCommands<'a> {
    pub execute: &'a RewriteCommandSpec,
}

#[derive(Serialize)]
pub struct RewriteImplementationCommands<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub confirm_worker: Option<&'a RewriteCommandSpec>,
    pub report_worker: &'a RewriteCommandSpec,
    pub acceptance: &'a RewriteCommandSpec,
}

#[derive(Serialize)]
pub struct RewriteWorkerCoordinationDetails<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub execution_mode: Option<super::model::RewriteExecutionMode>,
    pub worker: &'a RewriteWorkerDispatchView,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub handoff_id: Option<&'a str>,
}

#[derive(Serialize)]
pub struct RewriteExpertDetails<'a> {
    #[serde(flatten)]
    pub expert: &'a super::expert::model::RewriteExpertView,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub execution_mode: Option<super::model::RewriteExecutionMode>,
}

#[derive(Serialize)]
pub struct RewriteWorkerCoordinationCommands<'a> {
    pub report_worker: &'a RewriteCommandSpec,
}

#[derive(Serialize)]
pub struct RewriteApplyCommands<'a> {
    pub apply: &'a RewriteCommandSpec,
}

#[derive(Serialize)]
pub struct RewriteAdvanceCommands<'a> {
    pub advance: &'a RewriteCommandSpec,
}

#[derive(Serialize)]
pub struct RewriteAcceptanceCommands<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub acceptance: Option<&'a RewriteCommandSpec>,
}

/// Scheduling responses retain identity; inventory owns the expanded workflow view.
pub fn compact_workflow<S>(
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
