use serde::{Serialize, Serializer};
use serde_json::Value;

use crate::E2eRepresentativeDifference;

use super::model::{
    RewriteAction, RewriteCommandSpec, RewriteEvidenceCommand, RewriteInputRequiredReason,
    RewriteIssue, RewriteIssueKind, RewriteIssueOwner, RewriteRecordingInputDiagnosis,
    RewriteRecordingInputMode, RewriteRouteRecord,
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
                status,
            } => RewriteActionView {
                kind: "recording_in_progress",
                summary,
                details: RewriteRecordingRunDetails { run_id },
                commands: RewriteStatusCommands { status },
            }
            .serialize(serializer),
            Self::ImplementationRequired {
                issue,
                evidence_commands,
                acceptance,
            } => RewriteActionView {
                kind: "implementation_required",
                summary: &issue.summary,
                details: RewriteIssueDetails::from(issue),
                commands: RewriteImplementationCommands {
                    evidence: evidence_commands,
                    acceptance,
                },
            }
            .serialize(serializer),
            Self::PlanApplyRequired { summary, command } => RewriteActionView {
                kind: "plan_apply_required",
                summary,
                details: RewriteNoDetails {},
                commands: RewriteApplyCommands { apply: command },
            }
            .serialize(serializer),
            Self::ResumeRequired { summary, command } => RewriteActionView {
                kind: "resume_required",
                summary,
                details: RewriteNoDetails {},
                commands: RewriteResumeCommands { resume: command },
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
                issue,
                route,
                acceptance,
            } => RewriteActionView {
                kind: "system_repair_required",
                summary: &issue.summary,
                details: RewriteSystemRepairDetails {
                    issue: RewriteIssueDetails::from(issue),
                    route: route.as_ref(),
                },
                commands: RewriteAcceptanceCommands {
                    acceptance: acceptance.as_ref(),
                },
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
struct RewriteIssueDetails<'a> {
    issue_id: &'a str,
    issue_kind: &'a RewriteIssueKind,
    owner: &'a RewriteIssueOwner,
    #[serde(skip_serializing_if = "Option::is_none")]
    pointer_pattern: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    representative: Option<&'a E2eRepresentativeDifference>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    possible_causes: &'a Vec<String>,
    observed_target_fingerprint: &'a str,
    attempt: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    comparison_observation: Option<&'a Value>,
}

impl<'a> From<&'a RewriteIssue> for RewriteIssueDetails<'a> {
    fn from(issue: &'a RewriteIssue) -> Self {
        Self {
            issue_id: &issue.id,
            issue_kind: &issue.kind,
            owner: &issue.owner,
            pointer_pattern: issue.pointer_pattern.as_deref(),
            representative: issue.representative.as_ref(),
            possible_causes: &issue.possible_causes,
            observed_target_fingerprint: &issue.observed_target_fingerprint,
            attempt: issue.attempt,
            comparison_observation: issue.comparison_observation.as_ref(),
        }
    }
}

#[derive(Serialize)]
struct RewriteSystemRepairDetails<'a> {
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
    evidence: &'a [RewriteEvidenceCommand],
    acceptance: &'a RewriteCommandSpec,
}

#[derive(Serialize)]
struct RewriteApplyCommands<'a> {
    apply: &'a RewriteCommandSpec,
}

#[derive(Serialize)]
struct RewriteResumeCommands<'a> {
    resume: &'a RewriteCommandSpec,
}

#[derive(Serialize)]
struct RewriteAcceptanceCommands<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    acceptance: Option<&'a RewriteCommandSpec>,
}
