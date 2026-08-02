use std::fmt;
use std::num::{NonZeroU64, NonZeroUsize};
use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{E2eDiagnosisCounts, E2eRepresentativeDifference, E2eVerificationGates};

pub(super) const STATE_VERSION: u32 = 1;
pub(super) const ACTION_SCHEMA_VERSION: u32 = 1;

const DEFAULT_RECORDING_DURATION_SECONDS: NonZeroU64 = NonZeroU64::new(60).unwrap();
const DEFAULT_RECORDING_CASE_LIMIT: NonZeroUsize = NonZeroUsize::new(100).unwrap();

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RewritePhase {
    RecordingRequired,
    ImplementationRequired,
    ComparisonRecordingRequired,
    SystemRepairRequired,
    SliceComplete,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RewriteIssueKind {
    Response,
    TargetRuntime,
    Replay,
    Dependency,
    Comparison,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RewriteIssueOwner {
    TargetCode,
    TargetRuntime,
    TrafficE2eSystem,
    SourceInvestigation,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RewriteRecordingKind {
    Standard,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RewriteRecordingReason {
    UserRequested,
    RecorderContractChanged,
    SourceBaselineChanged,
}

impl fmt::Display for RewriteRecordingReason {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::UserRequested => "user_requested",
            Self::RecorderContractChanged => "recorder_contract_changed",
            Self::SourceBaselineChanged => "source_baseline_changed",
        })
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub(super) struct RewriteRecordingSettings {
    pub duration_seconds: NonZeroU64,
    pub case_limit: NonZeroUsize,
}

impl Default for RewriteRecordingSettings {
    fn default() -> Self {
        Self {
            duration_seconds: DEFAULT_RECORDING_DURATION_SECONDS,
            case_limit: DEFAULT_RECORDING_CASE_LIMIT,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RewriteAttemptSummary {
    pub attempt: u64,
    pub passed: bool,
    pub gates: E2eVerificationGates,
    pub counts: E2eDiagnosisCounts,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RewriteAttemptDelta {
    pub previous_attempt: u64,
    pub current_attempt: u64,
    pub response_passed_delta: i64,
    pub response_nonpassing_delta: i64,
    pub improved: bool,
    pub regressed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RewriteIssue {
    pub id: String,
    pub kind: RewriteIssueKind,
    pub owner: RewriteIssueOwner,
    pub summary: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pointer_pattern: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub representative: Option<E2eRepresentativeDifference>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub possible_causes: Vec<String>,
    pub observed_target_fingerprint: String,
    pub attempt: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comparison_observation: Option<Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RewriteRouteRecord {
    pub kind: String,
    pub evidence_id: String,
    pub source_ref: String,
    pub required_change: String,
    pub acceptance_command: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RewriteRulePlanRecord {
    pub id: String,
    pub issue_id: String,
    pub kind: String,
    pub json_pointer: String,
    #[serde(default)]
    pub dynamic_mechanisms: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_evidence: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_example: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_example: Option<String>,
    pub evidence_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct RewriteState {
    pub version: u32,
    pub revision: u64,
    pub workflow_id: String,
    pub phase: RewritePhase,
    pub api: String,
    pub source_route: String,
    pub recording_run_id: String,
    #[serde(default)]
    pub recording_rejection: Option<String>,
    #[serde(default)]
    pub recording_settings: RewriteRecordingSettings,
    #[serde(default)]
    pub recording_request_reason: Option<RewriteRecordingReason>,
    pub comparison_run_id: Option<String>,
    #[serde(default)]
    pub comparison_rejection: Option<String>,
    pub case_source: Option<PathBuf>,
    pub source_revision: Option<String>,
    pub group_id: Option<String>,
    pub target_fingerprint: Option<String>,
    pub attempts: Vec<RewriteAttemptSummary>,
    pub attempt_delta: Option<RewriteAttemptDelta>,
    pub active_issue: Option<RewriteIssue>,
    pub rule_plan: Option<RewriteRulePlanRecord>,
    pub route: Option<RewriteRouteRecord>,
    pub e2e_current: bool,
    pub comparison_current: bool,
}

impl RewriteState {
    pub(super) fn bump(&mut self) {
        self.revision = self.revision.saturating_add(1);
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct RewriteWorkflowView {
    pub id: String,
    pub revision: u64,
    pub phase: RewritePhase,
    pub scope: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct RewriteCommandSpec {
    pub argv: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub required_env_names: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum RewriteAction {
    InputRequired {
        summary: String,
        required: Vec<String>,
    },
    RecoveryRequired {
        summary: String,
        command: RewriteCommandSpec,
        resume: RewriteCommandSpec,
    },
    RecordingRequired {
        summary: String,
        command: RewriteCommandSpec,
        resume: RewriteCommandSpec,
    },
    ImplementationRequired {
        issue: RewriteIssue,
        evidence_commands: Vec<RewriteEvidenceCommand>,
        acceptance: RewriteCommandSpec,
    },
    ComparisonRecordingRequired {
        summary: String,
        command: RewriteCommandSpec,
        resume: RewriteCommandSpec,
    },
    SystemRepairRequired {
        issue: RewriteIssue,
        #[serde(skip_serializing_if = "Option::is_none")]
        route: Option<RewriteRouteRecord>,
    },
    Complete {
        summary: String,
        e2e_current: bool,
        comparison_current: bool,
    },
}

#[derive(Debug, Clone, Serialize)]
pub struct RewriteEvidenceCommand {
    pub purpose: String,
    pub query_id: String,
    pub command: RewriteCommandSpec,
}

#[derive(Debug, Clone, Serialize)]
pub struct RewriteActionEnvelope {
    pub schema_version: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub workflow: Option<RewriteWorkflowView>,
    pub action: RewriteAction,
    pub terminal_allowed: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct RewriteStatusReport {
    pub initialized: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub workflow: Option<RewriteWorkflowView>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub active_issue: Option<RewriteIssue>,
    pub e2e_current: bool,
    pub comparison_current: bool,
    pub terminal_allowed: bool,
    pub next: RewriteCommandSpec,
}

#[derive(Debug, Clone, Serialize)]
pub struct RewriteRecoveryReport {
    pub recovered_stale_lock: bool,
    pub recovered_focused_attempt: bool,
    pub next: RewriteCommandSpec,
}

#[derive(Debug, Clone, Serialize)]
pub struct RewriteEvidenceReport {
    pub schema_version: u32,
    pub evidence_id: String,
    pub issue_id: String,
    pub query: String,
    pub facts: Value,
    pub does_not_prove: Vec<String>,
    pub next_step: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct RewriteRuleReport {
    pub plan_id: String,
    pub issue_id: String,
    pub traffic_e2e_report: Value,
    pub next_command: RewriteCommandSpec,
}

#[derive(Debug, Clone, Serialize)]
pub struct RewriteRouteReport {
    pub accepted: bool,
    pub issue_id: String,
    pub route: RewriteRouteRecord,
    pub next_command: RewriteCommandSpec,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn older_state_uses_bounded_recording_defaults() {
        let mut value = serde_json::to_value(crate::rewrite::test_state()).unwrap();
        let object = value.as_object_mut().unwrap();
        object.remove("recording_settings");
        object.remove("recording_request_reason");

        let state: RewriteState = serde_json::from_value(value).unwrap();

        assert_eq!(state.recording_settings.duration_seconds.get(), 60);
        assert_eq!(state.recording_settings.case_limit.get(), 100);
        assert!(state.recording_request_reason.is_none());
    }
}
