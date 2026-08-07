use std::collections::BTreeMap;
use std::fmt;
use std::num::{NonZeroU64, NonZeroUsize};
use std::ops::{Deref, DerefMut};
use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::RedisKeyPatternConfig;
use crate::{E2eDiagnosisCounts, E2eRepresentativeDifference, E2eVerificationGates};

pub(super) const STATE_VERSION: u32 = 1;
pub(super) const ACTION_SCHEMA_VERSION: u32 = 12;

const DEFAULT_RECORDING_DURATION_SECONDS: NonZeroU64 = NonZeroU64::new(60).unwrap();
const DEFAULT_RECORDING_CASE_LIMIT: NonZeroUsize = NonZeroUsize::new(100).unwrap();

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RewritePhase {
    RecordingRequired,
    ApiPending,
    ImplementationRequired,
    AwaitingRecordingRefresh,
    ComparisonRecordingRequired,
    SystemRepairRequired,
    SliceComplete,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RewriteApiStatus {
    #[default]
    Pending,
    Active,
    ImplementationRequired,
    AwaitingRecordingRefresh,
    RevalidationPending,
    Complete,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RewriteApiProgress {
    pub api: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_route: Option<String>,
    #[serde(default)]
    pub status: RewriteApiStatus,
    #[serde(default)]
    pub attempts: usize,
    #[serde(default)]
    pub e2e_current: bool,
    #[serde(default)]
    pub comparison_current: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verified_target_fingerprint: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct RewriteApiInventoryView {
    pub total: usize,
    pub completed: usize,
    pub pending: usize,
    pub implementation_required: usize,
    pub awaiting_recording_refresh: usize,
    pub revalidation_pending: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub current_index: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub current_api: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct RewriteApiInventoryDetails {
    #[serde(flatten)]
    pub summary: RewriteApiInventoryView,
    pub items: Vec<RewriteApiProgress>,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RewriteFocusedE2eExecutionMode {
    FreshStandardCases,
    ReusedStandardCases,
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

impl RewriteRecordingReason {
    pub(super) fn requires_external_live_traffic(self) -> bool {
        matches!(
            self,
            Self::UserRequested | Self::RecorderContractChanged | Self::SourceBaselineChanged
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct RewriteRecordingSettings {
    pub duration_seconds: NonZeroU64,
    #[serde(default = "default_recording_case_limit")]
    pub per_api_case_limit: NonZeroUsize,
}

const fn default_recording_case_limit() -> NonZeroUsize {
    DEFAULT_RECORDING_CASE_LIMIT
}

impl Default for RewriteRecordingSettings {
    fn default() -> Self {
        Self {
            duration_seconds: DEFAULT_RECORDING_DURATION_SECONDS,
            per_api_case_limit: DEFAULT_RECORDING_CASE_LIMIT,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub repair_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub acceptance_kind: Option<RewriteRepairAcceptanceKind>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed_revision: Option<String>,
    #[serde(default, rename = "acceptance_command", skip_serializing)]
    pub(crate) legacy_acceptance_command: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RewriteRepairAcceptanceKind {
    TrafficE2eRevisionChanged,
    SourceRevisionChanged,
    SourceRuntimeInputsChanged,
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
#[serde(tag = "protocol", rename_all = "snake_case")]
pub(super) enum RewriteDependencyRuleSpec {
    Http {
        authority: String,
        method: String,
        path_prefix: String,
    },
    Memcached {
        breeze_resource: String,
        command: String,
        key_start: u64,
        key_end: u64,
        key_separator: String,
        key_suffix: String,
        initial_load_timeout_ms: u64,
    },
    Motan {
        group: String,
        interface_name: String,
        method_name: String,
    },
    RedisZcount {
        ports: Vec<u16>,
        key_prefix: String,
        key_suffix: String,
    },
    RedisGet {
        ports: Vec<u16>,
        keys: Vec<String>,
        initial_load_timeout_ms: u64,
    },
    RedisScard {
        ports: Vec<u16>,
        keys: Vec<String>,
        initial_load_timeout_ms: u64,
    },
    RedisHgetall {
        ports: Vec<u16>,
        keys: Vec<String>,
        initial_load_timeout_ms: u64,
    },
    RedisHashRead {
        command: String,
        ports: Vec<u16>,
        keys: Vec<String>,
        key_patterns: Vec<RedisKeyPatternConfig>,
        fields: Vec<String>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct RewriteDependencyRulePlanRecord {
    pub id: String,
    pub issue_id: String,
    pub evidence_id: String,
    pub name: String,
    pub source_evidence: String,
    pub spec: RewriteDependencyRuleSpec,
    #[serde(default)]
    pub reused_existing: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub effective_name: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct RewriteRecorderCapturePlanRecord {
    pub id: String,
    pub issue_id: String,
    pub evidence_id: String,
    pub endpoint: String,
    pub source_evidence: String,
    pub source_revision: String,
    pub recorder_config_revision: String,
    pub resource_identity: String,
    pub target_fingerprint: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct RewriteRecorderCaptureAppliedRecord {
    pub plan_id: String,
    pub issue_id: String,
    pub evidence_id: String,
    pub api: String,
    pub endpoint: String,
    pub resource_identity: String,
    pub source_revision: String,
    pub source_evidence: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct RewriteRecordingRefreshState {
    pub applied: Vec<RewriteRecorderCaptureAppliedRecord>,
    pub recorder_config_revision: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recording_run_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct RewriteWorkerBinding {
    pub agent_handle_fingerprint: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_name: Option<String>,
    pub confirmed_dispatch_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct RewriteSliceState {
    pub phase: RewritePhase,
    pub api: String,
    pub source_route: String,
    pub comparison_run_id: Option<String>,
    #[serde(default)]
    pub comparison_rejection: Option<String>,
    pub case_source: Option<PathBuf>,
    #[serde(default)]
    pub case_inventory_id: Option<String>,
    pub source_revision: Option<String>,
    pub group_id: Option<String>,
    pub target_fingerprint: Option<String>,
    pub attempts: Vec<RewriteAttemptSummary>,
    pub attempt_delta: Option<RewriteAttemptDelta>,
    pub active_issue: Option<RewriteIssue>,
    pub rule_plan: Option<RewriteRulePlanRecord>,
    #[serde(default)]
    pub dependency_rule_plan: Option<RewriteDependencyRulePlanRecord>,
    #[serde(default)]
    pub recorder_capture_plan: Option<RewriteRecorderCapturePlanRecord>,
    pub route: Option<RewriteRouteRecord>,
    pub e2e_current: bool,
    pub comparison_current: bool,
}

impl RewriteSliceState {
    pub(super) fn pending(api: String, source_route: String) -> Self {
        Self {
            phase: RewritePhase::ApiPending,
            api,
            source_route,
            comparison_run_id: None,
            comparison_rejection: None,
            case_source: None,
            case_inventory_id: None,
            source_revision: None,
            group_id: None,
            target_fingerprint: None,
            attempts: Vec::new(),
            attempt_delta: None,
            active_issue: None,
            rule_plan: None,
            dependency_rule_plan: None,
            recorder_capture_plan: None,
            route: None,
            e2e_current: false,
            comparison_current: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct RewriteState {
    pub version: u32,
    pub revision: u64,
    pub workflow_id: String,
    #[serde(default)]
    pub recording_apis: Vec<String>,
    #[serde(default)]
    pub api_inventory: Vec<RewriteApiProgress>,
    #[serde(default)]
    pub current_api_index: Option<usize>,
    #[serde(default)]
    pub parked_slices: BTreeMap<String, RewriteSliceState>,
    #[serde(default)]
    pub worker_bindings: BTreeMap<String, RewriteWorkerBinding>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_quality_fingerprint: Option<String>,
    pub recording_run_id: String,
    #[serde(default)]
    pub recording_rejection: Option<String>,
    #[serde(default)]
    pub recording_settings: RewriteRecordingSettings,
    #[serde(default)]
    pub recording_request_reason: Option<RewriteRecordingReason>,
    #[serde(default)]
    pub recording_input_case_source: Option<PathBuf>,
    #[serde(default)]
    pub recording_input_diagnosis: Option<RewriteRecordingInputDiagnosis>,
    #[serde(default)]
    pub recording_refresh: Option<RewriteRecordingRefreshState>,
    #[serde(flatten)]
    pub active_slice: RewriteSliceState,
}

impl Deref for RewriteState {
    type Target = RewriteSliceState;

    fn deref(&self) -> &Self::Target {
        &self.active_slice
    }
}

impl DerefMut for RewriteState {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.active_slice
    }
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
pub struct RewriteFocusedE2eExecution {
    pub execution_mode: RewriteFocusedE2eExecutionMode,
    pub recording_run_id: String,
    pub case_source: PathBuf,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub case_inventory_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub previous_attempt: Option<u64>,
    pub current_attempt: u64,
    pub passed: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct RewriteCommandSpec {
    pub cwd: PathBuf,
    pub argv: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub required_env_names: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RewriteWorkerDispatchState {
    DispatchRequired,
    ResumeRequired,
    Confirmed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RewriteWorkerBlockingReason {
    WorkerDispatchUnconfirmed,
}

#[derive(Debug, Clone, Serialize)]
pub struct RewriteWorkerDispatchView {
    pub binding_id: String,
    pub dispatch_id: String,
    pub state: RewriteWorkerDispatchState,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub blocking_reason: Option<RewriteWorkerBlockingReason>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub requested_api: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_name: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RewriteInputRequiredReason {
    WorkflowNotInitialized,
    SourceRouteRequired,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RewriteRecordingInputMode {
    ReusedAtomicRecording,
    ExternalLiveTraffic,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RewriteRecordingInputRejections {
    pub unreadable: usize,
    pub not_completed: usize,
    pub empty: usize,
    pub dirty: usize,
    pub scope_mismatch: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RewriteRecordingInputDiagnosis {
    pub requested_scope: String,
    pub inspected_runs: usize,
    pub omitted_older_runs: usize,
    pub finalized_clean_runs: usize,
    pub observed_apis: Vec<String>,
    pub rejections: RewriteRecordingInputRejections,
    pub candidates: Vec<RewriteRecordingInputCandidate>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RewriteRecordingInputCandidate {
    pub run_id: String,
    pub recording_apis: Vec<String>,
    pub omitted_recording_apis: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub published_cases: Option<usize>,
    pub disposition: RewriteRecordingInputCandidateDisposition,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RewriteRecordingInputCandidateDisposition {
    Unreadable,
    NotCompleted,
    Empty,
    Dirty,
    ScopeMismatch,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RewriteTrafficOperationKind {
    Recording,
    Replay,
    Comparison,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RewriteTrafficOperationView {
    pub operation_id: String,
    pub kind: RewriteTrafficOperationKind,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub api: Option<String>,
    pub started_at: String,
}

#[derive(Debug, Clone)]
pub enum RewriteAction {
    InputRequired {
        reason: RewriteInputRequiredReason,
        summary: String,
        required: Vec<String>,
    },
    RecoveryRequired {
        summary: String,
        command: RewriteCommandSpec,
    },
    WaitRequired {
        summary: String,
        resource: String,
        requested_api: Option<String>,
        blocking_api: Option<String>,
        active_operation: Option<RewriteTrafficOperationView>,
        retry_after_seconds: u64,
        status: RewriteCommandSpec,
    },
    RecordingRequired {
        summary: String,
        run_id: String,
        input_mode: RewriteRecordingInputMode,
        recording_input_diagnosis: Option<RewriteRecordingInputDiagnosis>,
        command: RewriteCommandSpec,
    },
    RecordingInProgress {
        summary: String,
        run_id: String,
        status: RewriteCommandSpec,
    },
    ImplementationRequired {
        summary: String,
        issue: RewriteIssue,
        worker: RewriteWorkerDispatchView,
        confirm_worker: Option<RewriteCommandSpec>,
        evidence_commands: Vec<RewriteEvidenceCommand>,
        acceptance: RewriteCommandSpec,
    },
    TargetQualityRequired {
        summary: String,
        gate_id: String,
        target_fingerprint: String,
        gates: Vec<String>,
        command: RewriteCommandSpec,
    },
    PlanApplyRequired {
        summary: String,
        command: RewriteCommandSpec,
    },
    AdvanceRequired {
        summary: String,
        command: RewriteCommandSpec,
    },
    ComparisonRecordingRequired {
        summary: String,
        run_id: String,
        command: RewriteCommandSpec,
    },
    SystemRepairRequired {
        issue: RewriteIssue,
        route: Option<RewriteRouteRecord>,
        acceptance: Option<RewriteCommandSpec>,
    },
    RecordingRefreshPending {
        summary: String,
        plan_ids: Vec<String>,
        resource_identities: Vec<String>,
        status: RewriteCommandSpec,
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
pub struct RewriteApplicableRulePlanner {
    pub kind: String,
    pub protocol: String,
    pub evidence_id: String,
    pub command: RewriteCommandSpec,
}

#[derive(Debug, Clone, Serialize)]
pub struct RewriteActionEnvelope {
    pub schema_version: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub workflow: Option<RewriteWorkflowView>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub api_inventory: Option<RewriteApiInventoryView>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latest_focused_e2e: Option<RewriteFocusedE2eExecution>,
    pub action: RewriteAction,
    pub terminal_allowed: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct RewriteStatusReport {
    pub schema_version: u32,
    pub initialized: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub workflow: Option<RewriteWorkflowView>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub api_inventory: Option<RewriteApiInventoryView>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latest_focused_e2e: Option<RewriteFocusedE2eExecution>,
    pub e2e_current: bool,
    pub comparison_current: bool,
    pub terminal_allowed: bool,
    pub action: RewriteAction,
}

#[derive(Debug, Clone, Serialize)]
pub struct RewriteInventoryReport {
    pub schema_version: u32,
    pub initialized: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub workflow: Option<RewriteWorkflowView>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub api_inventory: Option<RewriteApiInventoryDetails>,
}

#[derive(Debug, Clone, Serialize)]
pub struct RewriteRecoveryReport {
    pub recovered_stale_lock: bool,
    pub recovered_stale_traffic_operation: bool,
    pub recovered_focused_attempt: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recovered_recording_run: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub replacement_recording_run: Option<String>,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub removed_managed_containers: usize,
    pub next: RewriteCommandSpec,
}

fn is_zero(value: &usize) -> bool {
    *value == 0
}

#[derive(Debug, Clone, Serialize)]
pub struct RewriteRecordingExecutionReport {
    pub action_id: String,
    pub run_id: String,
    pub operation: String,
    pub already_completed: bool,
    pub manifest: PathBuf,
    pub next: RewriteCommandSpec,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RewriteRecordingStartState {
    Started,
    AlreadyRunning,
    AlreadyCompleted,
    WaitingForTrafficRuntime,
}

#[derive(Debug, Clone, Serialize)]
pub struct RewriteRecordingStartReport {
    pub action_id: String,
    pub run_id: String,
    pub operation: String,
    pub execution_state: RewriteRecordingStartState,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub waiting_on: Option<RewriteTrafficOperationView>,
    pub status: RewriteCommandSpec,
}

#[derive(Debug, Clone, Serialize)]
pub struct RewriteEvidenceReport {
    pub schema_version: u32,
    pub evidence_id: String,
    pub issue_id: String,
    pub query: String,
    pub facts: Value,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub applicable_rule_planners: Vec<RewriteApplicableRulePlanner>,
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
pub struct RewriteDependencyRuleReport {
    pub plan_id: String,
    pub issue_id: String,
    pub traffic_e2e_report: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub evidence_reclassification: Option<Value>,
    pub next_command: RewriteCommandSpec,
}

#[derive(Debug, Clone, Serialize)]
pub struct RewriteRecorderCaptureReport {
    pub plan_id: String,
    pub issue_id: String,
    pub api: String,
    pub traffic_e2e_report: Value,
    pub recording_refresh_pending: bool,
    pub awaiting_apis: Vec<String>,
    pub next_command: RewriteCommandSpec,
}

#[derive(Debug, Clone, Serialize)]
pub struct RewriteRouteReport {
    pub accepted: bool,
    pub issue_id: String,
    pub route: RewriteRouteRecord,
    pub acceptance: RewriteCommandSpec,
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;

    #[test]
    fn older_state_uses_bounded_recording_defaults() {
        let mut value = serde_json::to_value(crate::rewrite::test_state()).unwrap();
        let object = value.as_object_mut().unwrap();
        object.remove("recording_settings");
        object.remove("recording_request_reason");
        object.remove("recording_input_case_source");
        object.remove("recording_input_diagnosis");
        object.remove("case_inventory_id");
        object.remove("recording_apis");
        object.remove("api_inventory");
        object.remove("current_api_index");
        object.remove("parked_slices");
        object.remove("worker_bindings");

        let state: RewriteState = serde_json::from_value(value).unwrap();

        assert_eq!(state.recording_settings.duration_seconds.get(), 60);
        assert_eq!(state.recording_settings.per_api_case_limit.get(), 100);
        assert!(state.recording_request_reason.is_none());
        assert!(state.recording_input_case_source.is_none());
        assert!(state.recording_input_diagnosis.is_none());
        assert!(state.case_inventory_id.is_none());
        assert!(state.recording_apis.is_empty());
        assert!(state.api_inventory.is_empty());
        assert!(state.current_api_index.is_none());
        assert!(state.parked_slices.is_empty());
        assert!(state.worker_bindings.is_empty());
        assert!(state.target_quality_fingerprint.is_none());
    }

    #[test]
    fn implementation_action_has_one_stable_public_shape() {
        let command = RewriteCommandSpec {
            cwd: PathBuf::from("/target"),
            argv: vec!["backend-rewrite".to_string(), "status".to_string()],
            required_env_names: Vec::new(),
        };
        let action = RewriteAction::ImplementationRequired {
            summary: "response status differs".to_string(),
            issue: RewriteIssue {
                id: "issue-response".to_string(),
                kind: RewriteIssueKind::Response,
                owner: RewriteIssueOwner::TargetCode,
                summary: "response status differs".to_string(),
                pointer_pattern: Some("/status".to_string()),
                representative: None,
                possible_causes: vec!["target behavior differs".to_string()],
                observed_target_fingerprint: "fnv1a64:target".to_string(),
                attempt: 2,
                comparison_observation: None,
            },
            worker: RewriteWorkerDispatchView {
                binding_id: "worker-binding".to_string(),
                dispatch_id: "worker-dispatch".to_string(),
                state: RewriteWorkerDispatchState::DispatchRequired,
                blocking_reason: Some(RewriteWorkerBlockingReason::WorkerDispatchUnconfirmed),
                requested_api: None,
                agent_name: None,
            },
            confirm_worker: Some(command.clone()),
            evidence_commands: vec![RewriteEvidenceCommand {
                purpose: "inspect representative".to_string(),
                query_id: "representatives".to_string(),
                command: command.clone(),
            }],
            acceptance: command,
        };

        let value = serde_json::to_value(&action).unwrap();
        let keys = value
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect::<BTreeSet<_>>();
        assert_eq!(
            keys,
            BTreeSet::from(["commands", "details", "kind", "summary"])
        );
        assert_eq!(
            value.pointer("/details/issue_id"),
            Some(&serde_json::json!("issue-response"))
        );
        assert_eq!(
            value.pointer("/details/possible_causes/0"),
            Some(&serde_json::json!("target behavior differs"))
        );
        assert_eq!(
            value.pointer("/commands/evidence/0/query_id"),
            Some(&serde_json::json!("representatives"))
        );
        assert_eq!(
            value.pointer("/details/worker/state"),
            Some(&serde_json::json!("dispatch_required"))
        );
        assert_eq!(
            value.pointer("/commands/confirm_worker/argv/1"),
            Some(&serde_json::json!("status"))
        );
        assert!(value.get("issue").is_none());
        assert!(value.get("evidence_commands").is_none());
        assert!(value.get("acceptance").is_none());

        let status = serde_json::to_value(RewriteStatusReport {
            schema_version: ACTION_SCHEMA_VERSION,
            initialized: true,
            workflow: None,
            api_inventory: None,
            latest_focused_e2e: None,
            e2e_current: false,
            comparison_current: false,
            terminal_allowed: false,
            action,
        })
        .unwrap();
        assert_eq!(status.get("schema_version"), Some(&serde_json::json!(12)));
        assert!(status.get("active_issue").is_none());
        assert!(status.get("next").is_none());
    }
}
