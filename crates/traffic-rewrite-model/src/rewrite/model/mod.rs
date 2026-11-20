use std::collections::BTreeMap;
use std::fmt;
use std::num::{NonZeroU64, NonZeroUsize};
use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::work_scope::RewriteWorkScope;
pub use super::worker::model::{RewriteWorkerBinding, RewriteWorkerTransferRecord};
pub use super::worker::model::{
    RewriteWorkerBlockingReason, RewriteWorkerDispatchState, RewriteWorkerDispatchView,
};
use crate::RedisKeyPatternConfig;
use crate::{
    E2eDiagnosisCounts, E2eRepresentativeDifference, E2eResponseDifferenceDiagnosis,
    E2eVerificationGates,
};

pub use traffic_rewrite_core::RewriteAttemptDelta;
pub use traffic_rewrite_core::RewriteCasePatternIdentification;
pub use traffic_rewrite_core::{RewriteApiProgress, RewriteApiStatus, RewritePhase};

#[derive(Debug, Clone)]
pub struct ApplicationData;

impl traffic_rewrite_core::WorkflowData for ApplicationData {
    type AttemptSummary = RewriteAttemptSummary;
    type Issue = RewriteIssue;
    type RulePlan = RewriteRulePlanRecord;
    type DependencyRulePlan = RewriteDependencyRulePlanRecord;
    type RecorderCapturePlan = RewriteRecorderCapturePlanRecord;
    type Route = RewriteRouteRecord;
    type ReviewLedger = super::dependency_review::ReviewLedger;
    type Regression = super::regression::RegressionOrigin;
    type RevalidationRound = super::inventory::revalidation_round::RevalidationRound;
    type AcceptedReview = super::review::pre_revalidation::AcceptedReview;
    type WorkerBinding = RewriteWorkerBinding;
    type ImplementerPool = super::implementer::ImplementerPool;
    type RepositoryAnalysis = super::repository_analysis::RepositoryAnalysisSnapshot;
    type GroupReplayRound = super::group_replay::GroupReplayRound;
    type GroupReplaySummary = super::group_replay::GroupReplaySummary;
    type ReviewRework = super::review::ReviewRework;
    type CasePatternAnalysis = super::repository_analysis::CasePatternAnalysisCommit;
    type RecordingSettings = RewriteRecordingSettings;
    type RecordingReason = RewriteRecordingReason;
    type RecordingInputDiagnosis = RewriteRecordingInputDiagnosis;
    type RecordingRefresh = RewriteRecordingRefreshState;
}

pub type RewriteState = traffic_rewrite_core::RewriteState<ApplicationData>;
pub type RewriteSliceState = traffic_rewrite_core::RewriteSliceState<ApplicationData>;

pub const STATE_VERSION: u32 = 2;
pub const ACTION_SCHEMA_VERSION: u32 = 41;

const DEFAULT_RECORDING_DURATION_SECONDS: NonZeroU64 = NonZeroU64::new(60).unwrap();
const DEFAULT_RECORDING_CASE_LIMIT: NonZeroUsize = NonZeroUsize::new(100).unwrap();

#[derive(Debug, Clone, Serialize)]
pub struct RewriteApiInventoryView {
    pub total: usize,
    pub completed: usize,
    pub skipped: usize,
    #[serde(rename = "unverified")]
    pub pending: usize,
    pub active: usize,
    pub implementation_required: usize,
    pub system_repair_required: usize,
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
    pub items: Vec<RewriteApiInventoryItem>,
}

#[derive(Debug, Clone, Serialize)]
pub struct RewriteApiInventoryItem {
    pub api: String,
    pub status: RewriteApiStatus,
    pub methods: Vec<RewriteApiProgress>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RewriteIssueKind {
    TargetQuality,
    Response,
    TargetRuntime,
    Replay,
    Dependency,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct RewriteRecordingSettings {
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub engine_fingerprint: Option<String>,
    pub attempt: u64,
    pub passed: bool,
    pub gates: E2eVerificationGates,
    pub counts: E2eDiagnosisCounts,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RewriteIssue {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub egress_rejections: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recorder_capture_diagnosis: Option<Value>,
    pub id: String,
    pub kind: RewriteIssueKind,
    pub owner: RewriteIssueOwner,
    pub summary: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pointer_pattern: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub representative: Option<E2eRepresentativeDifference>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub response_diagnosis: Option<E2eResponseDifferenceDiagnosis>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub possible_causes: Vec<String>,
    pub observed_target_fingerprint: String,
    pub attempt: u64,
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
    pub legacy_acceptance_command: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RewriteRepairAcceptanceKind {
    TrafficE2eRevisionChanged,
    SourceRuntimeInputsChanged,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RewriteRulePlanRecord {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unified: Option<super::unified_rule::UnifiedRulePlanRecord>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub generated_witnesses: Vec<(PathBuf, String)>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub response_jwts: Vec<crate::ResponseJwtRule>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub header_dates: Vec<crate::ResponseHeaderDateRule>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dynamic_value: Option<crate::DynamicValueRule>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mysql_time: Option<crate::DynamicValueMysqlTimeRule>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub redis_time: Option<crate::DynamicValueRedisTimeRule>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dependency_request: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub time: Option<crate::ResponseTimeRule>,
    pub id: String,
    pub issue_id: String,
    pub kind: String,
    pub json_pointer: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_evidence: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_example: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_example: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub separator: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub response_body: Option<RewriteResponseBodyRuleSpec>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jwt: Option<super::jwt_rule::JwtPlanRecord>,
    pub evidence_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RewriteResponseBodyRuleSpec {
    pub codec: crate::ResponseBodyCodec,
    #[serde(default)]
    pub unordered_paths: Vec<crate::ResponseBodyUnorderedPath>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub unordered_joined_string_paths: Vec<crate::ResponseBodyJoinedStringPath>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub docx_timestamps: Vec<crate::DocxTimestampRule>,
}

pub mod dependency_rule;
pub use dependency_rule::{RewriteDependencyRulePlanRecord, RewriteDependencyRuleSpec};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RewriteRecorderCapturePlanRecord {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub http_response: Option<super::recorder_capture::http_response::HttpResponseCaptureSpec>,
    pub id: String,
    pub issue_id: String,
    pub evidence_id: String,
    pub endpoint: String,
    pub source_evidence: String,
    pub source_revision: String,
    pub project_config_revision: String,
    pub resource_identity: String,
    pub target_fingerprint: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RewriteRecorderCaptureAppliedRecord {
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
pub struct RewriteDependencyRuleAppliedRecord {
    pub plan_id: String,
    pub issue_id: String,
    pub evidence_id: String,
    pub api: String,
    pub rule_name: String,
    pub source_evidence: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RewriteRecordingRefreshState {
    pub applied: Vec<RewriteRecorderCaptureAppliedRecord>,
    #[serde(default)]
    pub dependency_rules: Vec<RewriteDependencyRuleAppliedRecord>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub baseline_case_source: Option<PathBuf>,
    pub project_config_revision: String,
    pub source_traffic_policy_revision: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recording_run_id: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct RewriteWorkflowView {
    pub id: String,
    pub revision: u64,
    pub phase: RewritePhase,
    pub scope: String,
    pub recording_run_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub work_scope: Option<RewriteWorkScope>,
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
pub enum RewriteInputRequiredReason {
    WorkflowNotInitialized,
    RecordingEvidenceRequired,
    SourceRouteRequired,
    VerificationProgressCommitRequired,
    ConfigurationCommitRequired,
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
    Replay,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RewriteTrafficOperationView {
    pub operation_id: String,
    pub kind: RewriteTrafficOperationKind,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub api: Option<String>,
    pub started_at: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RewriteAdvanceKind {
    Replay,
    Workflow,
    BatchReplay,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RewriteExecutionMode {
    #[default]
    Single,
    AutoNext,
}

#[derive(Debug, Clone)]
pub enum RewriteAction {
    BatchDiagnosisRequired {
        summary: String,
        evidence: serde_json::Value,
        inspect: RewriteCommandSpec,
        retry: RewriteCommandSpec,
    },
    DependencyAttributionRequired {
        summary: String,
        assignment_id: String,
        dispatch_generation: u64,
        claim_kinds: BTreeMap<String, usize>,
        context: RewriteCommandSpec,
        apply: RewriteCommandSpec,
    },
    RepositoryAnalysisRequired {
        summary: String,
        analysis: super::repository_analysis::RepositoryAnalysisContext,
        context: RewriteCommandSpec,
        apply: RewriteCommandSpec,
    },
    ImplementerDispatchRequired {
        summary: String,
        dispatch: super::implementer::ImplementerDispatch,
        confirm: RewriteCommandSpec,
        report: RewriteCommandSpec,
    },
    Blocked {
        summary: String,
        system_repair_apis: Vec<String>,
        resume: RewriteCommandSpec,
    },
    WorkerEventsRequired {
        summary: String,
        inventory: RewriteCommandSpec,
        status: RewriteCommandSpec,
    },
    PurposeRequired {
        summary: String,
        pr_base: String,
        replay: RewriteCommandSpec,
    },
    InputRequired {
        reason: RewriteInputRequiredReason,
        summary: String,
        required: Vec<String>,
        recording_input_diagnosis: Option<RewriteRecordingInputDiagnosis>,
    },
    RecoveryRequired {
        summary: String,
        command: RewriteCommandSpec,
    },
    WaitRequired {
        summary: String,
        execution_mode: Option<RewriteExecutionMode>,
        resource: String,
        requested_api: Option<String>,
        blocking_api: Option<String>,
        active_operation: Option<RewriteTrafficOperationView>,
        retry_after_seconds: u64,
        status: RewriteCommandSpec,
    },
    RecordingInProgress {
        summary: String,
        run_id: String,
        progress: RewriteRecordingProgress,
        status_poll_after_seconds: u64,
        status: RewriteCommandSpec,
    },
    ImplementationRequired {
        summary: String,
        execution_mode: Option<RewriteExecutionMode>,
        issue: RewriteIssue,
        worker: RewriteWorkerDispatchView,
        confirm_worker: Option<RewriteCommandSpec>,
        report_worker: RewriteCommandSpec,
        acceptance: RewriteCommandSpec,
    },
    WorkerStatusRequired {
        summary: String,
        execution_mode: Option<RewriteExecutionMode>,
        worker: RewriteWorkerDispatchView,
        report_worker: RewriteCommandSpec,
    },
    ExpertRequired {
        summary: String,
        execution_mode: Option<RewriteExecutionMode>,
        expert: super::expert::model::RewriteExpertView,
        commands: super::expert::model::RewriteExpertCommands,
    },
    IntegrationRequired {
        summary: String,
        worker: RewriteWorkerDispatchView,
        handoff_id: String,
        report_worker: RewriteCommandSpec,
        report_rework: RewriteCommandSpec,
    },
    ExecutionFailed {
        summary: String,
        operation_id: String,
        retry: RewriteCommandSpec,
        status: RewriteCommandSpec,
    },
    PreRevalidationReviewRequired {
        summary: String,
        quality_check: String,
        quality_paths: Vec<std::path::PathBuf>,
        check: RewriteCommandSpec,
        accept: RewriteCommandSpec,
    },
    SourceReviewRequired {
        summary: String,
        check: RewriteCommandSpec,
        show: RewriteCommandSpec,
        rework: RewriteCommandSpec,
        accept: RewriteCommandSpec,
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
        /// Engine-owned selection; commands deliberately omit the selector.
        api: Option<String>,
        kind: RewriteAdvanceKind,
    },
    SystemRepairRequired {
        work_scope: RewriteWorkScope,
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
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct RewriteRecordingProgress {
    pub apis: usize,
    pub published_cases: usize,
    pub failed_cases: usize,
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
    #[serde(
        skip_serializing_if = "Option::is_none",
        serialize_with = "super::action_contract::compact_workflow"
    )]
    pub workflow: Option<RewriteWorkflowView>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub api_inventory: Option<RewriteApiInventoryView>,
    pub pending: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latest_focused_e2e: Option<RewriteFocusedE2eExecution>,
    pub action: RewriteAction,
    pub terminal_allowed: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct RewriteStatusReport {
    pub schema_version: u32,
    pub initialized: bool,
    #[serde(
        skip_serializing_if = "Option::is_none",
        serialize_with = "super::action_contract::compact_workflow"
    )]
    pub workflow: Option<RewriteWorkflowView>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub api_inventory: Option<RewriteApiInventoryView>,
    pub pending: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latest_focused_e2e: Option<RewriteFocusedE2eExecution>,
    pub e2e_current: bool,
    pub terminal_allowed: bool,
    pub action: RewriteAction,
}

#[derive(Debug, Clone, Serialize)]
pub struct RewriteInventoryReport {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub implementers: Option<super::implementer::ImplementerPoolView>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub repository_analysis: Option<super::repository_analysis::RepositoryAnalysisSnapshot>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub group_replay: Option<super::group_replay::GroupReplayRound>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_group_replay: Option<super::group_replay::GroupReplaySummary>,
    pub schema_version: u32,
    pub initialized: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub workflow: Option<RewriteWorkflowView>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub api_inventory: Option<RewriteApiInventoryDetails>,
    pub pending: usize,
    pub details: super::coordination::RewriteCoordinationDetails,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub workers: Vec<super::worker::model::RewriteWorkerInventoryItem>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub experts: Vec<super::expert::model::RewriteExpertInventoryItem>,
}

#[derive(Debug, Clone, Serialize)]
pub struct RewriteRecoveryReport {
    pub recovered_stale_lock: bool,
    pub recovered_stale_traffic_operation: bool,
    pub recovered_focused_attempt: bool,
    pub next: RewriteCommandSpec,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cache_snapshot_overlay: Option<Value>,
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
#[serde(tag = "status", rename_all = "snake_case")]
pub enum RewriteHttpResponseCaptureReport {
    PathPatternReviewRequired {
        issue_id: String,
        api: String,
        evidence_id: String,
        pattern_review: Value,
        next_command: RewriteCommandSpec,
    },
    Planned {
        #[serde(flatten)]
        plan: RewriteRecorderCaptureReport,
    },
}

#[derive(Debug, Clone, Serialize)]
pub struct RewriteRouteReport {
    pub accepted: bool,
    pub issue_id: String,
    pub route: RewriteRouteRecord,
    pub acceptance: RewriteCommandSpec,
}

impl traffic_rewrite_core::Attempt for RewriteAttemptSummary {
    fn attempt(&self) -> u64 {
        self.attempt
    }
    fn counts(&self) -> traffic_rewrite_core::AttemptCounts {
        traffic_rewrite_core::AttemptCounts {
            selected: self.counts.selected,
            response_passed: self.counts.response_passed,
            response_nonpassing: self.counts.response_nonpassing,
        }
    }
}
