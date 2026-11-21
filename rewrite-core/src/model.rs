//! Serializable workflow state over application-owned typed records.
use crate::{Attempt, RewriteApiProgress, RewriteApiStatus, RewriteAttemptDelta, RewritePhase};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt::Debug,
    ops::{Deref, DerefMut},
    path::PathBuf,
};

pub trait WorkflowData: Clone + Debug {
    type AttemptSummary: Clone + Debug + Serialize + DeserializeOwned + Attempt;
    type Issue: Clone + Debug + Serialize + DeserializeOwned;
    type RulePlan: Clone + Debug + Serialize + DeserializeOwned;
    type DependencyRulePlan: Clone + Debug + Serialize + DeserializeOwned;
    type RecorderCapturePlan: Clone + Debug + Serialize + DeserializeOwned;
    type Route: Clone + Debug + Serialize + DeserializeOwned;
    type ReviewLedger: Clone + Debug + Serialize + DeserializeOwned;
    type Regression: Clone + Debug + Serialize + DeserializeOwned;
    type RevalidationRound: Clone + Debug + Serialize + DeserializeOwned;
    type AcceptedReview: Clone + Debug + Serialize + DeserializeOwned;
    type WorkerBinding: Clone + Debug + Serialize + DeserializeOwned;
    type ImplementerPool: Clone + Debug + Serialize + DeserializeOwned;
    type RepositoryAnalysis: Clone + Debug + Serialize + DeserializeOwned;
    type GroupReplayRound: Clone + Debug + Serialize + DeserializeOwned;
    type GroupReplaySummary: Clone + Debug + Serialize + DeserializeOwned;
    type ReviewRework: Clone + Debug + Serialize + DeserializeOwned;
    type CasePatternAnalysis: Clone + Debug + Serialize + DeserializeOwned;
    type RecordingSettings: Clone + Debug + Serialize + DeserializeOwned + Default;
    type RecordingReason: Clone + Debug + Serialize + DeserializeOwned;
    type RecordingInputDiagnosis: Clone + Debug + Serialize + DeserializeOwned;
    type RecordingRefresh: Clone + Debug + Serialize + DeserializeOwned;
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct RewriteSliceState<Data: WorkflowData> {
    pub phase: RewritePhase,
    pub api: String,
    pub source_route: String,
    pub case_source: Option<PathBuf>,
    #[serde(default)]
    pub case_inventory_id: Option<String>,
    pub source_revision: Option<String>,
    pub group_id: Option<String>,
    pub target_fingerprint: Option<String>,
    /// Code, verification policy, startup inputs and stream timing used by the actual Replay.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub replay_identity: Option<String>,
    pub attempts: Vec<Data::AttemptSummary>,
    /// Engine-upgrade retry permits consumed before starting execution.
    #[serde(default, skip_serializing_if = "std::collections::BTreeSet::is_empty")]
    pub engine_retry_fingerprints: std::collections::BTreeSet<String>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub engine_retry_running: bool,
    pub attempt_delta: Option<RewriteAttemptDelta>,
    pub active_issue: Option<Data::Issue>,
    pub rule_plan: Option<Data::RulePlan>,
    #[serde(default)]
    pub dependency_rule_plan: Option<Data::DependencyRulePlan>,
    #[serde(default)]
    pub recorder_capture_plan: Option<Data::RecorderCapturePlan>,
    pub route: Option<Data::Route>,
    #[serde(default)]
    pub system_repair_accepted: bool,
    /// A successfully applied rule authorizes one verification without a code handoff.
    #[serde(default)]
    pub rule_replay_pending: bool,
    pub e2e_current: bool,
}

impl<Data: WorkflowData> RewriteSliceState<Data> {
    pub fn pending(api: String, source_route: String) -> Self {
        Self {
            phase: RewritePhase::ApiPending,
            api,
            source_route,
            case_source: None,
            case_inventory_id: None,
            source_revision: None,
            group_id: None,
            target_fingerprint: None,
            replay_identity: None,
            attempts: Vec::new(),
            engine_retry_fingerprints: Default::default(),
            engine_retry_running: false,
            attempt_delta: None,
            active_issue: None,
            rule_plan: None,
            dependency_rule_plan: None,
            recorder_capture_plan: None,
            route: None,
            system_repair_accepted: false,
            rule_replay_pending: false,
            e2e_current: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct RewriteState<Data: WorkflowData> {
    pub version: u32,
    pub revision: u64,
    pub workflow_id: String,
    pub dependency_review: Data::ReviewLedger,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub regression: Option<Data::Regression>,
    #[serde(default)]
    pub recording_apis: Vec<String>,
    #[serde(default)]
    pub api_inventory: Vec<RewriteApiProgress>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revalidation_round: Option<Data::RevalidationRound>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pre_revalidation_review: Option<Data::AcceptedReview>,
    /// Original scheduling status retained while regression policy excludes an API.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub skipped_api_statuses: BTreeMap<String, RewriteApiStatus>,
    /// Confirmed dynamic routes survive recording batches, independently of verification.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub source_route_bindings: BTreeMap<String, String>,
    #[serde(default)]
    pub current_api_index: Option<usize>,
    #[serde(default)]
    pub parked_slices: BTreeMap<String, RewriteSliceState<Data>>,
    #[serde(default)]
    pub worker_bindings: BTreeMap<String, Data::WorkerBinding>,
    #[serde(default)]
    pub implementers: Option<Data::ImplementerPool>,
    #[serde(default)]
    pub repository_analysis: Option<Data::RepositoryAnalysis>,
    #[serde(default)]
    pub group_replay: Option<Data::GroupReplayRound>,
    #[serde(default)]
    pub last_group_replay: Option<Data::GroupReplaySummary>,
    #[serde(default)]
    pub source_review_rework: BTreeMap<String, Data::ReviewRework>,
    #[serde(default)]
    pub worker_event_revision: u64,
    #[serde(default)]
    pub rule_plan_event_revision: u64,
    #[serde(default)]
    pub api_catalog_initialized: bool,
    #[serde(default)]
    pub api_catalog: BTreeSet<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub case_pattern_identification: Option<RewriteCasePatternIdentification>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub case_pattern_analysis: Option<Data::CasePatternAnalysis>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_quality_fingerprint: Option<String>,
    /// A lost receipt must never restore the initial diagnostic Replay exemption.
    #[serde(default)]
    pub delivery_review_required: bool,
    pub recording_run_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recording_after_run_id: Option<String>,
    #[serde(default)]
    pub recording_rejection: Option<String>,
    #[serde(default)]
    pub recording_settings: Data::RecordingSettings,
    #[serde(default)]
    pub recording_request_reason: Option<Data::RecordingReason>,
    #[serde(default)]
    pub recording_input_case_source: Option<PathBuf>,
    #[serde(default)]
    pub recording_input_diagnosis: Option<Data::RecordingInputDiagnosis>,
    #[serde(default)]
    pub recording_refresh: Option<Data::RecordingRefresh>,
    #[serde(flatten)]
    pub active_slice: RewriteSliceState<Data>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RewriteCasePatternIdentification {
    pub id: String,
    pub recording_run_id: String,
    pub candidates: Vec<String>,
    pub observed_apis: Vec<String>,
    #[serde(default)]
    pub canonical_apis: Vec<String>,
    #[serde(default)]
    pub effective_patterns: Vec<String>,
}

impl<Data: WorkflowData> Deref for RewriteState<Data> {
    type Target = RewriteSliceState<Data>;

    fn deref(&self) -> &Self::Target {
        &self.active_slice
    }
}

impl<Data: WorkflowData> DerefMut for RewriteState<Data> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.active_slice
    }
}

impl<Data: WorkflowData> RewriteState<Data> {
    pub fn bump(&mut self) {
        self.revision = self.revision.saturating_add(1);
    }
}
