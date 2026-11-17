//! Persisted state compatibility with the concrete pre-extraction layouts.
use super::*;
use std::collections::BTreeSet;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct HistoricalSliceState {
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
    pub attempts: Vec<RewriteAttemptSummary>,
    /// Engine-upgrade retry permits consumed before starting execution.
    #[serde(default, skip_serializing_if = "std::collections::BTreeSet::is_empty")]
    pub engine_retry_fingerprints: std::collections::BTreeSet<String>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub engine_retry_running: bool,
    pub attempt_delta: Option<RewriteAttemptDelta>,
    pub active_issue: Option<RewriteIssue>,
    pub rule_plan: Option<RewriteRulePlanRecord>,
    #[serde(default)]
    pub dependency_rule_plan: Option<RewriteDependencyRulePlanRecord>,
    #[serde(default)]
    pub recorder_capture_plan: Option<RewriteRecorderCapturePlanRecord>,
    pub route: Option<RewriteRouteRecord>,
    #[serde(default)]
    pub system_repair_accepted: bool,
    /// A successfully applied rule authorizes one verification without a code handoff.
    #[serde(default)]
    pub rule_replay_pending: bool,
    pub e2e_current: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct HistoricalState {
    pub version: u32,
    pub revision: u64,
    pub workflow_id: String,
    pub dependency_review: crate::rewrite::dependency_review::ReviewLedger,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub regression: Option<crate::rewrite::regression::RegressionOrigin>,
    #[serde(default)]
    pub recording_apis: Vec<String>,
    #[serde(default)]
    pub api_inventory: Vec<RewriteApiProgress>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revalidation_round:
        Option<crate::rewrite::inventory::revalidation_round::RevalidationRound>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pre_revalidation_review: Option<crate::rewrite::review::pre_revalidation::AcceptedReview>,
    /// Original scheduling status retained while regression policy excludes an API.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub skipped_api_statuses: BTreeMap<String, RewriteApiStatus>,
    /// Confirmed dynamic routes survive recording batches, independently of verification.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub source_route_bindings: BTreeMap<String, String>,
    #[serde(default)]
    pub current_api_index: Option<usize>,
    #[serde(default)]
    pub parked_slices: BTreeMap<String, HistoricalSliceState>,
    #[serde(default)]
    pub worker_bindings: BTreeMap<String, RewriteWorkerBinding>,
    #[serde(default)]
    pub implementers: Option<crate::rewrite::implementer::ImplementerPool>,
    #[serde(default)]
    pub repository_analysis:
        Option<crate::rewrite::repository_analysis::RepositoryAnalysisSnapshot>,
    #[serde(default)]
    pub group_replay: Option<crate::rewrite::group_replay::GroupReplayRound>,
    #[serde(default)]
    pub last_group_replay: Option<crate::rewrite::group_replay::GroupReplaySummary>,
    #[serde(default)]
    pub source_review_rework: BTreeMap<String, crate::rewrite::review::ReviewRework>,
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
    pub case_pattern_analysis:
        Option<crate::rewrite::repository_analysis::CasePatternAnalysisCommit>,
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
    pub active_slice: HistoricalSliceState,
}

#[test]
fn extracted_state_preserves_existing_snapshot_bytes() {
    let mut state = crate::rewrite::test_state();
    state.recording_apis = vec!["GET /api".into()];
    state.api_inventory = vec![
        serde_json::from_value(serde_json::json!({
            "api": "GET /api", "status": "active"
        }))
        .unwrap(),
    ];
    state.current_api_index = Some(0);
    state.parked_slices.insert(
        "POST /other".into(),
        RewriteSliceState::pending("POST /other".into(), "/other".into()),
    );
    state.engine_retry_fingerprints.insert("engine-1".into());
    state
        .source_route_bindings
        .insert("GET /api".into(), "/api".into());
    state.replay_identity = Some("executed-inputs".into());
    state.case_inventory_id = Some("source-inventory".into());
    let bytes = serde_json::to_vec(&state).unwrap();
    let historical: HistoricalState = serde_json::from_slice(&bytes).unwrap();
    let original_bytes = serde_json::to_vec(&historical).unwrap();
    assert_eq!(bytes, original_bytes);
    let recovered: RewriteState = serde_json::from_slice(&original_bytes).unwrap();
    assert_eq!(serde_json::to_vec(&recovered).unwrap(), original_bytes);
}

#[test]
fn older_snapshots_keep_original_defaults() {
    let state = crate::rewrite::test_state();
    let mut value = serde_json::to_value(state).unwrap();
    for field in [
        "recording_apis",
        "api_inventory",
        "parked_slices",
        "worker_bindings",
        "recording_settings",
        "engine_retry_fingerprints",
        "engine_retry_running",
        "delivery_review_required",
        "replay_identity",
    ] {
        value.as_object_mut().unwrap().remove(field);
    }
    let historical: HistoricalState = serde_json::from_value(value.clone()).unwrap();
    let recovered: RewriteState = serde_json::from_value(value).unwrap();
    assert_eq!(
        serde_json::to_vec(&recovered).unwrap(),
        serde_json::to_vec(&historical).unwrap()
    );
}
