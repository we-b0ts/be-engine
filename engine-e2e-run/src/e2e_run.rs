//! Public managed E2E run API.

pub use crate::admin_source::{SourceUpgradeOptions, SourceUpgradeResult, upgrade_source_snapshot};
pub use crate::admin_startup::{
    StartupSnapshotRecaptureOptions, StartupSnapshotRecaptureResult, recapture_startup_snapshot,
};
pub use crate::batch_evidence::{ActualBatchEvidence, completed_batch_evidence};
pub use crate::batch_planning::batch_rule_evidence;
pub use crate::case_run::{
    E2eActiveProgress, E2eFocusedApiStatus, E2eFocusedAttemptSummary, E2eRunInitOptions,
    E2eRunInitResult, E2eRunPrepareOptions, E2eRunPrepareResult, E2eRunStatus,
    focused_active_progress, initialize_e2e_run, prepare_case_group_index_rebuild, prepare_e2e_run,
    reanchor_case_group_run_index, require_failed_unmanaged_index, status_e2e_run,
    workflow_active_progress,
};
pub use crate::case_selection::ReplayIteration;
pub use crate::delivery::resolve_managed_directories;
pub use crate::diagnostic_report::{batch_diagnostic_report, session_diagnostic_report};
pub use crate::dirty_evidence::{
    E2eDependencyDifference, E2eDependencyEndpoint, E2eDependencyObservation,
    E2eDependencyRepresentative, E2eDependencyTargetMatch, E2eDirtyCluster, E2eDirtyCounts,
    E2eSourcePreReadiness, E2eSourcePreReadinessEndpoint,
};
pub use crate::event_session::{
    event_session_report, run_e2e_event_session, run_e2e_event_session_with_apis,
    status_e2e_event_session,
};
pub use crate::evidence::{
    E2eCaseResponseDifference, E2eCaseResponseDifferences, E2eDependencyCorrelation,
    E2eSourceValueCount, E2eSourceVariation, E2eTargetLog, E2eTargetRuntimeDiagnostics,
    finalized_focused_attempt_summary, query_dependency_request_candidates,
    query_dynamic_capture_candidates, query_e2e_case_response_differences,
    query_e2e_dependency_correlation, query_e2e_dirty_counts, query_e2e_source_variation,
    query_e2e_target_runtime_diagnostics, query_execution_context, query_execution_failure_page,
    query_http_cross_case_candidates, query_http_unordered_candidates, query_rule_policy_freshness,
};
pub use crate::evidence_admission::{
    E2eResponseRuleEvidence, OptionalResponseRuleEvidence, ensure_response_rule_evidence_inactive,
    optional_response_rule_evidence, resolve_e2e_response_rule_evidence,
    resolve_single_e2e_response_rule_evidence,
};
pub use crate::execute::{
    abort_e2e_run, recover_e2e_run, recover_focused_e2e_api, run_e2e_api, run_e2e_apis,
    run_e2e_round,
};
pub use crate::implementer_execution::query_implementer_execution;
pub use crate::jwt_evidence;
pub use crate::model::{
    DEFAULT_MAX_FAILED_CASES_PER_API, ResolvedProjectConfig, TargetBuildContext,
};
pub use crate::result::{response_pointer_pattern, response_pointer_scope};
pub use crate::run_config::{
    render_project_config, resolve_project, with_project_resolution_cache,
};
pub use crate::startup_inputs::{
    StartupMountChange, StartupMountChangeStatus, StartupMountEntry, StartupMountList,
    StartupMountPresence, ensure_startup_mount, list_startup_mounts, startup_mount_exists,
};
pub use crate::workflow_evidence::completed_workflow_evidence;
pub use traffic_engine_e2e_contract::{
    BatchRuleEvidence, E2eApiRunResult, E2eDependencyGate, E2eDiagnosis, E2eDiagnosisCounts,
    E2eEventSessionApiProgress, E2eEventSessionCaseProgress, E2eEventSessionCounts,
    E2eEventSessionOptions, E2eEventSessionPhase, E2eEventSessionProgress, E2eEventSessionResult,
    E2eEventSessionState, E2eEventSessionStatus, E2eEventSessionStatusProgress, E2eFailureCluster,
    E2eReplayGate, E2eRepresentativeDifference, E2eResponseDifferenceDiagnosis, E2eResponseGate,
    E2eResponseUnavailableReason, E2eRunContext, E2eRunResult, E2eValueObservation,
    E2eValuePresence, E2eVerificationGates,
};
