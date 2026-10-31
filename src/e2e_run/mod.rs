mod active_artifact;
mod active_progress;
mod admin_source;
mod admin_startup;
mod assertion_publication;
mod batch_evidence;
mod batch_planning;
pub(crate) use batch_planning::{BatchRuleEvidence, batch_rule_evidence};
mod batch_publication;
pub(crate) use batch_publication::batch_diagnostic_report;
mod branch;
mod case_progress;
mod case_selection;
mod case_sequence;
mod config;
mod delivery;
mod dirty_evidence;
mod evidence;
mod evidence_admission;
mod execute;
mod execution_failure;
mod failure_limit;
mod final_evidence;
mod focused_batch;
mod interrupted_evidence;
pub(crate) mod jwt_evidence;
mod model;
mod primary_driver;
mod progress;
mod project_validation;
mod replay_publication;
mod request_feedback;
mod request_view;
mod result;
mod runtime;
mod source_response;
mod startup_inputs;
mod store;
mod support;
mod target_stop;
#[cfg(test)]
pub(crate) mod test_session;
mod workflow_evidence;

use std::path::PathBuf;

use anyhow::{Result, ensure};
use serde::Serialize;

use crate::case_group::{
    CaseGroupOptions, ensure_case_group_with_target_root, load_case_group_inventory,
    load_complete_case_group_inventory,
};

pub use admin_source::{SourceUpgradeOptions, SourceUpgradeResult, upgrade_source_snapshot};
pub use admin_startup::{
    StartupSnapshotRecaptureOptions, StartupSnapshotRecaptureResult, recapture_startup_snapshot,
};

pub(crate) use batch_evidence::{ActualBatchEvidence, completed_batch_evidence};
pub(crate) use case_selection::ReplayIteration;
pub(crate) use config::render_project_config;
pub(crate) use config::resolve_project;
pub(crate) use config::with_project_resolution_cache;
pub(crate) use delivery::resolve_managed_directories;
pub use dirty_evidence::{
    E2eDependencyDifference, E2eDependencyEndpoint, E2eDependencyObservation,
    E2eDependencyRepresentative, E2eDependencyTargetMatch, E2eDirtyCluster, E2eDirtyCounts,
    E2eSourcePreReadiness, E2eSourcePreReadinessEndpoint,
};
pub(crate) use evidence::finalized_focused_attempt_summary;
pub use evidence::{
    E2eCaseResponseDifference, E2eCaseResponseDifferences, E2eDependencyCorrelation,
    E2eSourceValueCount, E2eSourceVariation, E2eTargetLog, E2eTargetRuntimeDiagnostics,
    query_e2e_case_response_differences, query_e2e_dependency_correlation, query_e2e_dirty_counts,
    query_e2e_source_variation, query_e2e_target_runtime_diagnostics,
};
pub(crate) use evidence::{query_execution_context, query_execution_failure_page};
pub use execute::{abort_e2e_run, recover_e2e_run, run_e2e_api, run_e2e_round};
pub(crate) use execute::{recover_focused_e2e_api, run_e2e_apis};
pub use model::DEFAULT_MAX_FAILED_CASES_PER_API;
use model::{CaseStatus, RunStatus};
pub(crate) use model::{ResolvedProjectConfig, TargetBuildContext};
pub(crate) use primary_driver::wait_until_ready;
pub use result::{
    E2eApiRunResult, E2eDependencyGate, E2eDiagnosis, E2eDiagnosisCounts, E2eFailureCluster,
    E2eReplayGate, E2eRepresentativeDifference, E2eResponseDifferenceDiagnosis, E2eResponseGate,
    E2eResponseUnavailableReason, E2eRunResult, E2eValueObservation, E2eValuePresence,
    E2eVerificationGates,
};
pub(crate) use result::{response_pointer_pattern, response_pointer_scope};
pub use startup_inputs::{
    StartupMountChange, StartupMountChangeStatus, StartupMountEntry, StartupMountList,
    StartupMountPresence, ensure_startup_mount, list_startup_mounts, startup_mount_exists,
};
pub(crate) use workflow_evidence::completed_workflow_evidence;

#[derive(Debug, Clone)]
pub struct E2eRunInitOptions {
    pub target_root: PathBuf,
    pub target_dockerfile: PathBuf,
    pub target_startup: crate::startup::StartupConfig,
    pub replay_policy: PathBuf,
    pub pr_base: String,
    pub recorder_config: PathBuf,
    pub force: bool,
}

#[derive(Debug, Serialize)]
pub struct E2eRunInitResult {
    pub config: PathBuf,
    pub runtime_root: PathBuf,
    pub pr_base: String,
    pub recorder_feedback: bool,
    pub replaced: bool,
}

#[derive(Debug, Clone)]
pub struct E2eRunContext {
    pub target_root: PathBuf,
    pub case_source: PathBuf,
    pub run_key: Option<String>,
}

#[derive(Debug, Clone)]
pub struct E2eRunPrepareOptions {
    pub context: E2eRunContext,
    pub case_dir: PathBuf,
    pub method: String,
    pub source_route: String,
    pub pattern: Option<String>,
    pub source_revision: String,
}

#[derive(Debug, Serialize)]
pub struct E2eRunPrepareResult {
    pub run_key: String,
    pub group_index: PathBuf,
    pub group: crate::CaseGroupEnsureResult,
    pub ready_for_full_run: bool,
    pub group_cases: usize,
    pub published_cases: Option<usize>,
}

#[derive(Debug, Serialize)]
pub struct E2eRunStatus {
    pub run_key: String,
    pub status: String,
    pub progress: PathBuf,
    pub focused_apis: Vec<E2eFocusedApiStatus>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub runtime_outputs: Vec<crate::RuntimeOutputLocation>,
}

#[derive(Debug, Serialize)]
pub struct E2eFocusedApiStatus {
    pub api: String,
    pub status: String,
    pub active: bool,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub runtime_outputs: Vec<crate::RuntimeOutputLocation>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct E2eFocusedAttemptSummary {
    pub(crate) attempt: u64,
    pub(crate) passed: bool,
    pub(crate) case_source: PathBuf,
    pub(crate) case_inventory_id: String,
    pub(crate) selected_case_ids: std::collections::BTreeSet<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum E2eActiveProgress {
    PreparingIndex,
    PreparingReplay,
    StartingTarget,
    PreparingCase { completed: usize, total: usize },
    Building,
    Replaying { completed: usize, total: usize },
    Finalizing,
}

#[derive(Debug, Clone, Serialize)]
pub struct E2eResponseRuleEvidence {
    pub replay: PathBuf,
    pub assertions: PathBuf,
    pub aggregate: PathBuf,
}

pub(crate) enum OptionalResponseRuleEvidence {
    Absent,
    Unavailable(PathBuf),
    Available(E2eResponseRuleEvidence, PathBuf),
}

pub fn initialize_e2e_run(options: E2eRunInitOptions) -> Result<E2eRunInitResult> {
    config::initialize(options)
}

pub fn prepare_e2e_run(options: E2eRunPrepareOptions) -> Result<E2eRunPrepareResult> {
    let (config, layout) = config::resolve_layout(
        &options.context.target_root,
        &options.context.case_source,
        options.context.run_key.as_deref(),
    )?;
    branch::require_work_branch(&layout.target_root, &config.pr_base)?;
    config::require_internal_root_ignored(&layout.target_root, &layout.internal_root)?;
    ensure!(
        !layout.active_dir.exists(),
        "cannot change case grouping while an E2E run is active"
    );
    ensure!(
        store::focused_active_directories(&layout)?.is_empty(),
        "cannot change case grouping while a focused API attempt is active"
    );
    std::fs::create_dir_all(&layout.run_root)?;
    let group = ensure_case_group_with_target_root(
        CaseGroupOptions {
            case_source: options.context.case_source,
            case_dir: options.case_dir,
            method: options.method,
            source_route: options.source_route,
            pattern: options.pattern,
            source_revision: options.source_revision,
            output: layout.group_index_path.clone(),
            recorder_config: Some(config.recorder_config),
        },
        &layout.target_root,
    )?;
    let group_cases = group.case_ids.len();
    let complete =
        load_complete_case_group_inventory(&layout.group_index_path, &layout.case_source).ok();
    let published_cases = complete.as_ref().map(|inventory| {
        inventory
            .groups
            .iter()
            .map(|candidate| candidate.cases.len())
            .sum()
    });
    Ok(E2eRunPrepareResult {
        run_key: layout.run_key.clone(),
        group_index: layout.group_index_path,
        group,
        ready_for_full_run: complete.is_some(),
        group_cases,
        published_cases,
    })
}

pub(crate) fn prepare_case_group_index_rebuild(context: &E2eRunContext) -> Result<PathBuf> {
    let (_, layout) = config::resolve_layout(
        &context.target_root,
        &context.case_source,
        context.run_key.as_deref(),
    )?;
    ensure!(
        !layout.active_dir.exists(),
        "cannot rebuild case grouping while an E2E run is active"
    );
    ensure!(
        store::focused_active_directories(&layout)?.is_empty(),
        "cannot rebuild case grouping while a focused API attempt is active"
    );
    std::fs::create_dir_all(&layout.run_root)?;
    Ok(layout.group_index_path)
}

pub(crate) fn reanchor_case_group_run_index(
    context: &E2eRunContext,
    source_revision: &str,
    case_inventory_id: &str,
) -> Result<Option<PathBuf>> {
    let (_, layout) = config::resolve_layout(
        &context.target_root,
        &context.case_source,
        context.run_key.as_deref(),
    )?;
    store::reanchor_index_case_source(&layout, source_revision, case_inventory_id)
}

pub fn status_e2e_run(context: E2eRunContext) -> Result<E2eRunStatus> {
    let (_, layout) = config::resolve_layout(
        &context.target_root,
        &context.case_source,
        context.run_key.as_deref(),
    )?;
    let active_state = layout.active_dir.join("state.yaml");
    let latest_state = layout.latest_dir.join("state.yaml");
    let (status, runtime_outputs) = if active_state.is_file() {
        let state = store::read_active(&layout)?;
        (
            run_status_label(state.status).to_string(),
            state.runtime_outputs,
        )
    } else if latest_state.is_file() {
        let state: model::ActiveRunState = store::read_yaml(&latest_state)?;
        (
            run_status_label(state.status).to_string(),
            state.runtime_outputs,
        )
    } else {
        ("not_started".to_string(), Vec::new())
    };
    let focused_apis = if layout.group_index_path.is_file() {
        load_case_group_inventory(&layout.group_index_path, &layout.case_source)?
            .groups
            .into_iter()
            .map(|group| {
                let root = layout
                    .run_root
                    .join("focused")
                    .join(support::api_directory(&group.group_id));
                let active = root.join(".active/state.yaml").is_file();
                let latest_state = root.join("latest/state.yaml");
                let (status, runtime_outputs) = if active {
                    match store::read_yaml::<model::ActiveRunState>(
                        &root.join(".active/state.yaml"),
                    ) {
                        Ok(state) => ("running".to_string(), state.runtime_outputs),
                        Err(_) => ("invalid".to_string(), Vec::new()),
                    }
                } else if latest_state.is_file() {
                    match store::read_yaml::<model::ActiveRunState>(&latest_state) {
                        Ok(state) => (
                            run_status_label(state.status).to_string(),
                            state.runtime_outputs,
                        ),
                        Err(_) => ("invalid".to_string(), Vec::new()),
                    }
                } else {
                    ("not_started".to_string(), Vec::new())
                };
                E2eFocusedApiStatus {
                    api: group.group_id,
                    status,
                    active,
                    runtime_outputs,
                }
            })
            .collect()
    } else {
        Vec::new()
    };
    Ok(E2eRunStatus {
        run_key: layout.run_key,
        status,
        progress: layout.progress_path,
        focused_apis,
        runtime_outputs,
    })
}

pub(crate) fn focused_active_progress(
    context: &E2eRunContext,
    api_key: &str,
) -> Result<Option<E2eActiveProgress>> {
    let (_, layout) = config::resolve_layout(
        &context.target_root,
        &context.case_source,
        context.run_key.as_deref(),
    )?;
    let state_path = layout
        .run_root
        .join("focused")
        .join(support::api_directory(api_key))
        .join(".active/state.yaml");
    if !state_path.is_file() {
        return Ok(None);
    }
    let progress_path = state_path.with_file_name("progress.json");
    if progress_path.is_file()
        && let Ok(progress) = active_progress::read(&progress_path)
    {
        return Ok(Some(progress));
    }
    let state: model::ActiveRunState = store::read_yaml(&state_path)?;
    Ok(Some(match state.status {
        RunStatus::Running if state.replay_pid.is_none() => E2eActiveProgress::Building,
        RunStatus::Running => E2eActiveProgress::Replaying {
            completed: state
                .cases
                .iter()
                .filter(|case| {
                    matches!(
                        case.status,
                        CaseStatus::Passed | CaseStatus::Failed | CaseStatus::Incomplete
                    )
                })
                .count(),
            total: state.cases.len(),
        },
        RunStatus::Finalizing
        | RunStatus::Successful
        | RunStatus::Failed
        | RunStatus::Interrupted => E2eActiveProgress::Finalizing,
    }))
}

/// Foreign APIs without a complete attempt retain an explicit Replay obligation.
/// Known unfinished attempts retain their state identity; malformed complete or
/// active published evidence never becomes absence.
pub(crate) fn optional_response_rule_evidence(
    context: E2eRunContext,
    api: &str,
) -> Result<OptionalResponseRuleEvidence> {
    let (_, layout) = config::resolve_layout(
        &context.target_root,
        &context.case_source,
        context.run_key.as_deref(),
    )?;
    let focused = inactive_response_evidence_root(&layout, api)?.join("latest/state.yaml");
    let full = layout.latest_dir.join("state.yaml");
    let state_path = if !focused.is_file() {
        if !full.is_file() {
            return Ok(OptionalResponseRuleEvidence::Absent);
        }
        let state: model::ActiveRunState = store::read_yaml(&full)?;
        if !state.apis.iter().any(|candidate| candidate.group_id == api) {
            return Ok(OptionalResponseRuleEvidence::Absent);
        }
        full
    } else {
        focused
    };
    let state: model::ActiveRunState = store::read_yaml(&state_path)?;
    ensure!(
        state.status.is_terminal(),
        "foreign Replay evidence is not terminal"
    );
    ensure!(
        state.case_source == layout.case_source
            && state.apis.iter().any(|candidate| candidate.group_id == api),
        "foreign Replay evidence belongs to another recording or API"
    );
    if state.status == RunStatus::Interrupted && !state.replay_finalized
        || state.replay_finalized && !state.aggregate_complete
    {
        return Ok(OptionalResponseRuleEvidence::Unavailable(state_path));
    }
    resolve_e2e_response_rule_evidence(context, api)
        .map(|evidence| OptionalResponseRuleEvidence::Available(evidence, state_path))
}

pub fn resolve_e2e_response_rule_evidence(
    context: E2eRunContext,
    api: &str,
) -> Result<E2eResponseRuleEvidence> {
    let (_, layout) = config::resolve_layout(
        &context.target_root,
        &context.case_source,
        context.run_key.as_deref(),
    )?;
    let focused_root = inactive_response_evidence_root(&layout, api)?;
    let focused_state = focused_root.join("latest/state.yaml");
    let full_state = layout.latest_dir.join("state.yaml");
    let state_path = if focused_state.is_file() {
        focused_state
    } else if full_state.is_file() {
        ensure!(
            !layout.active_dir.exists(),
            "full-run evidence is unavailable while an E2E attempt is active"
        );
        full_state
    } else {
        anyhow::bail!(
            "no finalized E2E evidence exists for API {api:?} and case source {}",
            layout.case_source.display()
        );
    };
    let state: model::ActiveRunState = store::read_yaml(&state_path)?;
    ensure!(
        state.status.is_terminal(),
        "response-rule evidence is not terminal"
    );
    ensure!(
        state.case_source == layout.case_source,
        "response-rule evidence belongs to another case source"
    );
    ensure!(
        state.apis.iter().any(|candidate| candidate.group_id == api),
        "finalized E2E evidence does not contain API {api:?}"
    );
    // Response planners consume the published assertion and aggregate reports.
    // Consumers of the replay report validate it when reading it; do not require
    // that additional artifact for response-only planning.
    evidence_admission::require_response_reports(&state)?;
    Ok(E2eResponseRuleEvidence {
        replay: state.replay_report,
        assertions: state.assertions_report,
        aggregate: state.aggregate_report,
    })
}

pub(crate) fn ensure_response_rule_evidence_inactive(
    context: E2eRunContext,
    api: &str,
) -> Result<()> {
    let (_, layout) = config::resolve_layout(
        &context.target_root,
        &context.case_source,
        context.run_key.as_deref(),
    )?;
    inactive_response_evidence_root(&layout, api)?;
    Ok(())
}

fn inactive_response_evidence_root(layout: &model::RunLayout, api: &str) -> Result<PathBuf> {
    evidence_admission::focused_root(layout, api)
}

pub fn resolve_single_e2e_response_rule_evidence(
    context: E2eRunContext,
) -> Result<E2eResponseRuleEvidence> {
    let status = status_e2e_run(context.clone())?;
    let available = status
        .focused_apis
        .into_iter()
        .filter(|candidate| candidate.status != "not_started")
        .collect::<Vec<_>>();
    ensure!(
        available.len() == 1,
        "process-owned dependency evidence requires exactly one finalized focused API; use the rewrite coordinator when the case source has {} candidates",
        available.len()
    );
    resolve_e2e_response_rule_evidence(context, &available[0].api)
}

fn run_status_label(status: RunStatus) -> &'static str {
    match status {
        RunStatus::Running => "running",
        RunStatus::Finalizing => "finalizing",
        RunStatus::Successful => "passed",
        RunStatus::Failed => "failed",
        RunStatus::Interrupted => "interrupted",
    }
}

pub(crate) use evidence::query_http_cross_case_candidates;

pub(crate) use evidence::query_rule_policy_freshness;
pub(crate) use evidence::{query_dynamic_capture_candidates, query_http_unordered_candidates};

pub(crate) use evidence::query_redis_unordered_candidates;

pub(crate) use evidence::query_dependency_request_candidates;
