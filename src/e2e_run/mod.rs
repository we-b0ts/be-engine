mod branch;
mod case_progress;
mod config;
mod dirty_evidence;
mod evidence;
mod execute;
mod final_evidence;
mod http_driver;
mod model;
mod progress;
mod reclassify;
mod request_view;
mod result;
mod runtime;
mod store;
mod support;
mod target_quality_config;

use std::path::PathBuf;

use anyhow::{Context, Result, ensure};
use serde::Serialize;

use crate::case_group::{
    CaseGroupOptions, ensure_case_group, load_case_group_inventory,
    load_complete_case_group_inventory,
};

pub(crate) use config::render_project_config;
pub(crate) use config::resolve_project;
pub use dirty_evidence::{
    E2eDependencyDifference, E2eDependencyEndpoint, E2eDependencyObservation,
    E2eDependencyRepresentative, E2eDirtyCluster, E2eDirtyCounts, E2eSourcePreReadiness,
    E2eSourcePreReadinessEndpoint,
};
pub use evidence::{
    E2eCaseResponseDifference, E2eCaseResponseDifferences, E2eDependencyCorrelation,
    E2eSourceValueCount, E2eSourceVariation, query_e2e_case_response_differences,
    query_e2e_dependency_correlation, query_e2e_dirty_counts, query_e2e_source_variation,
};
pub(crate) use execute::recover_focused_e2e_api;
pub use execute::{abort_e2e_run, recover_e2e_run, run_e2e_api, run_e2e_round};
use model::RunStatus;
pub(crate) use model::{ResolvedProjectConfig, TargetQualityGateConfig};
pub(crate) use reclassify::{
    FocusedBackgroundReclassification, focused_background_reclassification_recovery_required,
    latest_focused_api, reclassify_focused_background_dependencies,
};
pub use result::{
    E2eApiRunResult, E2eDependencyGate, E2eDiagnosis, E2eDiagnosisCounts, E2eFailureCluster,
    E2eReplayGate, E2eRepresentativeDifference, E2eResponseDifferenceDiagnosis, E2eResponseGate,
    E2eRunResult, E2eValueObservation, E2eValuePresence, E2eVerificationGates,
};
pub(crate) use result::{response_pointer_pattern, response_pointer_scope};

#[derive(Debug, Clone)]
pub struct E2eRunInitOptions {
    pub target_root: PathBuf,
    pub source_container: String,
    pub breeze_container: Option<String>,
    pub target_dockerfile: PathBuf,
    pub target_boot_dir: PathBuf,
    pub target_http_host: String,
    pub target_port: u16,
    pub target_readiness_path: String,
    pub target_readiness_status: u16,
    pub target_startup_timeout_seconds: u64,
    pub target_request_timeout_seconds: u64,
    pub replay_policy: PathBuf,
    pub replay_startup_timeout_seconds: u64,
    pub pr_base: String,
    pub recorder_config: PathBuf,
    pub recording_rule: String,
    pub force: bool,
}

#[derive(Debug, Serialize)]
pub struct E2eRunInitResult {
    pub config: PathBuf,
    pub ai_forbidden_root: PathBuf,
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
}

#[derive(Debug, Serialize)]
pub struct E2eFocusedApiStatus {
    pub api: String,
    pub status: String,
    pub active: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct E2eResponseRuleEvidence {
    pub replay: PathBuf,
    pub assertions: PathBuf,
    pub aggregate: PathBuf,
}

pub fn initialize_e2e_run(options: E2eRunInitOptions) -> Result<E2eRunInitResult> {
    config::initialize(options)
}

pub fn initialize_standard_e2e_project(
    target_root: PathBuf,
    source_container: String,
) -> Result<E2eRunInitResult> {
    initialize_standard_e2e_project_with_force(target_root, source_container, false)
}

pub fn initialize_standard_e2e_project_with_force(
    target_root: PathBuf,
    source_container: String,
    force: bool,
) -> Result<E2eRunInitResult> {
    let resolved_root = std::fs::canonicalize(&target_root)
        .with_context(|| format!("failed to resolve target root {}", target_root.display()))?;
    let recorder_config = PathBuf::from(".traffic-e2e/recorder.toml");
    let recorder = crate::config::AppConfig::load(resolved_root.join(&recorder_config))?;
    let comparison = recorder
        .comparison_recording
        .as_ref()
        .context("recorder config has no comparison_recording section")?;
    let candidate_upstream = comparison
        .candidate_upstream
        .parse::<hyper::Uri>()
        .context("comparison_recording.candidate_upstream is not a valid URI")?;
    ensure!(
        candidate_upstream.scheme_str() == Some("http"),
        "comparison_recording.candidate_upstream must use http"
    );
    ensure!(
        candidate_upstream
            .path_and_query()
            .is_none_or(|value| value.as_str() == "/"),
        "comparison_recording.candidate_upstream must not contain a base path or query"
    );
    let target_http_host = candidate_upstream
        .host()
        .context("comparison_recording.candidate_upstream has no host")?
        .to_string();
    let target_port = candidate_upstream.port_u16().unwrap_or(80);
    ensure!(
        recorder.http_gateway.ready.enabled,
        "managed project replay requires an enabled http_gateway.ready probe"
    );
    initialize_e2e_run(E2eRunInitOptions {
        target_root,
        source_container,
        breeze_container: None,
        target_dockerfile: PathBuf::from(".traffic-e2e/Dockerfile.e2e"),
        target_boot_dir: PathBuf::from(crate::repository::LOCAL_BOOT_ROOT),
        target_http_host,
        target_port,
        target_readiness_path: recorder.http_gateway.ready.path.clone(),
        target_readiness_status: recorder.http_gateway.ready.success_status,
        target_startup_timeout_seconds: model::DEFAULT_TARGET_STARTUP_TIMEOUT_SECONDS,
        target_request_timeout_seconds: comparison
            .upstream_timeout_ms
            .saturating_add(999)
            .checked_div(1_000)
            .unwrap_or(1)
            .max(1),
        replay_policy: PathBuf::from(".traffic-e2e/verification.yaml"),
        replay_startup_timeout_seconds: model::DEFAULT_REPLAY_STARTUP_TIMEOUT_SECONDS,
        pr_base: "dev-migration".to_string(),
        recorder_config,
        recording_rule: crate::config::DEFAULT_RECORDING_RULE.to_string(),
        force,
    })
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
    let group = ensure_case_group(CaseGroupOptions {
        case_source: options.context.case_source,
        case_dir: options.case_dir,
        method: options.method,
        source_route: options.source_route,
        pattern: options.pattern,
        source_revision: options.source_revision,
        output: layout.group_index_path.clone(),
        recorder_config: Some(config.recorder_config),
        rule: Some(config.recording_rule),
    })?;
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

pub fn status_e2e_run(context: E2eRunContext) -> Result<E2eRunStatus> {
    let (_, layout) = config::resolve_layout(
        &context.target_root,
        &context.case_source,
        context.run_key.as_deref(),
    )?;
    let active_state = layout.active_dir.join("state.yaml");
    let latest_state = layout.latest_dir.join("state.yaml");
    let status = if active_state.is_file() {
        let state = store::read_active(&layout)?;
        run_status_label(state.status).to_string()
    } else if latest_state.is_file() {
        let state: model::ActiveRunState = store::read_yaml(&latest_state)?;
        run_status_label(state.status).to_string()
    } else {
        "not_started".to_string()
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
                let status = if active {
                    "running".to_string()
                } else if latest_state.is_file() {
                    store::read_yaml::<model::ActiveRunState>(&latest_state)
                        .map(|state| run_status_label(state.status).to_string())
                        .unwrap_or_else(|_| "invalid".to_string())
                } else {
                    "not_started".to_string()
                };
                E2eFocusedApiStatus {
                    api: group.group_id,
                    status,
                    active,
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
    })
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
    let focused_root = layout
        .run_root
        .join("focused")
        .join(support::api_directory(api));
    ensure!(
        !focused_root.join(".active").exists() && !layout.active_dir.exists(),
        "response-rule evidence is unavailable while an E2E attempt is active"
    );
    let focused_state = focused_root.join("latest/state.yaml");
    let full_state = layout.latest_dir.join("state.yaml");
    let state_path = if focused_state.is_file() {
        focused_state
    } else if full_state.is_file() {
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
    ensure!(
        state.replay_report.is_file(),
        "runner-owned replay evidence is missing"
    );
    ensure!(
        state.assertions_report.is_file(),
        "runner-owned assertion evidence is missing"
    );
    ensure!(
        state.aggregate_report.is_file(),
        "runner-owned aggregate evidence is missing"
    );
    Ok(E2eResponseRuleEvidence {
        replay: state.replay_report,
        assertions: state.assertions_report,
        aggregate: state.aggregate_report,
    })
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
        "background dependency evidence requires exactly one finalized focused API; use the rewrite coordinator when the case source has {} candidates",
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
