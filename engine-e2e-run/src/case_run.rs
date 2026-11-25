//! Managed Case preparation, persisted status and progress projection.

use std::path::PathBuf;

use anyhow::{Result, ensure};
use serde::Serialize;

use crate::{
    E2eRunContext, active_progress,
    case_group::{
        CaseGroupOptions, ensure_case_group_with_target_root, load_case_group_inventory,
        load_complete_case_group_inventory,
    },
    model::{self, CaseStatus, RunStatus},
    run_config, store, support,
};

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
pub struct E2eFocusedAttemptSummary {
    pub attempt: u64,
    pub passed: bool,
    pub case_source: PathBuf,
    pub case_inventory_id: String,
    pub selected_case_ids: std::collections::BTreeSet<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum E2eActiveProgress {
    PreparingIndex,
    PreparingReplay,
    StartingTarget,
    PreparingCase { completed: usize, total: usize },
    Building,
    Replaying { completed: usize, total: usize },
    GeneratingEvidence,
    Finalizing,
}

pub fn initialize_e2e_run(options: E2eRunInitOptions) -> Result<E2eRunInitResult> {
    run_config::initialize(options)
}

pub fn prepare_e2e_run(options: E2eRunPrepareOptions) -> Result<E2eRunPrepareResult> {
    let (config, layout) = run_config::resolve_layout(
        &options.context.target_root,
        &options.context.case_source,
        options.context.run_key.as_deref(),
    )?;
    run_config::require_internal_root_ignored(&layout.target_root, &layout.internal_root)?;
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

pub fn prepare_case_group_index_rebuild(context: &E2eRunContext) -> Result<PathBuf> {
    let (_, layout) = run_config::resolve_layout(
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

pub fn require_failed_unmanaged_index(
    context: &E2eRunContext,
    revision: &str,
    inventory_id: &str,
) -> Result<()> {
    let (_, layout) = run_config::resolve_layout(
        &context.target_root,
        &context.case_source,
        context.run_key.as_deref(),
    )?;
    ensure!(
        layout.index_path.is_file(),
        "unmanaged replay run index is missing"
    );
    let index = store::load_or_create_index(&layout, &layout.run_key, &layout.case_source)?;
    ensure!(
        index.source_revision == revision
            && index.case_inventory_id == inventory_id
            && index.executions > 0
            && index.passed_runs == 0
            && index.passed_cases == 0
            && index.latest_status == Some(model::RunStatus::Failed),
        "run index must bind the exact failed unmanaged inventory and contain no passing evidence"
    );
    Ok(())
}

pub fn reanchor_case_group_run_index(
    context: &E2eRunContext,
    source_revision: &str,
    case_inventory_id: &str,
) -> Result<Option<PathBuf>> {
    let (_, layout) = run_config::resolve_layout(
        &context.target_root,
        &context.case_source,
        context.run_key.as_deref(),
    )?;
    store::reanchor_index_case_source(&layout, source_revision, case_inventory_id)
}

pub fn status_e2e_run(context: E2eRunContext) -> Result<E2eRunStatus> {
    let (_, layout) = run_config::resolve_layout(
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

pub fn focused_active_progress(
    context: &E2eRunContext,
    api_key: &str,
) -> Result<Option<E2eActiveProgress>> {
    let (_, layout) = run_config::resolve_layout(
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

pub fn workflow_active_progress(
    context: &E2eRunContext,
    started_at: chrono::DateTime<chrono::Utc>,
) -> Result<Option<E2eActiveProgress>> {
    let (_, layout) = run_config::resolve_layout(
        &context.target_root,
        &context.case_source,
        context.run_key.as_deref(),
    )?;
    Ok(active_progress::workflow(&layout.run_root, started_at))
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
