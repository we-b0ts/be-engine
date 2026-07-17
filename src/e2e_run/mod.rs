mod branch;
mod config;
mod execute;
mod final_evidence;
mod model;
mod progress;
mod runtime;
mod store;
mod support;

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, ensure};
use serde::Serialize;

use crate::case_group::{
    CaseGroupOptions, ensure_case_group, load_case_group_inventory,
    load_complete_case_group_inventory,
};

pub use execute::{
    E2eApiRunResult, E2eRunResult, abort_e2e_run, recover_e2e_run, run_e2e_api, run_e2e_round,
};
use model::RunStatus;

#[derive(Debug, Clone)]
pub struct E2eRunInitOptions {
    pub target_root: PathBuf,
    pub project_cli: PathBuf,
    pub replay_policy: PathBuf,
    pub pr_base: String,
    pub recorder_config: Option<PathBuf>,
    pub recording_rule: Option<String>,
    pub force: bool,
}

#[derive(Debug, Serialize)]
pub struct E2eRunInitResult {
    pub config: PathBuf,
    pub local_root: PathBuf,
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
    pub active_state: Option<PathBuf>,
    pub latest_state: Option<PathBuf>,
    pub progress: PathBuf,
    pub focused_apis: Vec<E2eFocusedApiStatus>,
}

#[derive(Debug, Serialize)]
pub struct E2eFocusedApiStatus {
    pub api: String,
    pub status: String,
    pub active: bool,
    pub latest_state: Option<PathBuf>,
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
    config::require_local_ignored(&layout.target_root, &layout.local_root)?;
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
        recorder_config: config.recorder_config,
        rule: config.recording_rule,
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
    let (status, active_state) = if active_state.is_file() {
        let state = store::read_active(&layout)?;
        (
            run_status_label(state.status).to_string(),
            Some(active_state),
        )
    } else if latest_state.is_file() {
        let state: model::ActiveRunState = store::read_yaml(&latest_state)?;
        (run_status_label(state.status).to_string(), None)
    } else {
        ("not_started".to_string(), None)
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
                    latest_state: latest_state.is_file().then_some(latest_state),
                }
            })
            .collect()
    } else {
        Vec::new()
    };
    Ok(E2eRunStatus {
        run_key: layout.run_key,
        status,
        active_state,
        latest_state: latest_state.is_file().then_some(latest_state),
        progress: layout.progress_path,
        focused_apis,
    })
}

fn run_status_label(status: RunStatus) -> &'static str {
    match status {
        RunStatus::Running => "running",
        RunStatus::Finalizing => "finalizing",
        RunStatus::Successful => "successful",
        RunStatus::Failed => "failed",
        RunStatus::Interrupted => "interrupted",
    }
}

fn require_executable(path: &Path, label: &str) -> Result<()> {
    let metadata = std::fs::metadata(path)
        .with_context(|| format!("failed to inspect {label} {}", path.display()))?;
    ensure!(metadata.is_file(), "{label} must be a regular file");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        ensure!(
            metadata.permissions().mode() & 0o111 != 0,
            "{label} is not executable: {}",
            path.display()
        );
    }
    Ok(())
}
