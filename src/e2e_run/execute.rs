use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail, ensure};
use chrono::Utc;
use serde::Serialize;
use tokio::process::Child;

use super::final_evidence::{
    build_final_evidence, summarize_apis_without_aggregate, sync_verified_excludes,
};
use super::model::{ActiveRunState, CaseStatus, ResolvedProjectConfig, RunLayout, RunStatus};
use super::progress::{build_progress, refresh_verification, update_focused_index, update_index};
use super::runtime::{
    best_effort_stop, control, finalize_replay, run_project, spawn_replay, stop_replay_process,
    wait_for_replay, wait_for_replay_ready,
};
use super::store;
use super::support::{allocate_replay_report, api_directory, process_exists, status_label};
use super::{E2eRunContext, require_executable};
use super::{branch, config};
use crate::case_group::{
    CaseGroupInventory, load_case_group_inventory, load_complete_case_group_inventory,
};
use crate::replay::{ResponseAssertionOptions, assert_recorded_response, validate_replay_policy};

#[derive(Debug, Clone, Serialize)]
pub struct E2eRunResult {
    pub run_key: String,
    pub sequence: u64,
    pub status: String,
    pub successful: bool,
    pub latest_state: PathBuf,
    pub progress: PathBuf,
}

#[derive(Debug, Clone, Serialize)]
pub struct E2eApiRunResult {
    pub run_key: String,
    pub api: String,
    pub attempt: u64,
    pub status: String,
    pub successful: bool,
    pub latest_state: PathBuf,
    pub progress: PathBuf,
}

pub async fn run_e2e_round(context: E2eRunContext) -> Result<E2eRunResult> {
    let (config, layout) = resolve_for_execution(&context)?;
    ensure!(
        store::focused_active_directories(&layout)?.is_empty(),
        "a focused API attempt is active; finish or recover it before starting a full round"
    );
    let inventory =
        load_complete_case_group_inventory(&layout.group_index_path, &layout.case_source)
            .context("E2E run prepare is incomplete or stale")?;
    let mut index = store::load_or_create_index(&layout, &layout.run_key, &layout.case_source)?;

    let sequence = index.executions + 1;
    let mut state = ActiveRunState::new(
        layout.run_key.clone(),
        sequence,
        &inventory,
        config.recording_rule.clone(),
        &layout.active_dir,
    );
    state.replay_report = allocate_replay_report(
        &layout.case_source,
        &layout.run_key,
        &format!("round-{sequence:06}"),
    )?;
    store::begin_active(&layout, &state)?;

    if let Err(error) = run_active(&config, &layout, &inventory, &mut state).await {
        state.errors.push(format!("{error:#}"));
        state.status = RunStatus::Interrupted;
        mark_unfinished_cases(&mut state);
        best_effort_stop(&config, &layout, &mut state).await;
    }
    finish_and_publish(&config, &layout, &mut index, &mut state)
}

pub async fn abort_e2e_run(context: E2eRunContext) -> Result<E2eRunResult> {
    let (config, layout) = config::resolve_layout(
        &context.target_root,
        &context.case_source,
        context.run_key.as_deref(),
    )?;
    config::require_local_ignored(&layout.target_root, &layout.local_root)?;
    ensure!(
        layout.active_dir.is_dir(),
        "there is no active E2E run to abort"
    );
    let mut state = store::read_active(&layout)?;
    let mut index = store::load_or_create_index(&layout, &layout.run_key, &layout.case_source)?;
    best_effort_stop(&config, &layout, &mut state).await;
    state.status = RunStatus::Interrupted;
    state
        .errors
        .push("run aborted before terminal replay evidence".to_string());
    mark_unfinished_cases(&mut state);
    let inventory =
        load_complete_case_group_inventory(&layout.group_index_path, &layout.case_source)?;
    summarize_apis_without_aggregate(&layout, &mut state, &inventory);
    finish_and_publish(&config, &layout, &mut index, &mut state)
}

pub async fn run_e2e_api(context: E2eRunContext, api_key: &str) -> Result<E2eApiRunResult> {
    let (config, base_layout) = resolve_for_execution(&context)?;
    ensure!(
        !base_layout.active_dir.exists(),
        "a full E2E round is active; use status, abort, or recover before running one API"
    );
    let inventory =
        load_case_group_inventory(&base_layout.group_index_path, &base_layout.case_source)
            .context("E2E API has not been prepared or its grouping is stale")?;
    let inventory_complete =
        load_complete_case_group_inventory(&base_layout.group_index_path, &base_layout.case_source)
            .is_ok();
    let mut index =
        store::load_or_create_index(&base_layout, &base_layout.run_key, &base_layout.case_source)?;
    let group = inventory
        .groups
        .iter()
        .find(|group| group.group_id == api_key)
        .with_context(|| format!("prepared API group not found: {api_key}"))?
        .clone();
    let focused_inventory = CaseGroupInventory {
        case_source: inventory.case_source.clone(),
        source_revision: inventory.source_revision.clone(),
        case_inventory_id: inventory.case_inventory_id.clone(),
        groups: vec![group],
    };
    let focused_root = base_layout
        .run_root
        .join("focused")
        .join(api_directory(api_key));
    let focused_active = focused_root.join(".active");
    let other_active = store::focused_active_directories(&base_layout)?
        .into_iter()
        .filter(|path| path != &focused_active)
        .collect::<Vec<_>>();
    ensure!(
        other_active.is_empty(),
        "another focused API attempt is active at {}; finish or recover it first",
        other_active
            .first()
            .map(|path| path.display().to_string())
            .unwrap_or_default()
    );
    let global_layout = base_layout.clone();
    let mut layout = base_layout;
    layout.run_root = focused_root.clone();
    layout.active_dir = focused_root.join(".active");
    layout.latest_dir = focused_root.join("latest");
    if layout.active_dir.is_dir() {
        let mut interrupted = store::read_active(&layout)?;
        if !interrupted.status.is_terminal() {
            ensure!(
                interrupted
                    .replay_pid
                    .is_none_or(|pid| !process_exists(pid)),
                "the focused API attempt is still running; wait for it to finish"
            );
            best_effort_stop(&config, &layout, &mut interrupted).await;
            interrupted.status = RunStatus::Interrupted;
            interrupted.finished_at = Some(Utc::now());
            interrupted
                .errors
                .push("stale focused attempt recovered before rerun".to_string());
            mark_unfinished_cases(&mut interrupted);
            summarize_apis_without_aggregate(&layout, &mut interrupted, &focused_inventory);
        }
        finish_focused_and_publish(
            &config,
            &global_layout,
            &layout,
            &mut index,
            &inventory,
            inventory_complete,
            &mut interrupted,
        )?;
    }
    let previous_path = layout.latest_dir.join("state.yaml");
    if previous_path.is_file() {
        let mut previous: ActiveRunState = store::read_yaml(&previous_path)?;
        update_focused_index(
            &mut index,
            &previous,
            &inventory,
            inventory_complete,
            &config.api_verification,
        );
        sync_verified_excludes(&config, &mut previous, &index)?;
        store::write_yaml(&previous_path, &previous)?;
        store::write_yaml(&global_layout.index_path, &index)?;
        store::write_yaml(
            &global_layout.progress_path,
            &build_progress(&index, &previous),
        )?;
    }
    let attempt = if layout.latest_dir.join("state.yaml").is_file() {
        let previous: ActiveRunState = store::read_yaml(&layout.latest_dir.join("state.yaml"))?;
        previous.sequence + 1
    } else {
        1
    };
    let mut state = ActiveRunState::new(
        layout.run_key.clone(),
        attempt,
        &focused_inventory,
        config.recording_rule.clone(),
        &layout.active_dir,
    );
    state.replay_report = allocate_replay_report(
        &layout.case_source,
        &layout.run_key,
        &format!("focused-{}-{attempt:06}", api_directory(api_key)),
    )?;
    store::begin_active(&layout, &state)?;
    if let Err(error) = run_active(&config, &layout, &focused_inventory, &mut state).await {
        state.errors.push(format!("{error:#}"));
        state.status = RunStatus::Interrupted;
        mark_unfinished_cases(&mut state);
        best_effort_stop(&config, &layout, &mut state).await;
        summarize_apis_without_aggregate(&layout, &mut state, &focused_inventory);
    }
    state.finished_at.get_or_insert_with(Utc::now);
    finish_focused_and_publish(
        &config,
        &global_layout,
        &layout,
        &mut index,
        &inventory,
        inventory_complete,
        &mut state,
    )?;
    let successful = state.status == RunStatus::Successful;
    Ok(E2eApiRunResult {
        run_key: state.run_key,
        api: api_key.to_string(),
        attempt,
        status: status_label(state.status).to_string(),
        successful,
        latest_state: layout.latest_dir.join("state.yaml"),
        progress: global_layout.progress_path,
    })
}

fn finish_focused_and_publish(
    config: &ResolvedProjectConfig,
    global_layout: &RunLayout,
    focused_layout: &RunLayout,
    index: &mut super::model::RunIndex,
    inventory: &CaseGroupInventory,
    inventory_complete: bool,
    state: &mut ActiveRunState,
) -> Result<()> {
    state.finished_at.get_or_insert_with(Utc::now);
    ensure!(
        state.status.is_terminal(),
        "focused run state is not terminal"
    );
    update_focused_index(
        index,
        state,
        inventory,
        inventory_complete,
        &config.api_verification,
    );
    sync_verified_excludes(config, state, index)?;
    let progress = build_progress(index, state);
    store::publish_snapshot(
        &focused_layout.active_dir,
        &focused_layout.latest_dir,
        state,
    )?;
    store::write_yaml(&global_layout.index_path, index)?;
    store::write_yaml(&global_layout.progress_path, &progress)
}

pub async fn recover_e2e_run(context: E2eRunContext) -> Result<E2eRunResult> {
    let (config, layout) = config::resolve_layout(
        &context.target_root,
        &context.case_source,
        context.run_key.as_deref(),
    )?;
    config::require_local_ignored(&layout.target_root, &layout.local_root)?;
    std::fs::create_dir_all(&layout.run_root)?;
    store::recover_publication(&layout)?;
    if layout.active_dir.is_dir() {
        let mut state = store::read_active(&layout)?;
        if state.status.is_terminal() {
            let mut index =
                store::load_or_create_index(&layout, &layout.run_key, &layout.case_source)?;
            return finish_and_publish(&config, &layout, &mut index, &mut state);
        }
        return abort_e2e_run(context).await;
    }
    let latest_path = layout.latest_dir.join("state.yaml");
    ensure!(
        latest_path.is_file(),
        "there is no active or latest E2E run to recover"
    );
    let mut state: ActiveRunState = store::read_yaml(&latest_path)?;
    let mut index = store::load_or_create_index(&layout, &layout.run_key, &layout.case_source)?;
    refresh_verification(&mut index, &config.api_verification);
    sync_verified_excludes(&config, &mut state, &index)?;
    store::write_yaml(&latest_path, &state)?;
    store::write_yaml(&layout.progress_path, &build_progress(&index, &state))?;
    store::write_yaml(&layout.index_path, &index)?;
    Ok(result(&layout, &state))
}

fn resolve_for_execution(context: &E2eRunContext) -> Result<(ResolvedProjectConfig, RunLayout)> {
    let (config, layout) = config::resolve_layout(
        &context.target_root,
        &context.case_source,
        context.run_key.as_deref(),
    )?;
    branch::require_work_branch(&layout.target_root, &config.pr_base)?;
    config::require_local_ignored(&layout.target_root, &layout.local_root)?;
    require_executable(&config.project_cli, "project CLI")?;
    ensure!(
        config.replay_policy.is_file(),
        "replay policy does not exist: {}",
        config.replay_policy.display()
    );
    validate_replay_policy(&config.replay_policy).context("invalid replay policy")?;
    Ok((config, layout))
}

async fn run_active(
    config: &ResolvedProjectConfig,
    layout: &RunLayout,
    inventory: &CaseGroupInventory,
    state: &mut ActiveRunState,
) -> Result<()> {
    let mut replay = spawn_replay(config, layout, inventory, state)?;
    state.replay_pid = replay.id();
    store::write_active(layout, state)?;
    let outcome = run_active_with_replay(config, layout, inventory, state, &mut replay).await;
    if outcome.is_err() {
        stop_replay_process(state, &mut replay).await;
    }
    outcome
}

async fn run_active_with_replay(
    config: &ResolvedProjectConfig,
    layout: &RunLayout,
    inventory: &CaseGroupInventory,
    state: &mut ActiveRunState,
    replay: &mut Child,
) -> Result<()> {
    let ready = tokio::select! {
        ready = wait_for_replay_ready(state, config.replay_startup_timeout) => {
            ready.context("replay server did not become ready")?
        }
        status = replay.wait() => {
            let status = status.context("failed to wait for replay process during startup")?;
            bail!("replay process exited before becoming ready with {status}");
        }
    };
    state.session_id = ready
        .pointer("/session/session_id")
        .and_then(serde_json::Value::as_str)
        .map(ToOwned::to_owned);
    ensure!(
        state.session_id.is_some(),
        "replay session has no session id"
    );
    store::write_active(layout, state)?;

    state.target_started = true;
    store::write_active(layout, state)?;
    let start = run_project(
        config,
        layout,
        &["start"],
        &layout.active_dir.join("reports/target-start.json"),
    )
    .await?;
    ensure!(start.success, "project CLI start failed");
    let status = run_project(
        config,
        layout,
        &["status"],
        &layout.active_dir.join("reports/target-status.json"),
    )
    .await?;
    ensure!(
        status.success,
        "project CLI status did not confirm a running target"
    );

    for (position, case) in state.cases.clone().into_iter().enumerate() {
        execute_case(
            config,
            layout,
            state,
            position,
            &case.case_id,
            &case.case_dir,
        )
        .await;
    }

    let stop = run_project(
        config,
        layout,
        &["stop"],
        &layout.active_dir.join("reports/target-stop.json"),
    )
    .await?;
    if stop.success {
        state.target_started = false;
    } else {
        state.errors.push("project CLI stop failed".to_string());
    }
    state.status = RunStatus::Finalizing;
    store::write_active(layout, state)?;

    finalize_replay(state).await?;
    wait_for_replay(replay).await?;
    state.replay_pid = None;
    build_final_evidence(config, layout, inventory, state)?;
    if state.target_started {
        best_effort_stop(config, layout, state).await;
    }
    state.finished_at = Some(Utc::now());
    state.status = if state
        .cases
        .iter()
        .all(|case| case.status == CaseStatus::Passed)
        && state.replay_finalized
        && state.aggregate_complete
        && state.aggregate_clean
        && state.apis.iter().all(|api| api.successful)
        && state.errors.is_empty()
    {
        RunStatus::Successful
    } else {
        RunStatus::Failed
    };
    Ok(())
}

async fn execute_case(
    config: &ResolvedProjectConfig,
    layout: &RunLayout,
    state: &mut ActiveRunState,
    position: usize,
    case_id: &str,
    case_dir: &Path,
) {
    let Some(case_index) = state.cases.iter().position(|case| case.case_id == case_id) else {
        state
            .errors
            .push(format!("case {case_id} disappeared from run state"));
        return;
    };
    state.cases[case_index].status = CaseStatus::Running;
    let _ = store::write_active(layout, state);

    let begin = control(state, "begin", Some(case_id), false, false).await;
    if let Err(error) = begin {
        state.cases[case_index].status = CaseStatus::Incomplete;
        state
            .errors
            .push(format!("case {case_id} begin failed: {error:#}"));
        let _ = store::write_active(layout, state);
        return;
    }

    let log_path = layout
        .active_dir
        .join("reports")
        .join(format!("case-{:04}.json", position + 1));
    let case_arg = case_dir.display().to_string();
    let actual_response = layout
        .active_dir
        .join("reports")
        .join(format!("actual-response-{:04}.json", position + 1));
    let actual_arg = actual_response.display().to_string();
    let args = if config.runner_owned_response_assertions {
        vec![
            "e2e",
            "--case-dir",
            case_arg.as_str(),
            "--actual-response",
            actual_arg.as_str(),
        ]
    } else {
        vec!["e2e", "--case-dir", case_arg.as_str()]
    };
    let assertion_command = run_project(config, layout, &args, &log_path).await;
    let response_assertion = if config.runner_owned_response_assertions
        && assertion_command
            .as_ref()
            .is_ok_and(|result| result.success)
    {
        let expected_response = if case_dir.join("expected-response.json").is_file() {
            case_dir.join("expected-response.json")
        } else {
            case_dir.join("expected_response.json")
        };
        assert_recorded_response(ResponseAssertionOptions {
            case_id: case_id.to_string(),
            request: case_dir.join("request.json"),
            expected_response,
            actual_response,
            policy: config.replay_policy.clone(),
        })
        .map_err(|error| anyhow::anyhow!("runner-owned response assertion failed: {error:#}"))
    } else if config.runner_owned_response_assertions {
        Err(anyhow::anyhow!(
            "project CLI did not produce a successful actual response"
        ))
    } else {
        Err(anyhow::anyhow!(
            "legacy target-owned assertion has no response report"
        ))
    };
    let assertion_passed = if config.runner_owned_response_assertions {
        response_assertion
            .as_ref()
            .is_ok_and(|report| report.passed)
    } else {
        assertion_command
            .as_ref()
            .is_ok_and(|result| result.success)
    };
    match response_assertion {
        Ok(report) => state.cases[case_index].response_assertion = Some(report),
        Err(error) if config.runner_owned_response_assertions => state.errors.push(format!(
            "case {case_id} response assertion could not be evaluated: {error:#}"
        )),
        Err(_) => {}
    }
    state.cases[case_index].assertion_passed = Some(assertion_passed);
    if let Err(error) = assertion_command {
        state.errors.push(format!(
            "case {case_id} assertion command failed: {error:#}"
        ));
    }

    let ended = control(state, "end", Some(case_id), true, false).await;
    let replay_clean = ended.is_ok();
    state.cases[case_index].replay_clean = Some(replay_clean);
    state.cases[case_index].status = if assertion_passed && replay_clean {
        CaseStatus::Passed
    } else {
        CaseStatus::Failed
    };
    if let Err(error) = ended {
        state.errors.push(format!(
            "case {case_id} replay evidence is dirty: {error:#}"
        ));
    }
    let _ = store::write_active(layout, state);
}

fn mark_unfinished_cases(state: &mut ActiveRunState) {
    for case in &mut state.cases {
        if case.status == CaseStatus::Running {
            case.status = CaseStatus::Incomplete;
        }
    }
}

fn finish_and_publish(
    config: &ResolvedProjectConfig,
    layout: &RunLayout,
    index: &mut super::model::RunIndex,
    state: &mut ActiveRunState,
) -> Result<E2eRunResult> {
    if state.apis.is_empty() {
        let inventory =
            load_complete_case_group_inventory(&layout.group_index_path, &layout.case_source)?;
        summarize_apis_without_aggregate(layout, state, &inventory);
    }
    state.finished_at.get_or_insert_with(Utc::now);
    ensure!(state.status.is_terminal(), "run state is not terminal");
    update_index(index, state, &config.api_verification);
    sync_verified_excludes(config, state, index)?;
    let progress = build_progress(index, state);
    store::write_yaml(&layout.progress_path, &progress)?;
    store::publish_terminal(layout, state, index)?;
    Ok(result(layout, state))
}

fn result(layout: &RunLayout, state: &ActiveRunState) -> E2eRunResult {
    E2eRunResult {
        run_key: state.run_key.clone(),
        sequence: state.sequence,
        status: status_label(state.status).to_string(),
        successful: state.status == RunStatus::Successful,
        latest_state: layout.latest_dir.join("state.yaml"),
        progress: layout.progress_path.clone(),
    }
}
