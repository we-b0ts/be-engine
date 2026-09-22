use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail, ensure};
use chrono::Utc;
use tokio::process::Child;

use super::E2eRunContext;
use super::active_progress::{self, ActiveProgressPhase};
use super::case_progress;
use super::final_evidence::{build_final_evidence, summarize_apis_without_aggregate};
use super::model::{
    ActiveRunState, CaseStatus, MAX_RESPONSE_DIFFERENCE_INDEX, ResolvedProjectConfig,
    ResponseAssertionSummary, RunLayout, RunStatus,
};
use super::progress::{update_focused_index, update_index, write_replay_progress};
use super::request_view::RequestCaseView;
use super::result::{E2eApiRunResult, E2eRunResult, api_result, run_result};
use super::runtime::{
    best_effort_stop, build_target_image, control, finalize_replay, replay_ca_cert_path,
    spawn_replay, start_target_with_replay_ca, stop_replay_process, stop_target_runtime,
    verify_target_runtime_contract, wait_for_replay, wait_for_replay_ready,
};
use super::store;
use super::support::{allocate_replay_report, api_directory, process_exists};
use super::{branch, config};
use crate::case_group::{
    CaseGroupInventory, load_case_group_inventory, load_complete_case_group_inventory,
};
use crate::replay::{ResponseAssertionOptions, assert_recorded_response, validate_replay_policy};

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

    let sequence = index.latest_sequence.unwrap_or(0).saturating_add(1);
    let mut state = ActiveRunState::new(
        layout.run_key.clone(),
        sequence,
        &inventory,
        &layout.active_dir,
    );
    state.replay_report = allocate_replay_report(
        &layout.case_source,
        &layout.run_key,
        &format!("round-{sequence:06}"),
    )?;
    store::begin_active(&layout, &state)?;
    let _ = active_progress::write(&layout, &state, ActiveProgressPhase::Building);

    if let Err(error) = run_active(&config, &layout, &inventory, &mut state).await {
        state.push_error(format!("{error:#}"));
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
    config::require_internal_root_ignored(&layout.target_root, &layout.internal_root)?;
    ensure!(
        layout.active_dir.is_dir(),
        "there is no active E2E run to abort"
    );
    let mut state = store::read_active(&layout)?;
    let mut index = store::load_or_create_index(&layout, &layout.run_key, &layout.case_source)?;
    best_effort_stop(&config, &layout, &mut state).await;
    state.status = RunStatus::Interrupted;
    state.push_error("run aborted before terminal replay evidence");
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
            interrupted.push_error("stale focused attempt recovered before rerun");
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
        let previous: ActiveRunState = store::read_yaml(&previous_path)?;
        update_focused_index(&mut index, &previous, &inventory, inventory_complete);
        store::write_yaml(&previous_path, &previous)?;
        store::write_yaml(&global_layout.index_path, &index)?;
        write_replay_progress(
            &global_layout.progress_path,
            &global_layout.legacy_progress_path,
            &index,
            &previous,
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
        &layout.active_dir,
    );
    state.replay_report = allocate_replay_report(
        &layout.case_source,
        &layout.run_key,
        &format!("focused-{}-{attempt:06}", api_directory(api_key)),
    )?;
    store::begin_active(&layout, &state)?;
    let _ = active_progress::write(&layout, &state, ActiveProgressPhase::Building);
    if let Err(error) = run_active(&config, &layout, &focused_inventory, &mut state).await {
        state.push_error(format!("{error:#}"));
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
    Ok(api_result(&layout, &state, api_key, attempt))
}

fn finish_focused_and_publish(
    _config: &ResolvedProjectConfig,
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
    update_focused_index(index, state, inventory, inventory_complete);
    store::publish_snapshot(
        &focused_layout.active_dir,
        &focused_layout.latest_dir,
        state,
    )?;
    store::write_yaml(&global_layout.index_path, index)?;
    write_replay_progress(
        &global_layout.progress_path,
        &global_layout.legacy_progress_path,
        index,
        state,
    )
}

pub async fn recover_e2e_run(context: E2eRunContext) -> Result<E2eRunResult> {
    let (config, layout) = config::resolve_layout(
        &context.target_root,
        &context.case_source,
        context.run_key.as_deref(),
    )?;
    config::require_internal_root_ignored(&layout.target_root, &layout.internal_root)?;
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
    let state: ActiveRunState = store::read_yaml(&latest_path)?;
    let index = store::load_or_create_index(&layout, &layout.run_key, &layout.case_source)?;
    store::write_yaml(&latest_path, &state)?;
    write_replay_progress(
        &layout.progress_path,
        &layout.legacy_progress_path,
        &index,
        &state,
    )?;
    store::write_yaml(&layout.index_path, &index)?;
    Ok(run_result(&layout, &state))
}

pub(crate) async fn recover_focused_e2e_api(context: E2eRunContext, api_key: &str) -> Result<bool> {
    let (config, base_layout) = config::resolve_layout(
        &context.target_root,
        &context.case_source,
        context.run_key.as_deref(),
    )?;
    config::require_internal_root_ignored(&base_layout.target_root, &base_layout.internal_root)?;
    let global_layout = base_layout.clone();
    let mut layout = base_layout;
    let focused_root = layout.run_root.join("focused").join(api_directory(api_key));
    layout.run_root = focused_root.clone();
    layout.active_dir = focused_root.join(".active");
    layout.latest_dir = focused_root.join("latest");
    if !layout.active_dir.is_dir() {
        return Ok(false);
    }

    let mut state = store::read_active(&layout)?;
    if !state.status.is_terminal() {
        best_effort_stop(&config, &layout, &mut state).await;
        state.status = RunStatus::Interrupted;
        state.finished_at = Some(Utc::now());
        state.push_error("focused API attempt recovered by rewrite coordinator");
        mark_unfinished_cases(&mut state);
    }

    let inventory =
        load_case_group_inventory(&global_layout.group_index_path, &global_layout.case_source)
            .context("E2E API has not been prepared or its grouping is stale")?;
    let inventory_complete = load_complete_case_group_inventory(
        &global_layout.group_index_path,
        &global_layout.case_source,
    )
    .is_ok();
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
    if state.apis.is_empty() {
        summarize_apis_without_aggregate(&layout, &mut state, &focused_inventory);
    }
    let mut index = store::load_or_create_index(
        &global_layout,
        &global_layout.run_key,
        &global_layout.case_source,
    )?;
    finish_focused_and_publish(
        &config,
        &global_layout,
        &layout,
        &mut index,
        &inventory,
        inventory_complete,
        &mut state,
    )?;
    Ok(true)
}

fn resolve_for_execution(context: &E2eRunContext) -> Result<(ResolvedProjectConfig, RunLayout)> {
    let (config, layout) = config::resolve_layout(
        &context.target_root,
        &context.case_source,
        context.run_key.as_deref(),
    )?;
    branch::require_work_branch(&layout.target_root, &config.pr_base)?;
    config::require_internal_root_ignored(&layout.target_root, &layout.internal_root)?;
    ensure!(
        config.target_dockerfile.is_file(),
        "target Dockerfile does not exist: {}",
        config.target_dockerfile.display()
    );
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
    let target_image = build_target_image(config, layout).await?;
    let mut replay = spawn_replay(config, layout, inventory, state)?;
    state.replay_pid = replay.id();
    store::write_active(layout, state)?;
    let _ = active_progress::write(layout, state, ActiveProgressPhase::Replaying);
    let outcome =
        run_active_with_replay(config, layout, inventory, state, &target_image, &mut replay).await;
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
    target_image: &crate::TargetImage,
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
    super::runtime::validate_replay_case_selection(&ready, state)?;
    state.session_id = ready
        .pointer("/session/session_id")
        .and_then(serde_json::Value::as_str)
        .map(ToOwned::to_owned);
    ensure!(
        state.session_id.is_some(),
        "replay session has no session id"
    );
    let replay_ca_cert_path = replay_ca_cert_path(&ready)?;
    store::write_active(layout, state)?;

    start_target_with_replay_ca(config, layout, state, target_image, &replay_ca_cert_path).await?;
    super::http_driver::wait_until_ready(config).await?;
    verify_target_runtime_contract(config, layout, state)
        .await
        .context("target Replay runtime contract failed")?;

    let total_cases = state.cases.len();
    let mut failure_limit =
        super::failure_limit::ApiFailureLimit::new(config.max_failed_cases_per_api);
    case_progress::log_start(total_cases);
    for (position, case) in state.cases.clone().into_iter().enumerate() {
        if !failure_limit.should_execute(&case.group_id) {
            continue;
        }
        execute_case(
            config,
            layout,
            state,
            position,
            &case.case_id,
            &case.case_dir,
        )
        .await;
        case_progress::log_completion(position + 1, total_cases);
        if failure_limit.observe(&case.group_id, state.cases[position].status) {
            state.push_error(format!(
                "API {:?} stopped after reaching the configured failure limit of {} case(s)",
                case.group_id, config.max_failed_cases_per_api
            ));
        }
    }

    let intentionally_incomplete = state
        .cases
        .iter()
        .any(|case| case.status == CaseStatus::Pending);

    capture_target_process_outputs(config, layout, state).await?;
    stop_target_runtime(layout, state).await?;
    state.status = RunStatus::Finalizing;
    store::write_active(layout, state)?;
    let _ = active_progress::write(layout, state, ActiveProgressPhase::Finalizing);

    finalize_replay(state, intentionally_incomplete).await?;
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
        && state.apis.iter().all(|api| api.complete_pass)
        && state.errors.is_empty()
    {
        RunStatus::Successful
    } else {
        RunStatus::Failed
    };
    Ok(())
}

async fn capture_target_process_outputs(
    config: &ResolvedProjectConfig,
    layout: &RunLayout,
    state: &ActiveRunState,
) -> Result<()> {
    let configs = crate::process_output::configs_for_observation(
        &config.process_outputs,
        crate::process_output::ProcessOutputObservation::BeforeShutdown,
    );
    if configs.is_empty() {
        return Ok(());
    }
    let container = state
        .target_container_name
        .clone()
        .context("active E2E state has no target container name")?;
    let output_root = layout.active_dir.join("reports/process-outputs");
    tokio::task::spawn_blocking(move || {
        crate::process_output::capture_process_outputs(
            &container,
            &configs,
            crate::process_output::ProcessOutputCaptureSide::Target,
            &output_root,
        )
    })
    .await
    .context("target process output capture task failed")??;
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
        state.push_error(format!("case {case_id} disappeared from run state"));
        return;
    };
    state.cases[case_index].status = CaseStatus::Running;

    let begin = control(state, "begin", Some(case_id), false, false).await;
    if let Err(error) = begin {
        state.cases[case_index].status = CaseStatus::Incomplete;
        state.push_error(format!("case {case_id} begin failed: {error:#}"));
        let _ = active_progress::write(layout, state, ActiveProgressPhase::Replaying);
        return;
    }

    let actual_response = layout
        .active_dir
        .join("reports")
        .join(format!("actual-response-{:04}.json", position + 1));
    let case_view = RequestCaseView::prepare(case_dir, &layout.active_dir.join("tmp"));
    let assertion_command = match &case_view {
        Ok(case_view) => {
            super::http_driver::capture_case(
                &layout.target_root,
                config,
                &case_view.case_dir().join("request.json"),
                &actual_response,
            )
            .await
        }
        Err(error) => Err(anyhow::anyhow!(
            "failed to prepare replay request for case {case_id}: {error:#}"
        )),
    };
    let response_assertion =
        if config.runner_owned_response_assertions && assertion_command.as_ref().is_ok() {
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
                "traffic-e2e HTTP driver did not produce a usable actual response"
            ))
        } else {
            Err(anyhow::anyhow!(
                "legacy target-owned assertion has no response report"
            ))
        };
    state.cases[case_index].response_unavailable_reason = assertion_command
        .as_ref()
        .err()
        .map(super::http_driver::response_unavailable_reason);
    let mut assertion_passed = if config.runner_owned_response_assertions {
        response_assertion
            .as_ref()
            .is_ok_and(|report| report.passed)
    } else {
        assertion_command.as_ref().is_ok()
    };
    match response_assertion {
        Ok(report) => {
            let detail_report = layout
                .active_dir
                .join("reports")
                .join(format!("assertion-detail-{:04}.json", position + 1));
            if let Err(error) = store::write_json(&detail_report, &report) {
                assertion_passed = false;
                state.push_error(format!(
                    "case {case_id} assertion detail could not be persisted: {error:#}"
                ));
            } else {
                match std::fs::read(&detail_report) {
                    Ok(bytes) => {
                        state.cases[case_index].response_assertion =
                            Some(ResponseAssertionSummary {
                                passed: report.passed,
                                method: report.method.clone(),
                                path: report.path.clone(),
                                gateway_protocol: report.gateway_protocol,
                                body_codec: report.body_codec,
                                body_diagnosis: report.body_diagnosis.clone(),
                                difference_count: report.differences.len(),
                                difference_index: report
                                    .differences
                                    .iter()
                                    .take(MAX_RESPONSE_DIFFERENCE_INDEX)
                                    .cloned()
                                    .collect(),
                                representative_difference: report.differences.first().cloned(),
                                detail_report,
                                detail_fingerprint: crate::verification_progress::fingerprint(
                                    &bytes,
                                ),
                                request: PathBuf::from(report.request_path),
                                expected_response: PathBuf::from(report.expected_response_path),
                                actual_response: PathBuf::from(report.actual_response_path),
                                policy_path: report.policy_path,
                                policy_fingerprint: report.policy_fingerprint,
                            });
                    }
                    Err(error) => {
                        assertion_passed = false;
                        state.push_error(format!(
                            "case {case_id} assertion detail could not be fingerprinted: {error}"
                        ));
                    }
                }
            }
        }
        Err(error) if config.runner_owned_response_assertions => state.push_error(format!(
            "case {case_id} response assertion could not be evaluated: {error:#}"
        )),
        Err(_) => {}
    }
    state.cases[case_index].assertion_passed = Some(assertion_passed);
    if let Err(error) = assertion_command {
        state.push_error(format!("case {case_id} HTTP execution failed: {error:#}"));
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
        state.push_error(format!(
            "case {case_id} replay evidence is dirty: {error:#}"
        ));
    }
    let _ = active_progress::write(layout, state, ActiveProgressPhase::Replaying);
}

fn mark_unfinished_cases(state: &mut ActiveRunState) {
    for case in &mut state.cases {
        if case.status == CaseStatus::Running {
            case.status = CaseStatus::Incomplete;
        }
    }
}

fn finish_and_publish(
    _config: &ResolvedProjectConfig,
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
    update_index(index, state);
    store::publish_terminal(layout, state, index)?;
    write_replay_progress(
        &layout.progress_path,
        &layout.legacy_progress_path,
        index,
        state,
    )?;
    Ok(run_result(layout, state))
}
