use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result, bail, ensure};
use chrono::Utc;
use tokio::process::Child;

use super::E2eRunContext;
use super::active_progress::{self, ActiveProgressPhase};
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
use crate::policy::runtime::validate_replay_policy;
use crate::{
    primary_protocol::assertion::ResponseAssertionOptions,
    primary_protocol::assertion::ResponseAssertionRuntime,
};

mod engine_driver;
pub(super) mod timing_guard;

pub(super) struct CaseExecutionRuntime {
    pub(super) request_rules: Arc<crate::request_rules::RequestRuleRuntime>,
    pub(super) response_assertions: Option<ResponseAssertionRuntime>,
}

pub async fn run_e2e_round(context: E2eRunContext) -> Result<E2eRunResult> {
    let (config, layout) = resolve_for_execution(&context, false)?;
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

    if let Err(error) = run_active(
        &config,
        &layout,
        &inventory,
        &mut state,
        crate::replay::FinalizationScope::WholeSession,
    )
    .await
    {
        state.push_error(format!("{error:#}"));
        state.status = RunStatus::Interrupted;
        mark_unfinished_cases(&mut state);
        best_effort_stop(&config, &layout, &mut state).await;
    }
    if state.status != RunStatus::Interrupted
        && let Err(error) = super::batch_evidence::verify_actual_session(&state)
    {
        state.aggregate_clean = false;
        state.status = RunStatus::Failed;
        state.push_error(format!(
            "batch dependency reconciliation remains pending: {error:#}"
        ));
    }
    let result = finish_and_publish(&config, &layout, &mut index, &mut state)?;
    super::batch_publication::publish(&layout, &inventory)?;
    Ok(result)
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
    Ok(run_e2e_apis(context, &[api_key.to_string()], None)
        .await?
        .remove(0))
}

/// A single Replay/target session, with independently published method results.
pub async fn run_e2e_apis(
    context: E2eRunContext,
    api_keys: &[String],
    iteration: Option<&super::ReplayIteration>,
) -> Result<Vec<E2eApiRunResult>> {
    let api_key = api_keys
        .first()
        .context("focused Replay needs at least one API")?;
    ensure!(
        api_keys
            .iter()
            .collect::<std::collections::BTreeSet<_>>()
            .len()
            == api_keys.len(),
        "focused Replay API selectors must be unique"
    );
    let (config, base_layout) = resolve_for_execution(&context, iteration.is_some())?;
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
    let groups = api_keys
        .iter()
        .map(|api| {
            inventory
                .groups
                .iter()
                .find(|group| &group.group_id == api)
                .with_context(|| format!("prepared API group not found: {api}"))
                .cloned()
        })
        .collect::<Result<Vec<_>>>()?;
    let mut focused_inventory = CaseGroupInventory {
        case_source: inventory.case_source.clone(),
        source_revision: inventory.source_revision.clone(),
        case_inventory_id: inventory.case_inventory_id.clone(),
        groups,
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
            let mut interrupted_inventory = focused_inventory.clone();
            super::case_selection::restrict(&mut interrupted_inventory, &interrupted)?;
            summarize_apis_without_aggregate(&layout, &mut interrupted, &interrupted_inventory);
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
    let attempt = api_keys
        .iter()
        .map(|api| {
            let previous_path = global_layout
                .run_root
                .join("focused")
                .join(api_directory(api))
                .join("latest/state.yaml");
            if previous_path.is_file() {
                let previous: ActiveRunState = store::read_yaml(&previous_path)?;
                Ok(previous.sequence)
            } else {
                Ok(0)
            }
        })
        .collect::<Result<Vec<u64>>>()?
        .into_iter()
        .max()
        .unwrap_or(0)
        + 1;
    let selection =
        super::case_selection::prepare(&global_layout, &mut focused_inventory, iteration)?;
    let mut state = ActiveRunState::new(
        layout.run_key.clone(),
        attempt,
        &focused_inventory,
        &layout.active_dir,
    );
    state.case_selection = selection;
    state.replay_report = allocate_replay_report(
        &layout.case_source,
        &layout.run_key,
        &format!("focused-{}-{attempt:06}", api_directory(api_key)),
    )?;
    store::begin_active(&layout, &state)?;
    let _ = active_progress::write(&layout, &state, ActiveProgressPhase::Building);
    if let Err(error) = run_active(
        &config,
        &layout,
        &focused_inventory,
        &mut state,
        crate::replay::FinalizationScope::SelectedCases,
    )
    .await
    {
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
    api_keys
        .iter()
        .map(|api| {
            let (published, latest) =
                super::evidence::finalized_focused_evidence(context.clone(), api)?;
            let mut method_layout = layout.clone();
            method_layout.latest_dir = latest;
            Ok(api_result(&method_layout, &published, api, attempt))
        })
        .collect()
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
    super::focused_batch::publish(global_layout, focused_layout, state)?;
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

pub async fn recover_focused_e2e_api(context: E2eRunContext, api_key: &str) -> Result<bool> {
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
    let mut focused_inventory = CaseGroupInventory {
        case_source: inventory.case_source.clone(),
        source_revision: inventory.source_revision.clone(),
        case_inventory_id: inventory.case_inventory_id.clone(),
        groups: vec![group],
    };
    super::case_selection::restrict(&mut focused_inventory, &state)?;
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

pub(super) fn resolve_for_execution(
    context: &E2eRunContext,
    managed: bool,
) -> Result<(ResolvedProjectConfig, RunLayout)> {
    let (config, layout) = config::resolve_layout(
        &context.target_root,
        &context.case_source,
        context.run_key.as_deref(),
    )?;
    if managed {
        branch::require_work_branch(&layout.target_root, &config.pr_base)?;
    }
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
    finalization: crate::replay::FinalizationScope,
) -> Result<()> {
    let mut driver =
        engine_driver::ApplicationDriver::new(config, layout, inventory, state, finalization);
    crate::execute(&mut driver).await
}

pub(super) async fn execute_case(
    config: &ResolvedProjectConfig,
    layout: &RunLayout,
    state: &mut ActiveRunState,
    position: usize,
    case_id: &str,
    case_dir: &Path,
    runtime: &CaseExecutionRuntime,
) -> Result<()> {
    let case_index = position;
    if state
        .cases
        .get(case_index)
        .is_none_or(|case| case.case_id != case_id)
    {
        state.push_error(format!(
            "case {case_id} no longer matches run position {position}"
        ));
        return Ok(());
    }
    state.cases[case_index].status = CaseStatus::Running;

    let _ = active_progress::write(layout, state, ActiveProgressPhase::Replaying);
    let begin = control(state, "begin", Some(case_id), false, false).await;
    let target_stop_required = begin
        .as_ref()
        .is_ok_and(|response| response["target_stop_required"] == true);
    if let Err(error) = begin {
        state.cases[case_index].status = CaseStatus::Incomplete;
        state.push_error(format!("case {case_id} begin failed: {error:#}"));
        let _ = active_progress::write(layout, state, ActiveProgressPhase::Replaying);
        return Ok(());
    }
    let fast_case_deadline = (config.replay_stream_timing
        == Some(crate::replay::ReplayStreamTiming::Fast))
    .then(|| tokio::time::Instant::now() + crate::replay::FAST_CASE_TIMEOUT);

    if config.replay_loading.lazy_cases
        && let Some(next) = state.cases.get(position + 1)
    {
        // Optional read-ahead never prepares or changes the next case's inventory.
        let _ = control(state, "prefetch", Some(&next.case_id), false, false).await;
    }
    let actual_response = layout
        .active_dir
        .join("reports")
        .join(format!("actual-response-{:04}.json", position + 1));
    let case_view = RequestCaseView::prepare(case_dir);
    let assertion_command = match &case_view {
        Ok(case_view) => match control(state, "request_begin", Some(case_id), false, false).await {
            Err(error) => Err(error),
            Ok(_) => {
                super::primary_driver::capture_case(
                    config,
                    case_view.request_path(),
                    case_view.replay_request(),
                    &actual_response,
                    runtime.request_rules.clone(),
                    (&state.replay_session, case_id),
                    fast_case_deadline,
                )
                .await
            }
        },
        Err(error) => Err(anyhow::anyhow!(
            "failed to prepare replay request for case {case_id}: {error:#}"
        )),
    };
    let interaction_end = assertion_command
        .as_ref()
        .ok()
        .and_then(|bytes| serde_json::from_slice::<serde_json::Value>(bytes).ok())
        .and_then(|mut response| {
            use crate::interaction::model::{EndObservation, Protocol};
            let interaction = response.get_mut("interaction")?;
            let protocol =
                serde_json::from_value::<Protocol>(interaction.get_mut("protocol")?.take()).ok()?;
            let end = serde_json::from_value::<EndObservation>(interaction.get_mut("end")?.take())
                .ok()?;
            Some((protocol, end))
        });
    if interaction_end
        .as_ref()
        .is_some_and(|(protocol, end)| end.observes_replay_close_tail(*protocol))
    {
        control(state, "case_close_tail", Some(case_id), false, false).await?;
    }
    let execution_status =
        control(state, "case_execution_status", Some(case_id), false, false).await?;
    let response_times: crate::value_contract::time_copies::DeliveredTimeCopies = if runtime
        .response_assertions
        .as_ref()
        .is_some_and(|runtime| runtime.needs_time_copies())
        && execution_status["has_response_time_copies"].as_bool() != Some(false)
    {
        let snapshot = control(state, "response_time_copies", Some(case_id), false, false).await?;
        serde_json::from_value(snapshot["time_copies"].clone())
            .context("Replay did not publish bounded response time provenance")?
    } else {
        Default::default()
    };
    response_times.validate()?;
    super::execution_failure::record(
        &mut state.cases[case_index],
        execution_status,
        &assertion_command,
    );
    let mut response_assertion = if let Some(response_assertions) = &runtime.response_assertions {
        if let (Ok(actual_bytes), Ok(case_view)) = (&assertion_command, &case_view) {
            let expected_response = super::source_response::path(case_dir);
            std::fs::read(&expected_response)
                .with_context(|| {
                    format!(
                        "failed to read expected response {}",
                        expected_response.display()
                    )
                })
                .and_then(|expected_bytes| {
                    response_assertions.assert_recorded_response(
                        ResponseAssertionOptions {
                            case_id: case_id.to_string(),
                            request: case_view.request_path().to_path_buf(),
                            expected_response,
                            actual_response,
                            policy: config.replay_policy.clone(),
                        },
                        case_view.request(),
                        &expected_bytes,
                        actual_bytes,
                        &response_times,
                    )
                })
                .map_err(|error| {
                    anyhow::anyhow!("runner-owned response assertion failed: {error:#}")
                })
        } else {
            Err(anyhow::anyhow!(
                "traffic-e2e HTTP driver did not produce a usable actual response"
            ))
        }
    } else {
        Err(anyhow::anyhow!(
            "legacy target-owned assertion has no response report"
        ))
    };
    if let Ok(report) = &mut response_assertion
        && report.passed
        && let Err(error) = crate::value_contract::response_constraints::check_response_identities(
            &state.replay_session,
            case_id,
            &report.identity_pairs,
        )
        .await
    {
        report.passed = false;
        let mut difference =
            crate::primary_protocol::assertion::ResponseDifference::body_value_mismatch();
        difference.pointer = "$identity".into();
        report.differences.push(difference);
        state.push_error(format!(
            "case {case_id} identity relations failed: {error:#}"
        ));
    }
    state.cases[case_index].response_unavailable_reason = assertion_command
        .as_ref()
        .err()
        .map(super::primary_driver::response_unavailable_reason);
    // A different primary status (or no usable response) ends the normal
    // business path. Body-only differences retain the recorded async contract.
    let dependency_failed = interaction_end.as_ref().is_some_and(|(_, end)| {
        end.reason == crate::interaction::model::EndReason::DependencyFailure
    });
    let primary_failed = assertion_command.is_err()
        || dependency_failed
        || state.cases[case_index].execution_failure.is_some()
        || response_assertion.as_ref().is_ok_and(|report| {
            report.differences.iter().any(|difference| {
                difference.kind == crate::primary_protocol::assertion::ResponseDifferenceKind::StatusMismatch
            })
        });
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
            match super::active_artifact::write_json(&detail_report, &report) {
                Ok(bytes) => {
                    state.cases[case_index].response_assertion = Some(ResponseAssertionSummary {
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
                        detail_fingerprint: crate::verification_progress::fingerprint(&bytes),
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
                        "case {case_id} assertion detail could not be persisted: {error:#}"
                    ));
                }
            }
        }
        Err(error) if config.runner_owned_response_assertions => state.push_error(format!(
            "case {case_id} response assertion could not be evaluated: {error:#}"
        )),
        Err(_) => {}
    }
    state.cases[case_index].assertion_passed = Some(assertion_passed);
    if let Err(error) = &assertion_command {
        state.push_error(format!("case {case_id} HTTP execution failed: {error:#}"));
    }

    if primary_failed {
        control(state, "case_failed", Some(case_id), false, false).await?;
    }
    let ended = if target_stop_required {
        super::target_stop::finish(layout, state, case_index, case_id).await
    } else {
        control(state, "end", Some(case_id), true, false).await
    };
    let replay_clean = ended.is_ok();
    if !replay_clean
        && state.cases[case_index].execution_failure.is_none()
        && let Ok(execution_status) =
            control(state, "case_execution_status", Some(case_id), false, false).await
        && execution_status["failed"] == true
    {
        super::execution_failure::record(
            &mut state.cases[case_index],
            execution_status,
            &assertion_command,
        );
    }
    state.cases[case_index].replay_clean = Some(replay_clean);
    state.cases[case_index].status = if assertion_passed
        && replay_clean
        && state.cases[case_index].execution_failure.is_none()
    {
        CaseStatus::Passed
    } else {
        CaseStatus::Failed
    };
    if let Err(error) = ended {
        state.push_error(format!(
            "case {case_id} replay evidence is dirty: {error:#}"
        ));
        // Dirty evidence normally releases the case and permits the next input.
        // A cleanup failure retains ownership; stop this run through its existing
        // error cleanup instead of admitting another case into that live scope.
        let status = control(state, "status", None, false, false).await?;
        ensure!(
            status
                .pointer("/session/active_case_id")
                .is_some_and(serde_json::Value::is_null),
            "case {case_id} dependency cleanup retained active ownership: {error:#}"
        );
    }
    let _ = active_progress::write(layout, state, ActiveProgressPhase::Replaying);
    Ok(())
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

#[cfg(test)]
mod tests;
