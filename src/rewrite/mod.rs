mod action;
mod action_contract;
mod artifacts;
mod case_dependencies;
mod dependency_rule;
mod evidence;
mod fingerprint;
mod inventory;
mod issue;
mod model;
mod preparation;
mod recorder_capture;
mod recording;
mod recording_action;
mod recording_execution;
mod recording_input;
mod recovery;
mod repair;
mod revalidation;
mod route;
mod rule;
mod source_process_traffic;
mod status;
mod store;
mod target_quality;
#[cfg(test)]
mod test_support;
mod traffic_operation;
mod transition;
mod worker;

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, ensure};
use serde_json::Value;

pub use case_dependencies::{
    RewriteCapturePreview, RewriteCaseDependenciesOptions, RewriteCaseDependenciesReport,
    RewriteCaseDependencyProtocolDetail, RewriteCaseDependencyTarget,
    RewriteCaseDependencyTargetSummary, RewriteMemcachedExchangeDetail,
    RewriteMemcachedOperationDetail, RewriteRedisExchangeDetail, RewriteRedisOperationDetail,
    query as query_rewrite_case_dependencies,
};
pub use dependency_rule::{
    RewriteDependencyOwnership, RewriteDependencyRulePlanOptions, RewriteDependencyRulePlanReport,
    RewriteDependencyRuleSelector,
};
pub use model::{
    RewriteAction, RewriteActionEnvelope, RewriteApiInventoryDetails, RewriteApiInventoryView,
    RewriteApiProgress, RewriteApiStatus, RewriteApplicableRulePlanner, RewriteCommandSpec,
    RewriteDependencyRuleReport, RewriteEvidenceCommand, RewriteEvidenceReport,
    RewriteFocusedE2eExecution, RewriteFocusedE2eExecutionMode, RewriteInputRequiredReason,
    RewriteInventoryReport, RewriteIssue, RewriteIssueKind, RewriteIssueOwner, RewritePhase,
    RewriteRecorderCaptureReport, RewriteRecordingExecutionReport, RewriteRecordingInputCandidate,
    RewriteRecordingInputCandidateDisposition, RewriteRecordingInputDiagnosis,
    RewriteRecordingInputMode, RewriteRecordingInputRejections, RewriteRecordingKind,
    RewriteRecordingReason, RewriteRecordingStartReport, RewriteRecordingStartState,
    RewriteRecoveryReport, RewriteRepairAcceptanceKind, RewriteRouteReport, RewriteRuleReport,
    RewriteStatusReport, RewriteTrafficOperationKind, RewriteTrafficOperationView,
    RewriteWorkerBlockingReason, RewriteWorkerDispatchState, RewriteWorkerDispatchView,
    RewriteWorkflowView,
};
pub use recorder_capture::{
    RewriteRecorderCapturePlanOptions, apply_rewrite_recorder_capture,
    plan_rewrite_recorder_capture,
};
pub use recording::{
    RewriteRecordingRequestOptions, execute_rewrite_recording_worker, request_rewrite_recording,
    start_rewrite_recording,
};
pub use repair::resume_rewrite_replay_planning;
pub use revalidation::{
    RewriteRevalidationRequestOptions, RewriteRevalidationRequestReport,
    request as request_rewrite_revalidation,
};
pub use route::{RewriteRouteCause, RewriteRouteOptions, RewriteRouteOutcome};
pub use rule::RewriteRulePlanOptions;
pub use source_process_traffic::*;
pub use status::{inventory_rewrite, status_rewrite, status_rewrite_for_api};
pub use target_quality::{RewriteTargetQualityOptions, run as run_rewrite_target_quality};
pub use worker::{
    RewriteWorkerConfirmOptions, RewriteWorkerTransferOptions, confirm as confirm_rewrite_worker,
    transfer as transfer_rewrite_worker,
};

use model::{RewriteRecordingSettings, RewriteSliceState, RewriteState, STATE_VERSION};
use store::{RewriteLockState, RewriteStore};
#[cfg(test)]
pub(in crate::rewrite) use test_support::test_state;

use crate::e2e_run::{
    FocusedBackgroundReclassification, reclassify_focused_background_dependencies,
};
use crate::{
    ComparisonVerificationOptions, E2eRunContext, ManagedRecordingOperation, RecordingApi,
    run_e2e_api, update_comparison_progress, verify_comparison_recording,
};

#[derive(Debug, Clone)]
pub struct RewriteNextOptions {
    pub target_root: PathBuf,
    pub api: Option<RecordingApi>,
    pub source_route: Option<String>,
}

#[derive(Debug, Clone)]
pub struct RewriteContext {
    pub target_root: PathBuf,
}

pub async fn next_rewrite(options: RewriteNextOptions) -> Result<RewriteActionEnvelope> {
    let (target_root, project) = crate::e2e_run::resolve_project(&options.target_root)?;
    let store = RewriteStore::new(&target_root)?;
    let requested_api = options.api.as_ref().map(ToString::to_string);
    let Some(_lock) = store.try_lock()? else {
        if let Some(state) = store.load()? {
            match traffic_operation::state(&target_root)? {
                traffic_operation::TrafficOperationState::Live(active) => {
                    return Ok(action::wait_envelope(
                        &target_root,
                        &state,
                        requested_api,
                        &active,
                    ));
                }
                traffic_operation::TrafficOperationState::Stale(_) => {
                    return Ok(action::recovery_required(&target_root));
                }
                traffic_operation::TrafficOperationState::Absent => {}
            }
            return Ok(match store.lock_state()? {
                RewriteLockState::Live => {
                    action::coordinator_wait_envelope(&target_root, &state, requested_api)
                }
                RewriteLockState::Stale | RewriteLockState::Absent => {
                    action::recovery_required(&target_root)
                }
            });
        }
        return Ok(match store.lock_state()? {
            RewriteLockState::Live => {
                action::uninitialized_coordinator_wait_envelope(&target_root, requested_api)
            }
            RewriteLockState::Stale | RewriteLockState::Absent => {
                action::recovery_required(&target_root)
            }
        });
    };
    match traffic_operation::state(&target_root)? {
        traffic_operation::TrafficOperationState::Live(active) => {
            if let Some(state) = store.load()? {
                return Ok(action::wait_envelope(
                    &target_root,
                    &state,
                    requested_api,
                    &active,
                ));
            }
        }
        traffic_operation::TrafficOperationState::Stale(_) => {
            return Ok(action::recovery_required(&target_root));
        }
        traffic_operation::TrafficOperationState::Absent => {}
    }
    let mut state = match store.load()? {
        Some(mut state) => {
            let migrated = inventory::initialize_legacy(&mut state);
            let target_fingerprint = fingerprint::repository_fingerprint(&target_root)?;
            let invalidated =
                inventory::defer_completed_for_target_change(&mut state, &target_fingerprint)?;
            if recording::begin_pending_capture_refresh(&target_root, &mut state)? {
                store.save(&state)?;
            }
            let active_comparison_stale = state.phase == RewritePhase::ComparisonRecordingRequired
                && state.target_fingerprint.as_deref() != Some(target_fingerprint.as_str());
            if active_comparison_stale {
                state.phase = RewritePhase::ApiPending;
                state.e2e_current = false;
                state.comparison_current = false;
                state.comparison_run_id = None;
                state.comparison_rejection = None;
                state.active_issue = None;
                state.target_fingerprint = None;
                state.bump();
            }
            if let Some(requested_api) = options.api.as_ref()
                && requested_api.to_string() != state.api
                && matches!(
                    state.phase,
                    RewritePhase::RecordingRequired
                        | RewritePhase::ComparisonRecordingRequired
                        | RewritePhase::SystemRepairRequired
                )
            {
                if !state.api_inventory.is_empty() {
                    ensure!(
                        state
                            .api_inventory
                            .iter()
                            .any(|item| item.api == requested_api.to_string()),
                        "recorded API inventory does not contain {requested_api:?}"
                    );
                }
                if migrated || invalidated || active_comparison_stale {
                    store.save(&state)?;
                }
                return Ok(action::api_selection_wait_envelope(
                    &target_root,
                    &state,
                    requested_api.to_string(),
                ));
            }
            if state.phase == RewritePhase::SliceComplete {
                if migrated || invalidated || active_comparison_stale {
                    store.save(&state)?;
                }
                let scoped = inventory::scoped(&state, options.api.as_ref())?;
                return action::for_status(&target_root, &scoped);
            }
            if state.phase == RewritePhase::ImplementationRequired
                && !worker::current_is_confirmed(&state)
            {
                if migrated || invalidated || active_comparison_stale {
                    store.save(&state)?;
                }
                return Ok(worker::gate_envelope(
                    &target_root,
                    &state,
                    options
                        .api
                        .as_ref()
                        .map(ToString::to_string)
                        .filter(|requested| requested != &state.api),
                ));
            }
            let activated = inventory::activate_requested(&mut state, options.api.as_ref())?;
            let bound = inventory::bind_options(
                &mut state,
                options.api.as_ref(),
                options.source_route.as_deref(),
            )?;
            if migrated || invalidated || active_comparison_stale || activated || bound {
                store.save(&state)?;
            }
            state
        }
        None => {
            let (api, source_route, recording_apis) = match options.api {
                Some(api) => {
                    let source_route = match options.source_route {
                        Some(route) => route,
                        None if !api.is_dynamic() => api.path_pattern().to_string(),
                        None => return Ok(action::source_route_required(&target_root, &api)),
                    };
                    (api.to_string(), source_route, vec![api.to_string()])
                }
                None => {
                    ensure!(
                        options.source_route.is_none(),
                        "--source-route requires --api when starting a workflow"
                    );
                    (String::new(), String::new(), Vec::new())
                }
            };
            if !source_route.is_empty() {
                validate_single_line("source route", &source_route)?;
            }
            let recording_run_id =
                artifacts::allocate_run_id(&target_root, ManagedRecordingOperation::Record)?;
            let mut state = RewriteState {
                version: STATE_VERSION,
                revision: 1,
                workflow_id: format!("rewrite-{}", uuid::Uuid::new_v4().simple()),
                recording_apis,
                api_inventory: Vec::new(),
                current_api_index: None,
                parked_slices: std::collections::BTreeMap::new(),
                worker_bindings: std::collections::BTreeMap::new(),
                target_quality_fingerprint: None,
                recording_run_id,
                recording_rejection: None,
                recording_settings: RewriteRecordingSettings::default(),
                recording_request_reason: None,
                recording_input_case_source: None,
                recording_input_diagnosis: None,
                recording_refresh: None,
                active_slice: RewriteSliceState {
                    phase: RewritePhase::RecordingRequired,
                    api,
                    source_route,
                    comparison_run_id: None,
                    comparison_rejection: None,
                    case_source: None,
                    case_inventory_id: None,
                    source_revision: None,
                    group_id: None,
                    target_fingerprint: None,
                    attempts: Vec::new(),
                    attempt_delta: None,
                    active_issue: None,
                    rule_plan: None,
                    dependency_rule_plan: None,
                    recorder_capture_plan: None,
                    route: None,
                    e2e_current: false,
                    comparison_current: false,
                },
            };
            let excluded_run_id = state.recording_run_id.clone();
            recording_input::bind(&target_root, &mut state, Some(&excluded_run_id))?;
            store.save(&state)?;
            state
        }
    };

    if repair::initialize_legacy_acceptance(&target_root, &mut state)? {
        store.save(&state)?;
    }

    if preparation::restore_legacy_background_rule_recording_request(&target_root, &mut state)? {
        store.save(&state)?;
    }

    if preparation::restore_stale_dependency_finalize_result(&target_root, &mut state)? {
        store.save(&state)?;
    }

    if state.phase == RewritePhase::RecordingRequired
        && recording::standard_recording_input_source(&state).is_none()
        && !recording::requires_external_live_traffic(&state)
    {
        let excluded_run_id = state.recording_run_id.clone();
        if recording_input::bind(&target_root, &mut state, Some(&excluded_run_id))? {
            state.bump();
            store.save(&state)?;
        }
    }

    match state.phase {
        RewritePhase::RecordingRequired => {
            match artifacts::standard_recording_publication(&target_root, &state.recording_run_id)?
            {
                artifacts::RecordingPublication::Missing => {
                    return Ok(action::for_state(&target_root, &state));
                }
                artifacts::RecordingPublication::Running => {
                    return action::for_status(&target_root, &state);
                }
                artifacts::RecordingPublication::Finalized => {}
            }
            let apis = match artifacts::validate_standard_recording(&target_root, &state)
                .and_then(|()| artifacts::standard_recording_apis(&target_root, &state))
            {
                Ok(apis) => apis,
                Err(error) => {
                    state.recording_rejection = Some(artifacts::recording_rejection(&error));
                    state.recording_run_id = artifacts::allocate_run_id(
                        &target_root,
                        ManagedRecordingOperation::Record,
                    )?;
                    if let Some(refresh) = state.recording_refresh.as_mut() {
                        refresh.recording_run_id = Some(state.recording_run_id.clone());
                    }
                    state.bump();
                    store.save(&state)?;
                    return Ok(action::for_state(&target_root, &state));
                }
            };
            state.recording_rejection = None;
            crate::verification_progress::begin_epoch(&target_root, &state.recording_run_id)?;
            inventory::install(&mut state, apis)?;
            state.recording_refresh = None;
            if inventory::current_requires_source_route(&state) {
                state.phase = RewritePhase::ApiPending;
                state.bump();
                store.save(&state)?;
                return Ok(action::for_state(&target_root, &state));
            }
            preparation::prepare_recording(&target_root, &mut state)?;
            store.save(&state)?;
            let _traffic = claim_traffic_operation(
                &target_root,
                &state,
                traffic_operation::TrafficOperationKind::Replay,
            )?;
            run_and_transition(&target_root, &mut state).await?;
            store.save(&state)?;
            Ok(action::for_state(&target_root, &state))
        }
        RewritePhase::ImplementationRequired => {
            let current = fingerprint::repository_fingerprint(&target_root)?;
            if state.target_fingerprint.as_deref() == Some(current.as_str()) {
                return Ok(action::for_state(&target_root, &state));
            }
            if let Some(required) = target_quality::required_action(
                &target_root,
                &state,
                &current,
                &project.target_quality_gates,
            )? {
                return Ok(action::envelope(&target_root, &state, required));
            }
            state.e2e_current = false;
            state.comparison_current = false;
            let _traffic = claim_traffic_operation(
                &target_root,
                &state,
                traffic_operation::TrafficOperationKind::Replay,
            )?;
            run_and_transition(&target_root, &mut state).await?;
            store.save(&state)?;
            Ok(action::for_state(&target_root, &state))
        }
        RewritePhase::ApiPending => {
            if inventory::current_requires_source_route(&state) {
                return Ok(action::for_state(&target_root, &state));
            }
            preparation::prepare_recording(&target_root, &mut state)?;
            store.save(&state)?;
            let _traffic = claim_traffic_operation(
                &target_root,
                &state,
                traffic_operation::TrafficOperationKind::Replay,
            )?;
            run_and_transition(&target_root, &mut state).await?;
            store.save(&state)?;
            Ok(action::for_state(&target_root, &state))
        }
        RewritePhase::ComparisonRecordingRequired => {
            let run_id = state
                .comparison_run_id
                .as_deref()
                .context("comparison phase has no allocated run id")?;
            match artifacts::comparison_recording_publication(&target_root, run_id)? {
                artifacts::RecordingPublication::Missing => {
                    return Ok(action::for_state(&target_root, &state));
                }
                artifacts::RecordingPublication::Running => {
                    return action::for_status(&target_root, &state);
                }
                artifacts::RecordingPublication::Finalized => {}
            }
            if let Err(error) = artifacts::validate_comparison_recording(&target_root, &state) {
                state.comparison_rejection = Some(artifacts::comparison_rejection(&error));
                state.comparison_run_id = Some(artifacts::allocate_run_id(
                    &target_root,
                    ManagedRecordingOperation::RecordComparison,
                )?);
                state.bump();
                store.save(&state)?;
                return Ok(action::for_state(&target_root, &state));
            }
            state.comparison_rejection = None;
            let _traffic = claim_traffic_operation(
                &target_root,
                &state,
                traffic_operation::TrafficOperationKind::Comparison,
            )?;
            compare_and_transition(&target_root, &mut state)?;
            store.save(&state)?;
            Ok(action::for_state(&target_root, &state))
        }
        RewritePhase::AwaitingRecordingRefresh
        | RewritePhase::SystemRepairRequired
        | RewritePhase::SliceComplete => Ok(action::for_state(&target_root, &state)),
    }
}

fn claim_traffic_operation(
    target_root: &Path,
    state: &RewriteState,
    kind: traffic_operation::TrafficOperationKind,
) -> Result<traffic_operation::TrafficOperationGuard> {
    let operation_id = format!(
        "traffic-{}",
        fingerprint::id(&[
            &state.workflow_id,
            &state.api,
            match kind {
                traffic_operation::TrafficOperationKind::Recording => "recording",
                traffic_operation::TrafficOperationKind::Replay => "replay",
                traffic_operation::TrafficOperationKind::Comparison => "comparison",
            },
            &state.revision.to_string(),
        ])
        .trim_start_matches("fnv1a64:")
    );
    match traffic_operation::claim_current(
        target_root,
        operation_id,
        kind,
        (!state.api.is_empty()).then(|| state.api.clone()),
    )? {
        traffic_operation::TrafficOperationClaim::Acquired(guard) => Ok(guard),
        traffic_operation::TrafficOperationClaim::Busy(active) => anyhow::bail!(
            "traffic runtime is owned by {:?} operation {}; inspect `backend-rewrite status`",
            active.kind,
            active.operation_id
        ),
        traffic_operation::TrafficOperationClaim::Stale(active) => anyhow::bail!(
            "traffic runtime has stale {:?} operation {}; execute `backend-rewrite recover`",
            active.kind,
            active.operation_id
        ),
    }
}

pub fn query_rewrite_evidence(
    context: RewriteContext,
    query_id: &str,
) -> Result<RewriteEvidenceReport> {
    let (target_root, _) = crate::e2e_run::resolve_project(&context.target_root)?;
    let state = RewriteStore::new(&target_root)?
        .load()?
        .context("rewrite workflow has not been initialized")?;
    let api = inventory::api_for_evidence_query(&target_root, &state, query_id)
        .context("evidence query is stale or belongs to no concurrent API work item")?;
    worker::ensure_api_confirmed(&state, &api, "querying evidence")?;
    let scoped = inventory::scoped(&state, Some(&api.parse::<RecordingApi>()?))?;
    evidence::query(&target_root, &scoped, query_id)
}

pub fn plan_rewrite_rule(
    context: RewriteContext,
    options: RewriteRulePlanOptions,
) -> Result<RewriteRuleReport> {
    let (target_root, _) = crate::e2e_run::resolve_project(&context.target_root)?;
    let store = RewriteStore::new(&target_root)?;
    let _lock = store.lock()?;
    let mut state = store
        .load()?
        .context("rewrite workflow has not been initialized")?;
    let api = inventory::api_for_evidence_id(&target_root, &state, &options.evidence_id)
        .context("rule evidence is stale or belongs to no concurrent API work item")?;
    worker::ensure_api_confirmed(&state, &api, "planning a response rule")?;
    let report = inventory::with_slice_mut(&mut state, &api, |state| {
        rule::plan(&target_root, state, options)
    })?;
    store.save(&state)?;
    Ok(report)
}

pub fn apply_rewrite_rule(context: RewriteContext, plan_id: &str) -> Result<RewriteRuleReport> {
    let (target_root, _) = crate::e2e_run::resolve_project(&context.target_root)?;
    let store = RewriteStore::new(&target_root)?;
    let _lock = store.lock()?;
    let mut state = store
        .load()?
        .context("rewrite workflow has not been initialized")?;
    let api = inventory::api_for_rule_plan(&state, plan_id)
        .context("rule plan is stale or belongs to no concurrent API work item")?;
    let report = inventory::with_slice_mut(&mut state, &api, |state| {
        let report = rule::apply(&target_root, state, plan_id)?;
        state.target_fingerprint = None;
        Ok(report)
    })?;
    store.save(&state)?;
    Ok(report)
}

pub fn plan_rewrite_dependency_rule(
    context: RewriteContext,
    options: RewriteDependencyRulePlanOptions,
) -> Result<RewriteDependencyRulePlanReport> {
    let (target_root, _) = crate::e2e_run::resolve_project(&context.target_root)?;
    let store = RewriteStore::new(&target_root)?;
    let _lock = store.lock()?;
    let mut state = store
        .load()?
        .context("rewrite workflow has not been initialized")?;
    let api = inventory::api_for_evidence_id(&target_root, &state, &options.evidence_id)
        .context("dependency-rule evidence is stale or belongs to no concurrent API work item")?;
    worker::ensure_api_confirmed(&state, &api, "planning a dependency rule")?;
    let report = inventory::with_slice_mut(&mut state, &api, |state| {
        dependency_rule::plan(&target_root, state, options)
    })?;
    store.save(&state)?;
    Ok(report)
}

pub fn apply_rewrite_dependency_rule(
    context: RewriteContext,
    plan_id: &str,
) -> Result<RewriteDependencyRuleReport> {
    let (target_root, _) = crate::e2e_run::resolve_project(&context.target_root)?;
    let store = RewriteStore::new(&target_root)?;
    let _lock = store.lock()?;
    let mut state = store
        .load()?
        .context("rewrite workflow has not been initialized")?;
    let owner_api = inventory::api_for_dependency_rule_plan(&state, plan_id)
        .context("dependency-rule plan is stale or belongs to no concurrent API work item")?;
    let (mut report, cache_snapshot_refresh) =
        inventory::with_slice_mut(&mut state, &owner_api, |state| {
            let cache_snapshot_refresh =
                dependency_rule::pending_cache_snapshot_refresh(state, plan_id)?;
            let mut report = dependency_rule::apply(&target_root, state, plan_id)?;
            if let Some(applied) = cache_snapshot_refresh {
                dependency_rule::schedule_cache_snapshot_refresh(&target_root, state, applied)?;
                report.next_command = action::next_command_for_api(&target_root, &state.api);
                return Ok((report, true));
            }
            let case_source = state
                .case_source
                .clone()
                .context("rewrite workflow has no case source to reclassify")?;
            let api = state
                .group_id
                .clone()
                .context("rewrite workflow has no focused API to reclassify")?;
            let reclassification: FocusedBackgroundReclassification =
                reclassify_focused_background_dependencies(
                    E2eRunContext {
                        target_root: target_root.clone(),
                        case_source,
                        run_key: None,
                    },
                    &api,
                )?;
            transition::from_e2e_result(
                &target_root,
                state,
                &reclassification.result,
                transition::AttemptTransition::ReclassifyCurrent,
            )?;
            report.evidence_reclassification = Some(serde_json::to_value(&reclassification)?);
            report.next_command = action::next_command_for_api(&target_root, &state.api);
            Ok((report, false))
        })?;
    if cache_snapshot_refresh {
        let runnable = inventory::mark_awaiting_recording_refresh(&mut state, &owner_api)?;
        if !runnable {
            recording::begin_pending_capture_refresh(&target_root, &mut state)?;
        }
        report.next_command = action::next_command_for_api(&target_root, &owner_api);
    }
    store.save(&state)?;
    Ok(report)
}

pub use route::route as route_rewrite;

pub fn verify_rewrite_repair(
    context: RewriteContext,
    repair_id: &str,
) -> Result<RewriteActionEnvelope> {
    let (target_root, _) = crate::e2e_run::resolve_project(&context.target_root)?;
    let store = RewriteStore::new(&target_root)?;
    let _lock = store.lock()?;
    let mut state = store
        .load()?
        .context("rewrite workflow has not been initialized")?;
    let api = inventory::api_for_repair(&state, repair_id)
        .context("repair acceptance is stale or belongs to no concurrent API work item")?;
    if state.api != api {
        let requested_api = api.parse::<RecordingApi>()?;
        inventory::activate_requested(&mut state, Some(&requested_api))?;
    }
    let report = repair::verify(&target_root, &mut state, repair_id)?;
    store.save(&state)?;
    Ok(report)
}

pub async fn recover_rewrite(context: RewriteContext) -> Result<RewriteRecoveryReport> {
    recovery::recover(context).await
}

async fn run_and_transition(target_root: &Path, state: &mut RewriteState) -> Result<()> {
    let replay_target_fingerprint = fingerprint::repository_fingerprint(target_root)?;
    let case_source = state
        .case_source
        .clone()
        .context("rewrite workflow has no case source")?;
    let api = state
        .group_id
        .clone()
        .context("rewrite workflow has no prepared API group")?;
    let result = run_e2e_api(
        E2eRunContext {
            target_root: target_root.to_path_buf(),
            case_source,
            run_key: None,
        },
        &api,
    )
    .await?;
    let current_target_fingerprint = fingerprint::repository_fingerprint(target_root)?;
    if current_target_fingerprint != replay_target_fingerprint {
        state.phase = RewritePhase::ApiPending;
        state.target_fingerprint = None;
        state.active_issue = None;
        state.e2e_current = false;
        state.comparison_current = false;
        state.bump();
        return Ok(());
    }
    transition::from_e2e_result(
        target_root,
        state,
        &result,
        transition::AttemptTransition::Append,
    )
}

fn compare_and_transition(target_root: &Path, state: &mut RewriteState) -> Result<()> {
    let run_id = state
        .comparison_run_id
        .as_deref()
        .context("comparison phase has no run id")?;
    let case_source = artifacts::comparison_run(target_root, run_id);
    let policy = target_root.join(".traffic-e2e/verification.yaml");
    let report = verify_comparison_recording(ComparisonVerificationOptions {
        report: case_source.join("comparison-report.json"),
        case_source,
        policy: policy.clone(),
    })?;
    update_comparison_progress(
        &report,
        &policy
            .parent()
            .context("verification policy has no parent")?
            .join("comparison-progress.yaml"),
    )?;
    state.comparison_current = report.passed;
    if report.passed {
        state.active_issue = None;
        if !inventory::complete_current_and_advance(state)?
            && !recording::begin_pending_capture_refresh(target_root, state)?
        {
            state.phase = RewritePhase::SliceComplete;
        }
    } else {
        let observation = report
            .representative_difference
            .as_ref()
            .map(serde_json::to_value)
            .transpose()?;
        let pointer = observation
            .as_ref()
            .and_then(|value| value.get("pointer"))
            .and_then(Value::as_str)
            .unwrap_or("<comparison>");
        let id = issue::id(&state.api, "comparison", pointer);
        state.active_issue = Some(RewriteIssue {
            id,
            kind: RewriteIssueKind::Comparison,
            owner: RewriteIssueOwner::TargetCode,
            summary: format!(
                "comparison has {} candidate difference(s) and {} inconclusive case(s)",
                report.counts.failed, report.counts.inconclusive
            ),
            pointer_pattern: (pointer != "<comparison>")
                .then(|| crate::e2e_run::response_pointer_pattern(pointer)),
            representative: None,
            response_diagnosis: None,
            possible_causes: vec![
                "target_behavior".to_string(),
                "intentional_source_nondeterminism".to_string(),
                "source_changed_during_comparison".to_string(),
                "verification_policy_gap".to_string(),
            ],
            observed_target_fingerprint: fingerprint::repository_fingerprint(target_root)?,
            attempt: state.attempts.last().map_or(0, |attempt| attempt.attempt),
            comparison_observation: observation,
        });
        state.target_fingerprint = Some(fingerprint::repository_fingerprint(target_root)?);
        state.phase = RewritePhase::ImplementationRequired;
    }
    state.bump();
    Ok(())
}

fn validate_single_line(label: &str, value: &str) -> Result<()> {
    ensure!(
        value == value.trim() && !value.is_empty() && !value.contains(['\r', '\n']),
        "{label} must be a non-empty single line"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::process::Command;
    #[test]
    fn pointer_patterns_replace_only_array_indices() {
        assert_eq!(
            crate::e2e_run::response_pointer_pattern("/users/17/id"),
            "/users/*/id"
        );
        assert_eq!(
            crate::e2e_run::response_pointer_pattern("/v2/created_at"),
            "/v2/created_at"
        );
    }

    #[test]
    fn action_commands_are_argv_and_do_not_contain_secret_values() {
        let state = test_state();
        let target = Path::new("/target");
        let value = serde_json::to_value(action::for_state(target, &state)).unwrap();
        assert_eq!(value.get("schema_version"), Some(&serde_json::json!(16)));
        assert!(value.get("latest_focused_e2e").is_none());
        assert_eq!(
            value.pointer("/action/commands/execute/cwd"),
            Some(&serde_json::json!(target))
        );
        assert_eq!(
            value.pointer("/action/commands/execute/required_env_names/0"),
            Some(&Value::String("TRAFFIC_E2E_ENCRYPTION_KEY_B64".to_string()))
        );
        assert_eq!(
            value.pointer("/action/commands/execute/argv/0"),
            Some(&Value::String("backend-rewrite".to_string()))
        );
        assert_eq!(
            value.pointer("/action/commands/execute/argv/1"),
            Some(&serde_json::json!("--target-root"))
        );
        assert_eq!(
            value.pointer("/action/commands/execute/argv/2"),
            Some(&serde_json::json!("/target"))
        );
        assert_eq!(
            value.pointer("/action/commands/execute/argv/4"),
            Some(&serde_json::json!("execute"))
        );
        assert_eq!(
            value
                .pointer("/action/commands/execute/argv")
                .unwrap()
                .as_array()
                .unwrap()
                .len(),
            6
        );
        assert!(!value.to_string().contains("encryption-key-value"));
    }

    #[test]
    fn rejected_recording_action_allocates_a_replacement_without_exposing_paths() {
        let mut state = test_state();
        state.recording_rejection = Some(artifacts::recording_rejection(&anyhow::anyhow!(
            "standard recording published no cases"
        )));
        state.recording_run_id = "20260802000001".to_string();

        let target = Path::new("/target");
        let value = serde_json::to_value(action::for_state(target, &state)).unwrap();
        assert_eq!(
            value.pointer("/action/commands/execute/argv/5"),
            Some(&serde_json::json!(recording_action::recording_action_id(
                &state, false
            )))
        );
        let summary = value.pointer("/action/summary").unwrap().as_str().unwrap();
        assert!(summary.contains("published no cases"));
        assert!(!summary.contains(".traffic-e2e"));
    }

    #[test]
    fn status_mismatch_causes_do_not_suggest_collection_or_dynamic_rules() {
        let causes =
            issue::response_possible_causes(Some(crate::ResponseDifferenceKind::StatusMismatch));
        assert!(causes.iter().any(|cause| cause.contains("authentication")));
        assert!(!causes.iter().any(|cause| cause.contains("collection")));
        assert!(!causes.iter().any(|cause| cause.contains("nondeterminism")));
    }

    #[test]
    fn incomplete_work_never_allows_terminal_output() {
        let state = test_state();
        assert!(!action::for_state(Path::new("/target"), &state).terminal_allowed);
    }

    #[test]
    fn clean_reclassification_advances_without_replacing_standard_recording() {
        let target = tempfile::tempdir().unwrap();
        fs::write(
            target.path().join("Cargo.toml"),
            "[package]\nname='target'\n",
        )
        .unwrap();
        git_ok(target.path(), &["init"]);
        git_ok(target.path(), &["config", "user.email", "test@example.com"]);
        git_ok(target.path(), &["config", "user.name", "Traffic E2E Test"]);
        git_ok(target.path(), &["add", "."]);
        git_ok(target.path(), &["commit", "-m", "baseline"]);

        let counts = crate::E2eDiagnosisCounts {
            selected: 10,
            executed: 10,
            response_passed: 10,
            response_nonpassing: 0,
            response_incomplete: 0,
        };
        let mut state = test_state();
        state.phase = RewritePhase::ImplementationRequired;
        state.recording_run_id = "20260803023812".to_string();
        state.case_source = Some(PathBuf::from("recording-cases"));
        state.group_id = Some("GET /api".to_string());
        state.attempts.push(model::RewriteAttemptSummary {
            attempt: 3,
            passed: false,
            gates: crate::E2eVerificationGates {
                responses: crate::E2eResponseGate::Passed,
                replay: crate::E2eReplayGate::Complete,
                dependencies: crate::E2eDependencyGate::Dirty,
            },
            counts: counts.clone(),
        });
        let result = crate::E2eApiRunResult {
            run_key: "20260803023812".to_string(),
            api: "GET /api".to_string(),
            attempt: 3,
            status: "successful".to_string(),
            passed: true,
            gates: crate::E2eVerificationGates {
                responses: crate::E2eResponseGate::Passed,
                replay: crate::E2eReplayGate::Complete,
                dependencies: crate::E2eDependencyGate::Clean,
            },
            diagnosis: crate::E2eDiagnosis {
                counts,
                response_differences: crate::E2eResponseDifferenceDiagnosis {
                    total_differences: 0,
                    indexed_differences: 0,
                    omitted_differences: 0,
                    failure_clusters: Vec::new(),
                    omitted_failure_clusters: 0,
                },
                representative: None,
                lifecycle_errors: Vec::new(),
            },
            progress: PathBuf::from("replay-progress.yaml"),
        };

        transition::from_e2e_result(
            target.path(),
            &mut state,
            &result,
            transition::AttemptTransition::ReclassifyCurrent,
        )
        .unwrap();

        assert_eq!(state.phase, RewritePhase::ComparisonRecordingRequired);
        assert_eq!(state.recording_run_id, "20260803023812");
        assert_eq!(state.recording_request_reason, None);
        assert_eq!(state.attempts.len(), 1);
        assert!(state.attempts[0].passed);
        assert!(state.comparison_run_id.is_some());
    }

    #[test]
    fn stale_workflow_returns_only_a_public_recovery_command() {
        let target = Path::new("/target");
        let value = serde_json::to_value(action::recovery_required(target)).unwrap();
        assert_eq!(
            value.pointer("/action/commands/recover/argv"),
            Some(&serde_json::json!([
                "backend-rewrite",
                "--target-root",
                "/target",
                "recover"
            ]))
        );
        assert_eq!(
            value.pointer("/action/commands/recover/cwd"),
            Some(&serde_json::json!(target))
        );
        assert!(!value.to_string().contains(".traffic-e2e/local/runtime"));
        assert!(value.pointer("/action/commands/advance").is_none());
    }

    fn git_ok(repository: &Path, args: &[&str]) {
        let status = Command::new("git")
            .arg("-C")
            .arg(repository)
            .args(args)
            .status()
            .unwrap();
        assert!(status.success(), "git command failed: {args:?}");
    }
}
