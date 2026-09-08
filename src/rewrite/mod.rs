mod advance;
use advance::advance_rewrite;
mod action;
mod action_contract;
mod artifacts;
mod background_reclassification;
mod case_dependencies;
mod case_patterns;
mod comparison_issue;
mod configuration_commit;
mod coordination;
mod execution;
pub use configuration_commit::next_rewrite;
pub use coordination::RewriteCoordinationDetails;
pub use execution::{
    execute as execute_rewrite_operation, retry as retry_rewrite_operation,
    start_next as start_rewrite_next, start_quality as start_rewrite_target_quality,
};
pub use worker::model::{
    RewriteWorkerActivity, RewriteWorkerCoverageState, RewriteWorkerInventoryItem,
};
pub use worker::runtime::{RewriteWorkerReportOptions, report as report_rewrite_worker};
mod dependency_rule;
mod evidence;
mod evidence_model;
pub use evidence::{query_rewrite_evidence, query_rewrite_evidence_for_scope};
mod fingerprint;
mod inventory;
mod ip_capture;
mod issue;
mod model;
mod preparation;
mod process_output_model;
mod process_outputs;
mod progress_publication;
mod recorder_capture;
pub use ip_capture::RewriteIpCaptureReport;
#[cfg(test)]
mod comparison_requirement_tests;
mod jwt_rule;
mod recording;
mod recording_action;
mod recording_execution;
mod recording_input;
mod recovery;
mod repair;
mod response_url_evidence;
mod revalidation;
mod route;
mod rule;
pub use jwt_rule::JwtRulePlanOptions;
mod scheduling;
mod source_process_traffic;
mod status;
mod waiting;
pub use waiting::{RewriteWaitOptions, wait as wait_rewrite};
mod review;
mod source_diff;
mod store;
mod target_quality;
pub use review::{
    RewriteReviewOptions, RewriteReviewReport, check as check_rewrite_review,
    rework as rework_rewrite_review, show as show_rewrite_review,
};
#[cfg(test)]
mod test_support;
#[cfg(test)]
mod tests;
mod traffic_operation;
mod transition;
mod worker;

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, ensure};
pub use case_dependencies::{
    RewriteCapturePreview, RewriteCaseDependenciesOptions, RewriteCaseDependenciesReport,
    RewriteCaseDependencyProtocolDetail, RewriteCaseDependencyTarget,
    RewriteCaseDependencyTargetSummary, RewriteMemcachedExchangeDetail,
    RewriteMemcachedOperationDetail, RewriteMysqlExchangeDetail, RewriteMysqlOperationDetail,
    RewriteMysqlParameterDetail, RewriteRedisExchangeDetail, RewriteRedisOperationDetail,
    query as query_rewrite_case_dependencies,
};
pub use case_patterns::{RewriteCasePatternApplyOptions, apply as apply_rewrite_case_patterns};
pub use dependency_rule::{
    RewriteDependencyOwnership, RewriteDependencyPayloadRulePlanOptions,
    RewriteDependencyPayloadRulePlanReport, RewriteDependencyRulePlanOptions,
    RewriteDependencyRulePlanReport, RewriteDependencyRuleSelector,
};
pub use evidence_model::{
    RewriteApplicableRulePlanner, RewriteEvidenceContext, RewriteEvidenceReport, RewriteRuleHint,
};
pub use model::{
    RewriteAction, RewriteActionEnvelope, RewriteApiInventoryDetails, RewriteApiInventoryView,
    RewriteApiProgress, RewriteApiStatus, RewriteCommandSpec, RewriteDependencyRuleReport,
    RewriteEvidenceCommand, RewriteFocusedE2eExecution, RewriteFocusedE2eExecutionMode,
    RewriteHttpResponseCaptureReport, RewriteInputRequiredReason, RewriteInventoryReport,
    RewriteIssue, RewriteIssueKind, RewriteIssueOwner, RewritePhase, RewriteRecorderCaptureReport,
    RewriteRecordingExecutionReport, RewriteRecordingInputCandidate,
    RewriteRecordingInputCandidateDisposition, RewriteRecordingInputDiagnosis,
    RewriteRecordingInputMode, RewriteRecordingInputRejections, RewriteRecordingKind,
    RewriteRecordingReason, RewriteRecordingStartReport, RewriteRecordingStartState,
    RewriteRecoveryReport, RewriteRepairAcceptanceKind, RewriteRouteReport, RewriteRuleReport,
    RewriteStatusReport, RewriteTrafficOperationKind, RewriteTrafficOperationView,
    RewriteWorkerBlockingReason, RewriteWorkerDispatchState, RewriteWorkerDispatchView,
    RewriteWorkflowView,
};
pub use process_output_model::{
    RewriteProcessOutputInventoryDetails, RewriteProcessOutputInventoryView,
    RewriteProcessOutputProgress, RewriteProcessOutputStatus, RewriteWorkScope,
};
pub use recorder_capture::{
    RewriteHttpResponseCapturePlanOptions, RewriteRecorderCapturePlanOptions,
    apply_rewrite_recorder_capture, plan_rewrite_http_response_capture,
    plan_rewrite_recorder_capture,
};
pub use recording::{
    RewriteRecordingRequestOptions, execute_rewrite_recording_worker, request_rewrite_recording,
    start_rewrite_recording,
};
pub use repair::{
    RewriteRepairCancelOptions, RewriteReplayRetryOptions, cancel_misrouted_rewrite_repair,
    resume_rewrite_replay_planning, retry_rewrite_replay_after_out_of_band_run,
};
pub use revalidation::{
    RewriteRevalidationRequestOptions, RewriteRevalidationRequestReport,
    request as request_rewrite_revalidation,
};
pub use route::{RewriteRouteCause, RewriteRouteOptions, RewriteRouteOutcome};
pub use rule::RewriteRulePlanOptions;
pub use source_process_traffic::*;
pub use status::{
    inventory_rewrite, status_rewrite, status_rewrite_for_api, status_rewrite_for_process_output,
};
pub use target_quality::{RewriteTargetQualityOptions, run as run_rewrite_target_quality};
pub use worker::{
    RewriteWorkerConfirmOptions, RewriteWorkerTransferOptions, confirm as confirm_rewrite_worker,
    transfer as transfer_rewrite_worker,
};

use model::{RewriteRecordingSettings, RewriteSliceState, RewriteState, STATE_VERSION};
use store::{RewriteLockState, RewriteStore};
#[cfg(test)]
pub(in crate::rewrite) use test_support::test_state;

use crate::{
    ComparisonVerificationOptions, E2eRunContext, ManagedRecordingOperation, RecordingApi,
    run_e2e_api, update_comparison_progress, verify_comparison_recording,
};

#[derive(Debug, Clone)]
pub struct RewriteNextOptions {
    pub target_root: PathBuf,
    pub api: Option<RecordingApi>,
    pub process_output: Option<String>,
    pub source_route: Option<String>,
}

#[derive(Debug, Clone)]
pub struct RewriteContext {
    pub target_root: PathBuf,
}

pub(crate) struct AdminSourceUpgradeGuard {
    _coordinator: store::RewriteLock,
}

pub(crate) fn lock_admin_source_upgrade(target_root: &Path) -> Result<AdminSourceUpgradeGuard> {
    let store = RewriteStore::new(target_root)?;
    let coordinator = store.lock()?;
    match traffic_operation::state(target_root)? {
        traffic_operation::TrafficOperationState::Absent => Ok(AdminSourceUpgradeGuard {
            _coordinator: coordinator,
        }),
        traffic_operation::TrafficOperationState::Live(active) => anyhow::bail!(
            "cannot upgrade the source snapshot while {:?} traffic operation {} is running",
            active.kind,
            active.operation_id
        ),
        traffic_operation::TrafficOperationState::Stale(active) => anyhow::bail!(
            "cannot upgrade the source snapshot while stale traffic operation {} requires `backend-rewrite recover`",
            active.operation_id
        ),
    }
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
    worker::ensure_api_confirmed(&state, &api, "planning a verification rule")?;
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
    if report.traffic_e2e_report["kind"] == "jwt" {
        jwt_rule::invalidate_global(&mut state);
    }
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

pub fn plan_rewrite_dependency_payload_rule(
    context: RewriteContext,
    options: RewriteDependencyPayloadRulePlanOptions,
) -> Result<RewriteDependencyPayloadRulePlanReport> {
    let (target_root, _) = crate::e2e_run::resolve_project(&context.target_root)?;
    let store = RewriteStore::new(&target_root)?;
    let _lock = store.lock()?;
    let mut state = store
        .load()?
        .context("rewrite workflow has not been initialized")?;
    let api = inventory::api_for_evidence_id(&target_root, &state, &options.evidence_id)
        .context("dependency-rule evidence is stale or belongs to no concurrent API work item")?;
    worker::ensure_api_confirmed(&state, &api, "planning a dependency payload rule")?;
    let report = inventory::with_slice_mut(&mut state, &api, |state| {
        dependency_rule::plan_memcached_timestamp(&target_root, state, options)
    })?;
    store.save(&state)?;
    Ok(report)
}

pub fn apply_rewrite_dependency_rule(
    context: RewriteContext,
    plan_id: &str,
) -> Result<RewriteDependencyRuleReport> {
    let (target_root, project) = crate::e2e_run::resolve_project(&context.target_root)?;
    let store = RewriteStore::new(&target_root)?;
    let _lock = store.lock()?;
    let mut state = store
        .load()?
        .context("rewrite workflow has not been initialized")?;
    let owner_api = inventory::api_for_dependency_rule_plan(&state, plan_id)
        .context("dependency-rule plan is stale or belongs to no concurrent API work item")?;
    let changes_dependency_matching = inventory::with_slice_mut(&mut state, &owner_api, |slice| {
        Ok(slice.dependency_rule_plan.as_ref().is_some_and(|p| {
            matches!(
                p.spec,
                model::RewriteDependencyRuleSpec::HttpCrossCase { .. }
                    | model::RewriteDependencyRuleSpec::HttpUnordered { .. }
                    | model::RewriteDependencyRuleSpec::RedisUnordered { .. }
            )
        }))
    })?;
    let (mut report, cache_snapshot_refresh) =
        inventory::with_slice_mut(&mut state, &owner_api, |state| {
            let dependency_payload = state.dependency_rule_plan.as_ref().is_some_and(|plan| {
                matches!(
                    plan.spec,
                    model::RewriteDependencyRuleSpec::MemcachedProtobufTimestamp { .. }
                        | model::RewriteDependencyRuleSpec::MysqlSqlTime { .. }
                        | model::RewriteDependencyRuleSpec::HttpCrossCase { .. }
                        | model::RewriteDependencyRuleSpec::HttpUnordered { .. }
                        | model::RewriteDependencyRuleSpec::RedisUnordered { .. }
                )
            });
            let cache_snapshot_refresh =
                dependency_rule::pending_cache_snapshot_refresh(state, plan_id)?;
            let mut report = dependency_rule::apply(&target_root, state, plan_id)?;
            if let Some(applied) = cache_snapshot_refresh {
                let case_source = state
                    .case_source
                    .as_deref()
                    .context("rewrite workflow has no case source for Redis snapshot derivation")?;
                match crate::replay::inspect_case_source_snapshot_overlay(
                    case_source,
                    &project.source_traffic_policy,
                    &applied.rule_name,
                ) {
                    Ok(overlay) => {
                        report.cache_snapshot_overlay = Some(serde_json::json!({
                            "status": "reused_old_global_evidence",
                            "recording_required": false,
                            "overlay": overlay,
                        }));
                        report.evidence_reclassification =
                            Some(background_reclassification::apply(&target_root, state)?);
                        report.next_command =
                            action::next_command_for_api(&target_root, &state.api);
                        return Ok((report, false));
                    }
                    Err(error) => {
                        report.cache_snapshot_overlay = Some(serde_json::json!({
                            "status": "fresh_recording_required",
                            "recording_required": true,
                            "reason": format!("{error:#}"),
                        }));
                        dependency_rule::schedule_cache_snapshot_refresh(
                            &target_root,
                            state,
                            applied,
                        )?;
                        report.next_command =
                            action::next_command_for_api(&target_root, &state.api);
                        return Ok((report, true));
                    }
                }
            }
            if dependency_payload {
                return Ok((report, false));
            }
            report.evidence_reclassification =
                Some(background_reclassification::apply(&target_root, state)?);
            report.next_command = action::next_command_for_api(&target_root, &state.api);
            Ok((report, false))
        })?;
    if changes_dependency_matching {
        dependency_rule::invalidate_dependency_matching_validation(&mut state);
    }
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
    ensure!(
        matches!(
            traffic_operation::state(&target_root)?,
            traffic_operation::TrafficOperationState::Absent
        ),
        "system repair acceptance cannot switch APIs while a traffic operation is active"
    );
    let mut state = store
        .load()?
        .context("rewrite workflow has not been initialized")?;
    let api = inventory::api_for_repair(&state, repair_id)
        .context("repair acceptance is stale or belongs to no concurrent API work item")?;
    if state.api != api {
        let requested_api = api.parse::<RecordingApi>()?;
        inventory::activate_requested(&mut state, Some(&requested_api))?;
    }
    state.process_outputs.current_id = None;
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
    let context = E2eRunContext {
        target_root: target_root.to_path_buf(),
        case_source,
        run_key: None,
    };
    let result = run_e2e_api(context.clone(), &api).await?;
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
    let (_, project) = crate::e2e_run::resolve_project(target_root)?;
    let process_outputs = crate::process_output::configs_for_observation(
        &project.process_outputs,
        crate::process_output::ProcessOutputObservation::BeforeShutdown,
    );
    if !process_outputs.is_empty() {
        let root = crate::e2e_run::focused_process_output_evidence(&context, &api)?;
        crate::process_output::validate_capture_set(
            &process_outputs,
            crate::process_output::ProcessOutputCaptureSide::Target,
            &root,
            false,
        )?;
        process_outputs::observe_target_evidence(state, root, current_target_fingerprint.clone());
    }
    transition::from_e2e_result(
        target_root,
        state,
        &result,
        transition::AttemptTransition::Append,
    )?;
    transition::complete_replay_if_ready(target_root, state)?;
    Ok(())
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
            .join("progress.yaml"),
        &state.recording_run_id,
    )?;
    let (_, project) = crate::e2e_run::resolve_project(target_root)?;
    let target_fingerprint = fingerprint::repository_fingerprint(target_root)?;
    let process_output_issue = report.passed.then(|| {
        process_outputs::comparison_issue(
            target_root,
            state,
            &target_fingerprint,
            &project.process_outputs,
            &project.process_output_rules,
        )
    });
    let process_output_issue = process_output_issue.transpose()?.flatten();
    state.comparison_current = report.passed && process_output_issue.is_none();
    if let Some(issue) = process_output_issue {
        state.active_issue = Some(issue);
        state.target_fingerprint = Some(target_fingerprint);
        state.phase = RewritePhase::ImplementationRequired;
    } else if report.passed {
        state.active_issue = None;
        if !inventory::complete_current_and_advance(state)?
            && !recording::begin_pending_capture_refresh(target_root, state)?
        {
            state.phase = RewritePhase::SliceComplete;
        }
    } else {
        state.active_issue = Some(comparison_issue::from_report(
            &state.api,
            &report,
            fingerprint::repository_fingerprint(target_root)?,
            state.attempts.last().map_or(0, |attempt| attempt.attempt),
        )?);
        state.target_fingerprint = Some(target_fingerprint);
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
