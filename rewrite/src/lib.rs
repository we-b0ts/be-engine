//! Persistent backend rewrite coordination over engine services.
#[cfg(test)]
use traffic_engine::attribution_defaults;
#[cfg(test)]
use traffic_engine::startup;
#[cfg(any(test, feature = "test-support"))]
use traffic_engine::test_support;
use traffic_engine::verification_progress;
use traffic_engine::*;
use traffic_engine::{
    build_info, case_group, config, dependency, dependency_index, e2e_run, engine_binary,
    execution_identity, internal_runtime, path_pattern, policy_evidence, recording_api, replay,
    repository, source_snapshot,
};
mod action;
mod advance;
mod api_batch;
mod api_selector;
mod artifacts;
use traffic_rewrite_evidence::case_dependencies;
mod case_group_rebuild;
mod case_patterns;
mod configuration_commit;
mod coordination;
mod engine_retry;
mod execution;
mod expert;
pub use api_selector::{RewriteApiSelector, status_rewrite_for_selector};
mod next;
pub use coordination::RewriteCoordinationDetails;
pub use execution::{
    execute as execute_rewrite_operation, retry as retry_rewrite_operation,
    start_next as start_rewrite_next, start_quality as start_rewrite_target_quality,
};
pub use expert::model::{
    RewriteExpertApiCommands, RewriteExpertApiView, RewriteExpertCloseOptions,
    RewriteExpertCommands, RewriteExpertDeliveryOptions, RewriteExpertInventoryItem,
    RewriteExpertOptions, RewriteExpertPrepareOptions, RewriteExpertState, RewriteExpertView,
};
pub use expert::{
    close as close_rewrite_expert, confirm as confirm_rewrite_expert,
    delivered as report_rewrite_expert_delivery, prepare as prepare_rewrite_expert,
};
pub use next::next_rewrite;
pub use worker::model::{
    RewriteWorkerActivity, RewriteWorkerCoverageState, RewriteWorkerInventoryItem,
};
pub use worker::runtime::{RewriteWorkerReportOptions, report as report_rewrite_worker};
mod dependency_review;
pub use store::{compact_rewrite_decision_history, verify_rewrite_decision_history};
mod dependency_rule;
mod verification_obligations;
pub(crate) use dependency_review::{
    dependency_attribution_identity_for_source, freeze_dependency_attribution,
};
pub(crate) fn batch_execution_identity(root: &std::path::Path) -> anyhow::Result<String> {
    fingerprint::fresh_replay_identity(root)
}
pub(crate) fn dependency_attribution_snapshot(
    root: &std::path::Path,
    run: &str,
) -> anyhow::Result<String> {
    dependency_review::dependency_attribution_identity(root, run)
}
pub use dependency_review::{
    AttributionCommandOptions, AttributionReviewContext, AttributionRuleBinding,
    AttributionSubmission, ClaimRejection, ForeignUnusedClaim, ForeignUnusedSubmission,
    InvestigationOutcome, InvestigationResolution, ProposedAttribution, TargetInvestigation,
    TargetInvestigationResolutionSubmission, TargetInvestigationSubmission,
    apply_dependency_attribution, claim_foreign_unused, dependency_attribution_api_information,
    dependency_attribution_batch_information, dependency_attribution_candidates,
    dependency_attribution_context, dependency_attribution_context_page,
    dependency_attribution_group, dependency_attribution_hypotheses, dependency_attribution_rules,
    dependency_attribution_source_information, dependency_attribution_target,
    investigate_unmatched_dependency, resolve_target_investigation, retry_dependency_batch,
    verify_dependency_obligation,
};
pub use verification_obligations::{
    VerificationImpact, VerificationRequirement, VerificationScope,
};
mod evidence;
pub use evidence::{
    ImplementerEvidence, query_implementer_evidence, query_rewrite_evidence,
    query_rewrite_evidence_for_scope, query_rewrite_redis_argument_for_scope,
    query_rewrite_witness_for_scope,
};
use traffic_rewrite_evidence::evidence_model;
mod fingerprint;
mod inventory;
mod ip_capture;
mod issue;
mod model;
mod plan_recovery;
mod preparation;
pub use plan_recovery::recover_rewrite_rule_plan;
mod progress_publication;
mod recorder_capture;
pub use ip_capture::RewriteIpCaptureReport;
use traffic_rewrite_model::rewrite::work_scope;
mod group_replay;
mod implementer;
mod initialization;
mod repository_analysis;
pub use group_replay::{GroupReplayKind, GroupReplayResult, GroupReplayRound, GroupReplaySummary};
pub use implementer::{
    ImplementerConfirmOptions, ImplementerDelivery, ImplementerDispatch, ImplementerHandoffOptions,
    ImplementerPoolView, ImplementerReassignOptions, ImplementerReplaceRuntimeOptions,
    ImplementerReportOptions, ImplementerSlotView, ImplementerTask,
    confirm as confirm_rewrite_implementer, handoff as handoff_rewrite_implementer,
    reassign as reassign_rewrite_implementer,
    replace_runtime as replace_rewrite_implementer_runtime, report as report_rewrite_implementer,
};
pub use repository_analysis::{
    RepositoryAnalysisApplyOptions, RepositoryAnalysisContext, RepositoryAnalysisContextOptions,
    RepositoryAnalysisSnapshot, apply_repository_analysis, repository_analysis_context,
};
mod jwt_rule;
mod purpose;
mod recording;
mod recording_action;
mod recording_input;
mod recovery;
mod regression;
mod regression_scope;
pub use regression::{
    RewriteRegressionBeginOptions, RewriteRegressionBeginReport, begin as begin_rewrite_regression,
};
mod repair;
mod replay_admission;
use traffic_rewrite_evidence::response_url_evidence;
mod revalidation;
mod route;
mod rule;
mod rule_plans;
mod rule_replay;
pub(crate) mod unified_rule;
pub use jwt_rule::JwtRulePlanOptions;
pub use unified_rule::{RewriteUnifiedRulePlanOptions, plan_rewrite_unified_rule};
mod scheduling;
mod source_process_traffic;
mod status;
mod waiting;
pub use waiting::{RewriteWaitOptions, wait as wait_rewrite};
pub(crate) mod quality;
mod review;
use traffic_rewrite_review::source_diff;
mod store;
mod target_quality;
pub use review::{
    IntegrationHandoffSelection, RewriteIntegrationBatchDelivery, RewriteIntegrationBatchOptions,
    RewriteIntegrationBatchReport, RewriteReviewOptions, RewriteReviewReport,
    accept as accept_rewrite_review, check as check_rewrite_review,
    check_batch as check_batch_rewrite_review, check_batch_file as check_rewrite_review_batch_file,
    check_pre_revalidation as check_rewrite_pre_revalidation,
    export_batch as export_rewrite_integration_batch, rework as rework_rewrite_review,
    rework_with_report as rework_rewrite_review_with_report, show as show_rewrite_review,
};
#[cfg(test)]
mod pool_workflow_tests;
#[cfg(test)]
mod tests;
use traffic_rewrite_runtime::traffic_operation;
mod transition;
mod verification;
mod worker;
#[cfg(any(test, feature = "test-support"))]
mod workflow_test_support;

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, ensure};
pub use case_dependencies::{
    RewriteCapturePreview, RewriteCaseDependenciesOptions, RewriteCaseDependenciesReport,
    RewriteCaseDependencyProtocolDetail, RewriteCaseDependencySourceReference,
    RewriteCaseDependencyTarget, RewriteCaseDependencyTargetSummary,
    RewriteDependencyCaptureDetail, RewriteMemcachedExchangeDetail,
    RewriteMemcachedOperationDetail, RewriteMysqlExchangeDetail, RewriteMysqlOperationDetail,
    RewriteMysqlParameterDetail, RewriteRedisExchangeDetail, RewriteRedisOperationDetail,
    query as query_rewrite_case_dependencies,
    query_exchange as query_rewrite_case_dependency_exchange,
};
pub use case_group_rebuild::{
    RewriteCaseGroupRebuildOptions, RewriteCaseGroupRebuildReport,
    archive_unmanaged_rewrite_case_groups, rebuild_rewrite_case_groups,
};
pub use dependency_rule::{
    RewriteDependencyOwnership, RewriteDependencyPayloadRulePlanOptions,
    RewriteDependencyPayloadRulePlanReport, RewriteDependencyRulePlanOptions,
    RewriteDependencyRulePlanReport, RewriteDependencyRuleSelector,
};
pub use evidence_model::{
    RewriteApplicableRulePlanner, RewriteEvidenceContext, RewriteEvidenceReport, RewriteRuleHint,
};
pub use model::{
    RewriteAction, RewriteActionEnvelope, RewriteAdvanceKind, RewriteApiInventoryDetails,
    RewriteApiInventoryItem, RewriteApiInventoryView, RewriteApiProgress, RewriteApiStatus,
    RewriteCommandSpec, RewriteDependencyRuleReport, RewriteEvidenceCommand, RewriteExecutionMode,
    RewriteFocusedE2eExecution, RewriteFocusedE2eExecutionMode, RewriteHttpResponseCaptureReport,
    RewriteInputRequiredReason, RewriteInventoryReport, RewriteIssue, RewriteIssueKind,
    RewriteIssueOwner, RewritePhase, RewriteRecorderCaptureReport, RewriteRecordingInputCandidate,
    RewriteRecordingInputCandidateDisposition, RewriteRecordingInputDiagnosis,
    RewriteRecordingInputRejections, RewriteRecordingReason, RewriteRecoveryReport,
    RewriteRepairAcceptanceKind, RewriteRouteReport, RewriteRuleReport, RewriteStatusReport,
    RewriteTrafficOperationKind, RewriteTrafficOperationView, RewriteWorkerBlockingReason,
    RewriteWorkerDispatchState, RewriteWorkerDispatchView, RewriteWorkflowView,
};
pub use recorder_capture::{
    RewriteHttpResponseCapturePlanOptions, apply_rewrite_recorder_capture,
    plan_rewrite_http_response_capture,
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
pub use status::{inventory_rewrite, status_rewrite, status_rewrite_for_api};
pub use target_quality::{RewriteTargetQualityOptions, run as run_rewrite_target_quality};
pub use work_scope::RewriteWorkScope;
pub use worker::{
    RewriteWorkerConfirmOptions, RewriteWorkerMissingQuery, RewriteWorkerTransferOptions,
    confirm as confirm_rewrite_worker, transfer as transfer_rewrite_worker,
};

use model::RewriteState;
use store::{RewriteLockState, RewriteStore};
#[cfg(test)]
pub(crate) use workflow_test_support::test_state;

use crate::RecordingApi;

#[derive(Debug, Clone)]
pub struct RewriteNextOptions {
    pub target_root: PathBuf,
    pub api: Option<RewriteApiSelector>,
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
    let api = inventory::api_for_rule_evidence_id(&target_root, &state, &options.evidence_id)?;
    worker::ensure_api_confirmed(&state, &api, "planning a verification rule")?;
    crate::policy::retired_authoring()?;
    let report = inventory::with_slice_mut(&mut state, &api, |state| {
        rule::plan(&target_root, state, options)
    })?;
    store.save(&state)?;
    Ok(report)
}

pub fn apply_rewrite_rule(context: RewriteContext, plan_id: &str) -> Result<RewriteRuleReport> {
    let (target_root, _) = crate::e2e_run::resolve_project(&context.target_root)?;
    let store = RewriteStore::new(&target_root)?;
    let Some(_lock) = store.try_lock()? else {
        let state = store
            .load()?
            .context("rewrite workflow has not been initialized")?;
        return rule_plans::wait_report(&target_root, &state, plan_id);
    };
    let mut state = store
        .load()?
        .context("rewrite workflow has not been initialized")?;
    let api = inventory::api_for_rule_plan(&state, plan_id)
        .context("rule plan is stale or belongs to no concurrent API work item")?;
    let _scope = rule_plans::events::lock_api(&target_root, &api)?;
    if execution::status_action(&target_root)?.is_some() {
        return rule_plans::wait_report(&target_root, &state, plan_id);
    }
    match traffic_operation::state(&target_root)? {
        traffic_operation::TrafficOperationState::Absent => {}
        _ => return rule_plans::wait_report(&target_root, &state, plan_id),
    }
    let unified = inventory::scoped(&state, Some(&api.parse()?))?
        .rule_plan
        .as_ref()
        .is_some_and(|plan| plan.unified.is_some());
    ensure!(
        unified,
        "this plan uses a retired rule format; run `backend-rewrite rule recover {plan_id}`, obtain fresh evidence and use `rule plan --file <rule.yaml> --evidence <id>`"
    );
    let apply_intent = if unified {
        let intent = inventory::with_slice_mut(&mut state, &api, |slice| {
            unified_rule::begin_apply(&target_root, slice, plan_id)
        })?;
        store.save(&state)?;
        Some(intent)
    } else {
        None
    };
    let report = inventory::with_slice_mut(&mut state, &api, |state| {
        let report = rule::apply(&target_root, state, plan_id)?;
        Ok(report)
    })?;
    if report.traffic_e2e_report["kind"] == "jwt" {
        jwt_rule::invalidate_global(&mut state);
    }
    if report.traffic_e2e_report["requires_fresh_recording"] == true
        && report.traffic_e2e_report["kind"] != "unified"
    {
        let runnable = inventory::mark_awaiting_recording_refresh(&mut state, &api)?;
        if !runnable {
            recording::begin_pending_capture_refresh(&target_root, &mut state)?;
        }
    }
    if let Err(error) = store.save(&state) {
        if let Some(intent) = &apply_intent {
            unified_rule::rollback(intent).context("failed to save applied rule state and to restore original policy; pending apply intent remains recoverable")?;
        }
        return Err(error).context("failed to save applied rule state; original unified policy restored and pending intent retained");
    }
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
    crate::policy::retired_authoring()?;
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
    crate::policy::retired_authoring()?;
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
    worker::ensure_api_confirmed(&state, &owner_api, "applying a dependency rule")?;
    crate::policy::retired_authoring()?;
    let changes_dependency_matching = inventory::with_slice_mut(&mut state, &owner_api, |slice| {
        Ok(slice.dependency_rule_plan.as_ref().is_some_and(|p| {
            matches!(
                p.spec,
                model::RewriteDependencyRuleSpec::HttpCrossCase { .. }
            )
        }))
    })?;
    let (mut report, cache_snapshot_refresh, reclassify) =
        inventory::with_slice_mut(&mut state, &owner_api, |state| {
            let requires_fresh_replay = state
                .dependency_rule_plan
                .as_ref()
                .is_some_and(|plan| plan.spec.requires_fresh_replay());
            let cache_snapshot_refresh =
                dependency_rule::pending_cache_snapshot_refresh(state, plan_id)?;
            let mut report = dependency_rule::apply(&target_root, state, plan_id)?;
            if let Some(applied) = cache_snapshot_refresh {
                let case_source = state
                    .case_source
                    .as_deref()
                    .context("rewrite workflow has no case source for Redis snapshot derivation")?;
                match crate::protocols::replay::inspect_case_source_snapshot_overlay(
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
                        report.next_command = action::next_command(&target_root);
                        return Ok((report, false, true));
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
                        report.next_command = action::next_command(&target_root);
                        return Ok((report, true, false));
                    }
                }
            }
            if requires_fresh_replay {
                return Ok((report, false, false));
            }
            report.next_command = action::next_command(&target_root);
            Ok((report, false, true))
        })?;
    if reclassify {
        rule_replay::after_process_rule(
            &mut state,
            &owner_api,
            report.traffic_e2e_report["changed"] == true,
        );
    }
    if changes_dependency_matching {
        dependency_rule::invalidate_dependency_matching_validation(&mut state);
    }
    if cache_snapshot_refresh {
        let runnable = inventory::mark_awaiting_recording_refresh(&mut state, &owner_api)?;
        if !runnable {
            recording::begin_pending_capture_refresh(&target_root, &mut state)?;
        }
        report.next_command = action::next_command(&target_root);
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
    let report = repair::verify(&target_root, &mut state, repair_id)?;
    store.save(&state)?;
    Ok(report)
}

pub async fn recover_rewrite(context: RewriteContext) -> Result<RewriteRecoveryReport> {
    recovery::recover(context).await
}

fn validate_single_line(label: &str, value: &str) -> Result<()> {
    ensure!(
        value == value.trim() && !value.is_empty() && !value.contains(['\r', '\n']),
        "{label} must be a non-empty single line"
    );
    Ok(())
}

/// Bind this workflow owner to engine operations in the composing process.
pub fn initialize() {
    traffic_engine::coordination::initialize(|| std::sync::Arc::new(WorkflowCoordinator));
}

struct WorkflowCoordinator;

impl traffic_engine::coordination::Coordinator for WorkflowCoordinator {
    fn freeze(
        &self,
        target: Option<&std::path::Path>,
        source: &std::path::Path,
        run: &str,
    ) -> anyhow::Result<traffic_engine::coordination::FrozenAttribution> {
        freeze_dependency_attribution(target, source, run)
    }
    fn freeze_for_replay(
        &self,
        target: Option<&std::path::Path>,
        source: &std::path::Path,
        run: &str,
    ) -> anyhow::Result<traffic_engine::coordination::FrozenAttribution> {
        dependency_review::freeze_dependency_attribution_for_replay(target, source, run)
    }
    fn identity(
        &self,
        target: &std::path::Path,
        source: Option<&std::path::Path>,
        run: &str,
    ) -> anyhow::Result<String> {
        match source {
            Some(source) => dependency_attribution_identity_for_source(target, source, run),
            None => dependency_attribution_snapshot(target, run),
        }
    }
    fn lock_source_upgrade(
        &self,
        target: &std::path::Path,
    ) -> anyhow::Result<traffic_engine::coordination::SourceUpgradeGuard> {
        Ok(Box::new(lock_admin_source_upgrade(target)?))
    }
}

#[cfg(test)]
use traffic_engine::recorded_request;

#[cfg(feature = "test-support")]
#[doc(hidden)]
pub mod testing;
