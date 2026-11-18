//! Source-proven new-format rule transactions under the existing coordinator.
use std::{fs, path::Path, time::SystemTime};
use traffic_rewrite_rules::rewrite::unified_rule::preflight::PreflightMethods;

use anyhow::{Context, Result, ensure};
use serde_json::json;

use super::{
    RewriteContext, action, evidence, fingerprint, inventory,
    model::{RewriteIssueKind, RewriteRulePlanRecord, RewriteRuleReport, RewriteState},
    store::RewriteStore,
};

pub(crate) mod attribution;
pub(super) mod batch;
pub(super) mod discovery;
#[cfg(test)]
use std::path::PathBuf;
use traffic_rewrite_rules::rewrite::unified_rule::impact;
#[cfg(test)]
pub(crate) use traffic_rewrite_rules::rewrite::unified_rule::manifest;
use traffic_rewrite_rules::rewrite::unified_rule::planning;
#[cfg(test)]
mod tests;

pub use traffic_rewrite_rules::rewrite::unified_rule::planning::RewriteUnifiedRulePlanOptions;

pub use traffic_rewrite_model::rewrite::unified_rule::UnifiedRulePlanRecord;

pub fn plan_rewrite_unified_rule(
    context: RewriteContext,
    options: RewriteUnifiedRulePlanOptions,
) -> Result<RewriteRuleReport> {
    if attribution::matches(&options.evidence_id) {
        return attribution::plan(context, options);
    }
    if batch::matches(&options.evidence_id) {
        return batch::plan(context, options);
    }
    let (root, _) = crate::e2e_run::resolve_project(&context.target_root)?;
    let store = RewriteStore::new(&root)?;
    let mut state = store
        .load()?
        .context("rewrite workflow has not been initialized")?;
    let api = inventory::api_for_rule_evidence_id(&root, &state, &options.evidence_id)?;
    let _scope = super::rule_plans::events::lock_api(&root, &api)?;
    super::rule_plans::events::ensure_not_replaying(&root, &api)?;
    // Planning publishes an independent event, never a replacement of the
    // coordinator's in-flight snapshot. Other APIs may keep replaying.
    let expected = inventory::scoped(&state, Some(&api.parse()?))?;
    let report =
        inventory::with_slice_mut(&mut state, &api, |state| plan(&root, state, options, false))?;
    let record = inventory::scoped(&state, Some(&api.parse()?))?
        .rule_plan
        .clone()
        .context("planner did not produce a rule plan")?;
    super::rule_plans::events::publish(&root, &expected, record)?;
    Ok(report)
}

fn plan(
    root: &Path,
    state: &mut RewriteState,
    options: RewriteUnifiedRulePlanOptions,
    batch_scope: bool,
) -> Result<RewriteRuleReport> {
    let evidence_validation_started = SystemTime::now();
    let attribution_scope = attribution::matches(&options.evidence_id);
    let issue_id = if batch_scope || attribution_scope {
        options.evidence_id.clone()
    } else {
        let issue = state
            .active_issue
            .as_ref()
            .context("rule plan requires an active issue")?;
        ensure!(
            matches!(
                issue.kind,
                RewriteIssueKind::Response
                    | RewriteIssueKind::Dependency
                    | RewriteIssueKind::Replay
            ),
            "unified value rules require response or dependency evidence"
        );
        let evidence = evidence::report_for_id(root, state, &options.evidence_id)
            .context("rule evidence is stale or unavailable")?;
        evidence::policy_freshness::ensure_plannable(&evidence)?;
        issue.id.clone()
    };
    if let Some(record) = state.rule_plan.as_ref().and_then(|p| p.unified.as_ref()) {
        record.ensure_current(root, state)?;
    }
    let mut record = planning::build(root, state, &options.file, batch_scope, attribution_scope)?;
    let id = format!(
        "plan-{}",
        fingerprint::id(&[
            &state.workflow_id,
            &issue_id,
            &options.evidence_id,
            &serde_json::to_string(&record)?
        ])
        .trim_start_matches("fnv1a64:")
    );
    record.evidence_validation_started = Some(evidence_validation_started);
    let traffic_e2e_report = record.report(false);
    let outer: RewriteRulePlanRecord = serde_json::from_value(json!({
        "id":id, "issue_id":issue_id, "kind":"unified", "json_pointer":"",
        "evidence_id":options.evidence_id, "unified":record,
    }))?;
    state.rule_plan = Some(outer);
    state.dependency_rule_plan = None;
    state.recorder_capture_plan = None;
    state.bump();
    Ok(RewriteRuleReport {
        plan_id: id.clone(),
        issue_id,
        traffic_e2e_report,
        next_command: action::rule_apply_command(root, &id),
    })
}

pub use traffic_rewrite_rules::rewrite::unified_rule::record::UnifiedRulePlanRecordMethods;

pub(super) fn apply(
    root: &Path,
    state: &mut RewriteState,
    outer: RewriteRulePlanRecord,
) -> Result<RewriteRuleReport> {
    let record = outer
        .unified
        .as_ref()
        .context("pending plan has no unified contract")?;
    ensure!(
        record.apply_started,
        "unified apply requires the durable coordinator intent"
    );
    // begin_apply authenticated this plan under the same coordinator locks.
    let previous_execution = super::fingerprint::replay_identity(root)?;
    record.ensure_policy_baseline(root)?;
    crate::config::edit::write_atomic(&record.policy, record.updated.as_bytes())?;
    let mut report = record.report(true);
    if record.is_api_issue() {
        report["target_replay_drift_at_apply"] =
            json!(state.replay_identity.as_ref() != Some(&previous_execution));
    }
    state.rule_plan = None;
    if record.original != record.updated {
        if record.is_batch() {
            batch::request_replay(state, &record.original, &record.updated, &outer.id)?;
        } else {
            impact::request_replays(state, &record.original, &record.updated, &outer.id)?;
        }
        if record
            .preflight
            .obligations
            .contains(&crate::config::native_policy::SourceObligation::AttributionReview)
        {
            state.dependency_review.recording_run_id = None;
            state.dependency_review.revision += 1;
        }
        if record.is_api_issue()
            && impact::affects_api(&record.original, &record.updated, &state.api)?
        {
            super::rule_replay::request(state);
        }
        impact::rebase_unchanged(
            root,
            state,
            &record.original,
            &record.updated,
            &previous_execution,
        )?;
        super::dependency_review::refresh_receipts(root, state)?;
        if record.preflight.needs_recording() {
            let mut scopes = record.preflight.capture_scopes.clone();
            if scopes.is_empty() {
                scopes.insert(
                    state.api.clone(),
                    record.source_proofs.summary(&record.rule_ids),
                );
            }
            super::verification_obligations::request_capture(state, &scopes, &outer.id)?;
        }
    }
    state.bump();
    Ok(RewriteRuleReport {
        plan_id: outer.id,
        issue_id: outer.issue_id,
        traffic_e2e_report: report,
        next_command: action::next_command(root),
    })
}

/// Persist this marker with RewriteStore before changing the policy. A crash
/// after the write can recognize the exact authorized updated bytes on retry.
pub(super) fn begin_apply(
    root: &Path,
    state: &mut RewriteState,
    plan_id: &str,
) -> Result<UnifiedRulePlanRecord> {
    let mut record = super::rule::pending_plan_for_apply(state, plan_id)?
        .unified
        .context("pending unified rule plan unavailable")?;
    record.ensure_current(root, state).with_context(|| {
        format!("rule plan {plan_id} failed revalidation; use `backend-rewrite rule recover {plan_id}` to retire stale evidence")
    })?;
    record.apply_started = true;
    state.rule_plan.as_mut().unwrap().unified = Some(record.clone());
    if record.original != record.updated
        && record.is_api_issue()
        && impact::affects_api(&record.original, &record.updated, &state.api)?
    {
        super::rule_replay::request(state);
    }
    Ok(record)
}

pub(super) fn rollback(record: &UnifiedRulePlanRecord) -> Result<()> {
    let current = fs::read_to_string(&record.policy)?;
    if current == record.original {
        return Ok(());
    }
    ensure!(
        current == record.updated,
        "cannot roll back policy changed by another writer; retain the durable pending apply intent"
    );
    crate::config::edit::write_atomic(&record.policy, record.original.as_bytes())
}

pub(super) fn stale(root: &Path, state: &RewriteState, record: &UnifiedRulePlanRecord) -> bool {
    record.ensure_current(root, state).is_err()
}

#[cfg(test)]
pub(super) use traffic_rewrite_rules::rewrite::unified_rule::parse_proposal;
