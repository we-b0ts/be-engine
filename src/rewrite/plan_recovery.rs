//! Retire unavailable or policy-stale rule evidence without applying a plan.
use std::path::Path;

use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};

use super::{RewriteContext, action, inventory, model::RewriteState, store::RewriteStore};

pub(super) fn evidence_unusable(target_root: &Path, state: &RewriteState) -> Result<bool> {
    if let Some(plan) = state
        .rule_plan
        .as_ref()
        .and_then(|plan| plan.unified.as_ref())
    {
        return Ok(super::unified_rule::stale(target_root, state, plan));
    }
    let context = crate::E2eRunContext {
        target_root: target_root.into(),
        case_source: state
            .case_source
            .clone()
            .context("plan has no case source")?,
        run_key: None,
    };
    let api = state.group_id.as_deref().context("plan has no API group")?;
    crate::e2e_run::ensure_response_rule_evidence_inactive(context.clone(), api)?;
    if state
        .rule_plan
        .as_ref()
        .is_some_and(|plan| super::rule::generated_evidence_stale(target_root, state, plan))
    {
        return Ok(true);
    }
    let evidence = crate::resolve_e2e_response_rule_evidence(context, api)?;
    if !evidence.replay.is_file()
        || !crate::replay::report::dependency_evidence_path(&evidence.replay).is_file()
    {
        return Ok(true);
    }
    if state.dependency_rule_plan.as_ref().is_some_and(|plan| {
        matches!(
            plan.spec,
            super::model::RewriteDependencyRuleSpec::MysqlSqlTime { .. }
        )
    }) {
        let report: Value = serde_json::from_slice(&std::fs::read(&evidence.replay)?)?;
        if crate::MysqlTimeRuleFeedback::policy_evidence_stale(
            &target_root.join(".traffic-e2e/verification.yaml"),
            &report,
        )? {
            return Ok(true);
        }
    }
    // A generated-value plan freezes the policy identity its evidence was
    // validated against. When the verification policy or the assertion report
    // advanced afterwards, apply can never validate the frozen evidence again;
    // recovery must retire the plan so fresh Replay and replanning can proceed
    // instead of deadlocking the coordinator queue.
    if let Some(plan) = state.rule_plan.as_ref() {
        if let Some(spec) = plan.jwt.as_ref() {
            let (_, config) = crate::e2e_run::resolve_project(target_root)?;
            let current =
                crate::e2e_run::jwt_evidence::digest(&std::fs::read(&config.replay_policy)?);
            if current != spec.policy_revision() {
                return Ok(true);
            }
        }
        if !plan.response_jwts.is_empty() || !plan.header_dates.is_empty() {
            let current =
                crate::validate_replay_policy(&target_root.join(".traffic-e2e/verification.yaml"))?;
            let assertions: Value = serde_json::from_slice(&std::fs::read(&evidence.assertions)?)?;
            if assertions["policy_fingerprint"].as_str() != Some(current.fingerprint.as_str()) {
                return Ok(true);
            }
        }
        if plan.dependency_request.is_some() || plan.dynamic_value.is_some() {
            // Dependency-request and dynamic-value plans validate the replay
            // report's replay_policy fingerprint against the current policy at
            // apply time; retire the plan when the report is policy-stale.
            let current =
                crate::validate_replay_policy(&target_root.join(".traffic-e2e/verification.yaml"))?;
            let report: Value = serde_json::from_slice(&std::fs::read(&evidence.replay)?)?;
            if report["replay_policy"]["fingerprint"].as_str() != Some(current.fingerprint.as_str())
            {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

pub(super) fn required_action(
    target_root: &Path,
    state: &RewriteState,
) -> Option<super::model::RewriteAction> {
    let plan_id = state
        .rule_plan
        .as_ref()
        .filter(|plan| {
            plan.jwt.is_some()
                || plan.unified.is_some()
                || !plan.response_jwts.is_empty()
                || !plan.header_dates.is_empty()
                || plan.dynamic_value.is_some()
                || plan.dependency_request.is_some()
        })
        .map(|plan| &plan.id)
        .or_else(|| state.dependency_rule_plan.as_ref().map(|plan| &plan.id))?;
    if !evidence_unusable(target_root, state).unwrap_or(false) {
        return None;
    }
    Some(super::model::RewriteAction::PlanApplyRequired {
        summary: "pending rule evidence is unavailable or policy-stale; recover the plan and run fresh Replay before replanning".into(),
        command: action::command(target_root, vec!["rule".into(), "recover".into(), plan_id.clone()], vec![]),
    })
}

pub fn recover_rewrite_rule_plan(context: RewriteContext, plan_id: &str) -> Result<Value> {
    let (root, _) = crate::e2e_run::resolve_project(&context.target_root)?;
    let store = RewriteStore::new(&root)?;
    let _lock = store.lock()?;
    let mut state = store
        .load()?
        .context("rewrite workflow has not been initialized")?;
    let api = inventory::api_for_rule_plan(&state, plan_id)
        .or_else(|| inventory::api_for_dependency_rule_plan(&state, plan_id))
        .context("rule plan is stale or belongs to no API work item")?;
    if inventory::scoped(&state, Some(&api.parse()?))?
        .rule_plan
        .as_ref()
        .is_some_and(|p| p.unified.is_some())
    {
        super::worker::ensure_api_confirmed(&state, &api, "recovering a unified traffic rule")?;
    }
    let report = inventory::with_slice_mut(&mut state, &api, |state| {
        ensure!(
            evidence_unusable(&root, state)?,
            "rule evidence remains usable; apply the reviewed plan normally"
        );
        recover_slice(&root, state, plan_id)
    })?;
    store.save(&state)?;
    Ok(report)
}

fn recover_slice(root: &Path, state: &mut RewriteState, plan_id: &str) -> Result<Value> {
    let issue = state
        .active_issue
        .as_ref()
        .context("rule plan has no active issue")?;
    let plan = if let Some(plan) = state.rule_plan.as_ref().filter(|plan| plan.id == plan_id) {
        ensure!(
            plan.issue_id == issue.id,
            "active issue changed after rule planning"
        );
        serde_json::to_value(plan)?
    } else {
        let plan = state
            .dependency_rule_plan
            .as_ref()
            .filter(|plan| plan.id == plan_id)
            .context("pending rule plan does not match the requested id")?;
        ensure!(
            plan.issue_id == issue.id,
            "active issue changed after dependency rule planning"
        );
        serde_json::to_value(plan)?
    };
    if state
        .rule_plan
        .as_ref()
        .is_some_and(|plan| plan.id == plan_id)
    {
        state.rule_plan = None;
    }
    if state
        .dependency_rule_plan
        .as_ref()
        .is_some_and(|plan| plan.id == plan_id)
    {
        state.dependency_rule_plan = None;
    }
    super::rule_replay::request(state);
    state.bump();
    Ok(json!({
        "status": "fresh_replay_required", "applied": false,
        "retired_plan": plan,
        "next_command": action::next_command(root),
        "required_change": "Run fresh Replay using the existing recordings, then query current evidence and replan the retained selector and source proof."
    }))
}

#[cfg(test)]
mod tests;
