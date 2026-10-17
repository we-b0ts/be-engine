//! Retire unavailable or policy-stale rule evidence without applying a plan.
use std::path::Path;

use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};

use super::{RewriteContext, action, inventory, model::RewriteState, store::RewriteStore};

pub(super) fn evidence_unusable(target_root: &Path, state: &RewriteState) -> Result<bool> {
    let retired_format = state
        .rule_plan
        .as_ref()
        .is_some_and(|plan| plan.unified.is_none())
        || state.dependency_rule_plan.is_some();
    if retired_format {
        ensure!(
            matches!(
                super::traffic_operation::state(target_root)?,
                super::traffic_operation::TrafficOperationState::Absent
            ),
            "retired plans must wait for active traffic or workflow recovery"
        );
        if let (Some(case_source), Some(api)) = (&state.case_source, &state.group_id)
            && case_source.is_dir()
        {
            crate::e2e_run::ensure_response_rule_evidence_inactive(
                crate::E2eRunContext {
                    target_root: target_root.into(),
                    case_source: case_source.clone(),
                    run_key: None,
                },
                api,
            )?;
        }
        return Ok(true);
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
    if let Some(plan) = state
        .rule_plan
        .as_ref()
        .and_then(|plan| plan.unified.as_ref())
    {
        return Ok(super::unified_rule::stale(target_root, state, plan));
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
    super::worker::ensure_api_confirmed(&state, &api, "recovering a traffic rule")?;
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
    if let Some(record) = state
        .rule_plan
        .as_ref()
        .filter(|plan| plan.id == plan_id)
        .and_then(|plan| plan.unified.as_ref())
        && record.applying()
    {
        // Retirement cannot abandon a partially published capture/runtime effect.
        // Restore only the exact authorized bytes, retaining the intent on any CAS conflict.
        super::unified_rule::rollback(record)?;
    }
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
