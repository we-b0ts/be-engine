//! Recover unavailable rule evidence without applying an unverified plan.
use std::path::Path;

use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};

use super::{RewriteContext, action, inventory, model::RewriteState, store::RewriteStore};

pub(super) fn evidence_missing(target_root: &Path, state: &RewriteState) -> Result<bool> {
    let evidence = crate::resolve_e2e_response_rule_evidence(
        crate::E2eRunContext {
            target_root: target_root.into(),
            case_source: state
                .case_source
                .clone()
                .context("plan has no case source")?,
            run_key: None,
        },
        state.group_id.as_deref().context("plan has no API group")?,
    )?;
    Ok(!evidence.replay.is_file()
        || !crate::replay::report::dependency_evidence_path(&evidence.replay).is_file())
}

pub(super) fn required_action(
    target_root: &Path,
    state: &RewriteState,
) -> Option<super::model::RewriteAction> {
    let plan_id = state
        .rule_plan
        .as_ref()
        .filter(|plan| plan.dynamic_value.is_some() || plan.dependency_request.is_some())
        .map(|plan| &plan.id)
        .or_else(|| state.dependency_rule_plan.as_ref().map(|plan| &plan.id))?;
    if !evidence_missing(target_root, state).unwrap_or(false) {
        return None;
    }
    Some(super::model::RewriteAction::PlanApplyRequired {
        summary: "pending rule evidence is unavailable; recover the plan and run fresh Replay before replanning".into(),
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
    let report = inventory::with_slice_mut(&mut state, &api, |state| {
        ensure!(
            evidence_missing(&root, state)?,
            "rule evidence is available; apply the reviewed plan normally"
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
