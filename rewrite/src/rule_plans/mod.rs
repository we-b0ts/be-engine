//! Global pending-plan admission and coordinator-owned application at idle boundaries.
use crate::unified_rule::UnifiedRulePlanRecordMethods;
use std::path::Path;

use anyhow::{Context, Result};
use serde_json::json;

use super::{
    action, inventory,
    model::{RewriteAction, RewriteRuleReport, RewriteState},
    store::RewriteStore,
    traffic_operation,
};

pub(super) mod events;

pub(super) fn pending(state: &RewriteState) -> bool {
    std::iter::once(&state.active_slice)
        .chain(state.parked_slices.values())
        .any(|slice| {
            slice.rule_plan.is_some() && !super::regression_scope::is_skipped(state, &slice.api)
        })
}

/// A pending plan is global scheduling work, even when another API just failed
/// or a complete revalidation round is in progress. Actual recovery comes first.
pub(super) fn required_action(root: &Path, state: &RewriteState) -> Option<RewriteAction> {
    // Scheduling only checks the coordinator issue and policy baseline. Apply
    // and recover verify the frozen evidence before any state or policy write.
    let mut recovery = None;
    for slice in std::iter::once(&state.active_slice).chain(state.parked_slices.values()) {
        let Some(plan) = &slice.rule_plan else {
            continue;
        };
        if super::regression_scope::is_skipped(state, &slice.api) {
            continue;
        }
        let stale = (!plan
            .unified
            .as_ref()
            .is_some_and(|record| !record.is_api_issue())
            && slice.active_issue.as_ref().map(|i| i.id.as_str()) != Some(plan.issue_id.as_str()))
            || plan
                .unified
                .as_ref()
                .is_none_or(|record| record.ensure_policy_baseline(root).is_err());
        if stale {
            recovery.get_or_insert_with(|| RewriteAction::PlanApplyRequired {
                summary: format!(
                    "pending rule plan {} for {} is stale; recover it before replanning; preserve the current Replay result and issue",
                    plan.id, slice.api
                ),
                command: action::command(
                    root,
                    vec!["rule".into(), "recover".into(), plan.id.clone()],
                    vec![],
                ),
            });
            continue;
        }
        return Some(RewriteAction::PlanApplyRequired {
            summary: format!(
                "Replay is idle; review and apply pending rule plan {} for {} before starting another Replay or integration; application still requires fresh verification",
                plan.id, slice.api
            ),
            command: action::rule_apply_command(root, &plan.id),
        });
    }
    recovery
}

pub(super) fn idle_action(root: &Path, state: &RewriteState) -> Result<Option<RewriteAction>> {
    let store = RewriteStore::new(root)?;
    if super::execution::owned_by_other_process(root)?
        || !matches!(
            traffic_operation::state(root)?,
            traffic_operation::TrafficOperationState::Absent
        )
        || (store.lock_state()? != super::store::RewriteLockState::Absent && !store.owns_lock()?)
        || matches!(
            super::execution::status_action(root)?,
            Some(RewriteAction::ExecutionFailed { .. } | RewriteAction::RecoveryRequired { .. })
        )
    {
        return Ok(None);
    }
    Ok(required_action(root, state))
}

pub(super) fn wait_report(
    root: &Path,
    state: &RewriteState,
    id: &str,
) -> Result<RewriteRuleReport> {
    let api =
        inventory::api_for_rule_plan(state, id).context("rule plan is stale or unavailable")?;
    let scoped = inventory::scoped(state, Some(&api.parse()?))?;
    let plan = scoped
        .rule_plan
        .as_ref()
        .context("pending rule plan unavailable")?;
    let stale_lock =
        RewriteStore::new(root)?.lock_state()? == super::store::RewriteLockState::Stale;
    let action = match traffic_operation::state(root)? {
        traffic_operation::TrafficOperationState::Live(marker) => {
            action::wait_envelope(root, state, Some(api.clone()), &marker).action
        }
        traffic_operation::TrafficOperationState::Stale(_) => {
            action::recovery_required(root).action
        }
        traffic_operation::TrafficOperationState::Absent => super::execution::status_action(root)?
            .unwrap_or_else(|| {
                if stale_lock {
                    action::recovery_required(root).action
                } else {
                    action::coordinator_wait_envelope(root, state, Some(api.clone())).action
                }
            }),
    };
    let status = match &action {
        RewriteAction::RecoveryRequired { .. } => "recovery_required",
        RewriteAction::ExecutionFailed { .. } => "execution_failed",
        _ => "wait_required",
    };
    Ok(RewriteRuleReport {
        plan_id: id.into(),
        issue_id: plan.issue_id.clone(),
        traffic_e2e_report: json!({"status":status, "applied":false, "queued":false, "verified":false,
            "api":api, "action":action, "retry_command":action::rule_apply_command(root,id),
            "hint":"Keep this reviewed plan. After the current Replay attempt finishes, follow status/next to apply it before further verification. No automatic application was scheduled."}),
        next_command: action::status_command_for_api(root, None),
    })
}
