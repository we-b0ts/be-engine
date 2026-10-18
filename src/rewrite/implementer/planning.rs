use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use anyhow::{Result, ensure};

use super::model::{
    ImplementerDispatch, ImplementerPool, ImplementerPoolView, ImplementerSlotView, ImplementerTask,
};
use crate::rewrite::{
    action, fingerprint,
    model::{RewriteAction, RewriteState},
    worker,
};
use worker::model::RewriteWorkerCoverageState as Coverage;

pub(super) fn worktree(root: &Path, slot: usize) -> PathBuf {
    root.join(".traffic-e2e/local/rewrite-worktrees")
        .join(format!("api-implementer-{slot}"))
}

pub(super) fn mapped_pool(state: &RewriteState) -> Result<Option<ImplementerPool>> {
    let Some(mut pool) = state.implementers.clone() else {
        return Ok(None);
    };
    ensure!(
        pool.effective_max_implementers > 0,
        "max_implementers must be positive"
    );
    if let Some(analysis) = &state.repository_analysis {
        let groups = state
            .api_inventory
            .iter()
            .filter(|item| !crate::rewrite::regression_scope::is_skipped(state, &item.api))
            .filter_map(|item| {
                analysis
                    .api_groups
                    .get(crate::rewrite::api_selector::public_api(&item.api))
            })
            .collect::<BTreeSet<_>>();
        for group in groups {
            if !pool.group_slots.contains_key(group) {
                pool.group_slots.insert(
                    group.clone(),
                    pool.next_group_slot % pool.effective_max_implementers,
                );
                pool.next_group_slot = pool
                    .next_group_slot
                    .checked_add(1)
                    .ok_or_else(|| anyhow::anyhow!("implementer group mapping counter overflow"))?;
            }
        }
    }
    Ok(Some(pool))
}

pub(in crate::rewrite) fn refresh(state: &mut RewriteState) -> Result<bool> {
    let Some(pool) = mapped_pool(state)? else {
        return Ok(false);
    };
    let changed = state
        .implementers
        .as_ref()
        .is_none_or(|old| old.group_slots != pool.group_slots);
    if changed {
        state.implementers = Some(pool);
    }
    Ok(changed)
}

#[cfg(test)]
pub(super) fn dispatch(
    root: &Path,
    state: &RewriteState,
    group: &str,
) -> Result<Option<ImplementerDispatch>> {
    let Some(pool) = mapped_pool(state)? else {
        return Ok(None);
    };
    let Some(&slot_id) = pool.group_slots.get(group) else {
        return Ok(None);
    };
    dispatch_for_slot(root, state, group, slot_id)
}

pub(super) fn dispatch_for_slot(
    root: &Path,
    state: &RewriteState,
    group: &str,
    slot_id: usize,
) -> Result<Option<ImplementerDispatch>> {
    if !crate::rewrite::repository_analysis::is_complete(state) {
        return Ok(None);
    }
    let Some(pool) = mapped_pool(state)? else {
        return Ok(None);
    };
    let Some(slot) = pool.slots.get(&slot_id) else {
        return Ok(None);
    };
    let generation = slot
        .generation
        .checked_add(1)
        .ok_or_else(|| anyhow::anyhow!("implementer lease generation overflow"))?;
    let Some(analysis) = &state.repository_analysis else {
        return Ok(None);
    };
    let mut apis = worker::runtime::scopes(state)
        .into_iter()
        .filter(|scope| {
            analysis
                .api_groups
                .get(&scope.binding_key())
                .is_some_and(|value| value == group)
        })
        .filter(|scope| crate::rewrite::group_replay::dispatch_ready(state, &scope.binding_key()))
        .filter(|scope| {
            let assigned = pool.slots.iter().find_map(|(id, slot)| {
                slot.tasks.contains_key(&scope.binding_key()).then_some(*id)
            });
            assigned.unwrap_or_else(|| pool.group_slots[group]) == slot_id
        })
        .filter(|scope| {
            matches!(
                worker::runtime::coverage(state, scope),
                Coverage::DispatchRequired | Coverage::ResumeRequired
            )
        })
        .map(|scope| {
            let view = worker::dispatch_view(state, scope, None);
            ImplementerTask {
                api: view.work_scope.binding_key(),
                group_id: group.to_owned(),
                recording_run_id: state.recording_run_id.clone(),
                dispatch_id: view.dispatch_id,
                lease_generation: generation,
            }
        })
        .collect::<Vec<_>>();
    apis.sort_by(|left, right| left.api.cmp(&right.api));
    if apis.is_empty() {
        return Ok(None);
    }
    let identity = serde_json::to_string(&apis)?;
    let dispatch_id = fingerprint::id(&[
        "implementer-batch-v1",
        &state.workflow_id,
        &state.recording_run_id,
        &slot_id.to_string(),
        &identity,
    ]);
    Ok(Some(ImplementerDispatch {
        slot_id,
        name: format!("api-implementer-{slot_id}"),
        worktree: worktree(root, slot_id),
        agent_handle: slot.agent_handle.clone(),
        group_id: group.to_owned(),
        dispatch_id,
        lease_generation: generation,
        apis,
        current_api: slot.current_api.clone(),
        pending_api_count: slot.tasks.len(),
    }))
}

pub(in crate::rewrite) fn action(
    root: &Path,
    state: &RewriteState,
) -> Result<Option<RewriteAction>> {
    let Some(pool) = mapped_pool(state)? else {
        return Ok(None);
    };
    let mut candidates = pool
        .group_slots
        .iter()
        .map(|(group, slot)| (group.clone(), *slot))
        .collect::<BTreeSet<_>>();
    for (&slot_id, slot) in &pool.slots {
        for task in slot.tasks.values() {
            candidates.insert((task.group_id.clone(), slot_id));
        }
    }
    for (group, slot_id) in candidates {
        if let Some(dispatch) = dispatch_for_slot(root, state, &group, slot_id)? {
            let mut argv = vec![
                "implementer".into(),
                "confirm".into(),
                "--slot".into(),
                dispatch.slot_id.to_string(),
                "--group".into(),
                group.clone(),
                "--dispatch-id".into(),
                dispatch.dispatch_id.clone(),
            ];
            let mut env = Vec::new();
            if let Some(handle) = &dispatch.agent_handle {
                argv.extend(["--agent-handle".into(), handle.clone()]);
            } else {
                env.push(worker::AGENT_HANDLE_ENV.into());
            }
            return Ok(Some(RewriteAction::ImplementerDispatchRequired {
                summary: format!(
                    "dispatch this exact API batch to {}; retain its worktree and process one API at a time; hand off any completed subset through implementer handoff",
                    dispatch.name
                ),
                confirm: action::command(root, argv, env),
                report: report_command(root, dispatch.slot_id, dispatch.agent_handle.as_deref()),
                dispatch,
            }));
        }
    }
    Ok(None)
}

pub(super) fn report_command(
    root: &Path,
    slot: usize,
    handle: Option<&str>,
) -> crate::rewrite::RewriteCommandSpec {
    let mut argv = vec![
        "implementer".into(),
        "report".into(),
        "--slot".into(),
        slot.to_string(),
    ];
    let mut env = vec![
        "BACKEND_REWRITE_IMPLEMENTER_API".into(),
        "BACKEND_REWRITE_IMPLEMENTER_DISPATCH_ID".into(),
        "BACKEND_REWRITE_IMPLEMENTER_LEASE_GENERATION".into(),
        worker::runtime::ACTIVITY_ENV.into(),
    ];
    if let Some(handle) = handle {
        argv.extend(["--agent-handle".into(), handle.into()]);
    } else {
        env.push(worker::AGENT_HANDLE_ENV.into());
    }
    action::command(root, argv, env)
}

pub(in crate::rewrite) fn view(
    root: &Path,
    state: &RewriteState,
) -> Result<Option<ImplementerPoolView>> {
    let Some(pool) = mapped_pool(state)? else {
        return Ok(None);
    };
    let slots = pool
        .slots
        .iter()
        .map(|(&id, slot)| ImplementerSlotView {
            slot_id: id,
            name: format!("api-implementer-{id}"),
            worktree: worktree(root, id),
            agent_handle: slot.agent_handle.clone(),
            current_api: slot.current_api.clone(),
            developing_api_count: usize::from(slot.current_api.is_some()),
            pending_api_count: slot.tasks.len(),
            queued_api_count: slot
                .tasks
                .len()
                .saturating_sub(usize::from(slot.current_api.is_some())),
            state: if slot.agent_handle.is_none() {
                "not_started"
            } else if slot.current_api.is_some() {
                "running"
            } else if slot.tasks.is_empty() {
                "idle"
            } else if slot.tasks.keys().any(|api| {
                let scope = crate::rewrite::api_selector::work_scope(state, api);
                worker::runtime::scopes(state).contains(&scope)
                    && worker::runtime::coverage(state, &scope) == Coverage::ResumeRequired
            }) {
                "resume_required"
            } else {
                "queued"
            }
            .into(),
            groups: pool
                .group_slots
                .iter()
                .filter(|(_, value)| **value == id)
                .map(|(group, _)| group.clone())
                .chain(slot.tasks.values().map(|task| task.group_id.clone()))
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect(),
            tasks: slot.tasks.values().cloned().collect(),
            observed_at: slot.observed_at.clone(),
            report: report_command(root, id, slot.agent_handle.as_deref()),
        })
        .collect();
    Ok(Some(ImplementerPoolView {
        configured_max_implementers: crate::config::regression::RegressionScope::load(root)?
            .max_implementers,
        effective_max_implementers: pool.effective_max_implementers,
        group_slots: pool.group_slots,
        slots,
    }))
}
