//! Plan implementer slot dispatches and project the current pool.
use super::{
    binding, feedback,
    model::{
        ImplementerDispatch, ImplementerPool, ImplementerPoolView, ImplementerSlotView,
        ImplementerTask,
    },
    pool::{mapped_pool, worktree},
};
use crate::fingerprint;
use anyhow::Result;
use std::{collections::BTreeSet, path::Path};
use traffic_rewrite_model::rewrite::{
    RewriteCommandSpec, RewriteState, RewriteWorkScope, RewriteWorkerCoverageState as Coverage,
};
pub fn dispatch_for_slot(
    root: &Path,
    state: &RewriteState,
    group: &str,
    slot_id: usize,
    dispatchable_scopes: impl IntoIterator<Item = RewriteWorkScope>,
) -> Result<Option<ImplementerDispatch>> {
    if !crate::analyst::grouping::is_complete(state) {
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
    let mut apis = dispatchable_scopes
        .into_iter()
        .filter(|scope| {
            analysis
                .api_groups
                .get(&scope.binding_key())
                .is_some_and(|value| value == group)
        })
        .filter(|scope| {
            let assigned = pool.slots.iter().find_map(|(id, slot)| {
                slot.tasks.contains_key(&scope.binding_key()).then_some(*id)
            });
            assigned.unwrap_or_else(|| pool.group_slots[group]) == slot_id
        })
        .filter(|scope| {
            matches!(
                feedback::coverage(state, scope),
                Coverage::DispatchRequired | Coverage::ResumeRequired
            )
        })
        .map(|scope| {
            let view = binding::dispatch_view(state, scope, None);
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

pub fn view(
    root: &Path,
    state: &RewriteState,
    active_scopes: &[RewriteWorkScope],
    report_command: impl Fn(&Path, usize, Option<&str>) -> RewriteCommandSpec,
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
                let scope = RewriteWorkScope::Api {
                    api: crate::api_selector::public_api(api).into(),
                };
                active_scopes.contains(&scope)
                    && feedback::coverage(state, &scope) == Coverage::ResumeRequired
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
        configured_max_implementers: ImplementerPool::DEFAULT_CAPACITY,
        effective_max_implementers: pool.effective_max_implementers,
        group_slots: pool.group_slots,
        slots,
    }))
}
