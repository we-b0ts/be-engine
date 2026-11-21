//! Supersede a missing implementer runtime and retain its current API leases.
use super::{
    binding, feedback,
    model::{ImplementerReplaceRuntimeOptions, ImplementerRuntimeReplacement},
    pool,
};
use crate::{
    api_selector,
    runtime_identity::{validate_identity, validate_runtime_query},
};
use anyhow::{Context, Result, ensure};
use chrono::Utc;
use std::path::Path;
use traffic_rewrite_model::rewrite::{RewriteState, RewriteWorkScope, RewriteWorkerActivity};

pub fn validate(options: &ImplementerReplaceRuntimeOptions) -> Result<()> {
    validate_identity("replacement handle", &options.agent_handle, 4096)?;
    validate_identity("previous handle", &options.previous_agent_handle, 4096)?;
    validate_identity("replacement reason", &options.reason, 4096)?;
    validate_runtime_query(&options.runtime_query)?;
    ensure!(
        options.agent_handle != options.previous_agent_handle,
        "replacement requires a different runtime handle"
    );
    Ok(())
}

pub fn apply(
    root: &Path,
    state: &mut RewriteState,
    options: ImplementerReplaceRuntimeOptions,
    active_scopes: &[RewriteWorkScope],
    bind_review: impl Fn(
        &Path,
        &mut RewriteState,
        &RewriteWorkScope,
        Option<&Path>,
        bool,
    ) -> Result<bool>,
) -> Result<Option<Vec<RewriteWorkScope>>> {
    let pool = state
        .implementers
        .as_ref()
        .context("this workflow has no implementer pool")?;
    let slot = pool
        .slots
        .get(&options.slot_id)
        .context("unknown implementer slot")?;
    if slot.agent_handle.as_ref() == Some(&options.agent_handle)
        && slot.last_runtime_replacement.as_ref().is_some_and(|last| {
            last.previous_handle == options.previous_agent_handle
                && last.new_handle == options.agent_handle
                && last.reason == options.reason
        })
    {
        return Ok(None);
    }
    ensure!(
        slot.agent_handle.as_ref() == Some(&options.previous_agent_handle),
        "previous runtime handle no longer owns this slot"
    );
    ensure!(
        !pool.slots.iter().any(|(id, slot)| *id != options.slot_id
            && slot.agent_handle.as_ref() == Some(&options.agent_handle)),
        "replacement handle belongs to another implementer slot"
    );
    let generation = slot
        .generation
        .checked_add(1)
        .context("implementer generation overflow")?;
    let tasks = slot.tasks.values().cloned().collect::<Vec<_>>();
    let worktree = pool::worktree(root, options.slot_id);
    let mut retained = std::collections::BTreeMap::new();
    let mut scopes = Vec::new();
    for mut task in tasks {
        let scope = RewriteWorkScope::Api {
            api: api_selector::public_api(&task.api).into(),
        };
        if task.recording_run_id != state.recording_run_id || !active_scopes.contains(&scope) {
            continue;
        }
        let binding = state
            .worker_bindings
            .get_mut(&task.api)
            .context("assigned API has no worker binding")?;
        binding.rework_generation = binding
            .rework_generation
            .checked_add(1)
            .context("worker rework generation overflow")?;
        binding.observation = None;
        binding.review_report = None;
        let dispatch = binding::dispatch_view(state, scope.clone(), None).dispatch_id;
        binding::confirm_binding(
            state,
            &scope,
            &dispatch,
            &options.agent_handle,
            Some(format!("api-implementer-{}", options.slot_id)),
        )?;
        bind_review(root, state, &scope, Some(&worktree), true)?;
        feedback::apply_report(
            state,
            &scope,
            &feedback::RewriteWorkerReportOptions {
                delivery_commit: None,
                target_root: root.to_path_buf(),
                agent_handle: options.agent_handle.clone(),
                activity: RewriteWorkerActivity::Queued,
                handoff_id: None,
                review_report: None,
            },
            None,
        )?;
        task.dispatch_id = dispatch;
        task.lease_generation = generation;
        retained.insert(task.api.clone(), task);
        scopes.push(scope);
    }
    let slot = state
        .implementers
        .as_mut()
        .unwrap()
        .slots
        .get_mut(&options.slot_id)
        .unwrap();
    slot.agent_handle = Some(options.agent_handle.clone());
    slot.generation = generation;
    slot.tasks = retained;
    slot.current_api = None;
    slot.confirmed_batches.clear();
    slot.last_runtime_replacement = Some(ImplementerRuntimeReplacement {
        previous_handle: options.previous_agent_handle,
        new_handle: options.agent_handle,
        reason: options.reason,
        runtime_query: options.runtime_query,
    });
    slot.observed_at = Some(Utc::now().to_rfc3339());
    Ok(Some(scopes))
}
