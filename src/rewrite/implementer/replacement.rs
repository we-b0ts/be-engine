//! Replace a missing runtime session without discarding its fixed slot or pending APIs.
use anyhow::{Context, Result, ensure};
use chrono::Utc;

use super::model::{ImplementerReplaceRuntimeOptions, ImplementerRuntimeReplacement};
use crate::rewrite::{
    api_selector, model::RewriteActionEnvelope, review, store::RewriteStore, worker,
};

pub fn replace_runtime(options: ImplementerReplaceRuntimeOptions) -> Result<RewriteActionEnvelope> {
    crate::rewrite::purpose::require_work_branch(&options.target_root)?;
    worker::validate_identity("replacement handle", &options.agent_handle, 4096)?;
    worker::validate_identity("previous handle", &options.previous_agent_handle, 4096)?;
    worker::validate_identity("replacement reason", &options.reason, 4096)?;
    worker::validate_runtime_query(&options.runtime_query)?;
    ensure!(
        options.agent_handle != options.previous_agent_handle,
        "replacement requires a different runtime handle"
    );
    let (root, _) = crate::e2e_run::resolve_project(&options.target_root)?;
    let store = RewriteStore::new(&root)?;
    let lock = worker::events::lock(&root)?;
    let mut state = store
        .load()?
        .context("rewrite workflow is not initialized")?;
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
        drop(lock);
        return worker::runtime::current_envelope(&root);
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
    let worktree = super::planning::worktree(&root, options.slot_id);
    let mut retained = std::collections::BTreeMap::new();
    let mut scopes = Vec::new();
    for mut task in tasks {
        let scope = api_selector::work_scope(&state, &task.api);
        if task.recording_run_id != state.recording_run_id
            || !worker::runtime::scopes(&state).contains(&scope)
        {
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
        let dispatch = worker::dispatch_view(&state, scope.clone(), None).dispatch_id;
        worker::confirm_binding(
            &mut state,
            &scope,
            &dispatch,
            &options.agent_handle,
            Some(format!("api-implementer-{}", options.slot_id)),
        )?;
        review::bind(&root, &mut state, &scope, Some(&worktree), true)?;
        worker::runtime::apply_report(
            &mut state,
            &scope,
            &worker::runtime::RewriteWorkerReportOptions {
                delivery_commit: None,
                target_root: root.clone(),
                agent_handle: options.agent_handle.clone(),
                activity: worker::model::RewriteWorkerActivity::Queued,
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
    worker::events::publish_many(&root, &state, &scopes)?;
    drop(lock);
    worker::runtime::current_envelope(&root)
}
