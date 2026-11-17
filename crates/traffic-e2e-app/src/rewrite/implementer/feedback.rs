use std::collections::BTreeSet;
use std::path::Path;

use anyhow::{Context, Result, ensure};
use chrono::Utc;

use super::{delivery, model::*, planning};
use crate::rewrite::{
    api_selector, fingerprint,
    model::{RewriteActionEnvelope, RewriteState},
    review,
    store::RewriteStore,
    worker,
};
use worker::model::RewriteWorkerActivity as Activity;

fn load(root: &Path) -> Result<(std::path::PathBuf, RewriteStore)> {
    crate::rewrite::purpose::require_work_branch(root)?;
    let (root, _) = crate::e2e_run::resolve_project(root)?;
    let store = RewriteStore::new(&root)?;
    Ok((root, store))
}

fn canonical_api(input: &str) -> Result<String> {
    let selector = input.parse::<crate::rewrite::RewriteApiSelector>()?;
    let api = selector.to_string();
    ensure!(api == input, "use the exact canonical API selector {api:?}");
    Ok(api)
}

pub fn confirm(options: ImplementerConfirmOptions) -> Result<RewriteActionEnvelope> {
    let (root, store) = load(&options.target_root)?;
    worker::validate_identity("implementer handle", &options.agent_handle, 4096)?;
    let lock = worker::events::lock(&root)?;
    let mut state = store
        .load()?
        .context("rewrite workflow is not initialized")?;
    // Repeating a confirmed command does not allocate new leases or clear progress.
    if state
        .implementers
        .as_ref()
        .and_then(|pool| pool.slots.get(&options.slot_id))
        .is_some_and(|slot| {
            slot.agent_handle.as_deref() == Some(&options.agent_handle)
                && slot.confirmed_batches.contains(&options.dispatch_id)
        })
    {
        drop(lock);
        return worker::runtime::current_envelope(&root);
    }
    let dispatch = planning::dispatch_for_slot(&root, &state, &options.group_id, options.slot_id)?
        .context("this group has no dispatchable APIs")?;
    ensure!(
        dispatch.slot_id == options.slot_id && dispatch.dispatch_id == options.dispatch_id,
        "implementer dispatch is stale; refresh status"
    );
    state.implementers = planning::mapped_pool(&state)?;
    let pool = state
        .implementers
        .as_ref()
        .context("this workflow has no implementer pool")?;
    ensure!(
        !pool.slots.iter().any(|(id, slot)| *id != options.slot_id
            && slot.agent_handle.as_deref() == Some(&options.agent_handle)),
        "runtime handle already belongs to another implementer slot"
    );
    let slot = &pool.slots[&options.slot_id];
    ensure!(
        slot.agent_handle
            .as_deref()
            .is_none_or(|handle| handle == options.agent_handle)
            || slot.tasks.is_empty(),
        "resume this slot's retained runtime handle before replacing it"
    );
    ensure!(
        dispatch.worktree.is_dir(),
        "create the assigned implementer worktree {} before confirmation",
        dispatch.worktree.display()
    );
    let canonical_checkout = std::fs::canonicalize(&dispatch.worktree)?;
    let git_root = crate::rewrite::source_diff::git_text(
        &dispatch.worktree,
        &["rev-parse", "--show-toplevel"],
    )?;
    ensure!(
        canonical_checkout == dispatch.worktree
            && std::fs::canonicalize(git_root.trim())? == canonical_checkout,
        "the fixed implementer path must be an actual Git worktree root, not an ordinary directory or symlink"
    );
    let mut scopes = Vec::new();
    for task in &dispatch.apis {
        let scope = api_selector::work_scope(&state, &task.api);
        worker::confirm_binding(
            &mut state,
            &scope,
            &task.dispatch_id,
            &options.agent_handle,
            Some(dispatch.name.clone()),
        )?;
        review::bind(&root, &mut state, &scope, Some(&dispatch.worktree), true)?;
        worker::runtime::apply_report(
            &mut state,
            &scope,
            &worker::runtime::RewriteWorkerReportOptions {
                delivery_commit: None,
                target_root: root.clone(),
                agent_handle: options.agent_handle.clone(),
                activity: Activity::Queued,
                handoff_id: None,
                review_report: None,
            },
            None,
        )?;
        scopes.push(scope);
    }
    let slot = state
        .implementers
        .as_mut()
        .unwrap()
        .slots
        .get_mut(&options.slot_id)
        .unwrap();
    slot.agent_handle = Some(options.agent_handle);
    slot.generation = dispatch.lease_generation;
    slot.confirmed_batches.insert(options.dispatch_id);
    for task in dispatch.apis {
        slot.tasks.insert(task.api.clone(), task);
    }
    slot.observed_at = Some(Utc::now().to_rfc3339());
    worker::events::publish_many(&root, &state, &scopes)?;
    drop(lock);
    worker::runtime::current_envelope(&root)
}

fn validate_task<'a>(
    state: &'a RewriteState,
    slot_id: usize,
    api: &str,
    dispatch: &str,
    generation: u64,
    handle: &str,
    allow_retired: bool,
) -> Result<&'a ImplementerTask> {
    let slot = state
        .implementers
        .as_ref()
        .context("this workflow has no implementer pool")?
        .slots
        .get(&slot_id)
        .context("unknown implementer slot")?;
    ensure!(
        slot.agent_handle.as_deref() == Some(handle),
        "runtime handle does not own this implementer slot"
    );
    let task = slot
        .tasks
        .get(api)
        .context("API lease is no longer active; reject the stale callback")?;
    ensure!(
        task.dispatch_id == dispatch && task.lease_generation == generation,
        "stale API dispatch or implementer lease generation"
    );
    if allow_retired {
        return Ok(task);
    }
    ensure!(
        task.recording_run_id == state.recording_run_id,
        "API lease belongs to another recording"
    );
    let scope = api_selector::work_scope(state, api);
    ensure!(
        worker::runtime::scopes(state).contains(&scope),
        "API no longer needs implementation; report its task idle to release the lease"
    );
    let current = if worker::runtime::scopes(state).contains(&scope) {
        worker::dispatch_view(state, scope, None).dispatch_id
    } else {
        state
            .worker_bindings
            .get(api)
            .context("API has no retained worker binding")?
            .confirmed_dispatch_id
            .clone()
    };
    ensure!(
        current == dispatch,
        "API dispatch has changed; refresh the assignment"
    );
    Ok(task)
}

pub fn report(options: ImplementerReportOptions) -> Result<RewriteActionEnvelope> {
    let api = canonical_api(&options.api)?;
    ensure!(
        matches!(
            options.activity,
            Activity::Queued | Activity::Running | Activity::Idle
        ),
        "use implementer handoff for deliveries or worker report with the original review for integration"
    );
    let (root, store) = load(&options.target_root)?;
    let lock = worker::events::lock(&root)?;
    let mut state = store
        .load()?
        .context("rewrite workflow is not initialized")?;
    validate_task(
        &state,
        options.slot_id,
        &api,
        &options.dispatch_id,
        options.lease_generation,
        &options.agent_handle,
        options.activity == Activity::Idle,
    )?;
    let scope = api_selector::work_scope(&state, &api);
    let old_recording = state.implementers.as_ref().unwrap().slots[&options.slot_id].tasks[&api]
        .recording_run_id
        != state.recording_run_id;
    if old_recording
        || !worker::runtime::scopes(&state).contains(&scope)
        || worker::dispatch_view(&state, scope.clone(), None).dispatch_id != options.dispatch_id
    {
        ensure!(
            options.activity == Activity::Idle,
            "this API no longer needs implementation; confirm its task is idle to release the retained lease"
        );
        let slot = state
            .implementers
            .as_mut()
            .unwrap()
            .slots
            .get_mut(&options.slot_id)
            .unwrap();
        slot.tasks.remove(&api);
        if slot.current_api.as_deref() == Some(&api) {
            slot.current_api = None;
        }
        slot.observed_at = Some(Utc::now().to_rfc3339());
        worker::events::publish_many(&root, &state, &[])?;
        drop(lock);
        return worker::runtime::current_envelope(&root);
    }
    if options.activity == Activity::Running {
        let slot = &state.implementers.as_ref().unwrap().slots[&options.slot_id];
        ensure!(
            slot.current_api
                .as_ref()
                .is_none_or(|current| current == &api),
            "an implementer may develop only one API at a time; hand off or pause its current API first"
        );
    }
    worker::runtime::apply_report(
        &mut state,
        &scope,
        &worker::runtime::RewriteWorkerReportOptions {
            delivery_commit: None,
            target_root: root.clone(),
            agent_handle: options.agent_handle,
            activity: options.activity,
            handoff_id: None,
            review_report: None,
        },
        None,
    )?;
    let slot = state
        .implementers
        .as_mut()
        .unwrap()
        .slots
        .get_mut(&options.slot_id)
        .unwrap();
    if options.activity == Activity::Running {
        slot.current_api = Some(api);
    } else if slot.current_api.as_deref() == Some(&api) {
        slot.current_api = None;
    }
    slot.observed_at = Some(Utc::now().to_rfc3339());
    worker::events::publish(&root, &state, &scope)?;
    drop(lock);
    worker::runtime::current_envelope(&root)
}

pub fn handoff(options: ImplementerHandoffOptions) -> Result<RewriteActionEnvelope> {
    ensure!(
        !options.deliveries.is_empty(),
        "handoff requires at least one API delivery"
    );
    let (root, store) = load(&options.target_root)?;
    let lock = worker::events::lock(&root)?;
    let mut state = store
        .load()?
        .context("rewrite workflow is not initialized")?;
    let mut seen = BTreeSet::new();
    let mut handoff_ids = BTreeSet::new();
    let mut reviews = Vec::new();
    for item in &options.deliveries {
        let api = canonical_api(&item.api)?;
        ensure!(seen.insert(api.clone()), "duplicate API in handoff");
        ensure!(
            handoff_ids.insert(item.handoff_id.clone()),
            "each API delivery requires a distinct handoff id"
        );
        let scope = api_selector::work_scope(&state, &api);
        let duplicate = state
            .worker_bindings
            .get(&api)
            .and_then(|binding| binding.observation.as_ref())
            .is_some_and(|observation| {
                observation.dispatch_id == item.dispatch_id
                    && observation.recording_run_id == state.recording_run_id
                    && observation.handoff_id.as_ref() == Some(&item.handoff_id)
                    && matches!(
                        observation.activity,
                        Activity::HandoffReady | Activity::Integrated
                    )
            });
        if duplicate {
            continue;
        }
        validate_task(
            &state,
            options.slot_id,
            &api,
            &item.dispatch_id,
            item.lease_generation,
            &options.agent_handle,
            false,
        )?;
        ensure!(
            !state
                .worker_bindings
                .iter()
                .any(|(other, binding)| other != &api
                    && binding
                        .observation
                        .as_ref()
                        .is_some_and(
                            |observation| observation.handoff_id.as_ref() == Some(&item.handoff_id)
                        )),
            "handoff id already identifies another API"
        );
        let report = if let Some(commit) = item.delivery_commit.as_deref() {
            review::delivery::worker(&root, &state, &scope, commit)?
        } else {
            ensure!(
                !item.review_report.as_os_str().is_empty(),
                "delivery_commit is required for an implementer handoff"
            );
            review::accept_handoff(&root, &state, &scope, Some(&item.review_report))?
        };
        ensure!(
            fingerprint::matches_revision(&report.worktree, &report.head_revision)?,
            "commit all reviewed managed code before handing off a reusable implementer worktree"
        );
        reviews.push((scope, item, report));
    }
    // All API reports are admitted before any binding or slot is published.
    let mut scopes = Vec::new();
    for (scope, item, report) in reviews {
        let frozen = delivery::freeze(&root, &item.handoff_id, &report)?;
        worker::runtime::apply_report(
            &mut state,
            &scope,
            &worker::runtime::RewriteWorkerReportOptions {
                delivery_commit: None,
                target_root: root.clone(),
                agent_handle: options.agent_handle.clone(),
                activity: Activity::HandoffReady,
                handoff_id: Some(item.handoff_id.clone()),
                review_report: Some(frozen.report_path.clone()),
            },
            None,
        )?;
        state
            .worker_bindings
            .get_mut(&scope.binding_key())
            .unwrap()
            .review_report = Some(frozen);
        let slot = state
            .implementers
            .as_mut()
            .unwrap()
            .slots
            .get_mut(&options.slot_id)
            .unwrap();
        slot.tasks.remove(&scope.binding_key());
        if slot.current_api.as_deref() == Some(&scope.binding_key()) {
            slot.current_api = None;
        }
        slot.observed_at = Some(Utc::now().to_rfc3339());
        scopes.push(scope);
    }
    if !scopes.is_empty() {
        worker::events::publish_many(&root, &state, &scopes)?;
    }
    drop(lock);
    worker::runtime::current_envelope(&root)
}

pub fn reassign(options: ImplementerReassignOptions) -> Result<RewriteActionEnvelope> {
    worker::validate_identity("group reassignment reason", &options.reason, 4096)?;
    let (root, store) = load(&options.target_root)?;
    let lock = worker::events::lock(&root)?;
    let mut state = store
        .load()?
        .context("rewrite workflow is not initialized")?;
    state.implementers = planning::mapped_pool(&state)?;
    let pool = state
        .implementers
        .as_mut()
        .context("this workflow has no implementer pool")?;
    ensure!(
        pool.slots.contains_key(&options.slot_id),
        "unknown implementer slot"
    );
    ensure!(
        pool.group_slots.contains_key(&options.group_id),
        "unknown analysis group"
    );
    pool.group_slots.insert(options.group_id, options.slot_id);
    worker::events::publish_many(&root, &state, &[])?;
    drop(lock);
    worker::runtime::current_envelope(&root)
}
