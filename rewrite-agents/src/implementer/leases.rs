//! Validate implementer leases and publishable changes to slot state.
use super::{binding, delivery, feedback, model::*, pool};
use crate::{api_selector, fingerprint, source_diff};
use anyhow::{Context, Result, ensure};
use chrono::Utc;
use std::{collections::BTreeSet, path::Path};
use traffic_rewrite_model::rewrite::{
    RewriteReviewReport, RewriteState, RewriteWorkScope, RewriteWorkerActivity as Activity,
};

fn work_scope(api: &str) -> RewriteWorkScope {
    RewriteWorkScope::Api {
        api: api_selector::public_api(api).to_owned(),
    }
}

pub fn canonical_api(input: &str) -> Result<String> {
    let selector = input.parse::<crate::recording_api::RecordingApiScope>()?;
    let api = selector.to_string();
    ensure!(api == input, "use the exact canonical API selector {api:?}");
    Ok(api)
}

/// Repeating a confirmed command leaves leases and progress intact.
pub fn already_confirmed(state: &RewriteState, options: &ImplementerConfirmOptions) -> bool {
    // Repeating a confirmed command does not allocate new leases or clear progress.
    state
        .implementers
        .as_ref()
        .and_then(|pool| pool.slots.get(&options.slot_id))
        .is_some_and(|slot| {
            slot.agent_handle.as_deref() == Some(&options.agent_handle)
                && slot.confirmed_batches.contains(&options.dispatch_id)
        })
}

pub fn confirm(
    root: &Path,
    state: &mut RewriteState,
    options: ImplementerConfirmOptions,
    dispatch: ImplementerDispatch,
    bind_review: impl Fn(
        &Path,
        &mut RewriteState,
        &RewriteWorkScope,
        Option<&Path>,
        bool,
    ) -> Result<bool>,
) -> Result<Vec<RewriteWorkScope>> {
    ensure!(
        dispatch.slot_id == options.slot_id && dispatch.dispatch_id == options.dispatch_id,
        "implementer dispatch is stale; refresh status"
    );
    state.implementers = pool::mapped_pool(state)?;
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
    let git_root = source_diff::git_text(&dispatch.worktree, &["rev-parse", "--show-toplevel"])?;
    ensure!(
        canonical_checkout == dispatch.worktree
            && std::fs::canonicalize(git_root.trim())? == canonical_checkout,
        "the fixed implementer path must be an actual Git worktree root, not an ordinary directory or symlink"
    );
    let mut scopes = Vec::new();
    for task in &dispatch.apis {
        let scope = work_scope(&task.api);
        binding::confirm_binding(
            state,
            &scope,
            &task.dispatch_id,
            &options.agent_handle,
            Some(dispatch.name.clone()),
        )?;
        bind_review(root, state, &scope, Some(&dispatch.worktree), true)?;
        feedback::apply_report(
            state,
            &scope,
            &feedback::RewriteWorkerReportOptions {
                delivery_commit: None,
                target_root: root.to_path_buf(),
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
    Ok(scopes)
}
struct LeaseIdentity<'a> {
    slot_id: usize,
    api: &'a str,
    dispatch: &'a str,
    generation: u64,
    handle: &'a str,
}

fn validate_task<'a>(
    state: &'a RewriteState,
    lease: LeaseIdentity<'_>,
    allow_retired: bool,
    active_scopes: &[RewriteWorkScope],
) -> Result<&'a ImplementerTask> {
    let LeaseIdentity {
        slot_id,
        api,
        dispatch,
        generation,
        handle,
    } = lease;
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
    let scope = work_scope(api);
    ensure!(
        active_scopes.contains(&scope),
        "API no longer needs implementation; report its task idle to release the lease"
    );
    let current = if active_scopes.contains(&scope) {
        binding::dispatch_view(state, scope, None).dispatch_id
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

pub fn report(
    root: &Path,
    state: &mut RewriteState,
    options: ImplementerReportOptions,
    api: String,
    active_scopes: &[RewriteWorkScope],
) -> Result<Option<RewriteWorkScope>> {
    validate_task(
        state,
        LeaseIdentity {
            slot_id: options.slot_id,
            api: &api,
            dispatch: &options.dispatch_id,
            generation: options.lease_generation,
            handle: &options.agent_handle,
        },
        options.activity == Activity::Idle,
        active_scopes,
    )?;
    let scope = work_scope(&api);
    let old_recording = state.implementers.as_ref().unwrap().slots[&options.slot_id].tasks[&api]
        .recording_run_id
        != state.recording_run_id;
    if old_recording
        || !active_scopes.contains(&scope)
        || binding::dispatch_view(state, scope.clone(), None).dispatch_id != options.dispatch_id
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
        return Ok(None);
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
    feedback::apply_report(
        state,
        &scope,
        &feedback::RewriteWorkerReportOptions {
            delivery_commit: None,
            target_root: root.to_path_buf(),
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
    Ok(Some(scope))
}

pub fn handoff(
    root: &Path,
    state: &mut RewriteState,
    options: ImplementerHandoffOptions,
    active_scopes: &[RewriteWorkScope],
    review_commit: impl Fn(&Path, &RewriteState, &RewriteWorkScope, &str) -> Result<RewriteReviewReport>,
    review_receipt: impl Fn(
        &Path,
        &RewriteState,
        &RewriteWorkScope,
        Option<&Path>,
    ) -> Result<RewriteReviewReport>,
) -> Result<Vec<RewriteWorkScope>> {
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
        let scope = work_scope(&api);
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
            state,
            LeaseIdentity {
                slot_id: options.slot_id,
                api: &api,
                dispatch: &item.dispatch_id,
                generation: item.lease_generation,
                handle: &options.agent_handle,
            },
            false,
            active_scopes,
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
            review_commit(root, state, &scope, commit)?
        } else {
            ensure!(
                !item.review_report.as_os_str().is_empty(),
                "delivery_commit is required for an implementer handoff"
            );
            review_receipt(root, state, &scope, Some(&item.review_report))?
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
        let frozen = delivery::freeze(root, &item.handoff_id, &report)?;
        feedback::apply_report(
            state,
            &scope,
            &feedback::RewriteWorkerReportOptions {
                delivery_commit: None,
                target_root: root.to_path_buf(),
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
    Ok(scopes)
}

pub fn reassign(state: &mut RewriteState, options: ImplementerReassignOptions) -> Result<()> {
    state.implementers = pool::mapped_pool(state)?;
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
    Ok(())
}
