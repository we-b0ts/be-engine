//! Engine-owned API assistance timing and serialized diagnostic batches. The
//! coordinator submits one runtime task per batch and forwards per-API reports.
use std::path::Path;

use super::model::{RewriteAction, RewriteActionEnvelope, RewriteApiStatus, RewriteState};
use super::{RewriteWorkScope, action, store::RewriteStore, worker};
use anyhow::{Context, Result};

pub(super) mod model;
use model::*;

use traffic_rewrite_agents::expert::assignment;

pub(super) fn inventory(root: &Path, state: &RewriteState) -> Vec<RewriteExpertInventoryItem> {
    traffic_rewrite_agents::expert::inventory::inventory(
        root,
        state,
        &worker::runtime::scopes(state),
        verified,
        action::command,
    )
}

pub(super) fn required_action(
    root: &Path,
    state: &RewriteState,
    api: Option<&str>,
) -> Option<RewriteAction> {
    let item = inventory(root, state)
        .into_iter()
        .filter(|item| {
            api.is_none_or(|api| {
                item.expert
                    .apis
                    .iter()
                    .any(|item| item.work_scope.binding_key() == api)
            }) && matches!(
                item.expert.state,
                RewriteExpertState::PrepareRequired
                    | RewriteExpertState::DispatchRequired
                    | RewriteExpertState::CloseRequired
            )
        })
        .min_by_key(|item| match item.expert.state {
            RewriteExpertState::CloseRequired => 0,
            RewriteExpertState::DispatchRequired => 1,
            _ => 2,
        })?;
    let summary = match item.expert.state {
        RewriteExpertState::CloseRequired => "the assigned API has passed verification. Do not dispatch or resume an expert. Query the retained expert task; stop it if still running or queued, and confirm it has ended before executing commands.close_expert. If an accepted task was not yet confirmed, recover it and use commands.confirm_expert first; if no task was submitted, close the reservation directly. Retain late findings as reference only; do not forward them as new API work. Closing releases the expert slot and preserves one-time coverage",
        RewriteExpertState::PrepareRequired => "only one unfinished API remains, its implementer is running, and more than two hours have passed since its last integrated code delivery (or first binding before any code integration). Execute commands.prepare to reserve it as one diagnostic batch. Do not create an expert until the reserved batch returns dispatch_required",
        _ => "dispatch exactly one api-expert for all APIs in details.apis. Recover any existing task for expert_id before submitting; never dispatch twice. The expert uses each API's commands.evidence and worktree read-only and returns per-API findings to the coordinator. Confirm the accepted task, including queued tasks, through commands.confirm_expert. Continue engine work; forward each API's report to its retained implementer and acknowledge each delivery through inventory.experts[].apis[].commands.report_delivered",
    }.to_string();
    Some(RewriteAction::ExpertRequired {
        summary,
        execution_mode: None,
        expert: item.expert,
        commands: item.commands,
    })
}

pub(super) fn counts(state: &RewriteState) -> (usize, usize, usize) {
    let items = inventory(Path::new("."), state);
    let mut counts = (0, 0, 0);
    for item in items {
        match item.expert.state {
            RewriteExpertState::PrepareRequired | RewriteExpertState::DispatchRequired => {
                counts.0 += 1
            }
            RewriteExpertState::Confirmed => counts.1 += 1,
            RewriteExpertState::CloseRequired => counts.2 += 1,
            _ => {}
        }
    }
    counts
}

pub fn prepare(options: RewriteExpertPrepareOptions) -> Result<RewriteActionEnvelope> {
    crate::purpose::require_work_branch(&options.target_root)?;
    let (root, _) = crate::e2e_run::resolve_project(&options.target_root)?;
    let store = RewriteStore::new(&root)?;
    let lock = worker::events::lock(&root)?;
    let mut state = store
        .load()?
        .context("rewrite workflow is not initialized")?;
    let scopes = worker::runtime::scopes(&state);
    if let Some(apis) = assignment::prepare(&mut state, &options, scopes)? {
        publish_batch(&root, &state, &apis)?;
    }
    drop(lock);
    worker::runtime::current_envelope(&root)
}

pub fn confirm(options: RewriteExpertOptions) -> Result<RewriteActionEnvelope> {
    crate::purpose::require_work_branch(&options.target_root)?;
    let (root, _) = crate::e2e_run::resolve_project(&options.target_root)?;
    worker::validate_identity("expert handle", &options.agent_handle, 4096)?;
    let store = RewriteStore::new(&root)?;
    let lock = worker::events::lock(&root)?;
    let mut state = store
        .load()?
        .context("rewrite workflow is not initialized")?;
    if let Some(apis) = assignment::confirm(&mut state, &options)? {
        publish_batch(&root, &state, &apis)?;
    }
    drop(lock);
    worker::runtime::current_envelope(&root)
}

pub fn delivered(options: RewriteExpertDeliveryOptions) -> Result<RewriteActionEnvelope> {
    let (root, _) = crate::e2e_run::resolve_project(&options.expert.target_root)?;
    worker::validate_identity("expert handle", &options.expert.agent_handle, 4096)?;
    worker::validate_identity("expert report id", &options.report_id, 4096)?;
    worker::validate_identity("report recipient handle", &options.recipient_handle, 4096)?;
    let store = RewriteStore::new(&root)?;
    let lock = worker::events::lock(&root)?;
    let mut state = store
        .load()?
        .context("rewrite workflow is not initialized")?;
    if let Some(apis) = assignment::delivered(&mut state, options, verified)? {
        publish_batch(&root, &state, &apis)?;
    }
    drop(lock);
    worker::runtime::current_envelope(&root)
}

pub(crate) fn verified(state: &RewriteState, api: &str) -> bool {
    super::inventory::details(state)
        .items
        .iter()
        .any(|item| item.api == api && item.status == RewriteApiStatus::Complete)
}

/// Acknowledge runtime termination (or a reservation that never spawned a task).
/// The engine owns eligibility; only the coordinator can observe runtime exit.
pub fn close(options: RewriteExpertCloseOptions) -> Result<RewriteActionEnvelope> {
    let (root, _) = crate::e2e_run::resolve_project(&options.target_root)?;
    if let Some(handle) = &options.agent_handle {
        worker::validate_identity("expert handle", handle, 4096)?;
    }
    let store = RewriteStore::new(&root)?;
    let lock = worker::events::lock(&root)?;
    let mut state = store
        .load()?
        .context("rewrite workflow is not initialized")?;
    if let Some(apis) = assignment::close(&mut state, &options, verified)? {
        publish_batch(&root, &state, &apis)?;
    }
    drop(lock);
    worker::runtime::current_envelope(&root)
}

fn publish_batch(root: &Path, state: &RewriteState, apis: &[String]) -> Result<()> {
    worker::events::publish_many(
        root,
        state,
        &apis
            .iter()
            .map(|api| RewriteWorkScope::Api { api: api.clone() })
            .collect::<Vec<_>>(),
    )
}
