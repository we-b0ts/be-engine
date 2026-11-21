use std::path::Path;

use anyhow::{Context, Result, ensure};

use super::{model::*, planning};
use crate::{model::RewriteActionEnvelope, review, store::RewriteStore, worker};
use traffic_rewrite_agents::implementer::leases;
use worker::model::RewriteWorkerActivity as Activity;

fn load(root: &Path) -> Result<(std::path::PathBuf, RewriteStore)> {
    crate::purpose::require_work_branch(root)?;
    let (root, _) = crate::e2e_run::resolve_project(root)?;
    let store = RewriteStore::new(&root)?;
    Ok((root, store))
}

pub fn confirm(options: ImplementerConfirmOptions) -> Result<RewriteActionEnvelope> {
    let (root, store) = load(&options.target_root)?;
    worker::validate_identity("implementer handle", &options.agent_handle, 4096)?;
    let lock = worker::events::lock(&root)?;
    let mut state = store
        .load()?
        .context("rewrite workflow is not initialized")?;
    if leases::already_confirmed(&state, &options) {
        drop(lock);
        return worker::runtime::current_envelope(&root);
    }
    let dispatch = planning::dispatch_for_slot(&root, &state, &options.group_id, options.slot_id)?
        .context("this group has no dispatchable APIs")?;
    let scopes = leases::confirm(&root, &mut state, options, dispatch, review::bind)?;
    worker::events::publish_many(&root, &state, &scopes)?;
    drop(lock);
    worker::runtime::current_envelope(&root)
}

pub fn report(options: ImplementerReportOptions) -> Result<RewriteActionEnvelope> {
    let api = leases::canonical_api(&options.api)?;
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
    let active_scopes = worker::runtime::scopes(&state);
    if let Some(scope) = leases::report(&root, &mut state, options, api, &active_scopes)? {
        worker::events::publish(&root, &state, &scope)?;
    } else {
        worker::events::publish_many(&root, &state, &[])?;
    }
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
    let active_scopes = worker::runtime::scopes(&state);
    let scopes = leases::handoff(
        &root,
        &mut state,
        options,
        &active_scopes,
        review::delivery::worker,
        review::accept_handoff,
    )?;
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
    leases::reassign(&mut state, options)?;
    worker::events::publish_many(&root, &state, &[])?;
    drop(lock);
    worker::runtime::current_envelope(&root)
}
