//! Compatibility admission for the retired coordinator quality execution step.
//! Delivery review checks source and isolation. Final review records the
//! agent-owned quality_check; this module only reads admitted receipts.
use super::model::{RewriteAction, RewriteActionEnvelope, RewritePhase, RewriteState};
use super::store::RewriteStore;
use super::{action, review, traffic_operation, worker};
use anyhow::{Context, Result, ensure};
use std::path::Path;

#[derive(Debug, Clone)]
pub struct RewriteTargetQualityOptions {
    pub target_root: std::path::PathBuf,
    pub gate_id: String,
    pub api: super::RewriteApiSelector,
    pub hardcode_ai_verified: Vec<String>,
}

/// Legacy command compatibility. Never starts a compiler, scanner, or detached check.
pub fn run(options: RewriteTargetQualityOptions) -> Result<RewriteActionEnvelope> {
    let (root, project) = crate::e2e_run::resolve_project(&options.target_root)?;
    let store = RewriteStore::new(&root)?;
    let _lock = store.lock()?;
    ensure!(
        matches!(
            traffic_operation::state(&root)?,
            traffic_operation::TrafficOperationState::Absent
        ),
        "quality receipt admission must wait for traffic verification"
    );
    let state = store
        .load()?
        .context("rewrite workflow is not initialized")?;
    let scoped = super::api_selector::scoped(&state, &options.api.to_string())?;
    let scope = super::RewriteWorkScope::Api {
        api: scoped.api.clone(),
    };
    if let Some(required) = worker::scheduler::acceptance_gate(&root, &scoped, &scope) {
        return Ok(action::envelope(&root, &scoped, required));
    }
    if let Some(required) = review::gate(&root, &state, &project.pr_base)? {
        return Ok(action::envelope(&root, &scoped, required));
    }
    Ok(action::advance_envelope(
        &root,
        &scoped,
        "committed delivery is ready; advance coordinator verification without source review"
            .into(),
    ))
}

pub(super) fn status_action(root: &Path, state: &RewriteState) -> Result<Option<RewriteAction>> {
    if state.phase != RewritePhase::ImplementationRequired
        || !worker::runtime::acceptance_ready(
            state,
            &super::RewriteWorkScope::Api {
                api: state.api.clone(),
            },
        )
    {
        return Ok(None);
    }
    let (_, project) = crate::e2e_run::resolve_project(root)?;
    if let Some(required) = review::gate(root, state, &project.pr_base)? {
        return Ok(Some(required));
    }
    if super::engine_retry::pending(state, &state.active_slice) {
        return Ok(Some(action::state_action(root, state)));
    }
    Ok(Some(action::replay_advance(
        root,
        &state.api,
        "committed delivery is ready; advance coordinator verification without source review"
            .into(),
    )))
}
