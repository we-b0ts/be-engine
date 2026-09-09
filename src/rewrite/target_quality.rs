//! Compatibility admission for the retired coordinator quality execution step.
//! Complete checks run only through delivery-time review; this module reads receipts.
use super::model::{RewriteAction, RewriteActionEnvelope, RewritePhase, RewriteState};
use super::store::RewriteStore;
use super::{action, inventory, review, traffic_operation, worker};
use crate::RecordingApi;
use anyhow::{Context, Result, ensure};
use std::path::Path;

#[derive(Debug, Clone)]
pub struct RewriteTargetQualityOptions {
    pub target_root: std::path::PathBuf,
    pub gate_id: String,
    pub api: RecordingApi,
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
    let scoped = inventory::scoped(&state, Some(&options.api))?;
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
        "complete delivery quality receipt is current; advance coordinator verification".into(),
    ))
}

pub(super) fn status_action(root: &Path, state: &RewriteState) -> Result<Option<RewriteAction>> {
    if state.phase != RewritePhase::ImplementationRequired
        || state.process_outputs.current_id.is_some()
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
    Ok(Some(RewriteAction::AdvanceRequired {
        summary: "complete delivery quality receipt is current; advance coordinator verification"
            .into(),
        command: action::next_command_for_api(root, &state.api),
    }))
}
