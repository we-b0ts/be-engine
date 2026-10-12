//! Coordinator Replay transaction: reserve engine retries before execution and retain failures.
use std::path::Path;

use anyhow::{Context, Result};

use super::{
    api_batch, engine_retry, fingerprint,
    model::{RewritePhase, RewriteState},
    store::RewriteStore,
};
use crate::E2eRunContext;

pub(super) async fn run_and_transition(
    target_root: &Path,
    state: &mut RewriteState,
    route_batch: bool,
) -> Result<bool> {
    let result = run_attempt_and_transition(target_root, state, route_batch).await;
    // Errors after reservation (including evidence publication) cannot refund a
    // permit or leave the old issue hidden as a running retry.
    if engine_retry::clear_running(state) {
        state.bump();
        RewriteStore::new(target_root)?.save(state)?;
    }
    result
}

async fn run_attempt_and_transition(
    target_root: &Path,
    state: &mut RewriteState,
    route_batch: bool,
) -> Result<bool> {
    let in_round = state.revalidation_round.is_some();
    let replay_target_fingerprint = fingerprint::repository_fingerprint(target_root)?;
    let case_source = state
        .case_source
        .clone()
        .context("rewrite workflow has no case source")?;
    let api = state
        .group_id
        .clone()
        .context("rewrite workflow has no prepared API group")?;
    let context = E2eRunContext {
        target_root: target_root.to_path_buf(),
        case_source,
        run_key: None,
    };
    let mut prepared = route_batch
        .then(|| api_batch::prepare(target_root, state))
        .transpose()?;
    let apis = prepared
        .as_ref()
        .map_or_else(|| vec![api.clone()], |batch| batch.apis.clone());
    if engine_retry::reserve(state, prepared.as_mut()) {
        state.bump();
        RewriteStore::new(target_root)?.save(state)?;
    }
    let results = crate::e2e_run::run_e2e_apis(context.clone(), &apis).await?;
    let current_target_fingerprint = fingerprint::repository_fingerprint(target_root)?;
    if current_target_fingerprint != replay_target_fingerprint {
        state.phase = RewritePhase::ApiPending;
        state.target_fingerprint = None;
        state.active_issue = None;
        state.rule_replay_pending = false;
        state.e2e_current = false;
        state.bump();
        return Ok(false);
    }
    let (_, _project) = crate::e2e_run::resolve_project(target_root)?;
    api_batch::apply_results(target_root, state, &results, prepared.as_ref())?;
    Ok(!results.is_empty()
        && (results.iter().all(|result| result.passed)
            || in_round && state.revalidation_round.is_some()))
}
