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
    // Explicit API selection and a resumed round must share the same admission
    // boundary as status/next before starting any traffic execution.
    if super::review::pre_revalidation::required_action(target_root, state)?.is_some() {
        return Ok(false);
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn missing_final_review_stops_at_the_replay_execution_boundary() {
        let target = crate::rewrite::worker::tests::configured_target();
        let mut state = crate::rewrite::test_state();
        crate::rewrite::inventory::install(&mut state, vec!["GET /a".into()]).unwrap();
        state.api_inventory[0].status =
            crate::rewrite::model::RewriteApiStatus::RevalidationPending;
        state.phase = RewritePhase::SliceComplete;
        state.current_api_index = None;
        assert!(crate::rewrite::inventory::revalidation_round::begin(
            &mut state
        ));
        // No case source is prepared: reaching execution setup would fail. The
        // final gate must stop even callers that already hold a round member.
        assert!(state.case_source.is_none());
        assert!(
            !run_and_transition(target.path(), &mut state, false)
                .await
                .unwrap()
        );
        assert!(state.attempts.is_empty());
    }
}
