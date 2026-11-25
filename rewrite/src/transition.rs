use std::path::Path;

use anyhow::Result;

use super::model::{RewriteAttemptSummary, RewritePhase, RewriteState};
use super::{fingerprint, issue};
use crate::E2eApiRunResult;

pub(super) fn from_e2e_result(
    target_root: &Path,
    state: &mut RewriteState,
    result: &E2eApiRunResult,
) -> Result<()> {
    let api = state.api.clone();
    let transition = state.begin_execution(result.attempt)?;
    let target_fingerprint = fingerprint::repository_fingerprint(target_root)?;
    let replay_identity = fingerprint::replay_identity(target_root)?;
    let summary = RewriteAttemptSummary {
        engine_fingerprint: result.engine_fingerprint.clone(),
        attempt: result.attempt,
        passed: result.passed,
        gates: result.gates.clone(),
        counts: result.diagnosis.counts.clone(),
    };
    let active_issue =
        (!result.passed).then(|| issue::from_e2e(&api, result, target_fingerprint.clone()));
    transition.apply(traffic_rewrite_core::ExecutionUpdate {
        summary,
        passed: result.passed,
        target_fingerprint,
        replay_identity,
        issue: active_issue,
    })?;
    if !result.passed {
        super::inventory::revalidation_round::finish(state, &api);
    }
    state.bump();
    Ok(())
}

pub(super) fn replay_completion_pending(state: &RewriteState) -> bool {
    state.replay_completion_pending()
}

pub(super) fn complete_replay_if_ready(
    target_root: &Path,
    state: &mut RewriteState,
) -> Result<bool> {
    if !replay_completion_pending(state) {
        return Ok(false);
    }
    let current = fingerprint::repository_fingerprint(target_root)?;
    let replay_identity = fingerprint::replay_identity(target_root)?;
    let replay_changed = state
        .replay_identity
        .as_ref()
        .is_some_and(|executed| executed != &replay_identity);
    if !state.e2e_current
        || state.target_fingerprint.as_deref() != Some(current.as_str())
        || replay_changed
    {
        state.phase = RewritePhase::ApiPending;
        state.e2e_current = false;
        state.target_fingerprint = None;
        state.replay_identity = None;
    } else {
        state.phase = RewritePhase::SliceComplete;
        if !super::inventory::complete_current_and_advance(state)? {
            super::recording::begin_pending_capture_refresh(target_root, state)?;
        }
    }
    state.bump();
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn changed_replay_identity_cannot_complete_a_passing_slice() {
        let target = crate::worker::tests::configured_target();
        let root = target.path();
        let mut state = crate::test_state();
        super::super::inventory::install(&mut state, vec!["GET /api".into()]).unwrap();
        state.phase = RewritePhase::SliceComplete;
        state.e2e_current = true;
        state.target_fingerprint = Some(fingerprint::repository_fingerprint(root).unwrap());
        state.replay_identity = Some("stale-replay-identity".into());
        assert!(complete_replay_if_ready(root, &mut state).unwrap());
        assert_eq!(state.phase, RewritePhase::ApiPending);
        assert!(!state.e2e_current);
        assert!(state.replay_identity.is_none());
        assert_eq!(state.current_api_index, Some(0));
    }
}
