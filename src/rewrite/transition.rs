use std::path::Path;

use anyhow::{Result, ensure};

use super::model::{RewriteAttemptDelta, RewriteAttemptSummary, RewritePhase, RewriteState};
use super::{fingerprint, issue};
use crate::E2eApiRunResult;

pub(super) fn from_e2e_result(
    target_root: &Path,
    state: &mut RewriteState,
    result: &E2eApiRunResult,
) -> Result<()> {
    ensure!(
        state
            .attempts
            .last()
            .is_none_or(|attempt| result.attempt > attempt.attempt),
        "a new actual Replay attempt is required; a revised historical report cannot promote acceptance"
    );
    let target_fingerprint = fingerprint::repository_fingerprint(target_root)?;
    let replay_identity = fingerprint::replay_identity(target_root)?;
    let summary = RewriteAttemptSummary {
        engine_fingerprint: result.engine_fingerprint.clone(),
        attempt: result.attempt,
        passed: result.passed,
        gates: result.gates.clone(),
        counts: result.diagnosis.counts.clone(),
    };
    state.attempts.push(summary);
    state.attempt_delta = current_attempt_delta(&state.attempts);
    state.replay_identity = Some(replay_identity);
    state.target_fingerprint = Some(target_fingerprint.clone());
    state.e2e_current = result.passed;
    state.engine_retry_running = false;
    state.route = None;
    state.system_repair_accepted = false;
    state.rule_replay_pending = false;
    state.rule_plan = None;
    state.dependency_rule_plan = None;
    state.recorder_capture_plan = None;
    if result.passed {
        state.active_issue = None;
        state.phase = RewritePhase::SliceComplete;
    } else {
        state.active_issue = Some(issue::from_e2e(&state.api, result, target_fingerprint));
        state.phase = RewritePhase::ImplementationRequired;
        let api = state.api.clone();
        super::inventory::revalidation_round::finish(state, &api);
    }
    state.bump();
    Ok(())
}

pub(super) fn replay_completion_pending(state: &RewriteState) -> bool {
    state.phase == RewritePhase::SliceComplete
        && state.current_api_index.is_some_and(|index| {
            state.api_inventory[index].status != super::model::RewriteApiStatus::Complete
        })
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
        .is_some_and(|executed| executed != &replay_identity)
        || state.replay_identity.is_none()
            && crate::config::regression::RegressionScope::load(target_root)?
                .replay_timing
                .is_some();
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

fn current_attempt_delta(attempts: &[RewriteAttemptSummary]) -> Option<RewriteAttemptDelta> {
    let [.., previous, current] = attempts else {
        return None;
    };
    if previous.counts.selected != current.counts.selected {
        return None;
    }
    let passed_delta =
        current.counts.response_passed as i64 - previous.counts.response_passed as i64;
    let nonpassing_delta =
        current.counts.response_nonpassing as i64 - previous.counts.response_nonpassing as i64;
    Some(RewriteAttemptDelta {
        previous_attempt: previous.attempt,
        current_attempt: current.attempt,
        response_passed_delta: passed_delta,
        response_nonpassing_delta: nonpassing_delta,
        improved: passed_delta > 0 || nonpassing_delta < 0,
        regressed: passed_delta < 0 || nonpassing_delta > 0,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn changed_replay_timing_cannot_complete_a_passing_slice() {
        let target = crate::rewrite::worker::tests::configured_target();
        let root = target.path();
        let mut state = crate::rewrite::test_state();
        super::super::inventory::install(&mut state, vec!["GET /api".into()]).unwrap();
        state.phase = RewritePhase::SliceComplete;
        state.e2e_current = true;
        state.target_fingerprint = Some(fingerprint::repository_fingerprint(root).unwrap());
        state.replay_identity = Some(fingerprint::replay_identity(root).unwrap());
        std::fs::write(
            root.join(crate::config::regression::PATH),
            "replay_timing: fast\n",
        )
        .unwrap();
        assert!(complete_replay_if_ready(root, &mut state).unwrap());
        assert_eq!(state.phase, RewritePhase::ApiPending);
        assert!(!state.e2e_current);
        assert!(state.replay_identity.is_none());
        assert_eq!(state.current_api_index, Some(0));
    }
}
