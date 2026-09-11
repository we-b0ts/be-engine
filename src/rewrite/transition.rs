use std::path::Path;

use anyhow::{Context, Result, ensure};

use super::model::{RewriteAttemptDelta, RewriteAttemptSummary, RewritePhase, RewriteState};
use super::{artifacts, fingerprint, issue};
use crate::{E2eApiRunResult, ManagedRecordingOperation};

#[derive(Debug, Clone, Copy)]
pub(super) enum AttemptTransition {
    Append,
    ReclassifyCurrent,
}

pub(super) fn from_e2e_result(
    target_root: &Path,
    state: &mut RewriteState,
    result: &E2eApiRunResult,
    transition: AttemptTransition,
) -> Result<()> {
    let target_fingerprint = fingerprint::repository_fingerprint(target_root)?;
    let summary = RewriteAttemptSummary {
        attempt: result.attempt,
        passed: result.passed,
        gates: result.gates.clone(),
        counts: result.diagnosis.counts.clone(),
    };
    match transition {
        AttemptTransition::Append => state.attempts.push(summary),
        AttemptTransition::ReclassifyCurrent => {
            let current = state
                .attempts
                .last_mut()
                .context("rewrite workflow has no focused attempt to reclassify")?;
            ensure!(
                current.attempt == summary.attempt,
                "focused evidence attempt changed before process-owned-rule reclassification"
            );
            *current = summary;
        }
    }
    state.attempt_delta = current_attempt_delta(&state.attempts);
    state.target_fingerprint = Some(target_fingerprint.clone());
    state.e2e_current = result.passed;
    state.comparison_current = false;
    state.route = None;
    state.system_repair_accepted = false;
    state.rule_plan = None;
    state.dependency_rule_plan = None;
    state.recorder_capture_plan = None;
    if result.passed {
        state.active_issue = None;
        if state.require_comparison {
            state.phase = RewritePhase::ComparisonRecordingRequired;
            state.comparison_run_id = Some(artifacts::allocate_run_id(
                target_root,
                ManagedRecordingOperation::RecordComparison,
            )?);
        } else {
            state.comparison_run_id = None;
            state.comparison_rejection = None;
            // Reclassification can run on a temporarily selected parked slice.
            // Inventory scheduling must wait for the root coordinator transition.
            state.phase = RewritePhase::SliceComplete;
        }
    } else {
        state.active_issue = Some(issue::from_e2e(&state.api, result, target_fingerprint));
        state.phase = RewritePhase::ImplementationRequired;
    }
    state.bump();
    Ok(())
}

pub(super) fn replay_completion_pending(state: &RewriteState) -> bool {
    !state.require_comparison
        && matches!(
            state.phase,
            RewritePhase::SliceComplete | RewritePhase::ComparisonRecordingRequired
        )
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
    state.comparison_run_id = None;
    state.comparison_rejection = None;
    if !state.e2e_current || state.target_fingerprint.as_deref() != Some(current.as_str()) {
        state.phase = RewritePhase::ApiPending;
        state.e2e_current = false;
        state.target_fingerprint = None;
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
