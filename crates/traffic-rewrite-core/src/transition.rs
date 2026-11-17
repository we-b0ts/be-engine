use anyhow::{Result, ensure};

use crate::{RewriteAttemptDelta, RewritePhase, RewriteState, WorkflowData};

#[derive(Debug, Clone, Copy)]
pub struct AttemptCounts {
    pub selected: usize,
    pub response_passed: usize,
    pub response_nonpassing: usize,
}

pub trait Attempt {
    fn attempt(&self) -> u64;
    fn counts(&self) -> AttemptCounts;
}

pub struct ExecutionUpdate<Data: WorkflowData> {
    pub summary: Data::AttemptSummary,
    pub passed: bool,
    pub target_fingerprint: String,
    pub replay_identity: String,
    pub issue: Option<Data::Issue>,
}

/// Holds exclusive state access while the application resolves the independently
/// observed execution inputs. State changes begin only when applying the result.
pub struct ExecutionTransition<'a, Data: WorkflowData> {
    state: &'a mut RewriteState<Data>,
    attempt: u64,
}

impl<Data: WorkflowData> RewriteState<Data> {
    pub fn begin_execution(&mut self, attempt: u64) -> Result<ExecutionTransition<'_, Data>> {
        ensure!(
            self.attempts
                .last()
                .is_none_or(|previous| attempt > previous.attempt()),
            "a new actual Replay attempt is required; a revised historical report cannot promote acceptance"
        );
        Ok(ExecutionTransition {
            state: self,
            attempt,
        })
    }

    pub fn replay_completion_pending(&self) -> bool {
        self.phase == RewritePhase::SliceComplete
            && self.current_api_index.is_some_and(|index| {
                self.api_inventory[index].status != crate::RewriteApiStatus::Complete
            })
    }
}

impl<Data: WorkflowData> ExecutionTransition<'_, Data> {
    pub fn apply(self, update: ExecutionUpdate<Data>) -> Result<()> {
        ensure!(
            update.summary.attempt() == self.attempt,
            "execution result differs from its admitted attempt"
        );
        ensure!(
            update.passed == update.issue.is_none(),
            "execution result and issue state disagree"
        );
        let state = self.state;
        state.attempts.push(update.summary);
        state.attempt_delta = current_attempt_delta::<Data>(&state.attempts);
        state.replay_identity = Some(update.replay_identity);
        state.target_fingerprint = Some(update.target_fingerprint);
        state.e2e_current = update.passed;
        state.engine_retry_running = false;
        state.route = None;
        state.system_repair_accepted = false;
        state.rule_replay_pending = false;
        state.rule_plan = None;
        state.dependency_rule_plan = None;
        state.recorder_capture_plan = None;
        state.active_issue = update.issue;
        state.phase = if update.passed {
            RewritePhase::SliceComplete
        } else {
            RewritePhase::ImplementationRequired
        };
        Ok(())
    }
}

fn current_attempt_delta<Data: WorkflowData>(
    attempts: &[Data::AttemptSummary],
) -> Option<RewriteAttemptDelta> {
    let [.., previous, current] = attempts else {
        return None;
    };
    let previous_counts = previous.counts();
    let current_counts = current.counts();
    if previous_counts.selected != current_counts.selected {
        return None;
    }
    let passed_delta =
        current_counts.response_passed as i64 - previous_counts.response_passed as i64;
    let nonpassing_delta =
        current_counts.response_nonpassing as i64 - previous_counts.response_nonpassing as i64;
    Some(RewriteAttemptDelta {
        previous_attempt: previous.attempt(),
        current_attempt: current.attempt(),
        response_passed_delta: passed_delta,
        response_nonpassing_delta: nonpassing_delta,
        improved: passed_delta > 0 || nonpassing_delta < 0,
        regressed: passed_delta < 0 || nonpassing_delta > 0,
    })
}
