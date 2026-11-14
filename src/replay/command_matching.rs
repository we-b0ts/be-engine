//! Application diagnostic envelopes for the shared command candidate traversal.
use super::report::command::CommandMatchDiagnostic;
pub(super) use traffic_replay::command::{
    CaseConnectionBinding, CommandExchangeScope, PreferredMatch, is_process_lane, preferred_match,
    preferred_match_indexed_with_priority,
};

pub(super) fn unmatched_diagnostic<T: CommandExchangeScope>(
    exchanges: &[T],
    active_case_id: Option<&str>,
    mismatch_fields: impl Fn(&T) -> Vec<&'static str>,
) -> CommandMatchDiagnostic {
    match traffic_replay::command::unmatched_fields(exchanges, active_case_id, mismatch_fields) {
        Some(fields) => CommandMatchDiagnostic::Mismatch {
            fields: fields.into_iter().map(ToOwned::to_owned).collect(),
        },
        None => CommandMatchDiagnostic::NoScopedCandidate,
    }
}

pub(super) fn lane_blocked_diagnostic<T: CommandExchangeScope>(
    exchanges: &[T],
    candidate: usize,
    blocker: usize,
) -> CommandMatchDiagnostic {
    CommandMatchDiagnostic::LaneBlocked {
        candidate: Box::new(traffic_replay::command::exchange_ref(&exchanges[candidate])),
        blocked_by: Box::new(traffic_replay::command::exchange_ref(&exchanges[blocker])),
    }
}

#[cfg(test)]
pub(super) use traffic_replay::command::preferred_match_with_priority;
