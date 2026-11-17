//! Application diagnostic envelopes for the shared command candidate traversal.
use super::report::command::CommandMatchDiagnostic;
pub(crate) use traffic_replay::command::CommandExchangeScope;

pub(crate) fn unmatched_diagnostic<T: CommandExchangeScope, D>(
    exchanges: &[T],
    active_case_id: Option<&str>,
    mismatch_fields: impl Fn(&T) -> Vec<&'static str>,
) -> CommandMatchDiagnostic<D> {
    match traffic_replay::command::unmatched_fields(exchanges, active_case_id, mismatch_fields) {
        Some(fields) => CommandMatchDiagnostic::Mismatch {
            fields: fields.into_iter().map(ToOwned::to_owned).collect(),
        },
        None => CommandMatchDiagnostic::NoScopedCandidate,
    }
}

pub(crate) fn lane_blocked_diagnostic<T: CommandExchangeScope, D>(
    exchanges: &[T],
    candidate: usize,
    blocker: usize,
) -> CommandMatchDiagnostic<D> {
    CommandMatchDiagnostic::LaneBlocked {
        candidate: Box::new(traffic_replay::command::exchange_ref(&exchanges[candidate])),
        blocked_by: Box::new(traffic_replay::command::exchange_ref(&exchanges[blocker])),
    }
}

#[cfg(test)]
pub(crate) use traffic_replay::command::preferred_match_with_priority;
