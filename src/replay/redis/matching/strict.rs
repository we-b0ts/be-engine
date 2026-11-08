//! The native strict predicate is shared by indexed traversal and its scan oracle.
use super::*;

struct Request<'a> {
    case: Option<&'a str>,
    target: &'a TargetKey,
    connection: TargetConnection,
    resp_version: u8,
    database: i64,
    username: Option<&'a str>,
    command: &'a str,
    args: &'a [Vec<u8>],
}

impl Request<'_> {
    fn matches(&self, state: &RedisReplayState, exchange: &ReplayExchange) -> bool {
        (exchange.status.is_available()
            || exchange.reusable_snapshot && exchange.status != ReplayExchangeStatus::Failed)
            && state
                .connection_scopes
                .matches(exchange, self.case, self.connection)
            && target_matches(
                self.target,
                &exchange.record.target_host,
                exchange.record.target_port,
            )
            && exchange.record.resp_version == self.resp_version
            && exchange.record.database == self.database
            && normalize_optional(self.username)
                == normalize_optional(exchange.record.username.as_deref())
            && exchange.record.command.eq_ignore_ascii_case(self.command)
            && state.arguments_match(exchange, self.args)
    }

    fn priority(&self, state: &RedisReplayState, exchange: &ReplayExchange) -> bool {
        !matches!(self.command, "SUBSCRIBE" | "PSUBSCRIBE" | "SSUBSCRIBE")
            || state.pubsub.is_callback_subscription(exchange)
    }
}

impl RedisReplayState {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn match_strict_redis(
        &self,
        case: Option<&str>,
        target: &TargetKey,
        connection: TargetConnection,
        resp_version: u8,
        database: i64,
        username: Option<&str>,
        command: &str,
        args: &[Vec<u8>],
        expected_index: Option<usize>,
        serial_predecessors: Option<&[usize]>,
        fast_socketio: bool,
    ) -> PreferredMatch {
        let request = Request {
            case,
            target,
            connection,
            resp_version,
            database,
            username,
            command,
            args,
        };
        if let Some(candidate) = expected_index {
            let blocker = if let Some(prefix) = serial_predecessors {
                self.candidates
                    .lane_blocker_excluding(&self.exchanges, candidate, prefix)
            } else {
                self.strict_lane_blocker(candidate, fast_socketio)
            };
            return if !request.matches(self, &self.exchanges[candidate]) {
                PreferredMatch::NotFound
            } else if let Some(blocker) = blocker {
                PreferredMatch::LaneBlocked { candidate, blocker }
            } else {
                PreferredMatch::Matched(candidate)
            };
        }
        let case_candidates = self.candidates.select(
            ReplaySource::Case,
            case,
            target,
            resp_version,
            database,
            username,
            command,
        );
        let run_candidates = self.candidates.select(
            ReplaySource::Startup,
            None,
            target,
            resp_version,
            database,
            username,
            command,
        );
        preferred_match_indexed_with_priority(
            &self.exchanges,
            case,
            case_candidates,
            run_candidates,
            |exchange| request.matches(self, exchange),
            |exchange| request.priority(self, exchange),
            |index| self.strict_lane_blocker(index, fast_socketio),
        )
    }

    fn strict_lane_blocker(&self, candidate: usize, fast_socketio: bool) -> Option<usize> {
        let blocker = self.candidates.lane_blocker(&self.exchanges, candidate)?;
        let publish = &self.exchanges[candidate];
        let deletion = &self.exchanges[blocker];
        // A zero-subscriber publish had no receiver in Source. Fast replay can
        // preserve the independent delivery of the exact publish and a proven
        // state deletion when they arrive in the opposite order on the pool.
        if fast_socketio
            && publish.source == ReplaySource::Case
            && deletion.source == ReplaySource::Case
            && publish.record.command == "PUBLISH"
            && publish.args.len() == 2
            && publish.response == b":0\r\n"
            && publish.record.replay_safe
            && publish.record.parse_warnings.is_empty()
            && publish.record.outcome == crate::DependencyExchangeOutcome::Response
            && !publish.record.lifecycle_cleanup
            && !self.connection_scopes.is_stateful(publish)
            && !self.pubsub.is_adapter_source(publish)
            && deletion.record.command == "DEL"
            && deletion.args.len() == 1
            && deletion.status.is_available()
            && self.is_observed_state_mutation(blocker)
        {
            return self
                .candidates
                .lane_blocker_excluding(&self.exchanges, candidate, &[blocker]);
        }
        Some(blocker)
    }
}

#[cfg(test)]
mod tests;
