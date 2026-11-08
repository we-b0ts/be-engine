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
            return if !request.matches(self, &self.exchanges[candidate]) {
                PreferredMatch::NotFound
            } else if let Some(blocker) = self.candidates.lane_blocker(&self.exchanges, candidate)
                && !serial_predecessors.is_some_and(|prefix| prefix.contains(&blocker))
            {
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
            |index| self.candidates.lane_blocker(&self.exchanges, index),
        )
    }
}

#[cfg(test)]
mod tests;
