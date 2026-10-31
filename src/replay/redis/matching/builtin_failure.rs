//! Recorded builtin errors keep native auth/session and lane admission.
use super::*;

impl RedisReplayState {
    #[allow(clippy::too_many_arguments)]
    pub(in crate::replay::redis) fn match_redis_builtin_failure(
        &mut self,
        active_case_id: Option<&str>,
        target: &TargetKey,
        connection: TargetConnection,
        resp_version: u8,
        database: i64,
        username: Option<&str>,
        command: &RedisCommand,
    ) -> Option<MatchedRedisExchange> {
        self.candidates.register(&self.exchanges);
        let case_candidates = self.candidates.select(
            ReplaySource::Case,
            active_case_id,
            target,
            resp_version,
            database,
            username,
            &command.name,
        );
        let run_candidates = self.candidates.select(
            ReplaySource::Startup,
            None,
            target,
            resp_version,
            database,
            username,
            &command.name,
        );
        let index = match preferred_match_indexed_with_priority(
            &self.exchanges,
            active_case_id,
            case_candidates,
            run_candidates,
            |exchange| {
                exchange.status.is_available()
                    && (exchange.record.lifecycle_cleanup
                        || exchange.record.response_kind == "error"
                        || exchange.record.outcome.termination().is_some()
                        || exchange.record.outcome.is_client_terminated())
                    && self
                        .connection_scopes
                        .matches(exchange, active_case_id, connection)
                    && target_matches(
                        target,
                        &exchange.record.target_host,
                        exchange.record.target_port,
                    )
                    && exchange.record.resp_version == resp_version
                    && exchange.record.database == database
                    && normalize_optional(username)
                        == normalize_optional(exchange.record.username.as_deref())
                    && exchange.record.command.eq_ignore_ascii_case(&command.name)
                    && (matches!(command.name.as_str(), "AUTH" | "HELLO")
                        || exchange.args == command.args)
            },
            |_| true,
            |index| self.candidates.lane_blocker(&self.exchanges, index),
        ) {
            PreferredMatch::Matched(index) => index,
            PreferredMatch::LaneBlocked { .. } | PreferredMatch::NotFound => return None,
        };
        let response = self.exchanges[index].response_bytes().ok()?;
        let target_event_index = self.events.request_order.reserve(active_case_id);
        let requires_binding =
            self.connection_scopes
                .claim(&self.exchanges[index], active_case_id, connection);
        let exchange = &mut self.exchanges[index];
        let kind = if exchange.timing.outcome().is_client_terminated()
            && !exchange.record.lifecycle_cleanup
        {
            ClaimKind::ClientTermination
        } else {
            ClaimKind::Response
        };
        let ticket = self.lifecycle.claim(index, &mut exchange.status, kind)?;
        exchange.claim = Some(ticket.observer());
        Some(MatchedRedisExchange {
            claim: Claim::Finite(ticket),
            refresh: None,
            observation: None,
            append: None,
            unified_delivery: None,
            read_back: None,
            time_read: None,
            time_write: None,
            rpc_push: None,
            rpc_response: None,
            adapter_echo: None,
            publish_duration_ms: exchange.record.duration_ms,
            rule_ids: Vec::new(),
            index,
            connection_id: exchange.record.connection_id,
            response,
            timing: exchange.timing,
            requires_binding,
            report: CommandMatchedReport {
                case_id: active_case_id.map(ToOwned::to_owned),
                source: exchange.source,
                index,
                target: target.clone(),
                connection_id: exchange.record.connection_id,
                sequence: exchange.record.sequence,
                command: exchange.record.command.clone(),
                shared_origin: None,
                target_event_index: Some(target_event_index),
            },
        })
    }
}
