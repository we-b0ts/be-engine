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
            |exchange, _| {
                exchange.status.is_available()
                    && (exchange.record.lifecycle_cleanup
                        || exchange.record.native.response_kind == "error"
                        || exchange.record.native.outcome.termination().is_some()
                        || exchange.record.native.outcome.is_client_terminated())
                    && self
                        .connection_scopes
                        .matches(exchange, active_case_id, connection)
                    && target_matches(
                        target,
                        &exchange.record.native.target_host,
                        exchange.record.native.target_port,
                    )
                    && exchange.record.native.resp_version == resp_version
                    && exchange.record.native.database == database
                    && normalize_optional(username)
                        == normalize_optional(exchange.record.native.username.as_deref())
                    && exchange
                        .record
                        .native
                        .command
                        .eq_ignore_ascii_case(&command.name)
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
                .bind(&self.exchanges[index], active_case_id, connection);
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
            publish_duration_ms: exchange.record.native.duration_ms,
            rule_ids: Vec::new(),
            index,
            connection_id: exchange.record.native.connection_id,
            response,
            timing: exchange.timing,
            requires_binding,
            report: CommandMatchedReport {
                case_id: active_case_id.map(ToOwned::to_owned),
                source: exchange.source,
                index,
                target: target.clone(),
                connection_id: exchange.record.native.connection_id,
                sequence: exchange.record.native.sequence,
                command: exchange.record.native.command.clone(),
                shared_origin: None,
                target_event_index: Some(target_event_index),
            },
        })
    }
}
