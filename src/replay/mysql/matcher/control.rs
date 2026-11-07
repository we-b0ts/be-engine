//! Preserve recorded connection-control failures without requiring SQL text.
use super::*;

impl ReplayState {
    pub(in crate::replay) fn match_mysql_control(
        &mut self,
        case: Option<&str>,
        identity: &ReplaySessionIdentity,
        command: &str,
        argument: Option<&str>,
    ) -> Option<MatchedExchange> {
        if !matches!(command, "COM_PING" | "COM_INIT_DB") {
            return None;
        }
        for source in [ReplaySource::Case, ReplaySource::Startup] {
            let index = self.mysql.exchanges.iter().position(|exchange| {
                exchange.source.matches_scope(source)
                    && exchange.status.is_available()
                    && exchange.record.command == command
                    && exchange.record.sql.as_deref() == argument
                    && active_case_matches(case, exchange)
                    && identity_matches_exchange(identity, &exchange.identity)
            });
            let Some(index) = index else {
                continue;
            };
            let exchange = &mut self.mysql.exchanges[index];
            let kind = if exchange.record.outcome.is_client_terminated()
                && !exchange.record.lifecycle_cleanup
            {
                crate::replay::admission::ClaimKind::ClientTermination
            } else {
                crate::replay::admission::ClaimKind::Response
            };
            let claim = self
                .mysql
                .lifecycle
                .claim(index, &mut exchange.status, kind)?;
            let matched = MatchedExchange {
                deferred_prefix: None,
                target_observation_id: self.mysql.request_observation_id.clone(),
                claim,
                hypothesis_owner: self
                    .replay_policy
                    .as_ref()
                    .map(|p| p.request_contracts.clone()),
                transaction_owner: None,
                value_delivery: None,
                time_copy_delivery: None,
                source: exchange.source,
                index,
                record: exchange.record.clone(),
                timing: exchange.timing,
                report: MatchedQueryReport {
                    source_connection_id: exchange.record.connection_id,
                    source_query_sequence: exchange.record.query_sequence,
                    case_id: case.map(ToOwned::to_owned),
                    target: Some(exchange.identity.target.clone()),
                    database: exchange.identity.database.clone(),
                    username: exchange.identity.username.clone(),
                    source: exchange.source,
                    index,
                    command: command.into(),
                    sql: argument.map(str::to_owned),
                    params: None,
                    status: exchange.record.response.status.clone(),
                    target_event_index: self.mysql.events.request_order.latest(case),
                },
            };
            self.refresh_mysql_global_report(index);
            return Some(matched);
        }
        None
    }
}
