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
        for source in [ReplaySource::Case, ReplaySource::Global] {
            let index = self.mysql.exchanges.iter().position(|exchange| {
                exchange.source == source
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
            exchange.status = if exchange.record.outcome.is_client_terminated() {
                ReplayExchangeStatus::AwaitingClientTermination
            } else {
                ReplayExchangeStatus::Responding
            };
            let matched = MatchedExchange {
                transaction_owner: None,
                value_delivery: None,
                identity_delivery: None,
                response_time_shift_rules: Vec::new(),
                source,
                index,
                record: exchange.record.clone(),
                timing: exchange.timing,
                report: MatchedQueryReport {
                    case_id: case.map(ToOwned::to_owned),
                    target: Some(exchange.identity.target.clone()),
                    database: exchange.identity.database.clone(),
                    username: exchange.identity.username.clone(),
                    source,
                    index,
                    command: command.into(),
                    sql: argument.map(str::to_owned),
                    params: None,
                    status: exchange.record.response.status.clone(),
                    target_event_index: None,
                },
            };
            self.refresh_mysql_global_report(index);
            return Some(matched);
        }
        None
    }
}
