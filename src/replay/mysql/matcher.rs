use super::*;

#[derive(Debug, Default)]
pub(in crate::replay) struct MysqlReplayState {
    pub(in crate::replay) exchanges: Vec<ReplayExchange>,
    pub(in crate::replay) events: ReplayEvents,
}

impl ReplayState {
    pub(in crate::replay) fn record_connection(
        &mut self,
        peer_addr: SocketAddr,
        target: Option<&TargetKey>,
        database: Option<String>,
        username: Option<String>,
    ) {
        self.mysql.events.connections += 1;
        self.mysql.events.connection_events.push(ConnectionReport {
            peer_addr: peer_addr.to_string(),
            target: target.cloned(),
            database,
            username,
        });
    }

    pub(in crate::replay) fn record_builtin(
        &mut self,
        identity: &ReplaySessionIdentity,
        command: &str,
        sql: Option<&str>,
        reason: &str,
    ) {
        let recorded_match = self.consume_builtin_exchange(identity, command, sql);
        self.mysql.events.builtin_queries.push(QueryReport {
            case_id: self.active_case_id.clone(),
            target: identity.target.clone(),
            database: identity.database.clone(),
            username: identity.username.clone(),
            command: command.to_string(),
            sql: sql.map(ToOwned::to_owned),
            params: None,
            reason: reason.to_string(),
            recorded_source: recorded_match.map(|(source, _)| source),
            recorded_index: recorded_match.map(|(_, index)| index),
        });
    }

    pub(in crate::replay) fn record_unsupported(
        &mut self,
        identity: &ReplaySessionIdentity,
        command: &str,
        sql: Option<&str>,
        params: Option<&[RecordedMysqlValue]>,
        reason: &str,
    ) {
        self.mysql.events.unsupported_commands.push(QueryReport {
            case_id: self.active_case_id.clone(),
            target: identity.target.clone(),
            database: identity.database.clone(),
            username: identity.username.clone(),
            command: command.to_string(),
            sql: sql.map(ToOwned::to_owned),
            params: params.map(ToOwned::to_owned),
            reason: reason.to_string(),
            recorded_source: None,
            recorded_index: None,
        });
    }

    pub(in crate::replay) fn record_unmatched(
        &mut self,
        identity: &ReplaySessionIdentity,
        command: &str,
        sql: Option<&str>,
        params: Option<&[RecordedMysqlValue]>,
        reason: &str,
    ) {
        self.mysql.events.unmatched_queries.push(QueryReport {
            case_id: self.active_case_id.clone(),
            target: identity.target.clone(),
            database: identity.database.clone(),
            username: identity.username.clone(),
            command: command.to_string(),
            sql: sql.map(ToOwned::to_owned),
            params: params.map(ToOwned::to_owned),
            reason: reason.to_string(),
            recorded_source: None,
            recorded_index: None,
        });
    }

    pub(in crate::replay) fn record_metadata_warning(&mut self, warning: String) {
        self.mysql.events.metadata_warnings.push(warning);
    }

    pub(in crate::replay) fn match_exchange(
        &mut self,
        identity: &ReplaySessionIdentity,
        command: &str,
        sql: Option<&str>,
        params: Option<&[RecordedMysqlValue]>,
    ) -> Option<MatchedExchange> {
        let normalized_sql = sql.map(normalize_sql);
        let active_case_id = self.active_case_id.clone();
        for (index, exchange) in self.mysql.exchanges.iter_mut().enumerate() {
            if exchange.consumed || exchange.record.command != command {
                continue;
            }
            if !active_case_matches(active_case_id.as_deref(), exchange) {
                continue;
            }
            if !identity_matches_exchange(identity, &exchange.identity) {
                continue;
            }
            let Some(recorded_sql) = exchange.record.sql.as_deref().map(normalize_sql) else {
                continue;
            };
            if Some(recorded_sql) != normalized_sql {
                continue;
            }
            if !params_match(exchange.record.params.as_deref(), params) {
                continue;
            }
            exchange.consumed = true;
            let matched = MatchedQueryReport {
                case_id: exchange.case_id.clone(),
                target: Some(exchange.identity.target.clone()),
                database: exchange.identity.database.clone(),
                username: exchange.identity.username.clone(),
                source: exchange.source,
                index,
                command: command.to_string(),
                sql: sql.map(ToOwned::to_owned),
                params: params.map(ToOwned::to_owned),
                status: exchange.record.response.status.clone(),
            };
            self.mysql.events.matched_queries.push(matched);
            return Some(MatchedExchange {
                source: exchange.source,
                index,
                record: exchange.record.clone(),
            });
        }
        None
    }

    pub(in crate::replay) fn consume_builtin_exchange(
        &mut self,
        identity: &ReplaySessionIdentity,
        command: &str,
        sql: Option<&str>,
    ) -> Option<(ReplaySource, usize)> {
        let normalized_sql = sql.map(normalize_sql);
        let active_case_id = self.active_case_id.clone();
        for (index, exchange) in self.mysql.exchanges.iter_mut().enumerate() {
            if exchange.consumed || exchange.record.command != command {
                continue;
            }
            if !active_case_matches(active_case_id.as_deref(), exchange) {
                continue;
            }
            if !identity_matches_exchange(identity, &exchange.identity) {
                continue;
            }
            let recorded_sql = exchange.record.sql.as_deref().map(normalize_sql);
            if recorded_sql != normalized_sql {
                continue;
            }
            exchange.consumed = true;
            return Some((exchange.source, index));
        }
        None
    }

    pub(in crate::replay) fn statement_metadata(
        &self,
        identity: &ReplaySessionIdentity,
        sql: &str,
    ) -> StatementMetadata {
        let normalized_sql = normalize_sql(sql);
        for exchange in &self.mysql.exchanges {
            if exchange.record.command != "COM_STMT_EXECUTE" {
                continue;
            }
            if !self.active_case_matches(exchange) {
                continue;
            }
            if !identity_matches_exchange(identity, &exchange.identity) {
                continue;
            }
            if exchange
                .record
                .sql
                .as_deref()
                .is_some_and(|recorded_sql| normalize_sql(recorded_sql) == normalized_sql)
            {
                return StatementMetadata {
                    param_count: exchange
                        .record
                        .params
                        .as_ref()
                        .map_or_else(|| count_sql_placeholders(sql), Vec::len),
                    columns: exchange.record.response.columns.clone(),
                };
            }
        }
        StatementMetadata {
            param_count: count_sql_placeholders(sql),
            columns: Vec::new(),
        }
    }

    pub(in crate::replay) fn unused_exchanges(
        &self,
        source: ReplaySource,
    ) -> Vec<RecordedExchangeSummary> {
        self.mysql
            .exchanges
            .iter()
            .enumerate()
            .filter(|(_, exchange)| exchange.source == source && !exchange.consumed)
            .map(|(index, exchange)| RecordedExchangeSummary {
                index,
                case_id: exchange.case_id.clone(),
                target: Some(exchange.identity.target.clone()),
                database: exchange.identity.database.clone(),
                username: exchange.identity.username.clone(),
                command: exchange.record.command.clone(),
                sql: exchange.record.sql.clone(),
                status: exchange.record.response.status.clone(),
            })
            .collect()
    }

    fn active_case_matches(&self, exchange: &ReplayExchange) -> bool {
        active_case_matches(self.active_case_id.as_deref(), exchange)
    }
}
