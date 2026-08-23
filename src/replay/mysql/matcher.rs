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
        if self.mysql.events.connection_events.len() < SUCCESS_DETAIL_LIMIT {
            self.mysql.events.connection_events.push(ConnectionReport {
                peer_addr: peer_addr.to_string(),
                target: target.cloned(),
                database,
                username,
            });
        }
    }

    pub(in crate::replay) fn record_builtin(
        &mut self,
        identity: &ReplaySessionIdentity,
        command: &str,
        sql: Option<&str>,
        reason: &str,
    ) {
        let recorded_match = self.consume_builtin_exchange(identity, command, sql);
        push_success_detail(
            &mut self.mysql.events.builtin_query_count,
            &mut self.mysql.events.builtin_queries,
            QueryReport {
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
            },
        );
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
        for source in [ReplaySource::Case, ReplaySource::Global] {
            for index in 0..self.mysql.exchanges.len() {
                let exchange = &self.mysql.exchanges[index];
                if exchange.source != source
                    || !exchange.status.is_available()
                    || exchange.record.command != command
                {
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
                let policy_decision = if let Some(policy) = &self.replay_policy {
                    let context = MysqlPolicyContext {
                        case_id: active_case_id.as_deref(),
                        identity,
                        command,
                        recorded_sql: exchange.record.sql.as_deref(),
                        sql,
                        recorded: exchange.record.params.as_deref(),
                        actual: params,
                    };
                    if Some(recorded_sql) != normalized_sql
                        && !policy.allows_mysql_sql_difference(&context)
                    {
                        continue;
                    }
                    match policy.preview_mysql(&context, Utc::now()) {
                        Ok(decision) => decision,
                        Err(_) => continue,
                    }
                } else if Some(recorded_sql) != normalized_sql {
                    continue;
                } else if params_match(exchange.record.params.as_deref(), params) {
                    DependencyRuleDecision::default()
                } else {
                    continue;
                };
                let exchange = self.mysql.exchanges[index].clone();
                self.mysql.exchanges[index].status =
                    if exchange.record.outcome.is_client_terminated() {
                        ReplayExchangeStatus::AwaitingClientTermination
                    } else {
                        ReplayExchangeStatus::Responding
                    };
                if let Some(policy) = &mut self.replay_policy {
                    policy.commit(active_case_id.as_deref(), policy_decision);
                }
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
                return Some(MatchedExchange {
                    source: exchange.source,
                    index,
                    record: exchange.record.clone(),
                    timing: exchange.timing,
                    report: matched,
                });
            }
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
        for source in [ReplaySource::Case, ReplaySource::Global] {
            for (index, exchange) in self.mysql.exchanges.iter_mut().enumerate() {
                if exchange.source != source
                    || !exchange.status.is_available()
                    || exchange.record.command != command
                {
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
                exchange.status = ReplayExchangeStatus::Consumed;
                return Some((exchange.source, index));
            }
        }
        None
    }

    pub(in crate::replay) fn statement_metadata(
        &self,
        identity: &ReplaySessionIdentity,
        sql: &str,
    ) -> StatementMetadata {
        let normalized_sql = normalize_sql(sql);
        for source in [ReplaySource::Case, ReplaySource::Global] {
            for exchange in &self.mysql.exchanges {
                if exchange.source != source || exchange.record.command != "COM_STMT_EXECUTE" {
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
            .filter(|(_, exchange)| exchange.source == source && !exchange.status.is_consumed())
            .map(|(index, exchange)| RecordedExchangeSummary {
                index,
                case_id: exchange.case_id.clone(),
                target: Some(exchange.identity.target.clone()),
                database: exchange.identity.database.clone(),
                username: exchange.identity.username.clone(),
                command: exchange.record.command.clone(),
                sql_summary: exchange.record.sql.as_deref().map(SqlSummary::new),
                status: exchange.record.response.status.clone(),
            })
            .collect()
    }

    fn active_case_matches(&self, exchange: &ReplayExchange) -> bool {
        active_case_matches(self.active_case_id.as_deref(), exchange)
    }

    pub(in crate::replay) fn complete_exchange(&mut self, matched: &MatchedExchange) {
        let Some(exchange) = self.mysql.exchanges.get_mut(matched.index) else {
            return;
        };
        exchange.status = ReplayExchangeStatus::Consumed;
        push_success_detail(
            &mut self.mysql.events.matched_query_count,
            &mut self.mysql.events.matched_queries,
            matched.report.clone(),
        );
    }

    pub(in crate::replay) fn fail_exchange(
        &mut self,
        matched: &MatchedExchange,
        identity: &ReplaySessionIdentity,
        reason: &str,
    ) {
        if let Some(exchange) = self.mysql.exchanges.get_mut(matched.index) {
            exchange.status = ReplayExchangeStatus::Failed;
        }
        self.record_unmatched(
            identity,
            &matched.record.command,
            matched.record.sql.as_deref(),
            matched.record.params.as_deref(),
            reason,
        );
    }
}
