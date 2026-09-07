use super::*;

#[derive(Debug, Default)]
pub(in crate::replay) struct MysqlReplayState {
    pub(in crate::replay) exchanges: Vec<ReplayExchange>,
    pub(in crate::replay) events: ReplayEvents,
    pub(super) sql_cache: sql_match::cache::SqlCache,
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
        let actual_autocommit = sql
            .and_then(crate::mysql::autocommit::assignment)
            .filter(|_| {
                matches!(command, "COM_QUERY" | "COM_STMT_EXECUTE")
                    && params.is_none_or(<[_]>::is_empty)
            });
        let active_case_id = self.active_case_id.clone();
        let mut semantic_target = None;
        for source in [ReplaySource::Case, ReplaySource::Global] {
            // Preserve existing candidate precedence before trying compatible
            // projections, without allowing Global to outrank the active Case.
            for (project_columns, semantic) in [(false, false), (true, false), (false, true)] {
                for index in 0..self.mysql.exchanges.len() {
                    let exchange = &self.mysql.exchanges[index];
                    if exchange.source != source
                        || !exchange.status.is_available()
                        || !active_case_matches(active_case_id.as_deref(), exchange)
                        || !identity_matches_exchange(identity, &exchange.identity)
                    {
                        continue;
                    }
                    let cross_protocol = exchange.record.command != command;
                    let same_autocommit = actual_autocommit.is_some_and(|actual| {
                        matches!(
                            exchange.record.command.as_str(),
                            "COM_QUERY" | "COM_STMT_EXECUTE"
                        ) && exchange.record.params.as_ref().is_none_or(Vec::is_empty)
                            && exchange
                                .record
                                .sql
                                .as_deref()
                                .and_then(crate::mysql::autocommit::assignment)
                                == Some(actual)
                    });
                    let sql_value_decision = self.replay_policy.as_ref().and_then(|policy| {
                        policy.preview_mysql_sql_values(
                            &MysqlPolicyContext {
                                case_id: active_case_id.as_deref(),
                                identity,
                                command,
                                recorded_sql: exchange.record.sql.as_deref(),
                                sql,
                                recorded: exchange.record.params.as_deref(),
                                actual: params,
                            },
                            Utc::now(),
                        )
                    });
                    let (policy_decision, projected) = if let Some(decision) = sql_value_decision {
                        let Ok(decision) = decision else {
                            continue;
                        };
                        (decision, None)
                    } else if semantic {
                        let Some(actual) = semantic_target
                            .get_or_insert_with(|| {
                                sql.and_then(|sql| {
                                    self.mysql.sql_cache.get(sql).bind(command, params)
                                })
                            })
                            .as_ref()
                        else {
                            continue;
                        };
                        let Some(recorded_sql) = exchange.record.sql.as_deref() else {
                            continue;
                        };
                        // Positional dynamic policies keep their existing path.
                        // Semantic matching proves actual value equality; it
                        // never infers, moves or commits dynamic bindings.
                        if !cross_protocol
                            && self.replay_policy.as_ref().is_some_and(|policy| {
                                policy.allows_mysql_sql_difference(&MysqlPolicyContext {
                                    case_id: active_case_id.as_deref(),
                                    identity,
                                    command,
                                    recorded_sql: Some(recorded_sql),
                                    sql,
                                    recorded: exchange.record.params.as_deref(),
                                    actual: params,
                                })
                            })
                        {
                            continue;
                        }
                        let Some(recorded) = self
                            .mysql
                            .sql_cache
                            .get(recorded_sql)
                            .bind(&exchange.record.command, exchange.record.params.as_deref())
                        else {
                            continue;
                        };
                        let Some(response) =
                            projection::semantic_response(&exchange.record, &recorded, actual)
                        else {
                            continue;
                        };
                        (DependencyRuleDecision::default(), Some(response))
                    } else {
                        if cross_protocol
                            && !project_columns
                            && !same_autocommit
                            && !sql.is_some_and(|sql| {
                                sql_match::cross_protocol_matches(
                                    &exchange.record,
                                    command,
                                    sql,
                                    params,
                                )
                            })
                        {
                            continue;
                        }
                        let Some(recorded_sql) = exchange.record.sql.as_deref().map(normalize_sql)
                        else {
                            continue;
                        };
                        let policy_decision = if cross_protocol {
                            // The SQL matcher or projection adapter verifies values.
                            // A protocol change needs no dynamic-value exemption.
                            DependencyRuleDecision::default()
                        } else if let Some(policy) = &self.replay_policy {
                            let context = MysqlPolicyContext {
                                case_id: active_case_id.as_deref(),
                                identity,
                                command,
                                recorded_sql: exchange.record.sql.as_deref(),
                                sql,
                                recorded: exchange.record.params.as_deref(),
                                actual: params,
                            };
                            if !project_columns
                                && Some(recorded_sql) != normalized_sql
                                && !same_autocommit
                                && !policy.allows_mysql_sql_difference(&context)
                            {
                                continue;
                            }
                            match policy.preview_mysql(&context, Utc::now()) {
                                Ok(decision) => decision,
                                Err(_) => continue,
                            }
                        } else if !project_columns
                            && Some(recorded_sql) != normalized_sql
                            && !same_autocommit
                        {
                            continue;
                        } else if params_match(exchange.record.params.as_deref(), params) {
                            DependencyRuleDecision::default()
                        } else {
                            continue;
                        };
                        // Reject parameter/policy mismatches before copying any rows.
                        let projected = if project_columns {
                            let Some(response) = sql.and_then(|sql| {
                                projection::query_response(&exchange.record, command, sql, params)
                            }) else {
                                continue;
                            };
                            Some(response)
                        } else {
                            None
                        };
                        (policy_decision, projected)
                    };
                    let mut exchange = self.mysql.exchanges[index].clone();
                    // Only the delivered copy is projected. Capture identity and
                    // consumption still refer to the original recorded exchange.
                    if let Some(response) = projected.or_else(|| {
                        sql.filter(|sql| Some(*sql) != exchange.record.sql.as_deref())
                            .and_then(|sql| {
                                projection::query_response(&exchange.record, command, sql, params)
                            })
                    }) {
                        exchange.record.response = response;
                    }
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
                        record: exchange.record,
                        timing: exchange.timing,
                        report: matched,
                    });
                }
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
        &mut self,
        identity: &ReplaySessionIdentity,
        sql: &str,
    ) -> StatementMetadata {
        let normalized_sql = normalize_sql(sql);
        let param_count = count_sql_placeholders(sql);
        let mut semantic_target = None;
        for source in [ReplaySource::Case, ReplaySource::Global] {
            for (project_columns, semantic) in [(false, false), (true, false), (false, true)] {
                for exchange in &self.mysql.exchanges {
                    if exchange.source != source
                        || !self.active_case_matches(exchange)
                        || !identity_matches_exchange(identity, &exchange.identity)
                    {
                        continue;
                    }
                    if semantic {
                        let Some(actual) = semantic_target
                            .get_or_insert_with(|| self.mysql.sql_cache.get(sql).metadata())
                            .as_ref()
                        else {
                            continue;
                        };
                        let Some(recorded_sql) = exchange.record.sql.as_deref() else {
                            continue;
                        };
                        let Some(recorded) = self
                            .mysql
                            .sql_cache
                            .get(recorded_sql)
                            .bind(&exchange.record.command, exchange.record.params.as_deref())
                        else {
                            continue;
                        };
                        if let Some(columns) =
                            projection::semantic_columns(&exchange.record, &recorded, actual)
                        {
                            return StatementMetadata {
                                param_count,
                                columns,
                            };
                        }
                        continue;
                    }
                    if project_columns {
                        if let Some(columns) = projection::statement_columns(&exchange.record, sql)
                        {
                            return StatementMetadata {
                                param_count,
                                columns,
                            };
                        }
                        continue;
                    }
                    let Some(recorded_sql) = exchange.record.sql.as_deref() else {
                        continue;
                    };
                    let matches = match exchange.record.command.as_str() {
                        "COM_STMT_EXECUTE" => normalize_sql(recorded_sql) == normalized_sql,
                        "COM_QUERY" => sql_match::metadata_matches(sql, recorded_sql),
                        _ => false,
                    };
                    if matches {
                        return StatementMetadata {
                            param_count,
                            columns: projection::statement_columns(&exchange.record, sql)
                                .unwrap_or_else(|| exchange.record.response.columns.clone()),
                        };
                    }
                }
            }
        }
        StatementMetadata {
            param_count,
            columns: builtin_response(sql, identity.database.as_deref())
                .map_or_else(Vec::new, |r| r.columns),
        }
    }

    pub(in crate::replay) fn unused_exchanges(
        &self,
        source: ReplaySource,
    ) -> Vec<RecordedExchangeSummary> {
        self.mysql_unused_exchanges(source, None)
    }

    pub(in crate::replay) fn allowed_unused_rollbacks(&self) -> Vec<RecordedExchangeSummary> {
        self.allowed_unused_session_exchanges(OptionalSessionExchange::Rollback)
    }

    pub(in crate::replay) fn allowed_unused_autocommit(&self) -> Vec<RecordedExchangeSummary> {
        self.allowed_unused_session_exchanges(OptionalSessionExchange::Autocommit)
    }

    fn allowed_unused_session_exchanges(
        &self,
        kind: OptionalSessionExchange,
    ) -> Vec<RecordedExchangeSummary> {
        [ReplaySource::Case, ReplaySource::Global]
            .into_iter()
            .flat_map(|source| self.mysql_unused_exchanges(source, Some(kind)))
            .collect()
    }

    fn mysql_unused_exchanges(
        &self,
        source: ReplaySource,
        allowed: Option<OptionalSessionExchange>,
    ) -> Vec<RecordedExchangeSummary> {
        self.mysql
            .exchanges
            .iter()
            .enumerate()
            .filter(|(_, exchange)| {
                let optional = exchange.optional_session.filter(|kind| {
                    // Successful cleanup stays optional during delivery.
                    // Failed delivery still reports an error and stays required.
                    exchange.status.is_available()
                        || *kind == OptionalSessionExchange::Rollback
                            && exchange.status == ReplayExchangeStatus::Responding
                });
                exchange.source == source && !exchange.status.is_consumed() && optional == allowed
            })
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
