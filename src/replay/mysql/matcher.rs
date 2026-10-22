use super::*;
mod control;
mod request;
pub(super) use request::TransactionMatch;

#[derive(Debug, Default)]
pub(in crate::replay) struct MysqlReplayState {
    #[cfg(test)]
    pub(in crate::replay) observed_at_for_test: Option<DateTime<Utc>>,
    pub(in crate::replay) exchanges: Vec<ReplayExchange>,
    case_exchange_index: CaseExchangeIndex,
    pub(in crate::replay) events: ReplayEvents,
    pub(super) sql_cache: sql_match::cache::SqlCache,
    candidates: candidates::Candidates,
    cleanup_selection: cleanup_selection::Index,
    pub(in crate::replay) read_prefixes: optional_session::ReadPrefixes,
    pub(in crate::replay) transaction_equivalence: transaction_equivalence::Registry,
    pub(super) origins: ownership::Origins,
    pub(super) foreign: ownership::Foreign,
    pub(super) transaction_wires: std::collections::HashSet<(Uuid, u64)>,
    pub(super) transaction_provenance: BTreeMap<usize, transaction_ownership::Provenance>,
    pub(super) promoted_wires: std::collections::HashSet<(Uuid, u64)>,
    pub(in crate::replay) has_global_transaction_start: bool,
}

impl MysqlReplayState {
    #[cfg(test)]
    pub(in crate::replay) fn invalidate_scope_index(&mut self) {
        self.candidates = candidates::Candidates::default();
        self.cleanup_selection = cleanup_selection::Index::default();
    }
    pub(in crate::replay) fn register_exchange(&mut self, exchange: ReplayExchange) {
        if exchange.source == ReplaySource::Case
            && exchange
                .record
                .connection_id
                .zip(exchange.record.query_sequence)
                .is_some_and(|wire| self.promoted_wires.contains(&wire))
        {
            return;
        }
        self.has_global_transaction_start |= exchange.source == ReplaySource::Global
            && exchange
                .record
                .server_status_before
                .is_some_and(|flags| flags & 0x2009 == 0)
            && exchange
                .record
                .response
                .server_status
                .is_some_and(|flags| flags & 0x2009 == 1);
        let index = self.exchanges.len();
        self.case_exchange_index
            .register(exchange.source, exchange.case_id.as_deref(), index);
        self.exchanges.push(exchange);
        self.cleanup_selection.register(&self.exchanges);
        self.classify_origin(index);
    }

    pub(in crate::replay) fn case_is_dirty(&self, case_id: &str) -> bool {
        self.events.dirty_case_ids.contains(case_id)
            || self.case_exchange_index.any(case_id, |index| {
                self.exchanges.get(index).is_some_and(|exchange| {
                    let optional = exchange.optional_session.filter(|kind| {
                        exchange.status.is_available()
                            || matches!(
                                kind,
                                OptionalSessionExchange::Rollback | OptionalSessionExchange::Commit
                            ) && exchange.status == ReplayExchangeStatus::Responding
                    });
                    !exchange.status.is_consumed()
                        && optional.is_none()
                        && !self.foreign.contains_key(&index)
                })
            })
    }
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

    #[cfg(test)]
    pub(in crate::replay) fn record_builtin(
        &mut self,
        identity: &ReplaySessionIdentity,
        command: &str,
        sql: Option<&str>,
        reason: &str,
    ) {
        let case_id = self.active_case_id.clone();
        self.record_builtin_in_case(case_id.as_deref(), identity, command, sql, reason);
    }

    pub(super) fn record_builtin_in_case(
        &mut self,
        case: Option<&str>,
        identity: &ReplaySessionIdentity,
        command: &str,
        sql: Option<&str>,
        reason: &str,
    ) {
        // Plain ends already tried ordinary finite matching. An end rejected
        // there must not consume a business boundary through the fallback.
        let plain_end =
            sql.is_some_and(|sql| matches!(normalize_sql(sql).as_str(), "commit" | "rollback"));
        let recorded_match = (!plain_end)
            .then(|| self.consume_builtin_exchange_in_case(case, identity, command, sql))
            .flatten();
        let case_id = case.map(ToOwned::to_owned);
        let budget_case_id = case_id.clone();
        push_success_detail(
            &mut self.mysql.events.builtin_query_count,
            &mut self.mysql.events.builtin_queries,
            &mut self.mysql.events.builtin_query_details,
            budget_case_id.as_deref(),
            |target_event_index| QueryReport {
                diagnostic: None,
                case_id,
                target: identity.target.clone(),
                database: identity.database.clone(),
                username: identity.username.clone(),
                command: command.to_string(),
                sql: sql.map(ToOwned::to_owned),
                params: None,
                reason: reason.to_string(),
                recorded_source: recorded_match.map(|(source, _)| source),
                recorded_index: recorded_match.map(|(_, index)| index),
                target_event_index: Some(target_event_index),
            },
        );
    }

    pub(super) fn record_unsupported_in_case(
        &mut self,
        case: Option<&str>,
        identity: &ReplaySessionIdentity,
        command: &str,
        sql: Option<&str>,
        params: Option<&[RecordedMysqlValue]>,
        reason: &str,
    ) {
        if let Some(case_id) = case {
            self.mysql.events.dirty_case_ids.insert(case_id.to_owned());
        }
        self.mysql.events.unsupported_commands.push(QueryReport {
            diagnostic: None,
            case_id: case.map(ToOwned::to_owned),
            target: identity.target.clone(),
            database: identity.database.clone(),
            username: identity.username.clone(),
            command: command.to_string(),
            sql: sql.map(ToOwned::to_owned),
            params: params.map(ToOwned::to_owned),
            reason: reason.to_string(),
            recorded_source: None,
            recorded_index: None,
            target_event_index: None,
        });
    }

    #[cfg(test)]
    pub(in crate::replay) fn record_unmatched(
        &mut self,
        identity: &ReplaySessionIdentity,
        command: &str,
        sql: Option<&str>,
        params: Option<&[RecordedMysqlValue]>,
        reason: &str,
    ) {
        let case = self.active_case_id.clone();
        self.record_unmatched_in_case(case.as_deref(), identity, command, sql, params, reason);
    }

    pub(super) fn record_unmatched_in_case(
        &mut self,
        case: Option<&str>,
        identity: &ReplaySessionIdentity,
        command: &str,
        sql: Option<&str>,
        params: Option<&[RecordedMysqlValue]>,
        reason: &str,
    ) {
        if let Some(case_id) = case {
            self.mysql.events.dirty_case_ids.insert(case_id.to_owned());
        }
        self.mysql.events.unmatched_queries.push(QueryReport {
            diagnostic: None,
            case_id: case.map(ToOwned::to_owned),
            target: identity.target.clone(),
            database: identity.database.clone(),
            username: identity.username.clone(),
            command: command.to_string(),
            sql: sql.map(ToOwned::to_owned),
            params: params.map(ToOwned::to_owned),
            reason: reason.to_string(),
            recorded_source: None,
            recorded_index: None,
            target_event_index: None,
        });
    }

    pub(in crate::replay) fn record_metadata_warning(&mut self, warning: String) {
        self.mysql.events.metadata_warnings.push(warning);
    }

    #[cfg(test)]
    pub(in crate::replay) fn consume_builtin_exchange(
        &mut self,
        identity: &ReplaySessionIdentity,
        command: &str,
        sql: Option<&str>,
    ) -> Option<(ReplaySource, usize)> {
        let case = self.active_case_id.clone();
        self.consume_builtin_exchange_in_case(case.as_deref(), identity, command, sql)
    }

    fn consume_builtin_exchange_in_case(
        &mut self,
        case: Option<&str>,
        identity: &ReplaySessionIdentity,
        command: &str,
        sql: Option<&str>,
    ) -> Option<(ReplaySource, usize)> {
        let normalized_sql = sql.map(normalize_sql);
        let active_case_id = case.map(ToOwned::to_owned);
        for source in [ReplaySource::Case, ReplaySource::Global] {
            for (index, exchange) in self.mysql.exchanges.iter_mut().enumerate() {
                if exchange.source != source
                    || !exchange.status.is_available()
                    || exchange.record.command != command
                    || exchange.record.outcome != crate::DependencyExchangeOutcome::Response
                    || !matches!(
                        exchange.record.response.status.as_str(),
                        "ok" | "resultset" | "stmt_prepare"
                    )
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
                if exchange.source == ReplaySource::Global {
                    self.mysql.events.global_report.observe(
                        0,
                        index,
                        exchange.optional_session.is_none(),
                        false,
                    );
                }
                return Some((exchange.source, index));
            }
        }
        None
    }

    #[cfg(test)]
    pub(in crate::replay) fn statement_metadata(
        &mut self,
        identity: &ReplaySessionIdentity,
        sql: &str,
    ) -> StatementMetadata {
        let case = self.active_case_id.clone();
        self.statement_metadata_in_case(case.as_deref(), identity, sql)
    }

    pub(super) fn statement_metadata_in_case(
        &mut self,
        case: Option<&str>,
        identity: &ReplaySessionIdentity,
        sql: &str,
    ) -> StatementMetadata {
        let normalized_sql = normalize_sql(sql);
        let param_count = count_sql_placeholders(sql);
        let mut semantic_target = None;
        for source in [ReplaySource::Case, ReplaySource::Global] {
            let candidates =
                self.mysql
                    .candidates
                    .select(&self.mysql.exchanges, source, case, identity, None);
            for (project_columns, semantic) in [(false, false), (true, false), (false, true)] {
                for index in candidates.iter().copied() {
                    let exchange = &self.mysql.exchanges[index];
                    if exchange.source != source
                        || !active_case_matches(case, exchange)
                        || !identity_matches_exchange(identity, &exchange.identity)
                    {
                        continue;
                    }
                    if !project_columns
                        && !semantic
                        && matches!(
                            exchange.record.command.as_str(),
                            "COM_QUERY" | "COM_STMT_EXECUTE"
                        )
                        && self.replay_policy.as_ref().is_some_and(|policy| {
                            policy.mysql_sql_values_metadata_matches(&MysqlPolicyContext {
                                request_times: crate::replay::assertion::RequestTimes {
                                    source: contracts::source_started(&exchange.record),
                                    target: None,
                                },
                                case_id: case,
                                identity,
                                command: "COM_STMT_EXECUTE",
                                recorded_sql: exchange.record.sql.as_deref(),
                                sql: Some(sql),
                                recorded: exchange.record.params.as_deref(),
                                actual: None,
                            })
                        })
                    {
                        return StatementMetadata {
                            param_count,
                            columns: exchange.record.response.columns.clone(),
                        };
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
                        "COM_STMT_EXECUTE" => {
                            normalize_sql(recorded_sql) == normalized_sql
                                || sql_match::prepared_metadata_matches(&exchange.record, sql)
                        }
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
        self.mysql_unused_iter(source, None)
            .filter(|exchange| !self.mysql.foreign.contains_key(&exchange.index))
            .take(if source == ReplaySource::Global {
                100
            } else {
                usize::MAX
            })
            .collect()
    }

    pub(in crate::replay) fn allowed_unused_rollbacks(&self) -> Vec<RecordedExchangeSummary> {
        self.allowed_unused_session_exchanges(OptionalSessionExchange::Rollback)
    }

    pub(in crate::replay) fn allowed_unused_commits(&self) -> Vec<RecordedExchangeSummary> {
        self.allowed_unused_session_exchanges(OptionalSessionExchange::Commit)
    }

    pub(in crate::replay) fn allowed_unused_autocommit(&self) -> Vec<RecordedExchangeSummary> {
        self.allowed_unused_session_exchanges(OptionalSessionExchange::Autocommit)
    }

    pub(in crate::replay) fn transaction_equivalent_autocommit(
        &self,
    ) -> Vec<RecordedExchangeSummary> {
        self.allowed_unused_session_exchanges(OptionalSessionExchange::TransactionAutocommit)
    }

    fn allowed_unused_session_exchanges(
        &self,
        kind: OptionalSessionExchange,
    ) -> Vec<RecordedExchangeSummary> {
        [ReplaySource::Case, ReplaySource::Global]
            .into_iter()
            .flat_map(|source| {
                self.mysql_unused_iter(source, Some(kind))
                    .take(if source == ReplaySource::Global {
                        100
                    } else {
                        usize::MAX
                    })
            })
            .collect()
    }

    pub(super) fn mysql_unused_iter(
        &self,
        source: ReplaySource,
        allowed: Option<OptionalSessionExchange>,
    ) -> impl Iterator<Item = RecordedExchangeSummary> + '_ {
        (0..self.mysql.exchanges.len())
            .filter(move |&index| self.mysql_exchange_is_unused(index, source, allowed))
            .map(move |index| self.mysql_summary(index))
    }

    pub(super) fn mysql_exchange_is_unused(
        &self,
        index: usize,
        source: ReplaySource,
        allowed: Option<OptionalSessionExchange>,
    ) -> bool {
        let exchange = &self.mysql.exchanges[index];
        let optional = exchange.optional_session.filter(|kind| {
            // Successful cleanup stays optional during delivery. Failed
            // delivery still reports an error and stays required.
            exchange.status.is_available()
                || matches!(
                    kind,
                    OptionalSessionExchange::Rollback | OptionalSessionExchange::Commit
                ) && exchange.status == ReplayExchangeStatus::Responding
        });
        exchange.source == source && !exchange.status.is_consumed() && optional == allowed
    }

    pub(super) fn mysql_summary(&self, index: usize) -> RecordedExchangeSummary {
        let exchange = &self.mysql.exchanges[index];
        RecordedExchangeSummary {
            connection_id: exchange.record.connection_id,
            query_sequence: exchange.record.query_sequence,
            index,
            case_id: exchange.case_id.clone(),
            target: Some(exchange.identity.target.clone()),
            database: exchange.identity.database.clone(),
            username: exchange.identity.username.clone(),
            command: exchange.record.command.clone(),
            sql_summary: exchange.record.sql.as_deref().map(SqlSummary::new),
            status: exchange.record.response.status.clone(),
            row_count: exchange.record.result_row_count(),
            diagnostic: self.mysql.transaction_equivalence.diagnostic(index),
        }
    }

    pub(in crate::replay) fn complete_exchange(&mut self, matched: &MatchedExchange) {
        let Some(exchange) = self.mysql.exchanges.get_mut(matched.index) else {
            return;
        };
        exchange.status = ReplayExchangeStatus::Consumed;
        self.refresh_mysql_global_report(matched.index);
        if let Some(policy) = &mut self.replay_policy {
            policy.commit_mysql_response_shift(&matched.response_time_shift_rules);
        }
        let case_id = matched.report.case_id.clone();
        push_success_detail(
            &mut self.mysql.events.matched_query_count,
            &mut self.mysql.events.matched_queries,
            &mut self.mysql.events.matched_query_details,
            case_id.as_deref(),
            |target_event_index| {
                let mut report = matched.report.clone();
                report.target_event_index = Some(target_event_index);
                report
            },
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
        self.refresh_mysql_global_report(matched.index);
        self.record_unmatched_in_case(
            matched.report.case_id.as_deref(),
            identity,
            &matched.record.command,
            matched.record.sql.as_deref(),
            matched.record.params.as_deref(),
            reason,
        );
    }
}
