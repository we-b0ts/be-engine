use super::*;

#[derive(Debug, Default)]
pub(in crate::replay) struct MysqlReplayState {
    pub(in crate::replay) exchanges: Vec<ReplayExchange>,
    case_exchange_index: CaseExchangeIndex,
    pub(in crate::replay) events: ReplayEvents,
    pub(super) sql_cache: sql_match::cache::SqlCache,
    pub(in crate::replay) read_prefixes: optional_session::ReadPrefixes,
}

impl MysqlReplayState {
    pub(in crate::replay) fn register_exchange(&mut self, exchange: ReplayExchange) {
        let index = self.exchanges.len();
        self.case_exchange_index
            .register(exchange.source, exchange.case_id.as_deref(), index);
        self.exchanges.push(exchange);
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
                    !exchange.status.is_consumed() && optional.is_none()
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

    pub(in crate::replay) fn record_builtin(
        &mut self,
        identity: &ReplaySessionIdentity,
        command: &str,
        sql: Option<&str>,
        reason: &str,
    ) {
        let recorded_match = self.consume_builtin_exchange(identity, command, sql);
        let case_id = self.active_case_id.clone();
        let budget_case_id = case_id.clone();
        push_success_detail(
            &mut self.mysql.events.builtin_query_count,
            &mut self.mysql.events.builtin_queries,
            &mut self.mysql.events.builtin_query_details,
            budget_case_id.as_deref(),
            |target_event_index| QueryReport {
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

    pub(in crate::replay) fn record_unsupported(
        &mut self,
        identity: &ReplaySessionIdentity,
        command: &str,
        sql: Option<&str>,
        params: Option<&[RecordedMysqlValue]>,
        reason: &str,
    ) {
        if let Some(case_id) = &self.active_case_id {
            self.mysql.events.dirty_case_ids.insert(case_id.clone());
        }
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
            target_event_index: None,
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
        if let Some(case_id) = &self.active_case_id {
            self.mysql.events.dirty_case_ids.insert(case_id.clone());
        }
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
            target_event_index: None,
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
        let request_observed_at = Utc::now();
        let mut observation_id = Some(uuid::Uuid::new_v4());
        if let (Some(policy), Some(case)) = (&self.replay_policy, self.active_case_id.as_deref()) {
            match contracts::record_target(
                &policy.request_contracts,
                case,
                identity,
                contracts::ObservedRequest {
                    observation_id,
                    command,
                    sql,
                    params,
                    started_at: request_observed_at,
                },
            ) {
                Ok(crate::policy_evidence::ObservationRetention::Unavailable) => {
                    observation_id = None
                }
                Ok(crate::policy_evidence::ObservationRetention::Retained) => {}
                Err(error) => {
                    self.mysql
                        .events
                        .metadata_warnings
                        .push(format!("SQL Target observation unavailable: {error:#}"));
                    // Global candidates do not own Case rule witnesses. Keep the
                    // identity so an ordinary Case candidate still fails closed
                    // when association cannot find its retained Target.
                }
            }
        }
        let observed_sql = sql;
        let observed_params = params;
        let baseline_normalized_sql = sql.map(normalize_sql);
        let mut baseline_semantic_target = None;
        let actual_autocommit = sql
            .and_then(crate::mysql::autocommit::assignment)
            .filter(|_| {
                matches!(command, "COM_QUERY" | "COM_STMT_EXECUTE")
                    && params.is_none_or(<[_]>::is_empty)
            });
        let active_case_id = self.active_case_id.clone();
        let preferred_end = cleanup_selection::preferred_end(
            &self.mysql.exchanges,
            active_case_id.as_deref(),
            identity,
            command,
            baseline_normalized_sql.as_deref(),
        );
        for source in [ReplaySource::Case, ReplaySource::Global] {
            // Preserve existing candidate precedence before trying compatible
            // projections, without allowing Global to outrank the active Case.
            for (project_columns, semantic) in [(false, false), (true, false), (false, true)] {
                for index in preferred_end
                    .into_iter()
                    .chain(0..self.mysql.exchanges.len())
                {
                    let exchange = &self.mysql.exchanges[index];
                    if exchange.source != source
                        || !exchange.status.is_available()
                        || !active_case_matches(active_case_id.as_deref(), exchange)
                        || !identity_matches_exchange(identity, &exchange.identity)
                    {
                        continue;
                    }
                    if source == ReplaySource::Case
                        && let (Some(policy), Some(case)) =
                            (&self.replay_policy, active_case_id.as_deref())
                        && let Err(error) = contracts::record_request(
                            &policy.request_contracts,
                            case,
                            identity,
                            &exchange.record,
                            contracts::ObservedRequest {
                                observation_id,
                                command,
                                sql: observed_sql,
                                params: observed_params,
                                started_at: request_observed_at,
                            },
                        )
                    {
                        self.mysql
                            .events
                            .metadata_warnings
                            .push(format!("SQL request witness unavailable: {error:#}"));
                        return None;
                    }
                    let dynamic = self.replay_policy.as_ref().and_then(|policy| {
                        policy.dynamic_values.mysql(&MysqlPolicyContext {
                            case_id: exchange.case_id.as_deref(),
                            identity,
                            command,
                            recorded_sql: exchange.record.sql.as_deref(),
                            sql,
                            recorded: exchange.record.params.as_deref(),
                            actual: params,
                        })
                    });
                    let dynamic = match dynamic {
                        Some(Ok(normalized)) => Some(normalized),
                        Some(Err(_)) => continue,
                        None => None,
                    };
                    let normalized_exchange = dynamic.as_ref().map(|normalized| {
                        let mut copy = exchange.clone();
                        copy.record.sql = normalized.source_sql.clone();
                        copy.record.params = normalized.source_params.clone();
                        copy
                    });
                    let exchange = normalized_exchange.as_ref().unwrap_or(exchange);
                    let sql = dynamic
                        .as_ref()
                        .and_then(|value| value.actual_sql.as_deref())
                        .or(sql);
                    let params = dynamic
                        .as_ref()
                        .and_then(|value| value.actual_params.as_deref())
                        .or(params);
                    let dynamic_normalized_sql =
                        dynamic.as_ref().and_then(|_| sql.map(normalize_sql));
                    let normalized_sql = dynamic_normalized_sql
                        .as_deref()
                        .or(baseline_normalized_sql.as_deref());
                    let mut dynamic_semantic_target = None;
                    let semantic_target = if dynamic.is_some() {
                        &mut dynamic_semantic_target
                    } else {
                        &mut baseline_semantic_target
                    };
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
                    let same_prepared_values = !cross_protocol
                        && sql.is_some_and(|sql| {
                            sql_match::prepared_values_match(&exchange.record, command, sql, params)
                        });
                    let sql_value_decision = self.replay_policy.as_ref().and_then(|policy| {
                        policy
                            .request_contracts
                            .preview_mysql_values(
                                active_case_id.as_deref(),
                                identity,
                                &exchange.record,
                                command,
                                sql,
                                params,
                                request_observed_at,
                                policy,
                            )
                            .or_else(|| {
                                policy.preview_mysql_sql_values(&MysqlPolicyContext {
                                    case_id: active_case_id.as_deref(),
                                    identity,
                                    command,
                                    recorded_sql: exchange.record.sql.as_deref(),
                                    sql,
                                    recorded: exchange.record.params.as_deref(),
                                    actual: params,
                                })
                            })
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
                                && Some(recorded_sql.as_str()) != normalized_sql
                                && !same_autocommit
                                && !same_prepared_values
                                && !policy.allows_mysql_sql_difference(&context)
                            {
                                continue;
                            }
                            if same_prepared_values && !policy.allows_mysql_sql_difference(&context)
                            {
                                DependencyRuleDecision::default()
                            } else {
                                match policy.preview_mysql(&context, Utc::now()) {
                                    Ok(decision) => decision,
                                    Err(_) => continue,
                                }
                            }
                        } else if !project_columns
                            && Some(recorded_sql.as_str()) != normalized_sql
                            && !same_autocommit
                            && !same_prepared_values
                        {
                            continue;
                        } else if same_prepared_values
                            || params_match(exchange.record.params.as_deref(), params)
                        {
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
                    let mut response_time_shift_rules = Vec::new();
                    exchange.record.response = match exchange.record.response.materialize() {
                        Ok(response) => response,
                        Err(error) => {
                            self.mysql
                                .events
                                .metadata_warnings
                                .push(format!("MySQL response evidence unavailable: {error:#}"));
                            return None;
                        }
                    };
                    if exchange.source == ReplaySource::Case
                        && let Some(policy) = &self.replay_policy
                    {
                        let Ok((response, ids)) = policy.shift_mysql_response(
                            active_case_id.as_deref(),
                            identity,
                            &self.mysql.exchanges[index].record,
                            &exchange.record.response,
                        ) else {
                            continue;
                        };
                        exchange.record.response = response;
                        response_time_shift_rules = ids;
                    }
                    let value_delivery = if source == ReplaySource::Case {
                        if let (Some(policy), Some(case)) =
                            (&self.replay_policy, active_case_id.as_deref())
                        {
                            let mut original = self.mysql.exchanges[index].record.clone();
                            original.response = match original.response.materialize() {
                                Ok(response) => response,
                                Err(_) => continue,
                            };
                            match contracts::prepare_delivery(
                                &policy.request_contracts,
                                case,
                                identity,
                                &original,
                                &exchange.record.response,
                                contracts::ObservedRequest {
                                    observation_id,
                                    command,
                                    sql: observed_sql,
                                    params: observed_params,
                                    started_at: request_observed_at,
                                },
                            ) {
                                Ok(prepared) => prepared,
                                Err(_) => continue,
                            }
                        } else {
                            None
                        }
                    } else {
                        None
                    };
                    self.mysql.exchanges[index].status =
                        if exchange.record.outcome.is_client_terminated() {
                            ReplayExchangeStatus::AwaitingClientTermination
                        } else {
                            ReplayExchangeStatus::Responding
                        };
                    self.refresh_mysql_global_report(index);
                    if let Some(policy) = &mut self.replay_policy {
                        if let (Some(case_id), Some(normalized)) =
                            (active_case_id.as_deref(), dynamic.as_ref())
                        {
                            policy
                                .dynamic_values
                                .commit(case_id, normalized.decision.clone());
                        }
                        policy.commit(active_case_id.as_deref(), policy_decision);
                    }
                    let matched = MatchedQueryReport {
                        case_id: active_case_id.clone(),
                        target: Some(exchange.identity.target.clone()),
                        database: exchange.identity.database.clone(),
                        username: exchange.identity.username.clone(),
                        source: exchange.source,
                        index,
                        command: command.to_string(),
                        sql: observed_sql.map(ToOwned::to_owned),
                        params: observed_params.map(ToOwned::to_owned),
                        status: exchange.record.response.status.clone(),
                        target_event_index: None,
                    };
                    return Some(MatchedExchange {
                        value_delivery,
                        response_time_shift_rules,
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
                    if !project_columns
                        && !semantic
                        && matches!(
                            exchange.record.command.as_str(),
                            "COM_QUERY" | "COM_STMT_EXECUTE"
                        )
                        && self.replay_policy.as_ref().is_some_and(|policy| {
                            policy.mysql_sql_values_metadata_matches(&MysqlPolicyContext {
                                case_id: self.active_case_id.as_deref(),
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
        self.mysql
            .exchanges
            .iter()
            .enumerate()
            .filter(move |(_, exchange)| {
                let optional = exchange.optional_session.filter(move |kind| {
                    // Successful cleanup stays optional during delivery.
                    // Failed delivery still reports an error and stays required.
                    exchange.status.is_available()
                        || matches!(
                            kind,
                            OptionalSessionExchange::Rollback | OptionalSessionExchange::Commit
                        ) && exchange.status == ReplayExchangeStatus::Responding
                });
                exchange.source == source && !exchange.status.is_consumed() && optional == allowed
            })
            .map(move |(index, exchange)| RecordedExchangeSummary {
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
            })
    }

    fn active_case_matches(&self, exchange: &ReplayExchange) -> bool {
        active_case_matches(self.active_case_id.as_deref(), exchange)
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
        self.record_unmatched(
            identity,
            &matched.record.command,
            matched.record.sql.as_deref(),
            matched.record.params.as_deref(),
            reason,
        );
    }
}
