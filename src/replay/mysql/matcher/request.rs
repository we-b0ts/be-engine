//! Live MySQL request selection; ownership and protocol consumption stay explicit.
use super::*;

#[derive(Clone, Copy)]
pub(in crate::replay::mysql) struct TransactionMatch<'a> {
    pub(in crate::replay::mysql) savepoints: &'a super::super::savepoints::Bindings,
    pub(in crate::replay::mysql) preferred_end: Option<usize>,
    pub(in crate::replay::mysql) status_flags: u16,
}

impl ReplayState {
    #[cfg(test)]
    pub(in crate::replay) fn match_exchange(
        &mut self,
        identity: &ReplaySessionIdentity,
        command: &str,
        sql: Option<&str>,
        params: Option<&[RecordedMysqlValue]>,
    ) -> Option<MatchedExchange> {
        let case = self.active_case_id.clone();
        self.match_exchange_in_case(case.as_deref(), identity, command, sql, params)
    }

    pub(in crate::replay::mysql) fn match_exchange_in_case(
        &mut self,
        case: Option<&str>,
        identity: &ReplaySessionIdentity,
        command: &str,
        sql: Option<&str>,
        params: Option<&[RecordedMysqlValue]>,
    ) -> Option<MatchedExchange> {
        self.match_exchange_in_case_preferred(case, identity, command, sql, params, None)
    }

    pub(in crate::replay::mysql) fn match_exchange_in_case_preferred(
        &mut self,
        case: Option<&str>,
        identity: &ReplaySessionIdentity,
        command: &str,
        sql: Option<&str>,
        params: Option<&[RecordedMysqlValue]>,
        transaction: Option<TransactionMatch<'_>>,
    ) -> Option<MatchedExchange> {
        #[cfg(not(test))]
        let request_observed_at = Utc::now();
        #[cfg(test)]
        let request_observed_at = self.mysql.observed_at_for_test.unwrap_or_else(Utc::now);
        let mut observation_id = Some(uuid::Uuid::new_v4());
        if let (Some(policy), Some(case)) = (&self.replay_policy, case) {
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
        let transaction_end = transaction.and_then(|transaction| transaction.preferred_end);
        let plain_end = matches!(
            baseline_normalized_sql.as_deref(),
            Some("commit" | "rollback")
        );
        let mut baseline_semantic_target = None;
        let actual_autocommit = sql
            .and_then(crate::mysql::autocommit::assignment)
            .filter(|_| {
                matches!(command, "COM_QUERY" | "COM_STMT_EXECUTE")
                    && params.is_none_or(<[_]>::is_empty)
            });
        let active_case_id = case.map(ToOwned::to_owned);
        let preferred_end = transaction_end.or_else(|| {
            self.mysql.cleanup_selection.preferred_end(
                &self.mysql.exchanges,
                active_case_id.as_deref(),
                identity,
                command,
                baseline_normalized_sql.as_deref(),
            )
        });
        for source in [ReplaySource::Case, ReplaySource::Global] {
            // Preserve existing candidate precedence before trying compatible
            // projections, without allowing Global to outrank the active Case.
            // An authoritative socket witness admits exactly one end. Avoid
            // collecting the scope only to reject all of its other candidates.
            let candidates = transaction_end.is_none().then(|| {
                self.mysql.candidates.select(
                    &self.mysql.exchanges,
                    source,
                    active_case_id.as_deref(),
                    identity,
                    Some(command),
                )
            });
            for foreign in [false, true] {
                for (project_columns, semantic) in [(false, false), (true, false), (false, true)] {
                    for index in preferred_end
                        .into_iter()
                        .chain(candidates.as_deref().unwrap_or_default().iter().copied())
                    {
                        if transaction_end.is_some_and(|expected| expected != index) {
                            continue;
                        }
                        let exchange = &self.mysql.exchanges[index];
                        if self.mysql.foreign.contains_key(&index) != foreign
                            || exchange.source != source
                            || !exchange.status.is_available()
                            || !active_case_matches(active_case_id.as_deref(), exchange)
                            || !identity_matches_exchange(identity, &exchange.identity)
                        {
                            continue;
                        }
                        let savepoint_match = transaction.and_then(|t| {
                            sql.and_then(|sql| {
                                t.savepoints.preview(&exchange.record, sql, t.status_flags)
                            })
                        });
                        if savepoint_match == Some(false) {
                            continue;
                        }
                        let same_savepoint =
                            savepoint_match == Some(true) && params.is_none_or(<[_]>::is_empty);
                        if plain_end
                            && let Some(transaction) = transaction
                            && exchange.record.outcome == crate::DependencyExchangeOutcome::Response
                            && exchange.record.response.status == "ok"
                            && exchange.record.response.error_code.is_none()
                            && exchange.record.sql.as_deref().is_some_and(|sql| {
                                matches!(normalize_sql(sql).as_str(), "commit" | "rollback")
                            })
                            && (self.mysql.transaction_equivalence.requires_witness(index)
                                && transaction.preferred_end != Some(index)
                                || transaction.status_flags & 1 == 0
                                    && exchange.optional_session.is_none()
                                    && exchange
                                        .record
                                        .server_status_before
                                        .is_some_and(|before| before & 0x2009 == 1))
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
                                request_times: crate::replay::assertion::RequestTimes {
                                    source: contracts::source_started(&exchange.record),
                                    target: Some(request_observed_at),
                                },
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
                            Some(Err(error)) => {
                                if error.to_string().starts_with("dynamic SQL requires") {
                                    let warning = "dynamic SQL capability limit: one statement, at most 1 MiB and 16384 tokens";
                                    if !self
                                        .mysql
                                        .events
                                        .metadata_warnings
                                        .iter()
                                        .any(|w| w == warning)
                                    {
                                        self.mysql.events.metadata_warnings.push(warning.into());
                                    }
                                }
                                continue;
                            }
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
                                sql_match::prepared_values_match(
                                    &exchange.record,
                                    command,
                                    sql,
                                    params,
                                )
                            });
                        let sql_value_decision = self.replay_policy.as_ref().and_then(|policy| {
                            policy
                                .request_contracts
                                .preview_mysql_values_with_raw(
                                    active_case_id.as_deref(),
                                    identity,
                                    &exchange.record,
                                    command,
                                    sql,
                                    params,
                                    request_observed_at,
                                    policy,
                                    dynamic.as_ref().and_then(|_| {
                                        let raw = &self.mysql.exchanges[index].record;
                                        (raw.sql != exchange.record.sql
                                            || raw.params != exchange.record.params
                                            || observed_sql != sql
                                            || observed_params != params)
                                            .then_some(
                                                policy::request_contract::RawMysqlIdentityRequest {
                                                    source: raw,
                                                    target_sql: observed_sql,
                                                    target_params: observed_params,
                                                },
                                            )
                                    }),
                                )
                                .or_else(|| {
                                    policy.preview_mysql_sql_values(&MysqlPolicyContext {
                                        request_times: crate::replay::assertion::RequestTimes {
                                            source: contracts::source_started(&exchange.record),
                                            target: Some(request_observed_at),
                                        },
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
                        let (policy_decision, projected) =
                            if let Some(decision) = sql_value_decision {
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
                                            request_times: crate::replay::assertion::RequestTimes {
                                                source: contracts::source_started(&exchange.record),
                                                target: Some(request_observed_at),
                                            },
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
                                let Some(recorded) = self.mysql.sql_cache.get(recorded_sql).bind(
                                    &exchange.record.command,
                                    exchange.record.params.as_deref(),
                                ) else {
                                    continue;
                                };
                                let Some(response) = projection::semantic_response(
                                    &exchange.record,
                                    &recorded,
                                    actual,
                                ) else {
                                    continue;
                                };
                                (DependencyRuleDecision::default(), Some(response))
                            } else {
                                if cross_protocol
                                    && !project_columns
                                    && !same_autocommit
                                    && !same_savepoint
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
                                let Some(recorded_sql) =
                                    exchange.record.sql.as_deref().map(normalize_sql)
                                else {
                                    continue;
                                };
                                let policy_decision = if cross_protocol {
                                    // The SQL matcher or projection adapter verifies values.
                                    // A protocol change needs no dynamic-value exemption.
                                    DependencyRuleDecision::default()
                                } else if let Some(policy) = &self.replay_policy {
                                    let context = MysqlPolicyContext {
                                        request_times: crate::replay::assertion::RequestTimes {
                                            source: contracts::source_started(&exchange.record),
                                            target: Some(request_observed_at),
                                        },
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
                                        && !same_savepoint
                                        && !same_prepared_values
                                        && !policy.allows_mysql_sql_difference(&context)
                                    {
                                        continue;
                                    }
                                    if same_prepared_values
                                        && !policy.allows_mysql_sql_difference(&context)
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
                                    && !same_savepoint
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
                                        projection::query_response(
                                            &exchange.record,
                                            command,
                                            sql,
                                            params,
                                        )
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
                                    projection::query_response(
                                        &exchange.record,
                                        command,
                                        sql,
                                        params,
                                    )
                                })
                        }) {
                            exchange.record.response = response;
                        }
                        let mut response_time_shift_rules = Vec::new();
                        exchange.record.response = match exchange.record.response.materialize() {
                            Ok(response) => response,
                            Err(error) => {
                                self.mysql.events.metadata_warnings.push(format!(
                                    "MySQL response evidence unavailable: {error:#}"
                                ));
                                return None;
                            }
                        };
                        let mut time_copy_delivery = if let (Some(policy), Some(case)) =
                            (&self.replay_policy, active_case_id.as_deref())
                        {
                            match contracts::time_copies::prepare(
                                &policy.request_contracts,
                                case,
                                identity,
                                &self.mysql.exchanges[index].record,
                                &exchange.record.response,
                                observed_sql,
                            ) {
                                Ok(prepared) => prepared,
                                Err(_) => continue,
                            }
                        } else {
                            None
                        };
                        if exchange.source == ReplaySource::Case
                            && let Some(policy) = &self.replay_policy
                        {
                            let Ok((response, ids)) = policy.shift_mysql_response(
                                active_case_id.as_deref(),
                                identity,
                                &self.mysql.exchanges[index].record,
                                &exchange.record.response,
                                Some(request_observed_at),
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
                                match contracts::prepare_delivery(
                                    &policy.request_contracts,
                                    case,
                                    identity,
                                    &self.mysql.exchanges[index].record,
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
                        if let Some(prepared) = &mut time_copy_delivery
                            && prepared
                                .prepare_witness(
                                    &self.mysql.exchanges[index].record,
                                    identity,
                                    contracts::ObservedRequest {
                                        observation_id,
                                        command,
                                        sql: observed_sql,
                                        params: observed_params,
                                        started_at: request_observed_at,
                                    },
                                    value_delivery.as_ref(),
                                )
                                .is_err()
                        {
                            continue;
                        }
                        let identity_delivery = if source == ReplaySource::Case {
                            if let Some(policy) = &self.replay_policy {
                                match policy.dynamic_values.prepare_mysql_identity_delivery(
                                    active_case_id.as_deref(),
                                    identity,
                                    &self.mysql.exchanges[index].record,
                                    &exchange.record.response,
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
                        if let Some(policy) = &mut self.replay_policy {
                            if policy
                                .commit(active_case_id.as_deref(), policy_decision)
                                .is_err()
                            {
                                continue;
                            }
                            if let (Some(case_id), Some(normalized)) =
                                (active_case_id.as_deref(), dynamic.as_ref())
                            {
                                policy
                                    .dynamic_values
                                    .commit(case_id, normalized.decision.clone());
                            }
                        }
                        self.mysql.exchanges[index].status =
                            if exchange.record.outcome.is_client_terminated() {
                                ReplayExchangeStatus::AwaitingClientTermination
                            } else {
                                ReplayExchangeStatus::Responding
                            };
                        self.refresh_mysql_global_report(index);
                        let owned_global = self.mysql.foreign.contains_key(&index)
                            || (exchange.source == ReplaySource::Global
                                && exchange
                                    .record
                                    .connection_id
                                    .zip(exchange.record.query_sequence)
                                    .is_some_and(|wire| {
                                        self.mysql.transaction_wires.contains(&wire)
                                    }));
                        let matched = MatchedQueryReport {
                            case_id: if owned_global {
                                None
                            } else {
                                active_case_id.clone()
                            },
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
                            transaction_owner: if baseline_normalized_sql
                                .as_deref()
                                .is_some_and(super::super::transaction_scope::is_business)
                            {
                                if owned_global {
                                    Some(None)
                                } else if exchange.source == ReplaySource::Case {
                                    Some(exchange.case_id.clone())
                                } else {
                                    None
                                }
                            } else {
                                None
                            },
                            value_delivery,
                            time_copy_delivery,
                            identity_delivery,
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
        }
        None
    }
}
