//! Live MySQL request selection; ownership and protocol consumption stay explicit.
use super::*;
use crate::mysql::sql::bounds::statement_shared;
use std::cell::OnceCell;

// Dynamic normalization borrows unchanged values. Candidate scans must not
// compare every byte of the same SQL or parameter buffer again.
fn same_input<T: PartialEq + ?Sized>(left: Option<&T>, right: Option<&T>) -> bool {
    match (left, right) {
        (Some(left), Some(right)) => std::ptr::eq(left, right) || left == right,
        (None, None) => true,
        _ => false,
    }
}

impl ReplayState {
    #[allow(clippy::too_many_arguments)]
    pub(in crate::protocols::replay::mysql) fn select_mysql_exchange(
        &mut self,
        case: Option<&str>,
        identity: &ReplaySessionIdentity,
        command: &str,
        sql: Option<&str>,
        params: Option<&[RecordedMysqlValue]>,
        transaction: Option<TransactionMatch<'_>>,
        observation: &crate::replay::admission::RequestAdmission,
    ) -> Option<MatchedExchange> {
        let request_observed_at = observation
            .observed_at
            .expect("MySQL request observation captures native request time");
        let observation_id = observation.observation_id;
        let target_observation_id = observation_id
            .filter(|_| observation.observation_retained)
            .map(|id| {
                crate::policy_evidence::target_observation_id(
                    &id.to_string(),
                    crate::policy::Surface::DependencyRequest,
                    crate::policy_evidence::TargetRole::IndependentTargetObservation,
                )
            });
        let observed_sql = sql;
        let observed_params = params;
        let observed_statement = OnceCell::new();
        let target_savepoint = transaction
            .and(sql)
            .and_then(crate::mysql::savepoint::parse);
        self.protocols.mysql.prepare_candidates();
        let mut witnessed = (observation_id.is_some()
            && case.is_some()
            && self.replay_policy.as_ref().is_some_and(|policy| {
                policy.request_contracts.retains_value_witnesses()
                    && policy.request_contracts.compiled_rules().is_some()
            }))
        .then(std::collections::HashSet::new);
        let mut candidate_witness = None;
        if let Some(policy) = self
            .replay_policy
            .as_ref()
            .and_then(|policy| policy.request_contracts.compiled_rules())
        {
            self.protocols.mysql.source_formats.prepare(
                self.admission_epoch(),
                self.protocols.mysql.exchanges.len(),
                identity,
                policy,
            );
        }
        let baseline_normalized_sql = sql.map(normalize_sql);
        let sql_family = candidates::sql_family(sql);
        let select_hint = sql.and_then(candidates::select_hint);
        let legacy_sql_selector = self.replay_policy.as_ref().is_some_and(|policy| {
            policy.mysql_legacy_sql_selector_applies(case, identity, command)
        });
        let transaction_end = transaction.and_then(|transaction| transaction.preferred_end);
        let plain_end = matches!(
            baseline_normalized_sql.as_deref(),
            Some("commit" | "rollback")
        );
        let mut baseline_semantic_target = None;
        let mut baseline_projection = None;
        let mut projection_candidate = None;
        let mut strict_groups = std::collections::HashMap::new();
        let mut in_lists = in_list::Comparison::default();
        let mut transaction_rejection = None;
        let actual_autocommit = sql
            .and_then(crate::mysql::autocommit::assignment)
            .filter(|_| {
                matches!(command, "COM_QUERY" | "COM_STMT_EXECUTE")
                    && params.is_none_or(<[_]>::is_empty)
            });
        let active_case_id = case.map(ToOwned::to_owned);
        let preferred_end = transaction_end.or_else(|| {
            self.protocols.mysql.cleanup_selection.preferred_end(
                &self.protocols.mysql.exchanges,
                active_case_id.as_deref(),
                identity,
                command,
                baseline_normalized_sql.as_deref(),
            )
        });
        let window = if transaction_end.is_none() {
            active_case_id
                .as_deref()
                .zip(select_hint.as_ref())
                .zip(self.input_timing.as_ref())
                .and_then(|((case, hint), timeline)| {
                    self.protocols.mysql.candidates.select_window(
                        case,
                        identity,
                        command,
                        (!legacy_sql_selector).then_some(hint.table.as_str()),
                        timeline,
                    )
                })
        } else {
            None
        };
        for (source, allow_hypotheses) in [
            (ReplaySource::Case, false),
            (ReplaySource::Startup, false),
            (ReplaySource::Process, false),
            (ReplaySource::Case, true),
        ] {
            let sequence_index = self.protocols.mysql.lifecycle.sequence.expected_in(source);
            if allow_hypotheses && sequence_index.is_some() {
                break;
            }
            let hypothesis = if allow_hypotheses {
                // Explicit hypotheses may describe a different physical table.
                // They still have to stay within the same Source time boundary.
                let hypothesis_window = window.as_ref().and_then(|window| {
                    self.protocols.mysql.candidates.select_hypothesis_window(
                        active_case_id.as_deref()?,
                        identity,
                        command,
                        window,
                    )
                });
                let candidate = active_case_id.as_deref().and_then(|case| {
                    self.select_mysql_hypothesis(
                        case,
                        identity,
                        command,
                        observed_sql,
                        observed_params,
                        transaction,
                        request_observed_at,
                        observation_id,
                        hypothesis_window.as_deref(),
                        &mut transaction_rejection,
                    )
                });
                let Some(candidate) = candidate else { break };
                Some(candidate)
            } else {
                None
            };
            // Keep Case before run-owned traffic and respect an authoritative transaction end.
            let case_window =
                (source == ReplaySource::Case && !allow_hypotheses && sequence_index.is_none())
                    .then_some(window.as_ref())
                    .flatten();
            let candidates = if let Some(expected) = &sequence_index {
                let exempt = self.protocols.mysql.candidates.lookup_exempt(
                    source,
                    case,
                    identity,
                    Some(command),
                );
                let mut selected: Vec<_> = expected
                    .iter()
                    .copied()
                    .chain(exempt.iter().copied())
                    .collect();
                selected.sort_unstable();
                selected.dedup();
                Some(std::sync::Arc::from(selected))
            } else if let Some((index, _)) = &hypothesis {
                Some(std::sync::Arc::from(vec![*index]))
            } else {
                (transaction_end.is_none() && case_window.is_none()).then(|| {
                    if source == ReplaySource::Case
                        && plain_end
                        && !self.replay_policy.as_ref().is_some_and(|policy| {
                            policy.mysql_sql_difference_may_apply(case, identity, command, sql)
                        })
                        && let Some(ends) = self.protocols.mysql.cleanup_selection.candidates(
                            &self.protocols.mysql.exchanges,
                            case,
                            identity,
                            command,
                            baseline_normalized_sql.as_deref(),
                        )
                    {
                        return ends;
                    }
                    self.protocols.mysql.candidates.lookup(
                        source,
                        active_case_id.as_deref(),
                        identity,
                        Some(command),
                    )
                })
            };
            let indices = preferred_end
                .filter(|index| {
                    sequence_index.as_ref().is_none_or(|expected| {
                        expected.contains(index)
                            || self.protocols.mysql.recorded_sequence(*index).is_none()
                    })
                })
                .into_iter()
                .chain(
                    case_window
                        .into_iter()
                        .flat_map(|window| window.indices.iter().copied()),
                )
                .chain(candidates.as_deref().unwrap_or_default().iter().copied());
            for foreign in [false, true] {
                for (index, project_columns, semantic) in match_order::attempts(
                    indices.clone(),
                    case_window.is_some_and(|window| window.candidate_first),
                ) {
                    if !self
                        .protocols
                        .mysql
                        .candidates
                        .permits_sql(index, sql_family)
                    {
                        continue;
                    }
                    // A proven different table cannot reach ordinary SQL
                    // matching. Exclude it before recording candidate evidence.
                    if !legacy_sql_selector
                        && !allow_hypotheses
                        && !self.protocols.mysql.candidates.permits_select(
                            index,
                            select_hint.as_ref(),
                            false,
                        )
                    {
                        continue;
                    }
                    if allow_hypotheses && (foreign || project_columns || semantic) {
                        continue;
                    }
                    if transaction_end.is_some_and(|expected| expected != index) {
                        continue;
                    }
                    let exchange = &self.protocols.mysql.exchanges[index];
                    if transaction
                        .is_some_and(|context| !context.permits(&self.protocols.mysql, index))
                    {
                        continue;
                    }
                    if self.protocols.mysql.foreign.contains_key(&index) != foreign
                        || !exchange.source.matches_scope(source)
                        || !exchange.status.is_available()
                        || !active_case_matches(active_case_id.as_deref(), exchange)
                        || !identity_matches_exchange(identity, &exchange.identity)
                    {
                        continue;
                    }
                    let savepoint_match = transaction.and_then(|t| {
                        sql.and_then(|_| {
                            t.savepoints.preview_parsed(
                                &exchange.record,
                                self.protocols.mysql.candidates.savepoint(index),
                                target_savepoint.as_ref(),
                                t.status_flags,
                            )
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
                        && (self
                            .protocols
                            .mysql
                            .transaction_equivalence
                            .requires_witness(index)
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
                            && let Some(witnessed) = witnessed.as_mut()
                            // Strict, projected, and semantic passes may visit
                            // the same immutable Source occurrence. The request
                            // and candidate evidence are identical each time.
                            && witnessed.insert(index)
                            && let (Some(policy), Some(case)) =
                                (&self.replay_policy, active_case_id.as_deref())
                            && let Err(error) = contracts::record_request(
                                &policy.request_contracts,
                                case,
                                identity,
                                &exchange.record,
                                observation,
                                &mut candidate_witness,
                                self.protocols.mysql.request_sources.get(index).and_then(Option::as_ref),
                            )
                    {
                        self.protocols
                            .mysql
                            .events
                            .metadata_warnings
                            .push(format!("SQL request witness unavailable: {error:#}"));
                        return None;
                    }
                    // Keep evidence for alternate same-table shapes before
                    // applying the strict comparison's shape constraint.
                    if !legacy_sql_selector
                        && !allow_hypotheses
                        && !project_columns
                        && !semantic
                        && !self.protocols.mysql.candidates.permits_select(
                            index,
                            select_hint.as_ref(),
                            true,
                        )
                    {
                        continue;
                    }
                    let dynamic = self
                        .replay_policy
                        .as_ref()
                        .filter(|_| !allow_hypotheses)
                        .and_then(|policy| {
                            policy.dynamic_values.mysql(&MysqlPolicyContext {
                                request_times: traffic_contract::time::ClockPair {
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
                                    .protocols
                                    .mysql
                                    .events
                                    .metadata_warnings
                                    .iter()
                                    .any(|w| w == warning)
                                {
                                    self.protocols
                                        .mysql
                                        .events
                                        .metadata_warnings
                                        .push(warning.into());
                                }
                            }
                            continue;
                        }
                        None => None,
                    };
                    let normalized_exchange = dynamic.as_ref().and_then(|normalized| {
                        if same_input(
                            normalized.source_sql.as_deref(),
                            exchange.record.sql.as_deref(),
                        ) && same_input(
                            normalized.source_params.as_deref(),
                            exchange.record.params.as_deref(),
                        ) {
                            return None;
                        }
                        let mut copy = exchange.clone();
                        copy.record.sql = normalized.source_sql.as_deref().map(str::to_owned);
                        copy.record.params = normalized.source_params.as_deref().map(<[_]>::to_vec);
                        Some(copy)
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
                    let sql_changed = !same_input(sql, observed_sql);
                    let target_changed = sql_changed || !same_input(params, observed_params);
                    let sql_group = (!target_changed && normalized_exchange.is_none())
                        .then(|| self.protocols.mysql.candidates.sql_group(index))
                        .flatten();
                    let dynamic_normalized_sql =
                        sql_changed.then(|| sql.map(normalize_sql)).flatten();
                    let normalized_sql = dynamic_normalized_sql
                        .as_deref()
                        .or(baseline_normalized_sql.as_deref());
                    let mut dynamic_semantic_target = None;
                    let semantic_target = if target_changed {
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
                    let same_isolation = command == "COM_QUERY"
                        && exchange.record.command == "COM_QUERY"
                        && params.is_none_or(<[_]>::is_empty)
                        && transaction.is_some_and(|context| {
                            observed_sql.is_some_and(|sql| {
                                self.protocols.mysql.isolation.can_match(
                                    index,
                                    context.connection,
                                    context.status_flags,
                                    sql,
                                    &SessionContext(&self.protocols.mysql.exchanges),
                                )
                            })
                        });
                    let same_prepared_values = !cross_protocol
                        && sql.is_some_and(|sql| {
                            sql_match::prepared_values_match(&exchange.record, command, sql, params)
                        });
                    let sql_value_decision = if let Some((_, decision)) = &hypothesis {
                        Some(Ok(decision.clone()))
                    } else {
                        self.replay_policy.as_ref().and_then(|policy| {
                            let automatic =
                                policy
                                    .request_contracts
                                    .compiled_rules()
                                    .is_some_and(|compiled| {
                                        compiled.global_json.is_some() || compiled.mysql.is_some()
                                    });
                            let mut formats = automatic
                                .then(|| self.protocols.mysql.source_formats.entry(index))
                                .flatten();
                            let original = &self.protocols.mysql.exchanges[index].record;
                            let global = automatic
                                && (dynamic.is_none() || {
                                    let authored = || {
                                        policy
                                            .request_contracts
                                            .has_authored_mysql_formats(identity, original)
                                    };
                                    formats.as_mut().map_or_else(authored, |cached| {
                                        *cached.authored.get_or_insert_with(authored)
                                    })
                                });
                            // Authored global owners compare original values.
                            // Implicit textual-time recognition keeps the native
                            // identity projection already authenticated above.
                            // Original wire evidence was recorded before either
                            // comparison view was constructed.
                            let (record, selected_sql, selected_params) = if global {
                                (original, observed_sql, observed_params)
                            } else {
                                (&exchange.record, sql, params)
                            };
                            policy
                                .request_contracts
                                .preview_mysql_values_with_format_cache(
                                    active_case_id.as_deref(),
                                    identity,
                                    record,
                                    command,
                                    selected_sql,
                                    selected_params,
                                    request_observed_at,
                                    policy,
                                    if global || normalized_exchange.is_none() {
                                        formats.map(|cached| &mut cached.any)
                                    } else {
                                        None
                                    },
                                    || {
                                        if global || !sql_changed {
                                            observed_statement
                                                .get_or_init(|| {
                                                    observed_sql.and_then(statement_shared)
                                                })
                                                .clone()
                                        } else {
                                            selected_sql.and_then(statement_shared)
                                        }
                                    },
                                )
                                .or_else(|| {
                                    policy.preview_mysql_sql_values(&MysqlPolicyContext {
                                        request_times: traffic_contract::time::ClockPair {
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
                        })
                    };
                    let (mut policy_decision, projected) = if same_isolation {
                        (DependencyRuleDecision::default(), None)
                    } else if let Some(decision) = sql_value_decision {
                        let Ok(decision) = decision else {
                            continue;
                        };
                        (decision, None)
                    } else if semantic {
                        let Some(actual) = semantic_target
                            .get_or_insert_with(|| {
                                sql.and_then(|sql| {
                                    self.protocols
                                        .mysql
                                        .sql_cache
                                        .get(sql)
                                        .bind(command, params)
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
                                    request_times: traffic_contract::time::ClockPair {
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
                        let Some(recorded) = self
                            .protocols
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
                        let mut matches_in_lists = || {
                            !project_columns
                                && !allow_hypotheses
                                && !legacy_sql_selector
                                && !target_changed
                                && normalized_exchange.is_none()
                                && select_hint.is_some()
                                && sql.is_some_and(|sql| {
                                    in_lists.matches(
                                        &mut self.protocols.mysql.sql_cache,
                                        &exchange.record,
                                        (command, sql, params),
                                        sql_group,
                                    )
                                })
                        };
                        if cross_protocol
                            && !project_columns
                            && !same_autocommit
                            && !same_savepoint
                            && !sql.is_some_and(|sql| {
                                let compare = || {
                                    sql_match::cross_protocol_matches(
                                        &exchange.record,
                                        command,
                                        sql,
                                        params,
                                    )
                                };
                                sql_group.map_or_else(compare, |group| {
                                    *strict_groups.entry(group).or_insert_with(compare)
                                })
                            })
                            && !matches_in_lists()
                        {
                            continue;
                        }
                        let Some(recorded_sql) = exchange.record.sql.as_deref() else {
                            continue;
                        };
                        let sql_differs =
                            || Some(normalize_sql(recorded_sql).as_str()) != normalized_sql;
                        let same_bound_values = same_prepared_values
                            || !cross_protocol
                                && (Some(recorded_sql) != sql
                                    || !params_match(exchange.record.params.as_deref(), params))
                                && matches_in_lists();
                        let policy_decision = if cross_protocol {
                            // The SQL matcher or projection adapter verifies values.
                            // A protocol change needs no dynamic-value exemption.
                            DependencyRuleDecision::default()
                        } else if let Some(policy) = &self.replay_policy {
                            let context = MysqlPolicyContext {
                                request_times: traffic_contract::time::ClockPair {
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
                                && !same_autocommit
                                && !same_savepoint
                                && !same_bound_values
                                && sql_differs()
                                && !policy.allows_mysql_sql_difference(&context)
                            {
                                continue;
                            }
                            if same_bound_values && !policy.allows_mysql_sql_difference(&context) {
                                DependencyRuleDecision::default()
                            } else {
                                match policy.preview_mysql(&context, Utc::now()) {
                                    Ok(decision) => decision,
                                    Err(_) => continue,
                                }
                            }
                        } else if !project_columns
                            && !same_autocommit
                            && !same_savepoint
                            && !same_bound_values
                            && sql_differs()
                        {
                            continue;
                        } else if same_bound_values
                            || params_match(exchange.record.params.as_deref(), params)
                        {
                            DependencyRuleDecision::default()
                        } else {
                            continue;
                        };
                        // Reject parameter/policy mismatches before copying any rows.
                        let projected = if project_columns {
                            let Some(response) = sql.and_then(|sql| {
                                if target_changed {
                                    return projection::Candidate::compare(
                                        &mut projection_candidate,
                                        &exchange.record,
                                        command,
                                        sql,
                                        params,
                                    );
                                }
                                baseline_projection
                                    .get_or_insert_with(|| {
                                        projection::Query::prepare(command, sql, params)
                                    })
                                    .as_mut()?
                                    .grouped_response(&exchange.record, sql_group)
                            }) else {
                                continue;
                            };
                            Some(response)
                        } else {
                            None
                        };
                        (policy_decision, projected)
                    };
                    if transaction.is_some_and(|context| {
                        context.missing_for_member(
                            &self.protocols.mysql.transaction_equivalence,
                            index,
                            exchange,
                            baseline_normalized_sql.as_deref(),
                        )
                    }) {
                        transaction_rejection.get_or_insert(index);
                        continue;
                    }
                    let mut exchange = self.protocols.mysql.exchanges[index].clone();
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
                    exchange.record.response =
                        match exchange.record.response.materialize() {
                            Ok(response) => response,
                            Err(error) => {
                                self.protocols.mysql.events.metadata_warnings.push(format!(
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
                            &self.protocols.mysql.exchanges[index].record,
                            &exchange.record.response,
                            observed_sql,
                        ) {
                            Ok(prepared) => prepared,
                            Err(_) => continue,
                        }
                    } else {
                        None
                    };
                    let value_delivery = if source == ReplaySource::Case
                        || self
                            .replay_policy
                            .as_ref()
                            .and_then(|policy| policy.request_contracts.compiled_rules())
                            .is_some_and(|policy| {
                                policy.global_json.is_some() || policy.mysql.is_some()
                            }) {
                        if let (Some(policy), Some(case)) =
                            (&self.replay_policy, active_case_id.as_deref())
                        {
                            match contracts::prepare_delivery(
                                &policy.request_contracts,
                                case,
                                identity,
                                &self.protocols.mysql.exchanges[index].record,
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
                                &self.protocols.mysql.exchanges[index].record,
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
                    if let Some(policy) = &mut self.replay_policy
                        && let (Some(case), Some(normalized)) =
                            (active_case_id.as_deref(), dynamic.as_ref())
                    {
                        let mut captures =
                            crate::policy::runtime::request_contract::Decision::default();
                        if policy
                            .dynamic_values
                            .join_identities(case, &normalized.decision, &mut captures)
                            .is_err()
                        {
                            continue;
                        }
                        policy_decision.value_contracts.push(captures);
                    }
                    let dynamic_decision = dynamic.map(|normalized| normalized.decision);
                    let kind = if exchange.record.outcome.is_client_terminated()
                        && !exchange.record.lifecycle_cleanup
                    {
                        crate::replay::admission::ClaimKind::ClientTermination
                    } else {
                        crate::replay::admission::ClaimKind::Response
                    };
                    let claim = self.protocols.mysql.lifecycle.claim(
                        index,
                        &mut self.protocols.mysql.exchanges[index].status,
                        kind,
                    )?;
                    self.protocols.mysql.candidates.claimed(index);
                    if let Some(policy) = &mut self.replay_policy {
                        if policy
                            .commit(active_case_id.as_deref(), policy_decision)
                            .is_err()
                        {
                            self.protocols
                                .mysql
                                .lifecycle
                                .fail(&claim, &mut self.protocols.mysql.exchanges[index].status);
                            self.refresh_mysql_global_report(index);
                            self.record_unmatched_in_case(
                                active_case_id.as_deref(),
                                identity,
                                command,
                                observed_sql,
                                observed_params,
                                "MySQL request contract commit failed after finite admission",
                            );
                            if let Some(report) =
                                self.protocols.mysql.events.unmatched_queries.last_mut()
                            {
                                report.target_event_index = observation.event_index;
                                report.target_observation_id = target_observation_id.clone();
                            }
                            return None;
                        }
                        if let (Some(case_id), Some(decision)) =
                            (active_case_id.as_deref(), dynamic_decision)
                        {
                            policy
                                .dynamic_values
                                .commit_after_identities(case_id, decision);
                        }
                    }
                    if same_isolation {
                        self.protocols.mysql.isolation.claim_next(index);
                    }
                    self.refresh_mysql_global_report(index);
                    let owned_global = self.protocols.mysql.foreign.contains_key(&index)
                        || (exchange.source.is_run_owned()
                            && exchange
                                .record
                                .connection_id
                                .zip(exchange.record.query_sequence)
                                .is_some_and(|wire| {
                                    self.protocols.mysql.transaction_wires.contains(&wire)
                                }));
                    let matched = MatchedQueryReport {
                        source_connection_id: exchange.record.connection_id,
                        source_query_sequence: exchange.record.query_sequence,
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
                        target_event_index: observation.event_index,
                    };
                    return Some(MatchedExchange {
                        request_observed_at: Some(request_observed_at),
                        target_observation_id,
                        claim,
                        hypothesis_owner: self
                            .replay_policy
                            .as_ref()
                            .map(|p| p.request_contracts.clone()),
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
                        source: exchange.source,
                        index,
                        record: exchange.record,
                        timing: exchange.timing,
                        report: matched,
                    });
                }
            }
        }
        if let Some((index, context)) = transaction_rejection.zip(transaction) {
            let source = self.protocols.mysql.exchanges[index].source;
            let diagnostic = self
                .protocols
                .mysql
                .transaction_equivalence
                .missing_transaction_diagnostic(index, context.connection, context.status_flags);
            self.protocols
                .mysql
                .isolation
                .reject_connection(context.connection);
            self.record_unmatched_in_case(
                active_case_id.as_deref(),
                identity,
                command,
                observed_sql,
                observed_params,
                "MySQL transaction coverage: target_transaction_missing",
            );
            if let Some(report) = self.protocols.mysql.events.unmatched_queries.last_mut() {
                report.recorded_source = Some(source);
                report.recorded_index = Some(index);
                report.diagnostic = diagnostic;
                report.target_event_index = observation.event_index;
                report.target_observation_id = target_observation_id;
            }
        }
        None
    }
}

#[cfg(test)]
mod testing;
