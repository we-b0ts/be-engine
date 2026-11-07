use super::*;
mod control;
mod hypothesis;
mod in_list;
mod match_order;
mod observation;
mod request;
mod source_formats;
mod statement_metadata;
pub(super) use request::TransactionMatch;

#[derive(Debug, Default)]
pub(in crate::replay) struct MysqlReplayState {
    pub(super) lifecycle: crate::replay::admission::Lifecycle,
    pub(in crate::replay) request_observation_id: Option<String>,
    #[cfg(test)]
    pub(in crate::replay) observed_at_for_test: Option<DateTime<Utc>>,
    pub(in crate::replay) exchanges: Vec<ReplayExchange>,
    case_exchange_index: CaseExchangeIndex,
    pub(in crate::replay) events: ReplayEvents,
    pub(super) sql_cache: sql_match::cache::SqlCache,
    source_formats: source_formats::Cache,
    statement_metadata: statement_metadata::Cache,
    candidates: candidates::Candidates,
    request_sources: Vec<Option<crate::policy_evidence::PreparedRequestSource>>,
    cleanup_selection: cleanup_selection::Index,
    pub(in crate::replay) read_prefixes: optional_session::ReadPrefixes,
    pub(in crate::replay) transaction_equivalence: transaction_equivalence::Registry,
    pub(in crate::replay) isolation: isolation::Registry,
    pub(super) origins: ownership::Origins,
    pub(super) foreign: ownership::Foreign,
    pub(super) transaction_wires: std::collections::HashSet<(Uuid, u64)>,
    pub(super) transaction_provenance: BTreeMap<usize, transaction_ownership::Provenance>,
    pub(super) promoted_wires: std::collections::HashSet<(Uuid, u64)>,
    pub(in crate::replay) has_global_transaction_start: bool,
}

impl MysqlReplayState {
    pub(in crate::replay) fn exchange_status(&self, index: usize) -> Option<ReplayExchangeStatus> {
        self.exchanges
            .get(index)
            .map(|exchange| self.lifecycle.live_status(index, exchange.status))
    }

    pub(in crate::replay) fn has_in_flight(&self) -> bool {
        self.exchanges.iter().enumerate().any(|(index, exchange)| {
            matches!(
                self.lifecycle.live_status(index, exchange.status),
                ReplayExchangeStatus::Responding | ReplayExchangeStatus::AwaitingClientTermination
            )
        })
    }

    pub(in crate::replay) fn has_case_in_flight(&self) -> bool {
        self.exchanges.iter().enumerate().any(|(index, exchange)| {
            exchange.source == ReplaySource::Case
                && matches!(
                    self.lifecycle.live_status(index, exchange.status),
                    ReplayExchangeStatus::Responding
                        | ReplayExchangeStatus::AwaitingClientTermination
                )
        })
    }
    pub(in crate::replay) fn prepare_candidates(&mut self) {
        self.candidates.register(&self.exchanges);
    }

    pub(super) fn has_finite_prepare(
        &mut self,
        case: Option<&str>,
        identity: &ReplaySessionIdentity,
    ) -> bool {
        self.prepare_candidates();
        [ReplaySource::Case, ReplaySource::Startup]
            .into_iter()
            .any(|source| {
                !self
                    .candidates
                    .lookup(source, case, identity, Some("COM_STMT_PREPARE"))
                    .is_empty()
            })
    }

    pub(in crate::replay) fn prepared_case_members(&self, case: &str) -> Arc<[usize]> {
        self.candidates.case_members(case)
    }

    pub(in crate::replay) fn prepare_request_sources(
        &mut self,
        owner: &crate::replay::policy::request_contract::RequestContracts,
        case: &str,
        indices: &[usize],
    ) -> Result<()> {
        if !owner.retains_value_witnesses() || owner.compiled_rules().is_none() {
            return Ok(());
        }
        self.request_sources
            .resize_with(self.exchanges.len(), || None);
        let source_case_start = owner.request_times(case).source;
        for &index in indices {
            self.request_sources[index] = owner.prepare_mysql_request_source(
                case,
                &self.exchanges[index],
                source_case_start,
            )?;
        }
        Ok(())
    }

    #[cfg(test)]
    pub(in crate::replay) fn invalidate_scope_index(&mut self) {
        self.candidates = candidates::Candidates::default();
        self.cleanup_selection = cleanup_selection::Index::default();
        self.statement_metadata = statement_metadata::Cache::default();
        self.request_sources.clear();
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
        self.has_global_transaction_start |= exchange.source.is_run_owned()
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
                    let status = self.lifecycle.live_status(index, exchange.status);
                    let optional = exchange.optional_session.filter(|kind| {
                        status.is_available()
                            || matches!(
                                kind,
                                OptionalSessionExchange::Rollback | OptionalSessionExchange::Commit
                            ) && status == ReplayExchangeStatus::Responding
                    });
                    !status.is_consumed()
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
        let event_index = self.mysql.events.request_order.reserve(case);
        self.record_builtin_observed_in_case(
            case,
            identity,
            command,
            sql,
            reason,
            Some(event_index),
            None,
        );
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn record_builtin_observed_in_case(
        &mut self,
        case: Option<&str>,
        identity: &ReplaySessionIdentity,
        command: &str,
        sql: Option<&str>,
        reason: &str,
        event_index: Option<usize>,
        observation_id: Option<&str>,
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
            |_| QueryReport {
                target_observation_id: observation_id.map(str::to_owned),
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
                target_event_index: event_index,
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
            target_observation_id: None,
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
            target_observation_id: None,
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
        let family = candidates::sql_family(sql);
        for source in [ReplaySource::Case, ReplaySource::Startup] {
            let candidates = self.mysql.candidates.select(
                &self.mysql.exchanges,
                source,
                case,
                identity,
                Some(command),
            );
            for &index in candidates.iter() {
                if !self.mysql.candidates.permits_sql(index, family) {
                    continue;
                }
                let exchange = &mut self.mysql.exchanges[index];
                if !exchange.source.matches_scope(source)
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
                if !active_case_matches(case, exchange) {
                    continue;
                }
                if !identity_matches_exchange(identity, &exchange.identity) {
                    continue;
                }
                let recorded_sql = exchange.record.sql.as_deref().map(normalize_sql);
                if recorded_sql != normalized_sql {
                    continue;
                }
                let Some(ticket) = self.mysql.lifecycle.claim(
                    index,
                    &mut exchange.status,
                    crate::replay::admission::ClaimKind::Response,
                ) else {
                    continue;
                };
                self.mysql.candidates.claimed(index);
                ticket.publish_wire();
                if !self.mysql.lifecycle.complete(&ticket, &mut exchange.status) {
                    continue;
                }
                if exchange.source.is_run_owned() {
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

    pub(in crate::replay) fn unused_exchanges(
        &self,
        source: ReplaySource,
    ) -> Vec<RecordedExchangeSummary> {
        self.mysql_unused_iter(source, None)
            .filter(|exchange| !self.mysql.foreign.contains_key(&exchange.index))
            .take(if source.is_run_owned() {
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

    pub(in crate::replay) fn allowed_unused_connection_read_committed(
        &self,
    ) -> Vec<RecordedExchangeSummary> {
        self.allowed_unused_session_exchanges(OptionalSessionExchange::ConnectionReadCommitted)
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
        [ReplaySource::Case, ReplaySource::Startup]
            .into_iter()
            .flat_map(|source| {
                self.mysql_unused_iter(source, Some(kind))
                    .take(if source.is_run_owned() {
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
        let status = self.mysql.lifecycle.live_status(index, exchange.status);
        let optional = exchange.optional_session.filter(|kind| {
            // Successful cleanup stays optional during delivery. Failed
            // delivery still reports an error and stays required.
            status.is_available()
                || matches!(
                    kind,
                    OptionalSessionExchange::Rollback | OptionalSessionExchange::Commit
                ) && status == ReplayExchangeStatus::Responding
        });
        exchange.source.matches_scope(source) && !status.is_consumed() && optional == allowed
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

    pub(in crate::replay) fn complete_exchange(&mut self, matched: &MatchedExchange) -> bool {
        self.finish_mysql_exchange(matched, || Ok(()))
            .unwrap_or(false)
    }

    pub(in crate::replay::mysql) fn finish_mysql_exchange(
        &mut self,
        matched: &MatchedExchange,
        commit: impl FnOnce() -> Result<()>,
    ) -> Result<bool> {
        let Some(exchange) = self.mysql.exchanges.get_mut(matched.index) else {
            return Ok(false);
        };
        match self
            .mysql
            .lifecycle
            .finish(&matched.claim, &mut exchange.status, commit)
        {
            crate::replay::admission::Finish::Committed(()) => {}
            crate::replay::admission::Finish::Unchanged => return Ok(false),
            crate::replay::admission::Finish::Failed(error) => {
                self.refresh_mysql_global_report(matched.index);
                let identity = ReplaySessionIdentity {
                    target: matched.report.target.clone(),
                    database: matched.report.database.clone(),
                    username: matched.report.username.clone(),
                };
                self.record_unmatched_in_case(
                    matched.report.case_id.as_deref(),
                    &identity,
                    &matched.report.command,
                    matched.report.sql.as_deref(),
                    matched.report.params.as_deref(),
                    "MySQL delivery contract commit failed",
                );
                if let Some(report) = self.mysql.events.unmatched_queries.last_mut() {
                    report.target_event_index = matched.report.target_event_index;
                    report.target_observation_id = matched.target_observation_id.clone();
                }
                return Err(error);
            }
        }
        self.refresh_mysql_global_report(matched.index);
        let case_id = matched.report.case_id.clone();
        push_success_detail(
            &mut self.mysql.events.matched_query_count,
            &mut self.mysql.events.matched_queries,
            &mut self.mysql.events.matched_query_details,
            case_id.as_deref(),
            |_| matched.report.clone(),
        );
        Ok(true)
    }

    pub(in crate::replay) fn fail_exchange(
        &mut self,
        matched: &MatchedExchange,
        identity: &ReplaySessionIdentity,
        reason: &str,
    ) {
        let Some(exchange) = self.mysql.exchanges.get_mut(matched.index) else {
            return;
        };
        if !self
            .mysql
            .lifecycle
            .fail(&matched.claim, &mut exchange.status)
        {
            return;
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
        if let Some(report) = self.mysql.events.unmatched_queries.last_mut() {
            report.target_event_index = matched.report.target_event_index;
            report.target_observation_id = matched.target_observation_id.clone();
        }
    }
}
