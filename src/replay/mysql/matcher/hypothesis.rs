//! Bounded fallback selection; no Source slot or identity is committed here.
use super::request::TransactionMatch;
use super::*;

impl ReplayState {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn select_mysql_hypothesis(
        &mut self,
        case: &str,
        identity: &ReplaySessionIdentity,
        command: &str,
        sql: Option<&str>,
        params: Option<&[RecordedMysqlValue]>,
        transaction: Option<TransactionMatch<'_>>,
        observed: DateTime<Utc>,
        observation_id: Option<uuid::Uuid>,
    ) -> Option<(usize, crate::replay::DependencyRuleDecision)> {
        let owner = self.replay_policy.as_ref()?.request_contracts.clone();
        if !owner.pre_match_enabled() {
            return None;
        }
        let projected =
            crate::replay::mysql::sql_match::materialize(sql?, params.unwrap_or_default())?;
        let candidates = self.mysql.candidates.select(
            &self.mysql.exchanges,
            ReplaySource::Case,
            Some(case),
            identity,
            Some(command),
        );
        let mut selected = None;
        let mut visited = 0;
        for index in candidates.iter().copied() {
            let exchange = &self.mysql.exchanges[index];
            if !exchange.status.is_available()
                || !exchange.record.parse_warnings.is_empty()
                || exchange.record.response.rows_truncated
                || exchange.optional_session.is_some()
                || self.mysql.foreign.contains_key(&index)
                || transaction
                    .is_some_and(|context| !self.mysql.isolation.permits(context.connection, index))
            {
                continue;
            }
            if exchange.record.connection_id.is_some_and(|connection| {
                self.mysql.exchanges.iter().any(|prior| {
                    prior.source == exchange.source
                        && prior.case_id == exchange.case_id
                        && prior.record.connection_id == Some(connection)
                        && prior.record.query_sequence < exchange.record.query_sequence
                        && !prior.status.is_consumed()
                        && prior.optional_session.is_none()
                })
            }) {
                continue;
            }
            visited += 1;
            if visited > 256 {
                self.mysql
                    .events
                    .metadata_warnings
                    .push("MySQL hypothesis candidate budget exhausted".into());
                return None;
            }
            let Some(Ok(decision)) = owner.preview_mysql_hypothesis(
                case,
                identity,
                &exchange.record,
                command,
                sql,
                params,
                observed,
                observation_id,
                Some(&projected),
            ) else {
                continue;
            };
            if selected.is_some() {
                self.mysql
                    .events
                    .metadata_warnings
                    .push("MySQL hypothesis has multiple eligible Source exchanges".into());
                return None;
            }
            selected = Some((index, decision));
        }
        selected
    }
}
