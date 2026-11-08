//! Bounded fallback selection; no Source slot or identity is committed here.
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
        window: Option<&[usize]>,
        transaction_rejection: &mut Option<usize>,
    ) -> Option<(usize, crate::replay::DependencyRuleDecision)> {
        let owner = self.replay_policy.as_ref()?.request_contracts.clone();
        if !owner.pre_match_enabled() {
            return None;
        }
        let projected =
            crate::replay::mysql::sql_match::materialize(sql?, params.unwrap_or_default())?;
        let fallback;
        let candidates = if let Some(window) = window {
            window
        } else {
            fallback = self.mysql.candidates.lookup(
                ReplaySource::Case,
                Some(case),
                identity,
                Some(command),
            );
            &fallback
        };
        let mut search = crate::replay::candidate_selection::UniqueCandidate::new(256);
        let sql_family = candidates::sql_family(sql);
        let normalized_sql = sql.map(normalize_sql);
        for index in candidates.iter().copied() {
            let exchange = &self.mysql.exchanges[index];
            if !self.mysql.candidates.permits_sql(index, sql_family)
                || !exchange.status.is_available()
                || !exchange.record.parse_warnings.is_empty()
                || exchange.record.response.rows_truncated
                || exchange.optional_session.is_some()
                || self.mysql.foreign.contains_key(&index)
                || transaction.is_some_and(|context| !context.permits(&self.mysql, index))
            {
                continue;
            }
            if self
                .mysql
                .candidates
                .lane_blocker(&self.mysql.exchanges, index)
                .is_some()
            {
                continue;
            }
            if search.inspect().is_err() {
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
            if transaction.is_some_and(|context| {
                context.missing_for_member(
                    &self.mysql.transaction_equivalence,
                    index,
                    exchange,
                    normalized_sql.as_deref(),
                )
            }) {
                transaction_rejection.get_or_insert(index);
                continue;
            }
            if search.accept(index, decision).is_err() {
                self.mysql
                    .events
                    .metadata_warnings
                    .push("MySQL hypothesis has multiple eligible Source exchanges".into());
                return None;
            }
        }
        search.finish()
    }
}
