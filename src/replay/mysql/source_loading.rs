//! Appended native evidence and released response bodies retain stable positions.
use super::*;

impl MysqlReplayState {
    pub(crate) fn source_len(&self) -> usize {
        self.exchanges.len()
    }
    pub(crate) fn observe_registered_policy_exchanges(
        &self,
        policy: &mut ReplayPolicyRuntime,
        start: usize,
    ) {
        for (offset, exchange) in self.exchanges[start..].iter().enumerate() {
            policy.observe_recorded_mysql_exchange(
                exchange.case_id.as_deref(),
                &ReplaySessionIdentity {
                    target: Some(exchange.identity.target.clone()),
                    database: exchange.identity.database.clone(),
                    username: exchange.identity.username.clone(),
                },
                &exchange.record.command,
                exchange.record.sql.as_deref(),
                Some(start + offset),
            );
        }
    }
    pub(crate) fn release_consumed_payloads(
        &mut self,
        cases: &BTreeMap<String, crate::replay::ReplayCase>,
    ) {
        for exchange in &mut self.exchanges {
            if exchange.source == ReplaySource::Case
                && exchange.status.is_consumed()
                && exchange.case_id.as_ref().is_some_and(|id| {
                    cases
                        .get(id)
                        .is_some_and(|case| case.status == crate::replay::ReplayCaseStatus::Ended)
                })
            {
                exchange.record.response.rows = Vec::new();
            }
        }
    }
}
