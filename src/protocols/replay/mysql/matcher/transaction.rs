//! Transaction state constrains candidate admission before sending a recorded reply.
use super::*;

#[derive(Clone, Copy)]
pub(in crate::protocols::replay::mysql) struct TransactionMatch<'a> {
    pub(in crate::protocols::replay::mysql) savepoints: &'a super::super::savepoints::Bindings,
    pub(in crate::protocols::replay::mysql) preferred_end: Option<usize>,
    pub(in crate::protocols::replay::mysql) status_flags: u16,
    pub(in crate::protocols::replay::mysql) connection: Uuid,
    pub(in crate::protocols::replay::mysql) witness:
        &'a super::super::transaction_equivalence::Witness,
}

impl TransactionMatch<'_> {
    pub(super) fn permits(self, mysql: &MysqlReplayState, index: usize) -> bool {
        mysql
            .isolation
            .permits(self.connection, index, &SessionContext(&mysql.exchanges))
            && mysql
                .transaction_equivalence
                .permits_savepoint_member(index, self.witness)
    }

    pub(super) fn missing_for_member(
        self,
        registry: &super::super::transaction_equivalence::Registry,
        index: usize,
        exchange: &ReplayExchange,
        normalized_sql: Option<&str>,
    ) -> bool {
        self.status_flags & 3 == super::super::SERVER_STATUS_AUTOCOMMIT
            && !self.witness.has_active_transaction()
            && !matches!(normalized_sql, Some("begin" | "start transaction"))
            && exchange.record.outcome == crate::DependencyExchangeOutcome::Response
            && !exchange.record.lifecycle_cleanup
            && registry.requires_active_member(index)
    }
}
