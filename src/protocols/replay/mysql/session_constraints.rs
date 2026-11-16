//! Read-only projection of the framework inventory for native session constraints.
use super::*;
use traffic_protocol_mysql::session_constraints::{
    SessionContext as NativeContext, SourceExchange,
};

pub(crate) struct SessionContext<'a>(pub &'a [ReplayExchange]);

impl NativeContext for SessionContext<'_> {
    type Evidence = crate::dependency_index::RecordRef;

    fn exchange(&self, index: usize) -> SourceExchange<'_, Self::Evidence> {
        let exchange = &self.0[index];
        SourceExchange {
            record: &exchange.record,
            identity: &exchange.identity,
            source: exchange.source,
            case_id: exchange.case_id.as_deref(),
            optional_session: exchange.optional_session,
        }
    }

    fn available(&self, index: usize) -> bool {
        self.0[index].status.is_available()
    }

    fn admitted(&self, index: usize) -> bool {
        matches!(
            self.0[index].status,
            ReplayExchangeStatus::Responding | ReplayExchangeStatus::Consumed
        )
    }

    fn delivered(&self, index: usize) -> bool {
        self.0[index].status.is_consumed()
    }
}

impl traffic_protocol_mysql::cleanup_selection::SessionInventory for SessionContext<'_> {
    fn exchange_count(&self) -> usize {
        self.0.len()
    }
}
