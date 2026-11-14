//! Install native control facts while the framework retains live finite admission.
use super::*;
use crate::replay::dependencies::DependencyRecord;
pub(in crate::replay::mysql) use traffic_protocol_mysql::read_effect as read;
pub(in crate::replay) use traffic_protocol_mysql::session_control::ReadPrefixes;
pub(in crate::replay::mysql) use traffic_protocol_mysql::session_control::{
    successful_begin, successful_end,
};

impl MysqlReplayState {
    /// Reuse the native Source/Target proof without claiming consumption.
    /// A control Target has started must still finish its real delivery.
    pub(in crate::replay) fn permits_unstarted_omission(&self, index: usize) -> bool {
        self.exchanges.get(index).is_some_and(|exchange| {
            self.lifecycle
                .live_status(index, exchange.status)
                .is_available()
                && exchange.optional_session.is_some()
        })
    }

    /// A Source driver setup can depend on transaction coverage from later
    /// Socket.IO inputs. Defer that proof at dispatch only. The setup remains
    /// available and strict Target transaction checks still run at admission.
    pub(in crate::replay) fn can_defer_autocommit_for_dispatch(
        &self,
        index: usize,
        input_at: DateTime<Utc>,
    ) -> bool {
        self.exchanges.get(index).is_some_and(|exchange| {
            exchange.source == ReplaySource::Case
                && self
                    .lifecycle
                    .live_status(index, exchange.status)
                    .is_available()
                && exchange
                    .record
                    .sql
                    .as_deref()
                    .and_then(crate::mysql::autocommit::assignment)
                    == Some(false)
                && self
                    .transaction_equivalence
                    .can_defer_setup(index, input_at, &self.exchanges)
        })
    }
}

pub(in crate::replay) fn classify(
    records: &[DependencyRecord],
    source: ReplaySource,
    global_prefixes: &mut ReadPrefixes,
) -> BTreeMap<usize, OptionalSessionExchange> {
    traffic_protocol_mysql::session_control::classify(
        super::source_records(records),
        source,
        global_prefixes,
    )
}

#[cfg(test)]
mod autocommit;
#[cfg(test)]
mod tests;
