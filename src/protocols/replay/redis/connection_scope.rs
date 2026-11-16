//! Project recorded Redis facts into native session-binding constraints.
use super::{RecordedExchange, ReplayExchange, ReplaySource};
use traffic_protocol_redis::session_binding::{RecordedSession, SessionExchange};
use uuid::Uuid;

impl RecordedSession for RecordedExchange {
    fn connection_id(&self) -> Uuid {
        self.native.connection_id
    }
    fn sequence(&self) -> u64 {
        self.native.sequence
    }
    fn command(&self) -> &str {
        &self.native.command
    }
    fn session_setup(&self) -> bool {
        self.native.session_setup
    }
}

impl SessionExchange for ReplayExchange {
    type Record = RecordedExchange;
    fn record(&self) -> &Self::Record {
        &self.record
    }
    fn source(&self) -> ReplaySource {
        self.source
    }
    fn case_id(&self) -> Option<&str> {
        self.case_id.as_deref()
    }
    fn connection_independent(&self) -> bool {
        self.connection_independent
    }
}

#[cfg(test)]
mod tests;

impl traffic_protocol_redis::storage::StorageExchange for ReplayExchange {
    fn native_record(&self) -> &traffic_protocol_redis::recorded::RecordedExchange {
        &self.record.native
    }
    fn arguments(&self) -> &[Vec<u8>] {
        &self.args
    }
    fn response_bytes(&self) -> anyhow::Result<Vec<u8>> {
        ReplayExchange::response_bytes(self)
    }
    fn explicitly_shared(&self) -> bool {
        self.shared_rule_id.is_some() || self.reusable_snapshot
    }
}
