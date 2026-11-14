//! Project recorded Redis facts into native session-binding constraints.
use super::{RecordedExchange, ReplayExchange, ReplaySource};
use traffic_protocol_redis::session_binding::{RecordedSession, SessionExchange};
use uuid::Uuid;

impl RecordedSession for RecordedExchange {
    fn connection_id(&self) -> Uuid {
        self.connection_id
    }
    fn sequence(&self) -> u64 {
        self.sequence
    }
    fn command(&self) -> &str {
        &self.command
    }
    fn session_setup(&self) -> bool {
        self.session_setup
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
