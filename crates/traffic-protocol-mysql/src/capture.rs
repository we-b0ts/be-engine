//! MySQL capture completeness and native semantic obligations.
use traffic_model::recording::ProtocolRef;
use traffic_protocol::capture::{CaptureEvidence, CaptureFacts, SemanticRequirement};

use crate::events::*;
mod response;
mod semantic;
mod tracker;
mod upstream_tls;
pub use semantic::MysqlExchangeContext;
pub use tracker::{MysqlQueryCompletion, MysqlQueryTracker};
pub use upstream_tls::upstream_client_config;
#[path = "capture_classification.rs"]
mod classification;
#[cfg(test)]
mod continuation_tests;
pub use classification::{
    is_debug_only_mysql_exchange, is_debug_only_mysql_exchange_value,
    is_successful_mysql_session_setup,
};

impl CaptureEvidence for MysqlExchangeEvent {
    fn event_type(&self) -> &'static str {
        "mysql_exchange"
    }
    fn capture_facts(&self) -> CaptureFacts {
        let complete = self.response.status != "incomplete"
            && !self.response.rows_truncated
            && self
                .params
                .as_ref()
                .is_none_or(|params| params.iter().all(value_complete))
            && self.response.rows.iter().flatten().all(value_complete)
            && self
                .response
                .wire_prefix
                .iter()
                .all(|packet| !packet.packet.truncated);
        let mut facts = CaptureFacts::dependency(
            ProtocolRef::connection("mysql", self.connection_id, self.query_sequence),
            self.outcome.label(),
            complete,
        );
        facts.outcome = self.outcome;
        facts.case_dependency = self.command == "COM_PING" || !is_debug_only_mysql_exchange(self);
        if !facts.case_dependency || self.command == "COM_PING" {
            facts.semantic = SemanticRequirement::Observation;
        }
        facts.traffic_error = self.response.error_code.is_some();
        facts
    }
}

impl CaptureEvidence for MysqlConnectionEvent {
    fn event_type(&self) -> &'static str {
        "mysql_connection"
    }
    fn capture_facts(&self) -> CaptureFacts {
        let mut facts =
            CaptureFacts::observation(ProtocolRef::observation(self.id, self.event_type()));
        facts.traffic_error = self.error.is_some();
        facts
    }
}

impl CaptureEvidence for MysqlQueryEvent {
    fn event_type(&self) -> &'static str {
        "mysql_query"
    }
    fn capture_facts(&self) -> CaptureFacts {
        let mut facts = CaptureFacts::observation(ProtocolRef::connection(
            "mysql",
            self.connection_id,
            self.sequence,
        ));
        facts.debug = true;
        facts
    }
}

impl CaptureEvidence for MysqlPacketEvent {
    fn event_type(&self) -> &'static str {
        "mysql_packet"
    }
    fn capture_facts(&self) -> CaptureFacts {
        let mut facts =
            CaptureFacts::observation(ProtocolRef::observation(self.id, self.event_type()));
        facts.debug = true;
        facts.traffic_error = self.error_code.is_some();
        facts
    }
}

impl CaptureEvidence for MysqlResponseEvent {
    fn event_type(&self) -> &'static str {
        "mysql_response"
    }
    fn capture_facts(&self) -> CaptureFacts {
        let mut facts = CaptureFacts::observation(ProtocolRef::connection(
            "mysql",
            self.connection_id,
            self.query_sequence,
        ));
        facts.debug = true;
        facts.traffic_error = self.error_code.is_some();
        facts
    }
}

impl CaptureEvidence for MysqlTlsRejectedEvent {
    fn event_type(&self) -> &'static str {
        "mysql_tls_rejected"
    }
    fn capture_facts(&self) -> CaptureFacts {
        let mut facts =
            CaptureFacts::observation(ProtocolRef::observation(self.id, self.event_type()));
        facts.traffic_error = true;
        facts
    }
}

fn value_complete(value: &crate::semantic::MysqlValue) -> bool {
    value.raw.as_ref().is_none_or(|raw| !raw.truncated)
}
