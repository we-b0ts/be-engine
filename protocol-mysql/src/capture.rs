//! MySQL capture completeness and native semantic obligations.
use traffic_model::{DependencyExchangeOutcome, recording::ProtocolRef};
use traffic_protocol::capture::{
    CaptureEvidence, CaptureFacts, RecordingLayout, RecordingScalar, SemanticRequirement,
};

use crate::events::*;
use crate::semantic::MysqlExchangeResponse;
pub mod connection;
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
        )
        .with_recording_layout(RecordingLayout {
            protocol: "mysql",
            variant: "",
            event_type: self.event_type(),
            fields: &[
                ("query_sequence", RecordingScalar::Integer),
                ("database", RecordingScalar::Text),
                ("username", RecordingScalar::Text),
                ("server_status_before", RecordingScalar::Integer),
                ("statement_id", RecordingScalar::Integer),
            ],
            request_fields: &["command", "sql", "params"],
            response_fields: &["response"],
            use_dependency_id: true,
        });
        facts.outcome = self.outcome;
        facts.case_dependency = self.command == "COM_PING" || !is_debug_only_mysql_exchange(self);
        if !facts.case_dependency || self.command == "COM_PING" {
            facts.semantic = SemanticRequirement::Observation;
        }
        facts.traffic_error = self.response.error_code.is_some();
        if complete
            && self.outcome == DependencyExchangeOutcome::Response
            && self.parse_warnings.is_empty()
        {
            facts.recording_response_literal = recording_response_literal(&self.response);
        }
        facts
    }
}

fn recording_response_literal(response: &MysqlExchangeResponse) -> Option<&'static str> {
    matches!(
        response,
        MysqlExchangeResponse {
            wire_prefix,
            server_status: Some(0),
            status,
            error_code: None,
            error_message: None,
            affected_rows: Some(0),
            last_insert_id: Some(0),
            columns,
            rows,
            row_count: 0,
            rows_truncated: false,
        } if status == "ok" && wire_prefix.is_empty() && columns.is_empty() && rows.is_empty()
    )
    .then_some("mysql_ok_zero")
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
