//! Finite MySQL exchanges projected to the shared capture and Replay ports.
use std::{sync::Arc, time::Duration};

use anyhow::{Context, Result, ensure};
use serde_json::Value;
use traffic_model::{DependencyExchangeOutcome, recording::ProtocolRef};
use traffic_protocol::connection::{
    CaptureSession, ConnectionInfo, Endpoint, NativeProtocol, RecordedExchange, ServerSession,
};

use crate::{message::RequestMessage, recorded::RecordedMysqlExchange};

mod evidence;
mod prepared;
mod recording;
mod response;
mod server;
mod source_scope;
#[cfg(test)]
mod tests;

pub struct Native;

impl NativeProtocol for Native {
    fn has_replay_scope(&self) -> bool {
        true
    }

    fn prepare_replay_scope(
        &self,
        scope: traffic_model::attribution::DependencyScope,
        records: &[(usize, &Value)],
    ) -> Result<std::collections::BTreeMap<usize, traffic_protocol::connection::ReplaySessionStep>>
    {
        source_scope::prepare(scope, records, false)
    }

    fn prepare_event_session(
        &self,
        records: &[(usize, &Value)],
    ) -> Result<traffic_protocol::connection::EventSessionPreparation> {
        source_scope::prepare_event_session(records)
    }

    fn decode_evidence(
        &self,
        event: &Value,
        payload: &[u8],
        side: traffic_protocol::evidence::MessageSide,
    ) -> Result<traffic_protocol::evidence::MessageEvidence> {
        evidence::decode(event, payload, side)
    }

    fn report_semantics(&self) -> &'static str {
        "mysql-native/v1"
    }

    fn report_summary(&self, exchange: &RecordedExchange) -> Result<Value> {
        Ok(exchange
            .request()
            .expect("native request")
            .project()?
            .structure)
    }

    fn recorded_exchange(&self, event: &Value) -> Result<Option<RecordedExchange>> {
        if event["event_type"] != "mysql_exchange" {
            return Ok(None);
        }
        let record: RecordedMysqlExchange = serde_json::from_value(event.clone())?;
        ensure!(
            record.response.status != "resultset" || event["response"]["rows"].is_array(),
            "MySQL resultset has no recorded row evidence"
        );
        ensure!(
            record.outcome == DependencyExchangeOutcome::Response,
            "MySQL finite serving requires a complete response"
        );
        ensure!(
            record.parse_warnings.is_empty(),
            "MySQL capture has parse warnings"
        );
        if crate::capture::is_debug_only_mysql_exchange_value(event)
            || crate::is_no_response_command(&record.command)
        {
            return Ok(None);
        }
        ensure!(
            matches!(record.command.as_str(), "COM_QUERY" | "COM_INIT_DB"),
            "unsupported recorded MySQL command {}",
            record.command
        );
        let endpoint = crate::session_identity::target_from_exchange(&record)
            .context("MySQL exchange has no endpoint")?;
        let connection = record
            .connection_id
            .context("MySQL exchange has no connection identity")?;
        let sequence = record
            .query_sequence
            .context("MySQL exchange has no sequence")?;
        let response =
            response::ResponseMessage::new(record.response, record.server_status_before)?;
        Ok(Some(RecordedExchange {
            reference: ProtocolRef::connection("mysql", connection, sequence),
            endpoint,
            lane: Some(connection.to_string()),
            response_delay: Duration::from_millis(record.duration_ms),
            input: traffic_protocol::connection::RecordedInput::Request(Arc::new(RequestMessage {
                command: record.command,
                sql: record.sql,
                params: record.params,
                database: record.database,
                username: record.username,
            })),
            response: Arc::new(response),
        }))
    }

    fn recorded_endpoint(&self, event: &Value) -> Result<Option<Endpoint>> {
        match event["event_type"].as_str() {
            Some("mysql_exchange") => {
                let record: RecordedMysqlExchange = serde_json::from_value(event.clone())?;
                Ok(crate::session_identity::target_from_exchange(&record))
            }
            Some("mysql_connection") => {
                let record = serde_json::from_value(event.clone())?;
                Ok(crate::session_identity::target_from_connection(&record))
            }
            _ => Ok(None),
        }
    }

    fn server_session(&self, info: ConnectionInfo) -> Result<Box<dyn ServerSession>> {
        Ok(Box::new(server::Server(info)))
    }

    fn capture_session(&self, info: ConnectionInfo) -> Result<Box<dyn CaptureSession>> {
        Ok(Box::new(recording::Capture(info)))
    }
}
