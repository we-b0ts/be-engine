//! Finite MySQL exchanges projected to the shared capture and Replay ports.
use std::{sync::Arc, time::Duration};

use anyhow::{Context, Result, ensure};
use serde_json::Value;
use traffic_model::{DependencyExchangeOutcome, recording::ProtocolRef};
use traffic_protocol::connection::{
    CaptureSession, ConnectionInfo, Endpoint, NativeProtocol, RecordedExchange, ServerSession,
};

use crate::{message::RequestMessage, recorded::RecordedMysqlExchange};

mod recording;
mod response;
mod server;
#[cfg(test)]
mod tests;

pub struct Native;

impl NativeProtocol for Native {
    fn report_semantics(&self) -> &'static str {
        "mysql-native/v1"
    }

    fn report_summary(&self, exchange: &RecordedExchange) -> Result<Value> {
        Ok(exchange.request.project()?.structure)
    }

    fn recorded_exchange(&self, event: &Value) -> Result<Option<RecordedExchange>> {
        if event["event_type"] != "mysql_exchange" {
            return Ok(None);
        }
        let record: RecordedMysqlExchange = serde_json::from_value(event.clone())?;
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
            request: Arc::new(RequestMessage {
                command: record.command,
                sql: record.sql,
                params: record.params,
                database: record.database,
                username: record.username,
            }),
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
