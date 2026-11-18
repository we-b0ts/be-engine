//! Native recording projections and sessions for the shared engine execution path.
use std::{sync::Arc, time::Duration};

use anyhow::{Result, ensure};
use bytes::Bytes;
use serde_json::{Value, json};
use traffic_model::{DependencyExchangeOutcome, recording::ProtocolRef};
use traffic_protocol::connection::{
    CaptureSession, ConnectionInfo, Endpoint, NativeProtocol, RecordedExchange, ServerSession,
};

use crate::{
    message::{RequestMessage, ResponseMessage},
    recorded,
};

mod evidence;
pub(crate) mod notification;
mod recording;
mod server;
mod subscription;

#[cfg(test)]
mod tests;

pub struct Native;

impl NativeProtocol for Native {
    fn decode_evidence(
        &self,
        event: &Value,
        payload: &[u8],
        side: traffic_protocol::evidence::MessageSide,
    ) -> Result<traffic_protocol::evidence::MessageEvidence> {
        evidence::decode(event, payload, side)
    }

    fn report_semantics(&self) -> &'static str {
        "redis-native/v1"
    }

    fn report_summary(&self, exchange: &RecordedExchange) -> Result<Value> {
        let Some(request) = exchange.request() else {
            return Ok(json!({"notification":exchange.response.project()?.structure}));
        };
        let request = request.project()?;
        Ok(
            json!({"command":request.structure["command"],"database":request.structure["database"],"arguments":request.structure["arguments"]}),
        )
    }

    fn recorded_exchange(&self, event: &Value) -> Result<Option<RecordedExchange>> {
        if event["event_type"] == "redis_pub_sub_push" {
            return notification::recorded(event).map(Some);
        }
        if event["event_type"] == "redis_connection" {
            ensure!(
                event["replay_safe"] != false,
                "unsafe Redis connection evidence"
            );
        }
        if event["event_type"] != "redis_exchange" {
            return Ok(None);
        }
        let record: recorded::RecordedExchange = serde_json::from_value(event.clone())?;
        let decoded = record.decode_replay(false)?;
        ensure!(
            record.outcome == DependencyExchangeOutcome::Response,
            "Redis native serving requires a complete response"
        );
        ensure!(
            record.resp_version == 2,
            "Redis native serving currently requires RESP2"
        );
        ensure!(record.database >= 0, "Redis database must be nonnegative");
        let command = crate::RedisCommand {
            name: record.command.clone(),
            args: decoded.args.clone(),
        };
        if crate::is_client_library_info(&record.command, &decoded.args) {
            return Ok(None);
        }
        let mut version = record.resp_version;
        let mut database = record.database;
        let mut username = record.username.clone();
        let subscribed_ping = command.name == "PING" && record.response_kind == "array";
        if !subscribed_ping
            && crate::builtins::redis_builtin(&command, &mut version, &mut database, &mut username)
                .is_some()
        {
            ensure!(
                record.response_kind != "error",
                "recorded Redis session rejection requires native admission support"
            );
            return Ok(None);
        }
        ensure!(
            !crate::builtins::redis_is_unsupported(&command),
            "unsupported recorded Redis command mode"
        );
        Ok(Some(RecordedExchange {
            reference: ProtocolRef::connection("redis", record.connection_id, record.sequence),
            endpoint: Endpoint {
                host: traffic_protocol::observation::normalize_host(&record.target_host),
                port: record.target_port,
            },
            lane: Some(record.connection_id.to_string()),
            response_delay: Duration::from_millis(record.duration_ms),
            input: traffic_protocol::connection::RecordedInput::Request(Arc::new(RequestMessage {
                command: record.command,
                args: decoded.args.into_iter().map(Bytes::from).collect(),
                resp_version: record.resp_version,
                database: record.database,
                username: record.username,
            })),
            response: Arc::new(ResponseMessage::decode(decoded.response.into())?),
        }))
    }

    fn recorded_endpoint(&self, event: &Value) -> Result<Option<Endpoint>> {
        if !matches!(
            event["event_type"].as_str(),
            Some("redis_exchange" | "redis_connection" | "redis_pub_sub_push")
        ) {
            return Ok(None);
        }
        Ok(Some(serde_json::from_value(
            json!({"host":event["target_host"],"port":event["target_port"]}),
        )?))
    }

    fn server_session(&self, info: ConnectionInfo) -> Result<Box<dyn ServerSession>> {
        Ok(Box::new(server::Server {
            limit: info.max_frame_bytes,
        }))
    }

    fn capture_session(&self, info: ConnectionInfo) -> Result<Box<dyn CaptureSession>> {
        Ok(Box::new(recording::Capture(info)))
    }
}
