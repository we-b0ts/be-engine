//! Finite native HTTP sessions over the shared recording and Replay ports.
use crate::{
    message::{RequestMessage, ResponseMessage},
    recorded,
};
use anyhow::{Context, Result, ensure};
use bytes::Bytes;
use serde_json::Value;
use std::sync::Arc;
use traffic_model::{DependencyExchangeOutcome, recording::ProtocolRef};
use traffic_protocol::connection::{
    CaptureSession, ConnectionInfo, Endpoint, NativeProtocol, RecordedExchange, ServerSession,
};

mod evidence;
mod recording;
mod server;
#[cfg(test)]
mod tests;
mod wire;

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
        "http-native/v1"
    }
    fn recorded_exchange(&self, event: &Value) -> Result<Option<RecordedExchange>> {
        self.decode(event, None)
    }
    fn recorded_exchange_with_secrets(
        &self,
        event: &Value,
        secrets: &dyn traffic_protocol::evidence::EvidenceSecrets,
    ) -> Result<Option<RecordedExchange>> {
        self.decode(event, Some(secrets))
    }
    fn recorded_protocol(&self, event: &Value) -> Result<Option<traffic_protocol::ProtocolId>> {
        if event["event_type"] != "http_exchange" {
            return Ok(None);
        }
        let scheme = recorded::HttpScheme::from_recorded(
            event["scheme"].as_str().context("HTTP scheme missing")?,
        )?;
        Ok(Some(traffic_protocol::ProtocolId::new(match scheme {
            recorded::HttpScheme::Http => "http",
            recorded::HttpScheme::Https => "https",
        })))
    }
    fn recorded_endpoint(&self, event: &Value) -> Result<Option<Endpoint>> {
        if event["event_type"] != "http_exchange" {
            return Ok(None);
        }
        let record: recorded::RecordedExchange = serde_json::from_value(event.clone())?;
        Ok(Some(record.identity()?.1))
    }
    fn server_session(&self, _info: ConnectionInfo) -> Result<Box<dyn ServerSession>> {
        Ok(Box::new(server::Server))
    }
    fn capture_session(&self, info: ConnectionInfo) -> Result<Box<dyn CaptureSession>> {
        Ok(Box::new(recording::Capture(info)))
    }
}

fn finite_response_headers(headers: &crate::headers::HeaderSnapshot) -> Result<()> {
    let streaming = headers
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case("content-type"))
        .flat_map(|(_, values)| values)
        .any(|value| {
            matches!(
                value
                    .split(';')
                    .next()
                    .unwrap_or_default()
                    .trim()
                    .to_ascii_lowercase()
                    .as_str(),
                "text/event-stream" | "application/x-ndjson" | "application/ndjson"
            )
        });
    ensure!(
        !streaming,
        "HTTP event streams require an installed streaming capability"
    );
    Ok(())
}

impl Native {
    fn decode(
        &self,
        event: &Value,
        secrets: Option<&dyn traffic_protocol::evidence::EvidenceSecrets>,
    ) -> Result<Option<RecordedExchange>> {
        if event["event_type"] != "http_exchange" {
            return Ok(None);
        }
        let mut record: recorded::RecordedExchange = serde_json::from_value(event.clone())?;
        if let Some(secrets) = secrets {
            for (name, values) in &mut record.request_headers {
                for value in values {
                    *value = secrets
                        .unseal_text(&name.to_ascii_lowercase(), value)?
                        .into_owned();
                }
            }
        }
        ensure!(
            record
                .request_headers
                .values()
                .flatten()
                .all(|value| { !value.starts_with("traffic-e2e:enc:") && value != "<redacted>" }),
            "protected HTTP headers require an installed Source decryption capability"
        );
        finite_response_headers(
            record
                .response_headers
                .as_ref()
                .context("HTTP response headers missing")?,
        )?;
        ensure!(
            record.outcome == DependencyExchangeOutcome::Response && record.error.is_none(),
            "finite HTTP serving requires a complete response"
        );
        let (_, endpoint) = record.identity()?;
        let body = recorded::decode_body(
            record
                .response_body
                .as_ref()
                .context("HTTP response body missing")?,
        )?;
        if let Some(stream) = &record.response_stream {
            ensure!(
                stream.complete,
                "finite HTTP serving requires complete stream evidence"
            );
            stream.validate(body.len())?;
            ensure!(
                stream.trailers.is_none(),
                "HTTP trailers require a native streaming capability"
            );
        }
        let uri: hyper::Uri = record.uri.parse()?;
        let request = RequestMessage {
            method: record.method.to_ascii_uppercase(),
            uri: uri
                .path_and_query()
                .map_or("/", |path| path.as_str())
                .to_owned(),
            headers: record.request_headers,
            body: recorded::decode_body(&record.request_body)?.into(),
        };
        let response = ResponseMessage {
            status: record
                .response_status
                .context("HTTP response status missing")?,
            headers: record
                .response_headers
                .context("HTTP response headers missing")?,
            body: body.into(),
            head_request: request.method == "HEAD",
        };
        Ok(Some(RecordedExchange {
            reference: ProtocolRef::exchange(
                "http",
                record
                    .id
                    .context("HTTP exchange identity missing")?
                    .parse()?,
            ),
            endpoint,
            lane: None,
            response_delay: std::time::Duration::from_millis(
                record
                    .duration_ms
                    .as_ref()
                    .and_then(Value::as_u64)
                    .unwrap_or_default(),
            ),
            input: traffic_protocol::connection::RecordedInput::Request(Arc::new(request)),
            response: Arc::new(response),
        }))
    }
}
