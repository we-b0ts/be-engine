//! Native stored HTTP payloads, independent of Replay lifecycle and authenticated storage.
use crate::{headers::HeaderSnapshot, stream::ResponseStream};
use anyhow::{Context, Result, anyhow};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use chrono::{DateTime, Utc};
use serde::Deserialize;
use serde_json::Value;
use traffic_model::{DependencyExchangeOutcome, recording::CaptureMetadata};

#[derive(Debug, Clone, Deserialize)]
pub struct RecordedExchange {
    #[serde(default)]
    pub id: Option<String>,
    pub scheme: String,
    #[serde(default)]
    pub outcome: DependencyExchangeOutcome,
    #[serde(default)]
    pub timestamp: Option<DateTime<Utc>>,
    #[serde(default)]
    pub request_started_at: Option<DateTime<Utc>>,
    // Untrusted optional timing evidence must not prevent ordinary HTTP matching.
    #[serde(default)]
    pub duration_ms: Option<Value>,
    pub method: String,
    pub uri: String,
    pub authority: Option<String>,
    pub request_body: BodyCapture,
    #[serde(default)]
    pub request_headers: HeaderSnapshot,
    pub response_status: Option<u16>,
    pub response_headers: Option<HeaderSnapshot>,
    pub response_body: Option<BodyCapture>,
    #[serde(default)]
    pub response_stream: Option<ResponseStream>,
    #[serde(default)]
    pub capture: Option<CaptureMetadata>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct BodyCapture {
    pub encoding: String,
    pub truncated: bool,
    #[serde(default)]
    pub stored_len: Option<usize>,
    pub data: String,
}

pub fn decode_body(body: &BodyCapture) -> Result<Vec<u8>> {
    if body.truncated {
        return Err(anyhow!("recorded HTTP body is truncated"));
    }
    match body.encoding.as_str() {
        "utf8" => Ok(body.data.as_bytes().to_vec()),
        "base64" => STANDARD
            .decode(&body.data)
            .context("failed to decode recorded HTTP body base64"),
        other => Err(anyhow!("unsupported recorded HTTP body encoding {other}")),
    }
}
