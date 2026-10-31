use anyhow::{Context, Result, ensure};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use serde::Deserialize;

use crate::http::sse::SseObservation;
use crate::recorder::HeaderMapSnapshot;

use super::model::ResponseGatewayProtocol;
#[cfg(test)]
mod clock_tests;

#[derive(Debug, Deserialize)]
pub(super) struct RecordedRequest {
    #[serde(default)]
    pub(super) interaction: Option<crate::interaction::model::InputTranscript>,
    pub(super) timestamp: Option<chrono::DateTime<chrono::Utc>>,
    pub(super) method: String,
    pub(super) uri: String,
    #[serde(default)]
    pub(super) headers: Option<HeaderMapSnapshot>,
    pub(super) protocol_version: Option<String>,
    #[serde(default)]
    pub(super) body: Option<ResponseBody>,
}

impl RecordedRequest {
    pub(super) fn has_motan_frame(&self) -> bool {
        matches!(
            crate::protocol_contract::primary_version(self.protocol_version.as_deref()),
            Ok(crate::protocol_contract::NativeProtocolVersion::Motan1
                | crate::protocol_contract::NativeProtocolVersion::Motan2)
        )
    }

    pub(super) fn gateway_protocol(&self) -> Result<ResponseGatewayProtocol> {
        use crate::protocol_contract::{NativeProtocolVersion, primary_version};
        match primary_version(self.protocol_version.as_deref())? {
            NativeProtocolVersion::Http => Ok(ResponseGatewayProtocol::Http),
            NativeProtocolVersion::Motan1 => Ok(ResponseGatewayProtocol::Motan1),
            NativeProtocolVersion::Motan2 => Ok(ResponseGatewayProtocol::Motan2),
            _ => anyhow::bail!("primary protocol has no response assertion adapter"),
        }
    }
}

#[derive(Debug, Deserialize)]
pub(super) struct ExpectedResponse {
    pub(super) timestamp: Option<serde_json::Value>,
    pub(super) duration_ms: Option<serde_json::Value>,
    #[serde(default)]
    pub(super) interaction: Option<crate::interaction::model::OutputObservation>,
    #[serde(default)]
    pub(super) sse_observation: Option<SseObservation>,
    pub(super) status: Option<RecordedStatus>,
    #[serde(default)]
    pub(super) headers: Option<HeaderMapSnapshot>,
    pub(super) body: Option<ResponseBody>,
    pub(super) frame: Option<ResponseBody>,
    pub(super) response_expected: Option<bool>,
}

impl ExpectedResponse {
    /// Duration and event offsets share the capture's monotonic start. Legacy
    /// request.json timestamps were captured after admission and body reads.
    pub(super) fn clock_start(
        &self,
        fallback: Option<chrono::DateTime<chrono::Utc>>,
    ) -> Option<chrono::DateTime<chrono::Utc>> {
        self.interaction
            .as_ref()
            .and_then(|_| {
                let elapsed = i64::try_from(self.duration_ms.as_ref()?.as_u64()?).ok()?;
                chrono::DateTime::parse_from_rfc3339(self.timestamp.as_ref()?.as_str()?)
                    .ok()?
                    .with_timezone(&chrono::Utc)
                    .checked_sub_signed(chrono::TimeDelta::try_milliseconds(elapsed)?)
            })
            .or(fallback)
    }
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub(super) enum RecordedStatus {
    Http(u16),
    Rpc(String),
}

impl RecordedStatus {
    pub(super) fn code(&self) -> u16 {
        match self {
            Self::Http(value) => *value,
            Self::Rpc(value) => match value.as_str() {
                "normal" => 200,
                "value" => 201,
                "void" => 204,
                "attachment" => 206,
                "exception" => 500,
                _ => 520,
            },
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ActualResponse {
    #[serde(default)]
    pub(super) primary: Option<crate::primary_protocol::PrimaryMetadata>,
    #[serde(default)]
    pub(super) interaction_started_at: Option<chrono::DateTime<chrono::Utc>>,
    #[serde(default)]
    pub(super) interaction: Option<crate::interaction::model::OutputObservation>,
    #[serde(default)]
    pub(super) sse_observation: Option<SseObservation>,
    #[serde(default)]
    pub(super) request_sent_at: Option<chrono::DateTime<chrono::Utc>>,
    #[serde(default, rename = "request_rules")]
    _request_rules: Vec<crate::request_rules::RequestRuleObservation>,
    #[serde(default)]
    pub(super) request_headers: Option<HeaderMapSnapshot>,
    pub(super) version: u8,
    pub(super) status: u16,
    #[serde(default)]
    pub(super) headers: Option<HeaderMapSnapshot>,
    pub(super) body: ResponseBody,
}

#[derive(Debug, Deserialize)]
pub(super) struct ResponseBody {
    pub(super) encoding: String,
    pub(super) data: String,
    pub(super) truncated: bool,
    pub(super) decode_error: Option<String>,
}

pub(super) fn decode_body(body: &ResponseBody, label: &str) -> Result<Vec<u8>> {
    ensure!(!body.truncated, "{label} body is truncated");
    ensure!(
        body.decode_error.is_none(),
        "{label} body content decoding failed: {}",
        body.decode_error.as_deref().unwrap_or_default()
    );
    match body.encoding.as_str() {
        "utf8" => Ok(body.data.as_bytes().to_vec()),
        "base64" => STANDARD
            .decode(&body.data)
            .with_context(|| format!("{label} body contains invalid base64")),
        encoding => anyhow::bail!("{label} body uses unsupported encoding {encoding:?}"),
    }
}
