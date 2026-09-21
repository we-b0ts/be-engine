use anyhow::{Context, Result, ensure};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use serde::Deserialize;

use crate::recorder::HeaderMapSnapshot;

use super::model::ResponseGatewayProtocol;

#[derive(Debug, Deserialize)]
pub(super) struct RecordedRequest {
    pub(super) timestamp: Option<chrono::DateTime<chrono::Utc>>,
    pub(super) method: String,
    pub(super) uri: String,
    pub(super) protocol_version: Option<String>,
    pub(super) body: Option<ResponseBody>,
}

impl RecordedRequest {
    pub(super) fn has_motan_frame(&self) -> bool {
        self.method.eq_ignore_ascii_case("MOTAN")
            && matches!(self.protocol_version.as_deref(), Some("motan1" | "motan2"))
    }

    pub(super) fn gateway_protocol(&self) -> Result<ResponseGatewayProtocol> {
        if !self.method.eq_ignore_ascii_case("MOTAN") {
            return Ok(ResponseGatewayProtocol::Http);
        }
        match self.protocol_version.as_deref() {
            Some("motan1") => Ok(ResponseGatewayProtocol::Motan1),
            Some("motan2") => Ok(ResponseGatewayProtocol::Motan2),
            value => anyhow::bail!("MOTAN request uses unsupported protocol version {value:?}"),
        }
    }
}

#[derive(Debug, Deserialize)]
pub(super) struct ExpectedResponse {
    pub(super) status: Option<RecordedStatus>,
    #[serde(default)]
    pub(super) headers: Option<HeaderMapSnapshot>,
    pub(super) body: Option<ResponseBody>,
    pub(super) frame: Option<ResponseBody>,
    pub(super) response_expected: Option<bool>,
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
pub(super) struct ComparisonResponse {
    pub(super) timestamp: Option<chrono::DateTime<chrono::Utc>>,
    pub(super) version: u8,
    pub(super) status: Option<u16>,
    pub(super) headers: Option<HeaderMapSnapshot>,
    pub(super) body: Option<ResponseBody>,
    pub(super) error: Option<String>,
    pub(super) protocol_version: Option<String>,
    pub(super) serialization: Option<u8>,
    pub(super) rpc_status: Option<String>,
    pub(super) rpc_body_decoded: Option<bool>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ActualResponse {
    #[serde(default)]
    pub(super) request_sent_at: Option<chrono::DateTime<chrono::Utc>>,
    #[serde(default, rename = "request_rules")]
    _request_rules: Vec<crate::request_rules::RequestRuleObservation>,
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
    pub(super) limit_bytes: Option<usize>,
    pub(super) decoded: Option<bool>,
    pub(super) content_encoding: Option<String>,
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
