use anyhow::{Context, Result, ensure};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub(super) struct RecordedRequest {
    pub(super) method: String,
    pub(super) uri: String,
}

#[derive(Debug, Deserialize)]
pub(super) struct ExpectedResponse {
    pub(super) status: Option<u16>,
    pub(super) body: Option<ResponseBody>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ActualResponse {
    pub(super) version: u8,
    pub(super) status: u16,
    pub(super) body: ResponseBody,
}

#[derive(Debug, Deserialize)]
pub(super) struct ResponseBody {
    encoding: String,
    data: String,
    truncated: bool,
}

pub(super) fn decode_body(body: &ResponseBody, label: &str) -> Result<Vec<u8>> {
    ensure!(!body.truncated, "{label} body is truncated");
    match body.encoding.as_str() {
        "utf8" => Ok(body.data.as_bytes().to_vec()),
        "base64" => STANDARD
            .decode(&body.data)
            .with_context(|| format!("{label} body contains invalid base64")),
        encoding => anyhow::bail!("{label} body uses unsupported encoding {encoding:?}"),
    }
}
