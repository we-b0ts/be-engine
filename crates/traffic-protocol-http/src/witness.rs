//! Complete native HTTP evidence envelopes shared by capture and verification.
use crate::recorded::{BodyCapture, RecordedExchange, decode_body};
use anyhow::{Context, Result, ensure};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde_json::Value;
use traffic_protocol::evidence::{EvidenceSecrets, MessageSide};

pub fn source_payload(
    event: &Value,
    side: MessageSide,
    secrets: &dyn EvidenceSecrets,
) -> Result<Vec<u8>> {
    ensure!(
        event["event_type"] == "http_exchange",
        "not an HTTP semantic exchange"
    );
    let mut record: RecordedExchange = serde_json::from_value(event.clone())?;
    for (name, values) in &mut record.request_headers {
        for value in values {
            if let std::borrow::Cow::Owned(decoded) = secrets
                .unseal_text(&name.to_ascii_lowercase(), value)
                .context("failed to decrypt recorded HTTP dependency headers")?
            {
                *value = decoded;
            }
        }
    }
    Ok(serde_json::to_vec(&from_record(&record, side)?)?)
}

pub fn from_record(record: &RecordedExchange, side: MessageSide) -> Result<Value> {
    let (scheme, endpoint) = record.identity()?;
    let mut value = serde_json::json!({"protocol":"http","exchange_id":record.id,"scheme":scheme,
        "endpoint":endpoint,"method":record.method.to_ascii_uppercase(),"uri":record.uri,
        "request_headers":record.request_headers,"request_body":encode_body(&record.request_body)?,
        "request_started_at":record.source_started_at()});
    if side == MessageSide::Response {
        value["response_status"] = serde_json::to_value(record.response_status)?;
        value["response_headers"] = serde_json::to_value(&record.response_headers)?;
        value["response_body"] =
            serde_json::to_value(record.response_body.as_ref().map(encode_body).transpose()?)?;
        value["response_delivered_at"] = serde_json::to_value(record.timestamp)?;
        value["outcome"] = serde_json::to_value(record.outcome)?;
        value["error"] = serde_json::to_value(&record.error)?;
    }
    Ok(value)
}

fn encode_body(capture: &BodyCapture) -> Result<String> {
    let body = decode_body(capture)?;
    ensure!(
        body.len() <= crate::limits::MAX_BODY_BYTES,
        "HTTP witness body exceeds 64 MiB"
    );
    Ok(STANDARD.encode(body))
}

mod validation;
pub use validation::{multipart_witness_matches, validate_witness, witness_value};
