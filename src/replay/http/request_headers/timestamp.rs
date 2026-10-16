//! Timestamp validation shares the response-rule clock window and format parser.
use super::*;
use crate::replay::assertion::time::{RequestTimes, compare};
use crate::replay::policy::{ResponseTimeRule, ResponseTimestampFormat};
use sha2::{Digest, Sha256};

pub(in crate::replay) fn validate(
    format: ResponseTimestampFormat,
    expected: Option<&[String]>,
    actual: Option<&[String]>,
    times: RequestTimes,
) -> Result<(), String> {
    let (Some(expected), Some(actual)) = (expected, actual) else {
        return Err("timestamp header is missing".into());
    };
    if expected.len() != 1 || actual.len() != 1 {
        return Err("timestamp header must occur exactly once on both requests".into());
    }
    compare(
        ResponseTimeRule::Timestamp {
            format,
            mode: Default::default(),
        },
        &Value::String(expected[0].clone()),
        &Value::String(actual[0].clone()),
        times,
    )
    .map_err(|kind| {
        serde_json::to_value(kind)
            .unwrap()
            .as_str()
            .unwrap()
            .to_string()
    })
}

pub(in crate::replay) fn recorded_fingerprint(record: &RecordedHttpExchange) -> String {
    let bytes = serde_json::to_vec(&serde_json::json!({
        "scheme":record.scheme, "authority":record.authority, "method":record.method,
        "uri":record.uri, "headers":normalized(&record.request_headers),
        "request_started_at":record.request_started_at,
        "timestamp":record.timestamp, "duration_ms":record.duration_ms,
        "body_encoding":record.request_body.encoding, "body":record.request_body.data,
        "response_status":record.response_status,
    }))
    .unwrap();
    format!("{:x}", Sha256::digest(bytes))
}
