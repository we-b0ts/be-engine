//! Immutable request fingerprint for general header difference evidence.
use super::*;
use sha2::{Digest, Sha256};

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
