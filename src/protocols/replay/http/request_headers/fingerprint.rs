//! Immutable request fingerprint for general header difference evidence.
use super::*;
use sha2::{Digest, Sha256};

pub(crate) fn recorded_fingerprint(record: &RecordedHttpExchange) -> String {
    let bytes = serde_json::to_vec(&serde_json::json!({
        "scheme":record.native.scheme, "authority":record.native.authority, "method":record.native.method,
        "uri":record.native.uri, "headers":normalized(&record.native.request_headers),
        "request_started_at":record.native.request_started_at,
        "timestamp":record.native.timestamp, "duration_ms":record.native.duration_ms,
        "body_encoding":record.native.request_body.encoding, "body":record.native.request_body.data,
        "response_status":record.native.response_status,
    }))
    .unwrap();
    format!("{:x}", Sha256::digest(bytes))
}
