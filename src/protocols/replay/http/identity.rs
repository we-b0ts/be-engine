//! Stable request fingerprints without recording credentials or body values.
use super::*;

/// Keep secret values out of reports. Canonical JSON matches the ordinary matcher;
/// non-JSON bodies (including forms) retain byte identity. Query multiplicity is exact.
pub(super) fn request_fingerprint(uri: &str, body: &[u8], headers: &HeaderSnapshot) -> String {
    let body = serde_json::from_slice::<Value>(body)
        .map(|value| canonical_json(&value))
        .unwrap_or_else(|_| body.to_vec());
    traffic_protocol_http::request_contract::request_fingerprint(uri, &body, headers)
}

pub(super) use traffic_codec_json::canonical as canonical_json;

pub(super) fn recorded_fingerprint(record: &RecordedHttpExchange) -> Result<String> {
    Ok(request_fingerprint(
        &record.native.uri,
        &decode_body(&record.native.request_body)?,
        &record.native.request_headers,
    ))
}
