//! Stable request fingerprints without recording credentials or body values.
use super::*;
use sha2::{Digest, Sha256};

/// Keep secret values out of reports. Canonical JSON matches the ordinary matcher;
/// non-JSON bodies (including forms) retain byte identity. Query multiplicity is exact.
pub(super) fn request_fingerprint(uri: &str, body: &[u8], headers: &HeaderSnapshot) -> String {
    let body = serde_json::from_slice::<Value>(body)
        .map(|value| canonical_json(&value))
        .unwrap_or_else(|_| body.to_vec());
    let significant = ["authorization", "cookie", "content-type"].map(|name| {
        let values: Vec<_> = headers
            .iter()
            .filter(|(key, _)| key.eq_ignore_ascii_case(name))
            .flat_map(|(_, values)| values.iter())
            .collect();
        (name, values)
    });
    let material = serde_json::to_vec(&(normalize_uri(uri, &[]), significant))
        .expect("HTTP identity is serializable");
    let mut digest = Sha256::new();
    digest.update(b"traffic-e2e-http-cross-case-v1\0");
    digest.update((material.len() as u64).to_be_bytes());
    digest.update(material);
    digest.update(body);
    format!("sha256:{:x}", digest.finalize())
}

pub(super) use traffic_codec_json::canonical as canonical_json;

pub(super) fn recorded_fingerprint(record: &RecordedHttpExchange) -> Result<String> {
    Ok(request_fingerprint(
        &record.native.uri,
        &decode_body(&record.native.request_body)?,
        &record.native.request_headers,
    ))
}
