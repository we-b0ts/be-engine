//! Binary attachment limits include base64 expansion, independently per body.
use super::*;
use crate::dependency::http_limits::{MAX_BODY_BYTES, MAX_WITNESS_BYTES};

#[test]
fn attachments_at_64_mib_survive_both_http_witness_surfaces() {
    let body = vec![0xff; MAX_BODY_BYTES];
    let encoded = STANDARD.encode(&body);
    let envelope = serde_json::to_vec(&serde_json::json!({
        "protocol":"http", "request_body":encoded, "response_body":encoded,
        "response_status":200, "outcome":"response", "error":null,
    }))
    .unwrap();
    assert!(envelope.len() > 128 * 1024 * 1024);
    assert!(envelope.len() < MAX_WITNESS_BYTES);
    for surface in [Surface::DependencyRequest, Surface::DependencyResponse] {
        assert_eq!(witness_value(&envelope, surface).unwrap().unwrap(), body);
    }
}

#[test]
fn attachment_limit_rejects_a_decoded_extra_byte_even_with_the_same_base64_length() {
    let encoded = STANDARD.encode(vec![0xff; MAX_BODY_BYTES + 1]);
    assert_eq!(
        encoded.len(),
        crate::dependency::http_limits::MAX_BASE64_BODY_BYTES
    );
    let envelope = serde_json::to_vec(&serde_json::json!({
        "protocol":"http", "request_body":encoded,
    }))
    .unwrap();
    let error = witness_value(&envelope, Surface::DependencyRequest).unwrap_err();
    assert!(error.to_string().contains("exceeds 64 MiB"));
}
