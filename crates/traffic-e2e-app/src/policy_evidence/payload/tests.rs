use super::*;
use crate::request_headers::evidence::HeaderPolicy;

#[test]
fn plaintext_and_binary_payloads_need_no_key_and_reject_ambiguous_envelopes() {
    let temp = tempfile::tempdir().unwrap();
    for bytes in [
        &b"readable payload"[..],
        &b"\0\xffbinary"[..],
        &b""[..],
        &b"\0\0\0\0\0\0\0\0"[..],
    ] {
        let payload = StoredPayload::capture(bytes, 0, &[], temp.path()).unwrap();
        let stored = serde_json::to_value(&payload).unwrap();
        assert!(stored.get("encrypted").is_none());
        assert_eq!(payload.read(temp.path(), "unused").unwrap(), bytes);
        let restored: StoredPayload = serde_json::from_value(stored.clone()).unwrap();
        assert_eq!(restored.read(temp.path(), "unused").unwrap(), bytes);
        let mut ambiguous = stored;
        ambiguous["encrypted"] = serde_json::json!("traffic-e2e:enc:invalid");
        assert!(serde_json::from_value::<StoredPayload>(ambiguous).is_err());
    }
}

#[test]
fn project_without_a_recorder_section_has_no_implicit_header_encryption() {
    let (temp, artifacts, _store, _metadata) = super::super::tests::setup();
    std::fs::write(
        temp.path().join(".traffic-e2e/project.yaml"),
        "project:\n  policy: .traffic-e2e/policy.yaml\n",
    )
    .unwrap();
    let raw = br#"{"protocol":"http", "request_headers":{"authorization":["visible-token"]}}"#;
    let ranges = HeaderPolicy::load(&artifacts).unwrap().ranges(raw).unwrap();
    assert!(ranges.is_empty());
    let stored = StoredPayload::capture(raw, 0, &ranges, &artifacts).unwrap();
    assert!(
        serde_json::to_string(&stored)
            .unwrap()
            .contains("visible-token")
    );
}

#[test]
fn configured_headers_preserve_exact_bytes_and_do_not_encrypt_business_values() {
    let (temp, artifacts, _store, _metadata) = super::super::tests::setup();
    let config = temp.path().join(".traffic-e2e/project.yaml");
    std::fs::write(
        config,
        "version: 18\nrecorder:\n  recording:\n    encrypt_request_headers: [Authorization]\n",
    )
    .unwrap();
    let raw = br#"{ "protocol": "http", "request_headers": {"Authorization": ["Bearer private-token", "second-token"], "cookie": ["visible-cookie"]}, "request_body":"Bearer private-token", "response_headers":{"Authorization":["visible-response"]} }"#;
    let ranges = HeaderPolicy::load(&artifacts).unwrap().ranges(raw).unwrap();
    assert_eq!(ranges.len(), 2);
    let stored = StoredPayload::capture(raw, 0, &ranges, &artifacts).unwrap();
    let wire = serde_json::to_string(&stored).unwrap();
    assert!(!wire.contains("second-token"));
    assert_eq!(wire.matches("Bearer private-token").count(), 1);
    assert!(wire.contains("visible-cookie") && wire.contains("visible-response"));
    let restored: StoredPayload = serde_json::from_str(&wire).unwrap();
    assert_eq!(restored.read(&artifacts, "unused").unwrap(), raw);
    // Header values can cross a storage chunk boundary without changing a byte.
    let split = ranges[0].range.start + 5;
    let first = StoredPayload::capture(&raw[..split], 0, &ranges, &artifacts).unwrap();
    let second = StoredPayload::capture(&raw[split..], split, &ranges, &artifacts).unwrap();
    let mut decoded = first.read(&artifacts, "unused").unwrap();
    decoded.extend(second.read(&artifacts, "unused").unwrap());
    assert_eq!(decoded, raw);
    let mut tampered = serde_json::to_value(stored).unwrap();
    let header = tampered["parts"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|part| part["kind"] == "header")
        .unwrap();
    header["name"] = serde_json::json!("cookie");
    let tampered: StoredPayload = serde_json::from_value(tampered).unwrap();
    assert!(tampered.read(&artifacts, "unused").is_err());
}

#[test]
fn legacy_encrypted_payloads_and_candidate_field_remain_readable() {
    let (_temp, artifacts, _store, _metadata) = super::super::tests::setup();
    let encrypted =
        crate::request_headers::encrypt_evidence(&artifacts, "legacy", b"historical payload")
            .unwrap();
    for field in ["encrypted", "encrypted_target"] {
        let value = serde_json::json!({field:encrypted});
        let payload: StoredPayload = serde_json::from_value(value).unwrap();
        assert_eq!(
            payload.read(&artifacts, "legacy").unwrap(),
            b"historical payload"
        );
        assert!(payload.read(&artifacts, "wrong-label").is_err());
    }
    let envelope: super::super::v2::BlobEnvelope =
        serde_json::from_value(serde_json::json!({"id":"old-blob", "encrypted":encrypted}))
            .unwrap();
    assert_eq!(
        envelope.payload.read(&artifacts, "legacy").unwrap(),
        b"historical payload"
    );
}
