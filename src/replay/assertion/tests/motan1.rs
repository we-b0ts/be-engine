use super::*;

#[test]
fn process_time_does_not_affect_response_assertion() {
    let payload = hessian2_string_list(&["alice", "bob"]);
    let (_temp, options) = write_motan_case_with_rules(
        ProtocolVersion::Motan1,
        "",
        Some("3"),
        Some("100"),
        "",
        "",
        &payload,
        &payload,
        1,
    );

    let report = assert_recorded_response(options).unwrap();

    assert!(report.passed);
    assert_eq!(report.body_codec, ResponseBodyCodec::Hessian2);
    assert!(report.body_diagnosis.unwrap().used_for_verdict);
    assert!(report.differences.is_empty());
}

#[test]
fn body_length_does_not_duplicate_a_body_mismatch() {
    let expected = hessian2_string_list(&["short"]);
    let actual = hessian2_string_list(&["a longer response"]);
    let (_temp, options) = write_motan_case_with_rules(
        ProtocolVersion::Motan1,
        "",
        None,
        None,
        "",
        "",
        &expected,
        &actual,
        1,
    );

    let report = assert_recorded_response(options).unwrap();

    assert!(!report.passed);
    assert_eq!(report.differences.len(), 1);
    assert_eq!(
        report.differences[0].kind,
        ResponseDifferenceKind::ValueMismatch
    );
}

#[test]
fn object_stream_envelope_exposes_hessian2_payload() {
    let expected = hessian2_string_list(&["alice", "bob"]);
    let actual = hessian2_string_list(&["bob", "alice"]);
    let (_temp, options) = write_motan_case_with_rules(
        ProtocolVersion::Motan1,
        "",
        Some("3"),
        Some("1"),
        "",
        "",
        &expected,
        &actual,
        1,
    );

    let report = assert_recorded_response(options).unwrap();

    assert!(!report.passed);
    assert_eq!(report.body_codec, ResponseBodyCodec::Hessian2);
    assert_eq!(report.differences.len(), 1);
    assert_eq!(
        report.differences[0].kind,
        ResponseDifferenceKind::ValueMismatch
    );
    let diagnosis = report.body_diagnosis.unwrap();
    assert!(!diagnosis.configured);
    assert!(diagnosis.used_for_verdict);
}

#[test]
fn protocol_hessian2_comparison_ignores_map_wire_order() {
    let expected = hessian2_string_map(&[("businessId", "11"), ("sourceLog", "a,b")]);
    let actual = hessian2_string_map(&[("sourceLog", "a,b"), ("businessId", "11")]);
    assert_ne!(expected, actual);
    let (_temp, options) = write_motan_case_with_rules(
        ProtocolVersion::Motan1,
        "",
        None,
        None,
        "",
        "",
        &expected,
        &actual,
        1,
    );

    let report = assert_recorded_response(options).unwrap();

    assert!(report.passed);
    assert_eq!(report.body_codec, ResponseBodyCodec::Hessian2);
    assert!(report.body_diagnosis.unwrap().used_for_verdict);
    assert!(report.differences.is_empty());
}

#[test]
fn unordered_rule_compares_the_business_body() {
    let expected = protobuf_repeated_strings(&[b"alice", b"bob"]);
    let actual = protobuf_repeated_strings(&[b"bob", b"alice"]);
    let (_temp, options) = write_motan_case_with_rules(
        ProtocolVersion::Motan1,
        "response_rules:\n  protobuf:\n    \"MOTAN /rpc/example\":\n      unordered:\n        - field_path: [3]\n          display_path: response.names\n          element_type: string\n          source_evidence: src/service.rs:names is a Set\n",
        None,
        None,
        "",
        "",
        &expected,
        &actual,
        1,
    );

    let report = assert_recorded_response(options).unwrap();

    assert!(report.passed);
    assert_eq!(report.body_codec, ResponseBodyCodec::Protobuf);
    assert!(report.differences.is_empty());
}

#[test]
fn hessian2_unordered_rule_compares_the_business_body() {
    let expected = hessian2_string_list(&["alice", "bob"]);
    let actual = hessian2_string_list(&["bob", "alice"]);
    let (_temp, options) = write_motan_case_with_rules(
        ProtocolVersion::Motan1,
        "response_rules:\n  hessian2:\n    \"MOTAN /rpc/example\":\n      unordered:\n        - value_path: []\n          display_path: response.names\n          source_evidence: src/service.rs:names is a Set\n",
        None,
        None,
        "",
        "",
        &expected,
        &actual,
        1,
    );

    let report = assert_recorded_response(options).unwrap();

    assert!(report.passed);
    assert_eq!(report.body_codec, ResponseBodyCodec::Hessian2);
    assert!(report.differences.is_empty());
}

fn hessian2_string_map(entries: &[(&str, &str)]) -> Vec<u8> {
    fn compact_string(value: &str) -> Vec<u8> {
        assert!(value.len() < 32 && value.is_ascii());
        let mut encoded = vec![u8::try_from(value.len()).unwrap()];
        encoded.extend_from_slice(value.as_bytes());
        encoded
    }

    let mut payload = vec![b'H'];
    for (key, value) in entries {
        payload.extend(compact_string(key));
        payload.extend(compact_string(value));
    }
    payload.push(b'Z');
    let mut body = vec![3];
    body.extend_from_slice(&u32::try_from(payload.len()).unwrap().to_be_bytes());
    body.extend(payload);
    body
}
