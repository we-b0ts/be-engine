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
    assert_eq!(report.body_codec, ResponseBodyCodec::ExactBytes);
    assert!(report.differences.is_empty());
}

#[test]
fn body_length_does_not_duplicate_a_body_mismatch() {
    let (_temp, options) = write_motan_case_with_rules(
        ProtocolVersion::Motan1,
        "",
        None,
        None,
        "",
        "",
        b"short",
        b"a longer response",
        1,
    );

    let report = assert_recorded_response(options).unwrap();

    assert!(!report.passed);
    assert_eq!(report.differences.len(), 1);
    assert_eq!(
        report.differences[0].kind,
        ResponseDifferenceKind::ExactBodyMismatch
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
        ResponseDifferenceKind::ExactBodyMismatch
    );
    assert!(report.body_diagnosis.is_some());
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
