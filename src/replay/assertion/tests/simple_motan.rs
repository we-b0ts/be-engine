use motan_json::Json;
use motan_protocol::ProtocolVersion;
use motan_simple::{Limits, SERIALIZATION_ID, to_vec};
use serde::Serialize;

use crate::replay::policy::ResponseBodyCodec;

use super::{
    ResponseAssertionOptions, ResponseDifferenceKind, assert_recorded_response,
    write_motan_case_with_rules,
};

fn write_simple_case(
    expected_body: &[u8],
    actual_body: &[u8],
) -> (tempfile::TempDir, ResponseAssertionOptions) {
    write_motan_case_with_rules(
        ProtocolVersion::Motan2,
        "",
        Some("3"),
        Some("1"),
        "value",
        "value",
        expected_body,
        actual_body,
        SERIALIZATION_ID,
    )
}

#[test]
fn simple_json_response_wrapper_uses_semantic_json_comparison() {
    #[derive(Serialize)]
    struct SourceResponse {
        name: &'static str,
        active: bool,
    }

    #[derive(Serialize)]
    struct TargetResponse {
        active: bool,
        name: &'static str,
    }

    let expected = to_vec(
        &Json::new(SourceResponse {
            name: "motan",
            active: true,
        }),
        Limits::default(),
    )
    .unwrap();
    let actual = to_vec(
        &Json::new(TargetResponse {
            active: true,
            name: "motan",
        }),
        Limits::default(),
    )
    .unwrap();
    let (_temp, options) = write_simple_case(&expected, &actual);

    let report = assert_recorded_response(options).unwrap();

    assert!(report.passed);
    assert_eq!(report.body_codec, ResponseBodyCodec::Json);
    assert!(report.differences.is_empty());
}

#[test]
fn simple_string_exposes_json_for_semantic_comparison() {
    let expected = to_vec(r#"{"name":"motan","active":true}"#, Limits::default()).unwrap();
    let actual = to_vec(r#"{ "active": true, "name": "motan" }"#, Limits::default()).unwrap();
    let (_temp, options) = write_simple_case(&expected, &actual);

    let report = assert_recorded_response(options).unwrap();

    assert!(report.passed);
    assert_eq!(report.body_codec, ResponseBodyCodec::Json);
    assert!(report.differences.is_empty());
}

#[test]
fn simple_byte_array_exposes_json_for_semantic_comparison() {
    let expected = to_vec(
        br#"{"name":"motan","active":true}"#.as_slice(),
        Limits::default(),
    )
    .unwrap();
    let actual = to_vec(
        br#"{ "active": true, "name": "motan" }"#.as_slice(),
        Limits::default(),
    )
    .unwrap();
    let (_temp, options) = write_simple_case(&expected, &actual);

    let report = assert_recorded_response(options).unwrap();

    assert!(report.passed);
    assert_eq!(report.body_codec, ResponseBodyCodec::Json);
    assert!(report.differences.is_empty());
}

#[test]
fn simple_payload_type_remains_part_of_the_contract() {
    let payload = br#"{"value":1}"#;
    let expected = to_vec(std::str::from_utf8(payload).unwrap(), Limits::default()).unwrap();
    let actual = to_vec(payload.as_slice(), Limits::default()).unwrap();
    let (_temp, options) = write_simple_case(&expected, &actual);

    let report = assert_recorded_response(options).unwrap();

    assert!(!report.passed);
    assert_eq!(report.body_codec, ResponseBodyCodec::Json);
    assert_eq!(report.differences.len(), 1);
    assert_eq!(
        report.differences[0].kind,
        ResponseDifferenceKind::TypeMismatch
    );
}
