use std::fs;

use serde_json::json;

use super::*;

#[test]
fn echo_compares_each_response_with_its_request() {
    let (_temp, options) = write_raw_case("", r#"{"ok":true}"#, r#"{"ok":true}"#);
    write_header_field(
        &options.request,
        "headers",
        json!({"x-request-id": ["source-request-id"]}),
    );
    write_response_headers(
        &options.expected_response,
        json!({"x-request-id": ["source-request-id"]}),
    );
    write_header_field(
        &options.actual_response,
        "request_headers",
        json!({"x-request-id": ["target-request-id"]}),
    );
    write_response_headers(
        &options.actual_response,
        json!({"x-request-id": ["target-request-id"]}),
    );

    let report = assert_recorded_response(options).unwrap();

    assert!(report.passed);
    assert!(report.differences.is_empty());
}

#[test]
fn echo_mismatch_uses_the_standard_header_difference() {
    let (_temp, options) = write_raw_case("", r#"{"ok":true}"#, r#"{"ok":true}"#);
    write_header_field(
        &options.request,
        "headers",
        json!({"x-request-id": ["source-request-id"]}),
    );
    write_response_headers(
        &options.expected_response,
        json!({"x-request-id": ["source-request-id"]}),
    );
    write_header_field(
        &options.actual_response,
        "request_headers",
        json!({"x-request-id": ["target-request-id"]}),
    );
    write_response_headers(
        &options.actual_response,
        json!({"x-request-id": ["different-target-id"]}),
    );

    let report = assert_recorded_response(options).unwrap();

    assert!(!report.passed);
    assert_eq!(report.differences.len(), 1);
    assert_eq!(
        report.differences[0].kind,
        ResponseDifferenceKind::HeaderValueMismatch
    );
    assert_eq!(report.differences[0].pointer, "$headers/x-request-id");
}

fn write_header_field(path: &std::path::Path, field: &str, headers: serde_json::Value) {
    let mut value: serde_json::Value = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
    value[field] = headers;
    fs::write(path, serde_json::to_vec(&value).unwrap()).unwrap();
}
