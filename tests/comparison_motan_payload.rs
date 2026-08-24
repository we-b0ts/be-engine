use std::fs;
use std::path::{Path, PathBuf};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use motan_breeze::{Limits as BreezeLimits, SERIALIZATION_ID as BREEZE_SERIALIZATION_ID};
use motan_protocol::FrameBuilder;
use motan_simple::{Limits as SimpleLimits, SERIALIZATION_ID as SIMPLE_SERIALIZATION_ID};
use serde_json::{Value, json};
use tempfile::tempdir;
use traffic_e2e::{
    ComparisonVerificationClassification, ComparisonVerificationOptions, ResponseBodyCodec,
    verify_comparison_recording,
};

const API_PATH: &str = "/rpc/AlchemyJsonRpcService-getConfigJson-test";

#[test]
fn legacy_motan_simple_json_uses_request_serialization_for_comparison() {
    let temp = tempdir().unwrap();
    let request_payload =
        motan_simple::to_vec(r#"{"businessId":11}"#, SimpleLimits::default()).unwrap();
    let request = FrameBuilder::request(42)
        .serialization(SIMPLE_SERIALIZATION_ID)
        .body(request_payload)
        .encode()
        .unwrap()
        .to_vec();
    let expected = simple_string(r#"{"businessId":11,"sourceLog":"a,b,a"}"#);
    let actual = simple_string(r#"{"sourceLog":"b,a,a","businessId":11}"#);
    let run = write_run(temp.path(), Some(&request), &expected, &actual, None, None);
    let policy = write_policy(
        temp.path(),
        "response_rules:\n  json:\n    \"MOTAN /rpc/AlchemyJsonRpcService-getConfigJson-test\":\n      unordered_joined_string:\n        - pointer: /sourceLog\n          separator: ','\n          source_evidence: src/service.rs:sourceLog is set-joined\n",
    );

    let report = verify_comparison_recording(ComparisonVerificationOptions {
        case_source: run.clone(),
        policy,
        report: run.join("comparison-report.json"),
    })
    .unwrap();

    assert!(report.complete);
    assert!(report.passed);
    assert_eq!(report.counts.passed, 1);
    let response = report.cases[0].response.as_ref().unwrap();
    assert_eq!(response.body_codec, ResponseBodyCodec::Json);
    assert_eq!(response.applied_unordered_joined_string_rule_ids.len(), 1);
}

#[test]
fn recorded_response_serialization_drives_json_comparison_and_evidence() {
    let temp = tempdir().unwrap();
    let expected = simple_string(r#"{"value":1,"stable":true}"#);
    let actual = simple_string(r#"{"stable":true,"value":2}"#);
    let run = write_run(
        temp.path(),
        None,
        &expected,
        &actual,
        Some(SIMPLE_SERIALIZATION_ID),
        Some(SIMPLE_SERIALIZATION_ID),
    );
    let policy = write_policy(temp.path(), "");

    let report = verify_comparison_recording(ComparisonVerificationOptions {
        case_source: run.clone(),
        policy,
        report: run.join("comparison-report.json"),
    })
    .unwrap();

    assert!(report.complete);
    assert!(!report.passed);
    assert_eq!(
        report.cases[0].classification,
        ComparisonVerificationClassification::CandidateDifference
    );
    let response = report.cases[0].response.as_ref().unwrap();
    assert_eq!(response.body_codec, ResponseBodyCodec::Json);
    assert_eq!(response.differences[0].pointer, "/value");
    let representative = report.representative_difference.as_ref().unwrap();
    assert_eq!(representative.pointer, "/value");
    assert_eq!(representative.source_before, json!(1));
    assert_eq!(representative.candidate, json!(2));
}

#[test]
fn recorded_breeze_string_uses_the_same_comparison_normalizer() {
    let temp = tempdir().unwrap();
    let expected = motan_breeze::to_vec(
        r#"{"businessId":11,"sourceLog":"a,b,a"}"#,
        BreezeLimits::default(),
    )
    .unwrap();
    let actual = motan_breeze::to_vec(
        r#"{"sourceLog":"b,a,a","businessId":11}"#,
        BreezeLimits::default(),
    )
    .unwrap();
    let run = write_run(
        temp.path(),
        None,
        &expected,
        &actual,
        Some(BREEZE_SERIALIZATION_ID),
        Some(BREEZE_SERIALIZATION_ID),
    );
    let policy = write_policy(
        temp.path(),
        "response_rules:\n  json:\n    \"MOTAN /rpc/AlchemyJsonRpcService-getConfigJson-test\":\n      unordered_joined_string:\n        - pointer: /sourceLog\n          separator: ','\n          source_evidence: src/service.rs:sourceLog is set-joined\n",
    );

    let report = verify_comparison_recording(ComparisonVerificationOptions {
        case_source: run.clone(),
        policy,
        report: run.join("comparison-report.json"),
    })
    .unwrap();

    assert!(report.passed);
    assert_eq!(
        report.cases[0].response.as_ref().unwrap().body_codec,
        ResponseBodyCodec::Json
    );
}

#[test]
fn recorded_simple_byte_array_exposes_raw_protobuf_to_the_same_comparison_path() {
    let temp = tempdir().unwrap();
    let expected = simple_bytes(&protobuf_repeated_strings(&[b"alice", b"bob"]));
    let actual = simple_bytes(&protobuf_repeated_strings(&[b"bob", b"alice"]));
    let run = write_run(
        temp.path(),
        None,
        &expected,
        &actual,
        Some(SIMPLE_SERIALIZATION_ID),
        Some(SIMPLE_SERIALIZATION_ID),
    );
    let policy = write_policy(
        temp.path(),
        "response_rules:\n  protobuf:\n    \"MOTAN /rpc/AlchemyJsonRpcService-getConfigJson-test\":\n      unordered:\n        - field_path: [3]\n          display_path: response.names\n          element_type: string\n          source_evidence: src/service.rs:names is a set\n",
    );

    let report = verify_comparison_recording(ComparisonVerificationOptions {
        case_source: run.clone(),
        policy,
        report: run.join("comparison-report.json"),
    })
    .unwrap();

    assert!(report.passed);
    let response = report.cases[0].response.as_ref().unwrap();
    assert_eq!(response.body_codec, ResponseBodyCodec::Protobuf);
    assert_eq!(response.body_diagnosis.as_ref().unwrap().envelope, "raw");
}

fn simple_string(value: &str) -> Vec<u8> {
    motan_simple::to_vec(value, SimpleLimits::default()).unwrap()
}

fn simple_bytes(value: &[u8]) -> Vec<u8> {
    motan_simple::to_vec(value, SimpleLimits::default()).unwrap()
}

fn protobuf_repeated_strings(values: &[&[u8]]) -> Vec<u8> {
    let mut payload = Vec::new();
    for value in values {
        payload.push(0x1a);
        payload.push(value.len() as u8);
        payload.extend_from_slice(value);
    }
    payload
}

fn write_run(
    root: &Path,
    request_frame: Option<&[u8]>,
    expected: &[u8],
    actual: &[u8],
    expected_serialization: Option<u8>,
    actual_serialization: Option<u8>,
) -> PathBuf {
    let run = root.join("comparison-recordings/20260824141224");
    let case = run.join("apis/get-config-json/00000000-0000-4000-8000-000000000001");
    fs::create_dir_all(&case).unwrap();
    fs::write(
        run.join("comparison-recording-run.json"),
        serde_json::to_vec(&json!({
            "status": "completed",
            "ready": true,
            "finished_at": "2026-08-24T14:12:25Z",
            "counts": {"published": 1}
        }))
        .unwrap(),
    )
    .unwrap();
    fs::write(
        case.join("case-kind.json"),
        r#"{"version":1,"kind":"comparison_recording"}"#,
    )
    .unwrap();
    let mut request = json!({
        "protocol": "motan",
        "protocol_version": "motan2",
        "method": "MOTAN",
        "uri": API_PATH,
        "api_pattern": API_PATH,
        "api_key": "motan:test/com.example.Service#getConfigJson"
    });
    if let Some(frame) = request_frame {
        request["body"] = captured_body(frame);
    }
    fs::write(
        case.join("request.json"),
        serde_json::to_vec(&request).unwrap(),
    )
    .unwrap();
    write_response(
        &case.join("expected-response.json"),
        expected,
        expected_serialization,
    );
    write_response(&case.join("response.json"), actual, actual_serialization);
    run
}

fn write_response(path: &Path, body: &[u8], serialization: Option<u8>) {
    let mut response = json!({
        "version": 1,
        "status": 200,
        "protocol_version": "motan2",
        "rpc_status": "normal",
        "body": captured_body(body),
        "error": null
    });
    if let Some(serialization) = serialization {
        response["serialization"] = json!(serialization);
    }
    fs::write(path, serde_json::to_vec(&response).unwrap()).unwrap();
}

fn captured_body(body: &[u8]) -> Value {
    json!({
        "encoding": "base64",
        "data": STANDARD.encode(body),
        "original_len": body.len(),
        "stored_len": body.len(),
        "truncated": false
    })
}

fn write_policy(root: &Path, response_rules: &str) -> PathBuf {
    let policy = root.join("verification.yaml");
    fs::write(
        &policy,
        format!(
            "version: 3\nexpected_response: assertions_only\ndependency_rules: []\n{response_rules}"
        ),
    )
    .unwrap();
    policy
}
