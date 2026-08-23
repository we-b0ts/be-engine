use std::fs;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use serde_json::json;
use tempfile::tempdir;
use traffic_e2e::{
    ProtobufFieldPath, ProtobufRepeatedElementType, ProtobufUnorderedPath,
    ResponseAssertionOptions, ResponseBodyCodec, ResponseBodyRuleEvidence,
    ResponseBodyRuleFeedback, ResponseBodyUnorderedPath, assert_recorded_response,
    plan_response_body_rule, validate_replay_policy,
};

fn protobuf_body(values: &[&str]) -> Vec<u8> {
    let mut payload = Vec::new();
    for value in values {
        payload.push(0x1a);
        payload.push(value.len() as u8);
        payload.extend_from_slice(value.as_bytes());
    }
    [
        vec![3],
        (payload.len() as u32).to_be_bytes().to_vec(),
        payload,
    ]
    .concat()
}

#[test]
fn focused_e2e_evidence_can_plan_codec_and_unordered_path_in_one_step() {
    let temp = tempdir().unwrap();
    let policy = temp.path().join("verification.yaml");
    let request = temp.path().join("request.json");
    let expected = temp.path().join("expected-response.json");
    let actual = temp.path().join("actual-response.json");
    let detail = temp.path().join("assertion-detail.json");
    let assertions = temp.path().join("assertions.json");
    let aggregate = temp.path().join("aggregate.json");
    fs::write(
        &policy,
        "version: 3\nexpected_response: assertions_only\ndependency_rules: []\n",
    )
    .unwrap();
    fs::write(
        &request,
        serde_json::to_vec(&json!({"method": "POST", "uri": "/rpc/example"})).unwrap(),
    )
    .unwrap();
    fs::write(
        &expected,
        serde_json::to_vec(&json!({
            "status": 200,
            "body": {
                "encoding": "base64",
                "data": STANDARD.encode(protobuf_body(&["alice", "bob"])),
                "truncated": false
            }
        }))
        .unwrap(),
    )
    .unwrap();
    fs::write(
        &actual,
        serde_json::to_vec(&json!({
            "version": 1,
            "status": 200,
            "body": {
                "encoding": "base64",
                "data": STANDARD.encode(protobuf_body(&["bob", "alice"])),
                "truncated": false
            }
        }))
        .unwrap(),
    )
    .unwrap();
    let initial = assert_recorded_response(ResponseAssertionOptions {
        case_id: "case-1".to_string(),
        request: request.clone(),
        expected_response: expected.clone(),
        actual_response: actual.clone(),
        policy: policy.clone(),
    })
    .unwrap();
    assert!(!initial.passed);
    assert_eq!(initial.body_codec, ResponseBodyCodec::Protobuf);
    assert!(
        initial
            .body_diagnosis
            .as_ref()
            .unwrap()
            .candidates_explain_all_differences
    );
    fs::write(&detail, serde_json::to_vec(&initial).unwrap()).unwrap();
    let detail_fingerprint = format!("fnv1a64:{:016x}", fnv1a64(&fs::read(&detail).unwrap()));
    let policy_fingerprint = validate_replay_policy(&policy).unwrap().fingerprint;
    fs::write(
        &assertions,
        serde_json::to_vec(&json!({
            "version": 3,
            "case_source": temp.path(),
            "expected_response": "assertions_only",
            "assertion_mode": "runner_owned",
            "policy_fingerprint": policy_fingerprint,
            "cases": [{
                "case_id": "case-1",
                "passed": false,
                "response": {
                    "passed": false,
                    "method": "POST",
                    "path": "/rpc/example",
                    "gateway_protocol": "http",
                    "body_codec": "protobuf",
                    "difference_count": 1,
                    "detail_report": detail,
                    "detail_fingerprint": detail_fingerprint,
                    "request": request,
                    "expected_response": expected,
                    "actual_response": actual,
                    "policy_fingerprint": policy_fingerprint
                }
            }]
        }))
        .unwrap(),
    )
    .unwrap();
    fs::write(
        &aggregate,
        serde_json::to_vec(&json!({
            "case_source": temp.path(),
            "selected_case_ids": ["case-1"],
            "complete": true,
            "dirty": false
        }))
        .unwrap(),
    )
    .unwrap();

    let plan = plan_response_body_rule(ResponseBodyRuleFeedback {
        policy_path: policy.clone(),
        api: "POST /rpc/example".to_string(),
        codec: ResponseBodyCodec::Protobuf,
        unordered_paths: vec![ResponseBodyUnorderedPath::Protobuf(ProtobufUnorderedPath {
            field_path: ProtobufFieldPath(vec![3]),
            display_path: "response.names".to_string(),
            element_type: ProtobufRepeatedElementType::String,
            source_evidence: "src/service.rs:names is a set".to_string(),
        })],
        unordered_joined_string_paths: Vec::new(),
        evidence: ResponseBodyRuleEvidence::FocusedE2e {
            assertion_report: assertions,
            aggregate_report: aggregate,
        },
    })
    .unwrap();
    let report = plan.apply().unwrap();

    assert!(report.offline_verification.as_ref().unwrap().passed);
    assert!(fs::read_to_string(policy).unwrap().contains("protobuf:"));
}

fn fnv1a64(bytes: &[u8]) -> u64 {
    bytes.iter().fold(0xcbf29ce484222325, |hash, byte| {
        (hash ^ u64::from(*byte)).wrapping_mul(0x100000001b3)
    })
}
