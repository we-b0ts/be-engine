use std::fs;
use std::io::{Cursor, Write as _};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use serde_json::json;
use tempfile::tempdir;
use traffic_e2e::{
    DocxTimestampRule, ProtobufFieldPath, ProtobufRepeatedElementType, ProtobufUnorderedPath,
    ResponseAssertionOptions, ResponseBodyCodec, ResponseBodyRuleEvidence,
    ResponseBodyRuleFeedback, ResponseBodyUnorderedPath, ResponseTimestampFormat,
    assert_recorded_response, plan_response_body_rule, validate_replay_policy,
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
fn typed_protobuf_rules_preserve_members_and_retire_legacy_authoring() {
    let temp = tempdir().unwrap();
    let policy = temp.path().join("policy.yaml");
    let request = temp.path().join("request.json");
    let expected = temp.path().join("expected-response.json");
    let actual = temp.path().join("actual-response.json");
    let detail = temp.path().join("assertion-detail.json");
    let assertions = temp.path().join("assertions.json");
    let aggregate = temp.path().join("aggregate.json");
    fs::write(&policy, "format: traffic-policy/v3\nrules: []\n").unwrap();
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

    let retired = plan_response_body_rule(ResponseBodyRuleFeedback {
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
        docx_timestamps: Vec::new(),
        evidence: ResponseBodyRuleEvidence::FocusedE2e {
            assertion_report: assertions,
            aggregate_report: aggregate,
        },
    })
    .err()
    .expect("legacy authoring must be retired");
    assert!(
        retired
            .to_string()
            .contains("legacy rule authoring is retired")
    );
    write_body_policy(
        &policy,
        "POST /rpc/example",
        "protobuf",
        vec![json!({
            "contract":{"kind":"unordered","selector":{"kind":"protobuf","field_path":[3],"alias":"/names","element_type":"string"}},
            "proof":source_proof()
        })],
    );
    assert!(
        assert_recorded_response(ResponseAssertionOptions {
            case_id: "case-1".into(),
            request: request.clone(),
            expected_response: expected.clone(),
            actual_response: actual.clone(),
            policy: policy.clone()
        })
        .unwrap()
        .passed
    );
    fs::write(&actual, serde_json::to_vec(&json!({"version":1,"status":200,"body":{"encoding":"base64","data":STANDARD.encode(protobuf_body(&["alice","mallory"])),"truncated":false}})).unwrap()).unwrap();
    assert!(
        !assert_recorded_response(ResponseAssertionOptions {
            case_id: "case-1".into(),
            request,
            expected_response: expected,
            actual_response: actual,
            policy
        })
        .unwrap()
        .passed
    );
}

fn fnv1a64(bytes: &[u8]) -> u64 {
    bytes.iter().fold(0xcbf29ce484222325, |hash, byte| {
        (hash ^ u64::from(*byte)).wrapping_mul(0x100000001b3)
    })
}

fn docx_body(created: &str, second: u8) -> Vec<u8> {
    let mut output = Cursor::new(Vec::new());
    let mut zip = zip::ZipWriter::new(&mut output);
    let options = zip::write::SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated)
        .last_modified_time(zip::DateTime::from_date_and_time(2024, 1, 2, 3, 4, second).unwrap());
    let core = format!(
        "<cp:coreProperties><dcterms:created>{created}</dcterms:created></cp:coreProperties>"
    );
    for (name, body) in [
        (
            "[Content_Types].xml",
            "<Types><Override ContentType=\"application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml\"/></Types>",
        ),
        ("_rels/.rels", "<Relationships/>"),
        ("word/document.xml", "<document>same</document>"),
        ("docProps/core.xml", core.as_str()),
    ] {
        zip.start_file(name, options).unwrap();
        zip.write_all(body.as_bytes()).unwrap();
    }
    zip.finish().unwrap();
    output.into_inner()
}

#[test]
fn typed_docx_timestamp_rule_preserves_relative_time_and_retires_legacy_authoring() {
    let temp = tempdir().unwrap();
    let policy = temp.path().join("policy.yaml");
    let request = temp.path().join("request.json");
    let expected = temp.path().join("expected-response.json");
    let actual = temp.path().join("actual-response.json");
    let detail = temp.path().join("assertion-detail.json");
    let assertions = temp.path().join("assertions.json");
    let aggregate = temp.path().join("aggregate.json");
    fs::write(&policy, "format: traffic-policy/v3\nrules: []\n").unwrap();
    fs::write(
        &request,
        serde_json::to_vec(&json!({
            "method": "GET",
            "uri": "/api/tasks/1/export/docx",
            "timestamp": "2024-01-01T19:04:05Z"
        }))
        .unwrap(),
    )
    .unwrap();
    fs::write(
        &expected,
        serde_json::to_vec(&json!({
            "status": 200,
            "body": {"encoding":"base64","data":STANDARD.encode(docx_body("2024-01-02T03:04:05Z", 6)),"truncated":false}
        }))
        .unwrap(),
    )
    .unwrap();
    fs::write(
        &actual,
        serde_json::to_vec(&json!({
            "version": 1,
            "status": 200,
            "request_sent_at": "2024-01-01T20:04:05Z",
            "body": {"encoding":"base64","data":STANDARD.encode(docx_body("2024-01-02T04:04:05Z", 8)),"truncated":false}
        }))
        .unwrap(),
    )
    .unwrap();
    let initial = assert_recorded_response(ResponseAssertionOptions {
        case_id: "case-docx".into(),
        request: request.clone(),
        expected_response: expected.clone(),
        actual_response: actual.clone(),
        policy: policy.clone(),
    })
    .unwrap();
    assert!(!initial.passed);
    assert_eq!(initial.body_codec, ResponseBodyCodec::Docx);
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
            "version":3,"case_source":temp.path(),"expected_response":"assertions_only","assertion_mode":"runner_owned","policy_fingerprint":policy_fingerprint,
            "cases":[{"case_id":"case-docx","passed":false,"response":{"passed":false,"method":"GET","path":"/api/tasks/1/export/docx","gateway_protocol":"http","body_codec":"docx","difference_count":1,"detail_report":detail,"detail_fingerprint":detail_fingerprint,"request":request,"expected_response":expected,"actual_response":actual,"policy_fingerprint":policy_fingerprint}}]
        }))
        .unwrap(),
    )
    .unwrap();
    fs::write(
        &aggregate,
        serde_json::to_vec(&json!({"case_source":temp.path(),"selected_case_ids":["case-docx"],"complete":true,"dirty":false})).unwrap(),
    )
    .unwrap();
    let rule = DocxTimestampRule {
        part: "docProps/core.xml".into(),
        element: "dcterms:created".into(),
        format: ResponseTimestampFormat::Rfc3339,
        source_evidence: "src/docx.rs:generator sets core created from the request clock".into(),
        source_example: "2024-01-02T03:04:05Z".into(),
        target_example: "2024-01-02T04:04:05Z".into(),
    };
    let retired = plan_response_body_rule(ResponseBodyRuleFeedback {
        policy_path: policy.clone(),
        api: "GET /api/tasks/*/export/docx".into(),
        codec: ResponseBodyCodec::Docx,
        unordered_paths: Vec::new(),
        unordered_joined_string_paths: Vec::new(),
        docx_timestamps: vec![rule],
        evidence: ResponseBodyRuleEvidence::FocusedE2e {
            assertion_report: assertions,
            aggregate_report: aggregate,
        },
    })
    .err()
    .expect("legacy authoring must be retired");
    assert!(
        retired
            .to_string()
            .contains("legacy rule authoring is retired")
    );
    write_body_policy(
        &policy,
        "GET /api/tasks/*/export/docx",
        "docx",
        vec![json!({
            "contract":{"kind":"timestamp","part":"docProps/core.xml","element":"dcterms:created","format":"rfc3339"},
            "proof":source_proof()
        })],
    );
    assert!(
        assert_recorded_response(ResponseAssertionOptions {
            case_id: "case-docx".into(),
            request,
            expected_response: expected,
            actual_response: actual,
            policy
        })
        .unwrap()
        .passed
    );
}

#[test]
fn docx_codec_only_ignores_zip_metadata_but_compares_part_contents() {
    let temp = tempdir().unwrap();
    let policy = temp.path().join("policy.yaml");
    let request = temp.path().join("request.json");
    let expected = temp.path().join("expected-response.json");
    let actual = temp.path().join("actual-response.json");
    fs::write(&policy, "format: traffic-policy/v3\nrules: []\n").unwrap();
    fs::write(
        &request,
        serde_json::to_vec(&json!({"method":"GET","uri":"/export"})).unwrap(),
    )
    .unwrap();
    write_body_policy(&policy, "GET /export", "docx", vec![]);
    let write_response = |path: &std::path::Path, version: Option<u8>, body: Vec<u8>| {
        let mut response = json!({
            "status":200,
            "body":{"encoding":"base64","data":STANDARD.encode(body),"truncated":false}
        });
        if let Some(version) = version {
            response["version"] = json!(version);
        }
        fs::write(path, serde_json::to_vec(&response).unwrap()).unwrap();
    };
    write_response(&expected, None, docx_body("2024-01-02T03:04:05Z", 6));
    write_response(&actual, Some(1), docx_body("2024-01-02T03:04:05Z", 8));
    let report = assert_recorded_response(ResponseAssertionOptions {
        case_id: "case-docx-metadata".into(),
        request,
        expected_response: expected,
        actual_response: actual,
        policy,
    })
    .unwrap();
    assert!(report.passed);
    assert_eq!(report.body_codec, ResponseBodyCodec::Docx);
    assert!(report.body_diagnosis.unwrap().differences.is_empty());
}

fn source_proof() -> serde_json::Value {
    json!({"source":"src/service.rs:generate", "fact":"This isolated fixture generates only the selected value; business remainder stays exact."})
}

fn write_body_policy(
    path: &std::path::Path,
    api: &str,
    codec: &str,
    fields: Vec<serde_json::Value>,
) {
    fs::write(path, serde_json::to_vec(&json!({"format":"traffic-policy/v3", "rules":[{
        "id":"response-body", "match":{"api":api}, "effect":{"kind":"response_body","codec":codec,"fields":fields}, "proof":source_proof()
    }]})).unwrap()).unwrap();
}
