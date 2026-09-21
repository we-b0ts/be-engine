use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use flate2::Compression;
use flate2::write::GzEncoder;
use motan_hessian2::{
    ClassSchema as HessianClassSchema, Encoder as HessianEncoder, Limits as HessianLimits,
    to_vec as encode_hessian2,
};
use serde_json::json;
use tempfile::tempdir;
use traffic_e2e::{
    ComparisonVerificationClassification, ComparisonVerificationOptions,
    ComparisonVerificationReport, Hessian2UnorderedPath, Hessian2ValuePath,
    MatchedSourceObservation, ProtobufFieldPath, ProtobufJoinedStringFieldType,
    ProtobufJoinedStringPath, ProtobufRepeatedElementType, ProtobufUnorderedPath,
    ResponseBodyCodec, ResponseBodyDifferenceDetail, ResponseBodyJoinedStringCandidate,
    ResponseBodyJoinedStringPath, ResponseBodyRuleEvidence, ResponseBodyRuleFeedback,
    ResponseBodyUnorderedPath, ResponseBodyUnorderedPathCandidate, ResponseDifferenceKind,
    plan_response_body_rule, verify_comparison_recording,
};

#[test]
fn reuses_replay_response_rules_for_offline_comparison() {
    let temp = tempdir().unwrap();
    let run = create_run(
        temp.path(),
        json!({"token": "baseline"}),
        json!({"token": "candidate"}),
    );
    let policy = temp.path().join("replay.yaml");
    fs::write(
        &policy,
        r#"version: 3
expected_response: assertions_only
dependency_rules: []
response_rules:
  json:
    "GET /api/token":
      uuid:
        - pointer: /token
          source_evidence: src/token.rs:issue_token
          source_example: <redacted source UUID>
          target_example: <redacted target UUID>
"#,
    )
    .unwrap();
    let report_path = run.join("comparison-report.json");

    let report = verify_comparison_recording(ComparisonVerificationOptions {
        case_source: run,
        policy,
        report: report_path.clone(),
    })
    .unwrap();

    assert!(report.complete);
    assert!(report.passed);
    assert!(report.representative_difference.is_none());
    assert_eq!(report.counts.passed, 1);
    assert_eq!(report.counts.apis_total, 1);
    assert_eq!(report.counts.apis_passed, 1);
    assert!(report.apis["GET /api/token"].passed);
    assert_eq!(report.cases[0].api, "GET /api/token");
    assert_eq!(
        report.cases[0]
            .response
            .as_ref()
            .unwrap()
            .applied_generated_rule_ids
            .len(),
        1
    );
    assert!(report_path.is_file());
}

#[test]
fn standard_header_difference_flows_through_comparison_api_evidence() {
    let temp = tempdir().unwrap();
    let body = json!({"ok": true});
    let run = create_run(temp.path(), body.clone(), body);
    let case = run.join("apis/api-token/00000000-0000-4000-8000-000000000001");
    write_headers(
        &case.join("expected-response.json"),
        json!({"vary": ["Origin"]}),
    );
    write_headers(
        &case.join("response.json"),
        json!({"vary": ["Accept-Encoding"]}),
    );
    let policy = temp.path().join("verification.yaml");
    fs::write(
        &policy,
        "version: 3\nexpected_response: assertions_only\ndependency_rules: []\n",
    )
    .unwrap();

    let report = verify_comparison_recording(ComparisonVerificationOptions {
        case_source: run.clone(),
        policy,
        report: run.join("comparison-report.json"),
    })
    .unwrap();

    assert!(!report.passed);
    assert_eq!(report.counts.failed, 1);
    assert_eq!(report.apis["GET /api/token"].counts.failed, 1);
    assert_eq!(
        report.cases[0].classification,
        ComparisonVerificationClassification::CandidateDifference
    );
    let difference = &report.cases[0].response.as_ref().unwrap().differences[0];
    assert_eq!(difference.kind, ResponseDifferenceKind::HeaderValueMismatch);
    assert_eq!(difference.pointer, "$headers/vary");
    let representative = report.representative_difference.unwrap();
    assert_eq!(representative.pointer, "$headers/vary");
    assert_eq!(representative.source_before, json!(["Origin"]));
    assert_eq!(representative.candidate, json!(["Accept-Encoding"]));
}

#[test]
fn x_request_id_echo_difference_includes_request_context_in_evidence() {
    let temp = tempdir().unwrap();
    let body = json!({"ok": true});
    let run = create_run(temp.path(), body.clone(), body);
    let case = run.join("apis/api-token/00000000-0000-4000-8000-000000000001");
    write_request_headers(
        &case.join("request.json"),
        json!({"x-request-id": ["incoming-id"]}),
    );
    write_headers(
        &case.join("expected-response.json"),
        json!({"x-request-id": ["incoming-id"]}),
    );
    write_headers(
        &case.join("response.json"),
        json!({"x-request-id": ["candidate-id"]}),
    );
    let policy = temp.path().join("verification.yaml");
    fs::write(
        &policy,
        "version: 3\nexpected_response: assertions_only\ndependency_rules: []\n",
    )
    .unwrap();

    let report = verify_comparison_recording(ComparisonVerificationOptions {
        case_source: run.clone(),
        policy,
        report: run.join("comparison-report.json"),
    })
    .unwrap();

    assert!(!report.passed);
    let representative = report.representative_difference.unwrap();
    assert_eq!(representative.pointer, "$headers/x-request-id");
    assert_eq!(
        representative.source_before,
        json!({"response": ["incoming-id"], "request": ["incoming-id"]})
    );
    assert_eq!(
        representative.candidate,
        json!({"response": ["candidate-id"], "request": ["incoming-id"]})
    );
}

#[test]
fn verifies_motan_payloads_through_the_common_api_report() {
    let temp = tempdir().unwrap();
    let run = create_run(temp.path(), json!("unused"), json!("unused"));
    let case = run.join("apis/api-token/00000000-0000-4000-8000-000000000001");
    fs::write(
        case.join("request.json"),
        serde_json::to_vec(&json!({
            "protocol": "motan",
            "protocol_version": "motan2",
            "method": "MOTAN",
            "uri": "/rpc/alchemy-get-config",
            "api_pattern": "/rpc/alchemy-get-config",
            "api_key": "motan:com.weibo.AlchemyRpcService#getConfig(java.lang.String)"
        }))
        .unwrap(),
    )
    .unwrap();
    write_binary_response(&case.join("expected-response.json"), 201, b"source");
    write_binary_response(&case.join("response.json"), 201, b"candidate");
    let policy = temp.path().join("verification.yaml");
    fs::write(
        &policy,
        "version: 3\nexpected_response: assertions_only\ndependency_rules: []\n",
    )
    .unwrap();

    let report = verify_comparison_recording(ComparisonVerificationOptions {
        case_source: run.clone(),
        policy,
        report: run.join("comparison-report.json"),
    })
    .unwrap();

    assert!(!report.passed);
    assert_eq!(report.cases[0].api, "MOTAN /rpc/alchemy-get-config");
    assert_eq!(
        report.cases[0].response.as_ref().unwrap().differences[0].kind,
        ResponseDifferenceKind::ExactBodyMismatch
    );
}

#[test]
fn protobuf_response_body_rule_reuses_comparison_bodies_for_offline_verification() {
    fn repeated_strings(values: [&[u8]; 2]) -> Vec<u8> {
        let mut payload = Vec::new();
        for value in values {
            payload.push(0x1a); // field 3, length-delimited
            payload.push(value.len() as u8);
            payload.extend_from_slice(value);
        }
        let mut body = vec![3];
        body.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        body.extend(payload);
        body
    }

    let temp = tempdir().unwrap();
    let run = create_run(temp.path(), json!("unused"), json!("unused"));
    let case = run.join("apis/api-token/00000000-0000-4000-8000-000000000001");
    fs::write(
        case.join("request.json"),
        serde_json::to_vec(&json!({
            "protocol": "motan",
            "protocol_version": "motan2",
            "method": "MOTAN",
            "uri": "/rpc/example",
            "api_pattern": "/rpc/example",
            "api_key": "motan:example#method()"
        }))
        .unwrap(),
    )
    .unwrap();
    write_binary_response(
        &case.join("expected-response.json"),
        200,
        &repeated_strings([b"alice", b"bob"]),
    );
    write_binary_response(
        &case.join("response.json"),
        200,
        &repeated_strings([b"bob", b"alice"]),
    );
    let policy = temp.path().join("verification.yaml");
    fs::write(
        &policy,
        "version: 3\nexpected_response: assertions_only\ndependency_rules: []\n",
    )
    .unwrap();
    let report_path = run.join("comparison-report.json");
    let initial = verify_comparison_recording(ComparisonVerificationOptions {
        case_source: run.clone(),
        policy: policy.clone(),
        report: report_path.clone(),
    })
    .unwrap();
    assert!(!initial.passed);
    assert!(matches!(
        &initial.cases[0]
            .response
            .as_ref()
            .unwrap()
            .body_diagnosis
            .as_ref()
            .unwrap()
            .unordered_path_candidates[0],
        ResponseBodyUnorderedPathCandidate::Protobuf(candidate)
            if candidate.field_path == ProtobufFieldPath(vec![3])
    ));
    let protocol_plan = plan_response_body_rule(ResponseBodyRuleFeedback {
        policy_path: policy.clone(),
        api: "MOTAN /rpc/example".to_string(),
        codec: ResponseBodyCodec::Protobuf,
        unordered_paths: Vec::new(),
        unordered_joined_string_paths: Vec::new(),
        docx_timestamps: Vec::new(),
        evidence: ResponseBodyRuleEvidence::Comparison {
            comparison_report: report_path.clone(),
        },
    })
    .unwrap();
    let protocol_applied = protocol_plan.apply().unwrap();
    assert!(protocol_applied.applied);
    let protocol_outcome = protocol_applied.offline_verification.as_ref().unwrap();
    assert!(protocol_outcome.complete);
    assert!(!protocol_outcome.passed);
    assert_eq!(protocol_applied.order_only, Some(true));
    assert!(matches!(
        &protocol_applied.discovered_unordered_paths[0],
        ResponseBodyUnorderedPathCandidate::Protobuf(candidate)
            if candidate.field_path == ProtobufFieldPath(vec![3])
    ));
    assert_eq!(protocol_outcome.failed, 1);

    let wrong_type = plan_response_body_rule(ResponseBodyRuleFeedback {
        policy_path: policy.clone(),
        api: "MOTAN /rpc/example".to_string(),
        codec: ResponseBodyCodec::Protobuf,
        unordered_paths: vec![ResponseBodyUnorderedPath::Protobuf(ProtobufUnorderedPath {
            field_path: ProtobufFieldPath(vec![3]),
            display_path: "rule_collection.white_list".to_string(),
            element_type: ProtobufRepeatedElementType::Message,
            source_evidence: "src/rule.rs:white_list is a set".to_string(),
        })],
        unordered_joined_string_paths: Vec::new(),
        docx_timestamps: Vec::new(),
        evidence: ResponseBodyRuleEvidence::Comparison {
            comparison_report: report_path.clone(),
        },
    })
    .err()
    .unwrap();
    assert!(
        wrong_type
            .to_string()
            .contains("repeated message element is malformed")
    );

    let unordered_plan = plan_response_body_rule(ResponseBodyRuleFeedback {
        policy_path: policy.clone(),
        api: "MOTAN /rpc/example".to_string(),
        codec: ResponseBodyCodec::Protobuf,
        unordered_paths: vec![ResponseBodyUnorderedPath::Protobuf(ProtobufUnorderedPath {
            field_path: ProtobufFieldPath(vec![3]),
            display_path: "rule_collection.white_list".to_string(),
            element_type: ProtobufRepeatedElementType::String,
            source_evidence: "src/rule.rs:white_list is a set".to_string(),
        })],
        unordered_joined_string_paths: Vec::new(),
        docx_timestamps: Vec::new(),
        evidence: ResponseBodyRuleEvidence::Comparison {
            comparison_report: report_path.clone(),
        },
    })
    .unwrap();
    let unordered_applied = unordered_plan.apply().unwrap();
    assert!(
        unordered_applied
            .offline_verification
            .as_ref()
            .unwrap()
            .passed
    );

    let updated = fs::read_to_string(&policy).unwrap();
    assert!(updated.contains("protobuf:"));
    assert!(updated.contains("field_path:"));
    assert!(updated.contains("display_path: rule_collection.white_list"));
    assert!(updated.contains("element_type: string"));
}

#[test]
fn protobuf_joined_string_rule_reuses_comparison_bodies_for_offline_verification() {
    fn joined_string(value: &[u8]) -> Vec<u8> {
        let mut payload = vec![0x1a, value.len() as u8];
        payload.extend_from_slice(value);
        let mut body = vec![3];
        body.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        body.extend(payload);
        body
    }

    let temp = tempdir().unwrap();
    let run = create_run(temp.path(), json!("unused"), json!("unused"));
    let case = run.join("apis/api-token/00000000-0000-4000-8000-000000000001");
    fs::write(
        case.join("request.json"),
        serde_json::to_vec(&json!({
            "protocol": "motan",
            "protocol_version": "motan2",
            "method": "MOTAN",
            "uri": "/rpc/example",
            "api_pattern": "/rpc/example",
            "api_key": "motan:example#method()"
        }))
        .unwrap(),
    )
    .unwrap();
    write_binary_response(
        &case.join("expected-response.json"),
        200,
        &joined_string(b"alice,,bob,alice"),
    );
    write_binary_response(
        &case.join("response.json"),
        200,
        &joined_string(b"alice,bob,alice,"),
    );
    let policy = temp.path().join("verification.yaml");
    fs::write(
        &policy,
        "version: 3\nexpected_response: assertions_only\ndependency_rules: []\n",
    )
    .unwrap();
    let report_path = run.join("comparison-report.json");
    let initial = verify_comparison_recording(ComparisonVerificationOptions {
        case_source: run,
        policy: policy.clone(),
        report: report_path.clone(),
    })
    .unwrap();
    assert!(matches!(
        &initial.cases[0]
            .response
            .as_ref()
            .unwrap()
            .body_diagnosis
            .as_ref()
            .unwrap()
            .unordered_joined_string_candidates[0],
        ResponseBodyJoinedStringCandidate::Protobuf(candidate)
            if candidate.field_path == ProtobufFieldPath(vec![3])
                && candidate.separator == ","
    ));

    plan_response_body_rule(ResponseBodyRuleFeedback {
        policy_path: policy.clone(),
        api: "MOTAN /rpc/example".to_string(),
        codec: ResponseBodyCodec::Protobuf,
        unordered_paths: Vec::new(),
        unordered_joined_string_paths: Vec::new(),
        docx_timestamps: Vec::new(),
        evidence: ResponseBodyRuleEvidence::Comparison {
            comparison_report: report_path.clone(),
        },
    })
    .unwrap()
    .apply()
    .unwrap();

    let missing_error = plan_response_body_rule(ResponseBodyRuleFeedback {
        policy_path: policy.clone(),
        api: "MOTAN /rpc/example".to_string(),
        codec: ResponseBodyCodec::Protobuf,
        unordered_paths: vec![ResponseBodyUnorderedPath::Protobuf(ProtobufUnorderedPath {
            field_path: ProtobufFieldPath(vec![3]),
            display_path: "response.names".to_string(),
            element_type: ProtobufRepeatedElementType::String,
            source_evidence: "src/service.rs:names is a set".to_string(),
        })],
        unordered_joined_string_paths: Vec::new(),
        docx_timestamps: Vec::new(),
        evidence: ResponseBodyRuleEvidence::Comparison {
            comparison_report: report_path.clone(),
        },
    })
    .err()
    .unwrap()
    .to_string();
    assert!(
        missing_error.contains(
            "reviewed response-body unordered paths do not preserve exact values at their selected locations"
        ),
        "{missing_error}"
    );
    assert!(missing_error.contains("00000000-0000-4000-8000-000000000001"));

    let applied = plan_response_body_rule(ResponseBodyRuleFeedback {
        policy_path: policy.clone(),
        api: "MOTAN /rpc/example".to_string(),
        codec: ResponseBodyCodec::Protobuf,
        unordered_paths: Vec::new(),
        unordered_joined_string_paths: vec![ResponseBodyJoinedStringPath::Protobuf(
            ProtobufJoinedStringPath {
                field_path: ProtobufFieldPath(vec![3]),
                display_path: "response.names".to_string(),
                field_type: ProtobufJoinedStringFieldType::String,
                separator: ",".to_string(),
                source_evidence: "src/service.rs:names is set-joined".to_string(),
            },
        )],
        docx_timestamps: Vec::new(),
        evidence: ResponseBodyRuleEvidence::Comparison {
            comparison_report: report_path,
        },
    })
    .unwrap()
    .apply()
    .unwrap();

    assert!(applied.offline_verification.unwrap().passed);
    let updated = fs::read_to_string(&policy).unwrap();
    assert!(updated.contains("unordered_joined_string:"));
    assert!(updated.contains("field_type: string"));
}

#[test]
fn protobuf_codec_configuration_rejects_non_protobuf_bodies() {
    let temp = tempdir().unwrap();
    let run = create_run(temp.path(), json!("unused"), json!("unused"));
    let case = run.join("apis/api-token/00000000-0000-4000-8000-000000000001");
    fs::write(
        case.join("request.json"),
        serde_json::to_vec(&json!({
            "protocol": "motan",
            "protocol_version": "motan2",
            "method": "MOTAN",
            "uri": "/rpc/example",
            "api_pattern": "/rpc/example",
            "api_key": "motan:example#method()"
        }))
        .unwrap(),
    )
    .unwrap();
    write_binary_response(&case.join("expected-response.json"), 200, b"source");
    write_binary_response(&case.join("response.json"), 200, b"candidate");
    let policy = temp.path().join("verification.yaml");
    fs::write(
        &policy,
        "version: 3\nexpected_response: assertions_only\ndependency_rules: []\n",
    )
    .unwrap();
    let report_path = run.join("comparison-report.json");
    verify_comparison_recording(ComparisonVerificationOptions {
        case_source: run,
        policy: policy.clone(),
        report: report_path.clone(),
    })
    .unwrap();

    let error = plan_response_body_rule(ResponseBodyRuleFeedback {
        policy_path: policy,
        api: "MOTAN /rpc/example".to_string(),
        codec: ResponseBodyCodec::Protobuf,
        unordered_paths: Vec::new(),
        unordered_joined_string_paths: Vec::new(),
        docx_timestamps: Vec::new(),
        evidence: ResponseBodyRuleEvidence::Comparison {
            comparison_report: report_path,
        },
    })
    .err()
    .unwrap();

    assert!(
        error
            .to_string()
            .contains("source-before body is not valid protobuf response-body evidence")
    );
}

#[test]
fn response_body_rule_reports_that_a_value_difference_has_no_ordering_rule() {
    fn bare_hessian2_object(names: &[&str]) -> Vec<u8> {
        let mut payload = Vec::new();
        let mut encoder = HessianEncoder::new(&mut payload, HessianLimits::default());
        encoder
            .begin_object(HessianClassSchema::new("example.CacheResult", &["names"]))
            .unwrap();
        encoder.encode_value(&names.to_vec()).unwrap();
        encoder.end_object();
        payload
    }

    let temp = tempdir().unwrap();
    let run = create_run(temp.path(), json!("unused"), json!("unused"));
    let case = run.join("apis/api-token/00000000-0000-4000-8000-000000000001");
    fs::write(
        case.join("request.json"),
        serde_json::to_vec(&json!({
            "protocol": "motan",
            "protocol_version": "motan2",
            "method": "MOTAN",
            "uri": "/rpc/hessian-value",
            "api_pattern": "/rpc/hessian-value",
            "api_key": "motan:example#result()"
        }))
        .unwrap(),
    )
    .unwrap();
    write_binary_response(
        &case.join("expected-response.json"),
        200,
        &bare_hessian2_object(&["alice", "bob"]),
    );
    write_binary_response(
        &case.join("response.json"),
        200,
        &bare_hessian2_object(&["alice", "zoe"]),
    );
    let policy = temp.path().join("verification.yaml");
    fs::write(
        &policy,
        "version: 3\nexpected_response: assertions_only\ndependency_rules: []\n",
    )
    .unwrap();
    let report_path = run.join("comparison-report.json");
    verify_comparison_recording(ComparisonVerificationOptions {
        case_source: run,
        policy: policy.clone(),
        report: report_path.clone(),
    })
    .unwrap();

    let protocol_applied = plan_response_body_rule(ResponseBodyRuleFeedback {
        policy_path: policy.clone(),
        api: "MOTAN /rpc/hessian-value".to_string(),
        codec: ResponseBodyCodec::Hessian2,
        unordered_paths: Vec::new(),
        unordered_joined_string_paths: Vec::new(),
        docx_timestamps: Vec::new(),
        evidence: ResponseBodyRuleEvidence::Comparison {
            comparison_report: report_path.clone(),
        },
    })
    .unwrap()
    .apply()
    .unwrap();
    assert_eq!(protocol_applied.order_only, Some(false));
    assert!(protocol_applied.discovered_unordered_paths.is_empty());

    // With nothing reorder-only to declare, the second stage refuses exactly as
    // the protobuf flow does.
    let error = plan_response_body_rule(ResponseBodyRuleFeedback {
        policy_path: policy,
        api: "MOTAN /rpc/hessian-value".to_string(),
        codec: ResponseBodyCodec::Hessian2,
        unordered_paths: Vec::new(),
        unordered_joined_string_paths: Vec::new(),
        docx_timestamps: Vec::new(),
        evidence: ResponseBodyRuleEvidence::Comparison {
            comparison_report: report_path,
        },
    })
    .err()
    .unwrap();

    assert!(
        error
            .to_string()
            .contains("requires at least one newly reviewed unordered or joined-string path"),
        "{error}"
    );
}

#[test]
fn motan_gateway_hessian2_body_rule_accepts_a_raw_body_envelope() {
    // A Motan method that returns an object serializes the value directly into
    // the response body, without the byte-array envelope used for `byte[]`.
    fn bare_hessian2_object(names: &[&str]) -> Vec<u8> {
        let mut payload = Vec::new();
        let mut encoder = HessianEncoder::new(&mut payload, HessianLimits::default());
        encoder
            .begin_object(HessianClassSchema::new("example.CacheResult", &["names"]))
            .unwrap();
        encoder.encode_value(&names.to_vec()).unwrap();
        encoder.end_object();
        payload
    }

    let temp = tempdir().unwrap();
    let run = create_run(temp.path(), json!("unused"), json!("unused"));
    let case = run.join("apis/api-token/00000000-0000-4000-8000-000000000001");
    fs::write(
        case.join("request.json"),
        serde_json::to_vec(&json!({
            "protocol": "motan",
            "protocol_version": "motan2",
            "method": "MOTAN",
            "uri": "/rpc/hessian-object",
            "api_pattern": "/rpc/hessian-object",
            "api_key": "motan:example#result()"
        }))
        .unwrap(),
    )
    .unwrap();
    write_binary_response(
        &case.join("expected-response.json"),
        200,
        &bare_hessian2_object(&["alice", "bob"]),
    );
    write_binary_response(
        &case.join("response.json"),
        200,
        &bare_hessian2_object(&["bob", "alice"]),
    );
    let policy = temp.path().join("verification.yaml");
    fs::write(
        &policy,
        "version: 3\nexpected_response: assertions_only\ndependency_rules: []\n",
    )
    .unwrap();
    let report_path = run.join("comparison-report.json");
    let initial = verify_comparison_recording(ComparisonVerificationOptions {
        case_source: run,
        policy: policy.clone(),
        report: report_path.clone(),
    })
    .unwrap();

    let body_diagnosis = initial.cases[0]
        .response
        .as_ref()
        .unwrap()
        .body_diagnosis
        .as_ref()
        .unwrap();
    assert_eq!(body_diagnosis.codec, ResponseBodyCodec::Hessian2);
    assert_eq!(body_diagnosis.envelope, "raw");
    assert!(matches!(
        &body_diagnosis.unordered_path_candidates[0],
        ResponseBodyUnorderedPathCandidate::Hessian2(candidate)
            if candidate.value_path == Hessian2ValuePath(vec!["names".to_string()])
    ));

    let protocol_applied = plan_response_body_rule(ResponseBodyRuleFeedback {
        policy_path: policy.clone(),
        api: "MOTAN /rpc/hessian-object".to_string(),
        codec: ResponseBodyCodec::Hessian2,
        unordered_paths: Vec::new(),
        unordered_joined_string_paths: Vec::new(),
        docx_timestamps: Vec::new(),
        evidence: ResponseBodyRuleEvidence::Comparison {
            comparison_report: report_path.clone(),
        },
    })
    .unwrap()
    .apply()
    .unwrap();
    assert_eq!(protocol_applied.order_only, Some(true));

    let applied = plan_response_body_rule(ResponseBodyRuleFeedback {
        policy_path: policy.clone(),
        api: "MOTAN /rpc/hessian-object".to_string(),
        codec: ResponseBodyCodec::Hessian2,
        unordered_paths: vec![ResponseBodyUnorderedPath::Hessian2(Hessian2UnorderedPath {
            value_path: Hessian2ValuePath(vec!["names".to_string()]),
            display_path: "cache_result.names".to_string(),
            source_evidence: "src/cache.rs:names is a set".to_string(),
        })],
        unordered_joined_string_paths: Vec::new(),
        docx_timestamps: Vec::new(),
        evidence: ResponseBodyRuleEvidence::Comparison {
            comparison_report: report_path,
        },
    })
    .unwrap()
    .apply()
    .unwrap();

    assert!(applied.offline_verification.as_ref().unwrap().passed);
    let updated = fs::read_to_string(policy).unwrap();
    assert!(updated.contains("hessian2:"));
    assert!(updated.contains("value_path:\n        - names"));
}

#[test]
fn response_body_rule_can_apply_one_reviewed_path_while_another_difference_remains() {
    fn hessian2_object(names: &[&str], aliases: &[&str]) -> Vec<u8> {
        let mut payload = Vec::new();
        let mut encoder = HessianEncoder::new(&mut payload, HessianLimits::default());
        encoder
            .begin_object(HessianClassSchema::new(
                "example.CacheResult",
                &["names", "aliases"],
            ))
            .unwrap();
        encoder.encode_value(&names.to_vec()).unwrap();
        encoder.encode_value(&aliases.to_vec()).unwrap();
        encoder.end_object();
        payload
    }

    let temp = tempdir().unwrap();
    let run = create_run(temp.path(), json!("unused"), json!("unused"));
    let first_case_id = "00000000-0000-4000-8000-000000000001";
    let second_case_id = "00000000-0000-4000-8000-000000000002";
    let first_case = run.join(format!("apis/api-token/{first_case_id}"));
    let second_case = run.join(format!("apis/api-token/{second_case_id}"));
    fs::write(
        first_case.join("request.json"),
        serde_json::to_vec(&json!({
            "protocol": "motan",
            "protocol_version": "motan2",
            "method": "MOTAN",
            "uri": "/rpc/hessian-multiple-paths",
            "api_pattern": "/rpc/hessian-multiple-paths",
            "api_key": "motan:example#result()"
        }))
        .unwrap(),
    )
    .unwrap();
    write_binary_response(
        &first_case.join("expected-response.json"),
        200,
        &hessian2_object(&["alice", "bob"], &["one", "two"]),
    );
    write_binary_response(
        &first_case.join("response.json"),
        200,
        &hessian2_object(&["bob", "alice"], &["one", "two"]),
    );

    fs::create_dir_all(&second_case).unwrap();
    fs::copy(
        first_case.join("case-kind.json"),
        second_case.join("case-kind.json"),
    )
    .unwrap();
    fs::copy(
        first_case.join("request.json"),
        second_case.join("request.json"),
    )
    .unwrap();
    write_binary_response(
        &second_case.join("expected-response.json"),
        200,
        &hessian2_object(&["alice", "bob"], &["one", "two"]),
    );
    write_binary_response(
        &second_case.join("response.json"),
        200,
        &hessian2_object(&["alice", "bob"], &["two", "one"]),
    );
    fs::write(
        run.join("comparison-recording-run.json"),
        serde_json::to_vec(&json!({
            "status": "completed",
            "ready": true,
            "finished_at": "2026-07-22T16:00:01Z",
            "counts": {"published": 2}
        }))
        .unwrap(),
    )
    .unwrap();

    let policy = temp.path().join("verification.yaml");
    fs::write(
        &policy,
        "version: 3\nexpected_response: assertions_only\ndependency_rules: []\n",
    )
    .unwrap();
    let report_path = run.join("comparison-report.json");
    verify_comparison_recording(ComparisonVerificationOptions {
        case_source: run,
        policy: policy.clone(),
        report: report_path.clone(),
    })
    .unwrap();

    let plan = plan_response_body_rule(ResponseBodyRuleFeedback {
        policy_path: policy.clone(),
        api: "MOTAN /rpc/hessian-multiple-paths".to_string(),
        codec: ResponseBodyCodec::Hessian2,
        unordered_paths: vec![ResponseBodyUnorderedPath::Hessian2(Hessian2UnorderedPath {
            value_path: Hessian2ValuePath(vec!["names".to_string()]),
            display_path: "$.names".to_string(),
            source_evidence: "src/cache.rs:42-48 names is an unordered set".to_string(),
        })],
        unordered_joined_string_paths: Vec::new(),
        docx_timestamps: Vec::new(),
        evidence: ResponseBodyRuleEvidence::Comparison {
            comparison_report: report_path.clone(),
        },
    })
    .unwrap();

    assert_eq!(plan.report().selected_difference_cases, 1);
    assert_eq!(plan.report().residual_difference_cases, 1);

    let applied = plan.apply().unwrap();
    let outcome = applied.offline_verification.as_ref().unwrap();
    assert!(outcome.complete);
    assert!(!outcome.passed);
    assert_eq!(outcome.failed, 1);
    assert_eq!(applied.residual_difference_cases, 1);

    let updated = fs::read_to_string(policy).unwrap();
    assert!(updated.contains("display_path: $.names"));
    assert!(!updated.contains("display_path: $.aliases"));

    let refreshed: ComparisonVerificationReport =
        serde_json::from_slice(&fs::read(report_path).unwrap()).unwrap();
    assert!(
        refreshed
            .cases
            .iter()
            .find(|case| case.case_id == first_case_id)
            .unwrap()
            .passed
    );
    assert!(
        !refreshed
            .cases
            .iter()
            .find(|case| case.case_id == second_case_id)
            .unwrap()
            .passed
    );
}

#[test]
fn motan_gateway_hessian2_body_rule_reuses_comparison_bodies_offline() {
    fn hessian2_list(values: &[&str]) -> Vec<u8> {
        let payload = encode_hessian2(&values.to_vec(), HessianLimits::default()).unwrap();
        [
            vec![3],
            (payload.len() as u32).to_be_bytes().to_vec(),
            payload,
        ]
        .concat()
    }

    let temp = tempdir().unwrap();
    let run = create_run(temp.path(), json!("unused"), json!("unused"));
    let case = run.join("apis/api-token/00000000-0000-4000-8000-000000000001");
    fs::write(
        case.join("request.json"),
        serde_json::to_vec(&json!({
            "protocol": "motan",
            "protocol_version": "motan2",
            "method": "MOTAN",
            "uri": "/rpc/hessian",
            "api_pattern": "/rpc/hessian",
            "api_key": "motan:example#hessian()"
        }))
        .unwrap(),
    )
    .unwrap();
    write_binary_response(
        &case.join("expected-response.json"),
        200,
        &hessian2_list(&["alice", "bob"]),
    );
    write_binary_response(
        &case.join("response.json"),
        200,
        &hessian2_list(&["bob", "alice"]),
    );
    let policy = temp.path().join("verification.yaml");
    fs::write(
        &policy,
        "version: 3\nexpected_response: assertions_only\ndependency_rules: []\n",
    )
    .unwrap();
    let report_path = run.join("comparison-report.json");
    let initial = verify_comparison_recording(ComparisonVerificationOptions {
        case_source: run,
        policy: policy.clone(),
        report: report_path.clone(),
    })
    .unwrap();
    assert!(matches!(
        &initial.cases[0]
            .response
            .as_ref()
            .unwrap()
            .body_diagnosis
            .as_ref()
            .unwrap()
            .unordered_path_candidates[0],
        ResponseBodyUnorderedPathCandidate::Hessian2(candidate)
            if candidate.value_path == Hessian2ValuePath(vec![])
    ));
    let protocol_applied = plan_response_body_rule(ResponseBodyRuleFeedback {
        policy_path: policy.clone(),
        api: "MOTAN /rpc/hessian".to_string(),
        codec: ResponseBodyCodec::Hessian2,
        unordered_paths: Vec::new(),
        unordered_joined_string_paths: Vec::new(),
        docx_timestamps: Vec::new(),
        evidence: ResponseBodyRuleEvidence::Comparison {
            comparison_report: report_path.clone(),
        },
    })
    .unwrap()
    .apply()
    .unwrap();
    assert!(
        !protocol_applied
            .offline_verification
            .as_ref()
            .unwrap()
            .passed
    );
    assert_eq!(protocol_applied.order_only, Some(true));

    let unordered_applied = plan_response_body_rule(ResponseBodyRuleFeedback {
        policy_path: policy.clone(),
        api: "MOTAN /rpc/hessian".to_string(),
        codec: ResponseBodyCodec::Hessian2,
        unordered_paths: vec![ResponseBodyUnorderedPath::Hessian2(Hessian2UnorderedPath {
            value_path: Hessian2ValuePath(vec![]),
            display_path: "response.names".to_string(),
            source_evidence: "src/service.rs:names is a set".to_string(),
        })],
        unordered_joined_string_paths: Vec::new(),
        docx_timestamps: Vec::new(),
        evidence: ResponseBodyRuleEvidence::Comparison {
            comparison_report: report_path,
        },
    })
    .unwrap()
    .apply()
    .unwrap();

    assert!(
        unordered_applied
            .offline_verification
            .as_ref()
            .unwrap()
            .passed
    );
    let updated = fs::read_to_string(policy).unwrap();
    assert!(updated.contains("hessian2:"));
    assert!(updated.contains("value_path: []"));
    assert!(updated.contains("display_path: response.names"));
}

#[test]
fn protobuf_response_body_rule_uses_reviewed_type_for_packed_integer_order() {
    fn packed_uint32(values: &[u8]) -> Vec<u8> {
        let payload = [vec![0x12, values.len() as u8], values.to_vec()].concat();
        [
            vec![3],
            (payload.len() as u32).to_be_bytes().to_vec(),
            payload,
        ]
        .concat()
    }

    let temp = tempdir().unwrap();
    let run = create_run(temp.path(), json!("unused"), json!("unused"));
    let case = run.join("apis/api-token/00000000-0000-4000-8000-000000000001");
    fs::write(
        case.join("request.json"),
        serde_json::to_vec(&json!({
            "protocol": "motan",
            "protocol_version": "motan2",
            "method": "MOTAN",
            "uri": "/rpc/packed",
            "api_pattern": "/rpc/packed",
            "api_key": "motan:example#packed()"
        }))
        .unwrap(),
    )
    .unwrap();
    write_binary_response(
        &case.join("expected-response.json"),
        200,
        &packed_uint32(&[1, 2, 3]),
    );
    write_binary_response(&case.join("response.json"), 200, &packed_uint32(&[3, 1, 2]));
    let policy = temp.path().join("verification.yaml");
    fs::write(
        &policy,
        "version: 3\nexpected_response: assertions_only\ndependency_rules: []\n",
    )
    .unwrap();
    let report_path = run.join("comparison-report.json");
    verify_comparison_recording(ComparisonVerificationOptions {
        case_source: run,
        policy: policy.clone(),
        report: report_path.clone(),
    })
    .unwrap();

    plan_response_body_rule(ResponseBodyRuleFeedback {
        policy_path: policy.clone(),
        api: "MOTAN /rpc/packed".to_string(),
        codec: ResponseBodyCodec::Protobuf,
        unordered_paths: Vec::new(),
        unordered_joined_string_paths: Vec::new(),
        docx_timestamps: Vec::new(),
        evidence: ResponseBodyRuleEvidence::Comparison {
            comparison_report: report_path.clone(),
        },
    })
    .unwrap()
    .apply()
    .unwrap();

    let typed = plan_response_body_rule(ResponseBodyRuleFeedback {
        policy_path: policy,
        api: "MOTAN /rpc/packed".to_string(),
        codec: ResponseBodyCodec::Protobuf,
        unordered_paths: vec![ResponseBodyUnorderedPath::Protobuf(ProtobufUnorderedPath {
            field_path: ProtobufFieldPath(vec![2]),
            display_path: "config_scene.values".to_string(),
            element_type: ProtobufRepeatedElementType::Uint32,
            source_evidence: "src/config.rs:values is a set".to_string(),
        })],
        unordered_joined_string_paths: Vec::new(),
        docx_timestamps: Vec::new(),
        evidence: ResponseBodyRuleEvidence::Comparison {
            comparison_report: report_path.clone(),
        },
    })
    .unwrap()
    .apply()
    .unwrap();

    assert!(typed.offline_verification.as_ref().unwrap().passed);
    assert_eq!(typed.order_only, Some(true));
    let refreshed: traffic_e2e::ComparisonVerificationReport =
        serde_json::from_slice(&fs::read(report_path).unwrap()).unwrap();
    let differences = &refreshed.cases[0]
        .response
        .as_ref()
        .unwrap()
        .body_diagnosis
        .as_ref()
        .unwrap()
        .differences;
    assert_eq!(differences.len(), 1);
    assert!(matches!(
        &differences[0],
        ResponseBodyDifferenceDetail::Protobuf(difference)
            if difference.display_path == "config_scene.values"
    ));
}

#[test]
fn applies_explicit_comparison_counter_rules_by_representation_class() {
    let temp = tempdir().unwrap();
    let run = create_run(
        temp.path(),
        json!({
            "followers_count": 100,
            "followers_count_str": "100",
            "empty_count_str": ""
        }),
        json!({
            "followers_count": 101,
            "followers_count_str": "101",
            "empty_count_str": ""
        }),
    );
    let policy = temp.path().join("verification.yaml");
    fs::write(
        &policy,
        r#"version: 3
expected_response: assertions_only
dependency_rules: []
response_rules:
  json:
    "GET /api/token":
      counter:
        - pointer: /empty_count_str
          source_evidence: src/user.rs:load live counters
          source_example: <empty>
          target_example: <nonempty observation>
        - pointer: /followers_count
          source_evidence: src/user.rs:load live counters
          source_example: "100"
          target_example: "101"
        - pointer: /followers_count_str
          source_evidence: src/user.rs:load live counters
          source_example: "100"
          target_example: "101"
"#,
    )
    .unwrap();

    let report = verify_comparison_recording(ComparisonVerificationOptions {
        case_source: run.clone(),
        policy,
        report: run.join("comparison-report.json"),
    })
    .unwrap();

    assert!(report.passed);
    assert_eq!(
        report.cases[0]
            .response
            .as_ref()
            .unwrap()
            .applied_counter_rule_ids
            .len(),
        3
    );
}

#[test]
fn comparison_counter_rules_preserve_type_presence_and_empty_string() {
    let temp = tempdir().unwrap();
    let run = create_run(
        temp.path(),
        json!({
            "followers_count": 100,
            "followers_count_str": "",
            "friends_count": 3
        }),
        json!({
            "followers_count": "101",
            "followers_count_str": "0"
        }),
    );
    let policy = temp.path().join("verification.yaml");
    fs::write(
        &policy,
        r#"version: 3
expected_response: assertions_only
dependency_rules: []
response_rules:
  json:
    "GET /api/token":
      counter:
        - pointer: /followers_count
          source_evidence: src/user.rs:load live counters
          source_example: "100"
          target_example: "101"
        - pointer: /followers_count_str
          source_evidence: src/user.rs:load live counters
          source_example: <empty>
          target_example: "0"
        - pointer: /friends_count
          source_evidence: src/user.rs:load live counters
          source_example: "3"
          target_example: <missing>
"#,
    )
    .unwrap();

    let report = verify_comparison_recording(ComparisonVerificationOptions {
        case_source: run.clone(),
        policy,
        report: run.join("comparison-report.json"),
    })
    .unwrap();

    assert!(!report.passed);
    let response = report.cases[0].response.as_ref().unwrap();
    assert_eq!(response.differences.len(), 3);
    assert_eq!(
        response
            .differences
            .iter()
            .map(|difference| difference.pointer.as_str())
            .collect::<Vec<_>>(),
        vec!["/followers_count", "/followers_count_str", "/friends_count"]
    );
    assert!(response.applied_counter_rule_ids.is_empty());
}

#[test]
fn applies_a_candidate_rule_when_the_source_recheck_is_stable() {
    let temp = tempdir().unwrap();
    let run = create_run(
        temp.path(),
        json!({"token": "baseline"}),
        json!({"token": "candidate"}),
    );
    let case = run.join("apis/api-token/00000000-0000-4000-8000-000000000001");
    write_response(
        &case.join("expected-response-after.json"),
        json!({"token": "baseline"}),
    );
    let policy = temp.path().join("replay.yaml");
    fs::write(
        &policy,
        r#"version: 3
expected_response: assertions_only
dependency_rules: []
response_rules:
  json:
    "GET /api/token":
      uuid:
        - pointer: /token
          source_evidence: src/token.rs:issue_token
          source_example: <redacted source UUID>
          target_example: <redacted target UUID>
"#,
    )
    .unwrap();

    let report = verify_comparison_recording(ComparisonVerificationOptions {
        case_source: run.clone(),
        policy,
        report: run.join("comparison-report.json"),
    })
    .unwrap();

    assert!(report.passed);
    assert_eq!(report.counts.policy_mismatch, 0);
    assert!(report.cases[0].policy_mismatch_rule_ids.is_empty());
}

#[test]
fn compares_a_legacy_gzip_response_with_an_uncompressed_response() {
    let temp = tempdir().unwrap();
    let body = json!({"token": "same"});
    let run = create_run(temp.path(), body.clone(), body.clone());
    let case = run.join("apis/api-token/00000000-0000-4000-8000-000000000001");
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder
        .write_all(&serde_json::to_vec(&body).unwrap())
        .unwrap();
    let compressed = encoder.finish().unwrap();
    fs::write(
        case.join("expected-response.json"),
        serde_json::to_vec(&json!({
            "version": 1,
            "status": 200,
            "headers": {
                "content-encoding": ["gzip"],
                "content-type": ["application/json"]
            },
            "body": {
                "encoding": "base64",
                "data": STANDARD.encode(compressed),
                "truncated": false
            },
            "error": null
        }))
        .unwrap(),
    )
    .unwrap();
    let policy = temp.path().join("verification.yaml");
    fs::write(
        &policy,
        "version: 3\nexpected_response: assertions_only\ndependency_rules: []\n",
    )
    .unwrap();

    let report = verify_comparison_recording(ComparisonVerificationOptions {
        case_source: run.clone(),
        policy,
        report: run.join("comparison-report.json"),
    })
    .unwrap();

    assert!(report.complete);
    assert!(report.passed);
    assert_eq!(report.counts.passed, 1);
}

#[test]
fn writes_a_failed_report_for_an_unexempted_difference() {
    let temp = tempdir().unwrap();
    let run = create_run(
        temp.path(),
        json!({"token": "baseline"}),
        json!({"token": "candidate"}),
    );
    let policy = temp.path().join("replay.yaml");
    fs::write(
        &policy,
        "version: 3\nexpected_response: assertions_only\ndependency_rules: []\n",
    )
    .unwrap();
    let report_path = run.join("comparison-report.json");

    let report = verify_comparison_recording(ComparisonVerificationOptions {
        case_source: run,
        policy,
        report: report_path.clone(),
    })
    .unwrap();

    assert!(report.complete);
    assert!(!report.passed);
    assert_eq!(report.counts.failed, 1);
    assert_eq!(
        report.cases[0]
            .response
            .as_ref()
            .unwrap()
            .generated_scalar_candidates,
        ["/token"]
    );
    let representative = report.representative_difference.as_ref().unwrap();
    assert_eq!(representative.api, "GET /api/token");
    assert_eq!(
        representative.case_id,
        "00000000-0000-4000-8000-000000000001"
    );
    assert_eq!(representative.pointer, "/token");
    assert_eq!(
        representative.difference_kind,
        ResponseDifferenceKind::ValueMismatch
    );
    assert_eq!(representative.source_before, json!("baseline"));
    assert_eq!(representative.candidate, json!("candidate"));
    assert_eq!(representative.source_after, json!("not_recorded"));
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&fs::read(report_path).unwrap()).unwrap()["passed"],
        false
    );
}

#[test]
fn classifies_an_overlapping_baseline_change_as_source_change() {
    let temp = tempdir().unwrap();
    let run = create_run(
        temp.path(),
        json!({"value": "before"}),
        json!({"value": "candidate"}),
    );
    let case = run.join("apis/api-token/00000000-0000-4000-8000-000000000001");
    write_response(
        &case.join("expected-response-after.json"),
        json!({"value": "after"}),
    );
    let policy = temp.path().join("verification.yaml");
    fs::write(
        &policy,
        "version: 3\nexpected_response: assertions_only\ndependency_rules: []\n",
    )
    .unwrap();

    let report = verify_comparison_recording(ComparisonVerificationOptions {
        case_source: run.clone(),
        policy,
        report: run.join("comparison-report.json"),
    })
    .unwrap();

    assert!(report.complete);
    assert!(!report.passed);
    assert_eq!(report.counts.inconclusive, 1);
    assert_eq!(report.counts.source_changed_cases, 1);
    assert_eq!(
        report.cases[0].classification,
        ComparisonVerificationClassification::SourceChange
    );
    assert_eq!(report.cases[0].source_change_pointers, ["/value"]);
    assert!(report.cases[0].candidate_only_pointers.is_empty());
    assert!(!report.cases[0].baseline_recheck.as_ref().unwrap().passed);
    let representative = report.representative_difference.as_ref().unwrap();
    assert_eq!(representative.pointer, "/value");
    assert_eq!(representative.source_before, json!("before"));
    assert_eq!(representative.candidate, json!("candidate"));
    assert_eq!(representative.source_after, json!("after"));
}

#[test]
fn source_after_is_not_an_alternate_oracle_by_default() {
    let temp = tempdir().unwrap();
    let run = create_run(
        temp.path(),
        json!({"left": "before", "right": "before"}),
        json!({"left": "after", "right": "after"}),
    );
    let case = run.join("apis/api-token/00000000-0000-4000-8000-000000000001");
    write_response(
        &case.join("expected-response-after.json"),
        json!({"left": "after", "right": "after"}),
    );
    let policy = temp.path().join("verification.yaml");
    fs::write(
        &policy,
        "version: 3\nexpected_response: assertions_only\ndependency_rules: []\n",
    )
    .unwrap();

    let report = verify_comparison_recording(ComparisonVerificationOptions {
        case_source: run.clone(),
        policy,
        report: run.join("comparison-report.json"),
    })
    .unwrap();

    assert!(!report.passed);
    assert_eq!(
        report.cases[0].classification,
        ComparisonVerificationClassification::SourceChange
    );
    assert_eq!(report.cases[0].matched_source, None);
    assert!(report.cases[0].response_after.is_none());
}

#[test]
fn before_or_after_accepts_a_complete_source_after_match() {
    let temp = tempdir().unwrap();
    let run = create_run(
        temp.path(),
        json!({"left": "before", "right": "before"}),
        json!({"left": "after", "right": "after"}),
    );
    let case = run.join("apis/api-token/00000000-0000-4000-8000-000000000001");
    write_response(
        &case.join("expected-response-after.json"),
        json!({"left": "after", "right": "after"}),
    );
    let policy = temp.path().join("verification.yaml");
    fs::write(
        &policy,
        "version: 3\nexpected_response: assertions_only\ndependency_rules: []\nresponse_settings:\n  comparison:\n    source_match: before_or_after\n",
    )
    .unwrap();

    let report = verify_comparison_recording(ComparisonVerificationOptions {
        case_source: run.clone(),
        policy,
        report: run.join("comparison-report.json"),
    })
    .unwrap();

    assert!(report.complete);
    assert!(report.passed);
    assert_eq!(report.counts.passed, 1);
    assert_eq!(
        report.cases[0].matched_source,
        Some(MatchedSourceObservation::After)
    );
    assert!(
        report.cases[0]
            .response_after
            .as_ref()
            .unwrap()
            .differences
            .is_empty()
    );
}

#[test]
fn before_or_after_does_not_mix_fields_from_source_observations() {
    let temp = tempdir().unwrap();
    let run = create_run(
        temp.path(),
        json!({"left": "before", "right": "before"}),
        json!({"left": "before", "right": "after"}),
    );
    let case = run.join("apis/api-token/00000000-0000-4000-8000-000000000001");
    write_response(
        &case.join("expected-response-after.json"),
        json!({"left": "after", "right": "after"}),
    );
    let policy = temp.path().join("verification.yaml");
    fs::write(
        &policy,
        "version: 3\nexpected_response: assertions_only\ndependency_rules: []\nresponse_settings:\n  comparison:\n    source_match: before_or_after\n",
    )
    .unwrap();

    let report = verify_comparison_recording(ComparisonVerificationOptions {
        case_source: run.clone(),
        policy,
        report: run.join("comparison-report.json"),
    })
    .unwrap();

    assert!(!report.passed);
    assert_eq!(
        report.cases[0].classification,
        ComparisonVerificationClassification::SourceChange
    );
    assert_eq!(report.cases[0].matched_source, None);
    assert_eq!(
        report.cases[0]
            .response_after
            .as_ref()
            .unwrap()
            .differences
            .len(),
        1
    );
}

#[test]
fn before_or_after_requires_a_source_after_artifact() {
    let temp = tempdir().unwrap();
    let body = json!({"value": "stable"});
    let run = create_run(temp.path(), body.clone(), body);
    let policy = temp.path().join("verification.yaml");
    fs::write(
        &policy,
        "version: 3\nexpected_response: assertions_only\ndependency_rules: []\nresponse_settings:\n  comparison:\n    source_match: before_or_after\n",
    )
    .unwrap();

    let report = verify_comparison_recording(ComparisonVerificationOptions {
        case_source: run.clone(),
        policy,
        report: run.join("comparison-report.json"),
    })
    .unwrap();

    assert!(!report.complete);
    assert!(!report.passed);
    assert_eq!(report.counts.unevaluable, 1);
    assert!(
        report.cases[0]
            .error
            .as_deref()
            .unwrap()
            .contains("requires expected-response-after.json")
    );
}

#[test]
fn unrelated_source_change_does_not_hide_a_candidate_difference() {
    let temp = tempdir().unwrap();
    let run = create_run(
        temp.path(),
        json!({"source_owned": "before", "candidate_owned": "expected"}),
        json!({"source_owned": "before", "candidate_owned": "wrong"}),
    );
    let case = run.join("apis/api-token/00000000-0000-4000-8000-000000000001");
    write_response(
        &case.join("expected-response-after.json"),
        json!({"source_owned": "after", "candidate_owned": "expected"}),
    );
    let policy = temp.path().join("verification.yaml");
    fs::write(
        &policy,
        "version: 3\nexpected_response: assertions_only\ndependency_rules: []\n",
    )
    .unwrap();

    let report = verify_comparison_recording(ComparisonVerificationOptions {
        case_source: run.clone(),
        policy,
        report: run.join("comparison-report.json"),
    })
    .unwrap();

    assert_eq!(
        report.cases[0].classification,
        ComparisonVerificationClassification::CandidateDifference
    );
    assert_eq!(report.cases[0].source_change_pointers, ["/source_owned"]);
    assert_eq!(
        report.cases[0].candidate_only_pointers,
        ["/candidate_owned"]
    );
    assert_eq!(report.counts.failed, 1);
    assert_eq!(report.counts.source_changed_cases, 1);
}

#[test]
fn source_change_is_diagnostic_when_candidate_matches_source_before() {
    let temp = tempdir().unwrap();
    let body = json!({"value": "before"});
    let run = create_run(temp.path(), body.clone(), body);
    let case = run.join("apis/api-token/00000000-0000-4000-8000-000000000001");
    write_response(
        &case.join("expected-response-after.json"),
        json!({"value": "after"}),
    );
    let policy = temp.path().join("verification.yaml");
    fs::write(
        &policy,
        "version: 3\nexpected_response: assertions_only\ndependency_rules: []\n",
    )
    .unwrap();

    let report = verify_comparison_recording(ComparisonVerificationOptions {
        case_source: run.clone(),
        policy,
        report: run.join("comparison-report.json"),
    })
    .unwrap();

    assert!(report.passed);
    assert_eq!(
        report.cases[0].classification,
        ComparisonVerificationClassification::Passed
    );
    assert_eq!(report.cases[0].source_change_pointers, ["/value"]);
    assert_eq!(report.counts.source_changed_cases, 1);
}

#[test]
fn allows_a_rule_absent_from_the_entire_api_sample() {
    let temp = tempdir().unwrap();
    let body = json!({"value": "stable"});
    let run = create_run(temp.path(), body.clone(), body);
    let policy = temp.path().join("verification.yaml");
    fs::write(
        &policy,
        r#"version: 3
expected_response: assertions_only
dependency_rules: []
response_rules:
  json:
    "GET /api/token":
      uuid:
        - pointer: /missing
          source_evidence: src/token.rs:issue_token
          source_example: <redacted source UUID>
          target_example: <redacted target UUID>
"#,
    )
    .unwrap();

    let report = verify_comparison_recording(ComparisonVerificationOptions {
        case_source: run.clone(),
        policy,
        report: run.join("comparison-report.json"),
    })
    .unwrap();

    assert!(report.passed);
    assert_eq!(
        report.cases[0].classification,
        ComparisonVerificationClassification::Passed
    );
    assert_eq!(report.counts.policy_mismatch, 0);
    assert!(report.cases[0].policy_mismatch_rule_ids.is_empty());
    assert!(report.apis["GET /api/token"].passed);
    assert!(report.representative_policy_mismatch.is_none());
}

#[test]
fn an_absent_rule_does_not_mask_a_candidate_difference() {
    let temp = tempdir().unwrap();
    let run = create_run(
        temp.path(),
        json!({"value": "expected"}),
        json!({"value": "wrong"}),
    );
    let policy = temp.path().join("verification.yaml");
    fs::write(
        &policy,
        r#"version: 3
expected_response: assertions_only
dependency_rules: []
response_rules:
  json:
    "GET /api/token":
      uuid:
        - pointer: /missing
          source_evidence: src/token.rs:issue_token
          source_example: <redacted source UUID>
          target_example: <redacted target UUID>
"#,
    )
    .unwrap();

    let report = verify_comparison_recording(ComparisonVerificationOptions {
        case_source: run.clone(),
        policy,
        report: run.join("comparison-report.json"),
    })
    .unwrap();

    assert_eq!(
        report.cases[0].classification,
        ComparisonVerificationClassification::CandidateDifference
    );
    assert_eq!(report.counts.failed, 1);
    assert_eq!(report.counts.policy_mismatch, 0);
    assert_eq!(report.apis["GET /api/token"].counts.policy_mismatch, 0);
    assert!(report.cases[0].policy_mismatch_rule_ids.is_empty());
    assert!(report.representative_policy_mismatch.is_none());
    assert!(report.representative_difference.is_some());
}

#[test]
fn marks_a_response_content_decoding_failure_as_unevaluable() {
    let temp = tempdir().unwrap();
    let run = create_run(
        temp.path(),
        json!({"value": "baseline"}),
        json!({"value": "candidate"}),
    );
    let case = run.join("apis/api-token/00000000-0000-4000-8000-000000000001");
    fs::write(
        case.join("expected-response.json"),
        serde_json::to_vec(&json!({
            "version": 1,
            "status": 200,
            "body": {
                "encoding": "base64",
                "data": STANDARD.encode(b"not gzip"),
                "truncated": false,
                "decoded": false,
                "content_encoding": "gzip",
                "decode_error": "failed to decode gzip body"
            },
            "error": null
        }))
        .unwrap(),
    )
    .unwrap();
    let policy = temp.path().join("verification.yaml");
    fs::write(
        &policy,
        "version: 3\nexpected_response: assertions_only\ndependency_rules: []\n",
    )
    .unwrap();

    let report = verify_comparison_recording(ComparisonVerificationOptions {
        case_source: run.clone(),
        policy,
        report: run.join("comparison-report.json"),
    })
    .unwrap();

    assert!(!report.complete);
    assert!(!report.passed);
    assert_eq!(report.counts.unevaluable, 1);
    assert_eq!(
        report.cases[0].classification,
        ComparisonVerificationClassification::Unevaluable
    );
    assert!(
        report.cases[0]
            .error
            .as_deref()
            .unwrap()
            .contains("content decoding failed: failed to decode gzip body")
    );
}

fn create_run(root: &Path, expected: serde_json::Value, response: serde_json::Value) -> PathBuf {
    let run = root.join("comparison-recordings/20260722160000");
    let case = run.join("apis/api-token/00000000-0000-4000-8000-000000000001");
    fs::create_dir_all(&case).unwrap();
    fs::write(
        run.join("comparison-recording-run.json"),
        serde_json::to_vec(&json!({
            "status": "completed",
            "ready": true,
            "finished_at": "2026-07-22T16:00:01Z",
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
    fs::write(
        case.join("request.json"),
        serde_json::to_vec(&json!({
            "method": "GET",
            "uri": "/api/token",
            "api_pattern": "/api/token"
        }))
        .unwrap(),
    )
    .unwrap();
    write_response(&case.join("expected-response.json"), expected);
    write_response(&case.join("response.json"), response);
    run
}

fn write_response(path: &Path, body: serde_json::Value) {
    fs::write(
        path,
        serde_json::to_vec(&json!({
            "version": 1,
            "status": 200,
            "body": {
                "encoding": "base64",
                "data": STANDARD.encode(serde_json::to_vec(&body).unwrap()),
                "truncated": false
            },
            "error": null
        }))
        .unwrap(),
    )
    .unwrap();
}

fn write_headers(path: &Path, headers: serde_json::Value) {
    let mut response: serde_json::Value = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
    response["headers"] = headers;
    fs::write(path, serde_json::to_vec(&response).unwrap()).unwrap();
}

fn write_request_headers(path: &Path, headers: serde_json::Value) {
    let mut request: serde_json::Value = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
    request["headers"] = headers;
    fs::write(path, serde_json::to_vec(&request).unwrap()).unwrap();
}

fn write_binary_response(path: &Path, status: u16, body: &[u8]) {
    fs::write(
        path,
        serde_json::to_vec(&json!({
            "version": 1,
            "status": status,
            "body": {
                "encoding": "base64",
                "data": STANDARD.encode(body),
                "truncated": false
            },
            "error": null
        }))
        .unwrap(),
    )
    .unwrap();
}
