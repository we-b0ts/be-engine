use super::super::tests::{args, match_value, selector, state};
use super::*;
use crate::{RedisUnorderedFeedback, plan_redis_unordered};
use std::path::PathBuf;
const SOURCE: &[u8] = br#"{"ids":["secret-b","secret-a","secret-a"],"ordered":[1,2]}"#;
const TARGET: &[u8] = br#"{"ids":["secret-a","secret-b","secret-a"],"ordered":[1,2]}"#;
fn fixture(source: &[u8], target: &[u8]) -> (tempfile::TempDir, RedisUnorderedFeedback, PathBuf) {
    let temp = tempfile::tempdir().unwrap();
    fs::write(
        temp.path().join("recording-run.json"),
        r#"{"status":"completed"}"#,
    )
    .unwrap();
    let case = temp.path().join("apis/models/case");
    fs::create_dir_all(&case).unwrap();
    let mut state = state(source);
    let mut record = serde_json::to_value(&state.exchanges[0].record).unwrap();
    record["event_type"] = "redis_exchange".into();
    let dependencies = case.join("dependencies.jsonl");
    fs::write(&dependencies, record.to_string()).unwrap();
    assert!(match_value(&mut state, target).is_err());
    let report = temp.path().join("replay.json");
    fs::write(
        &report,
        json!({"finalized":true,"redis":state.snapshot()}).to_string(),
    )
    .unwrap();
    let policy = temp.path().join("policy.yaml");
    crate::replay::write_policy_fixture(&policy,"version: 3\nexpected_response: assertions_only\ndependency_rules: []\nresponse_rules: {json: {}}\n").unwrap();
    let feedback = RedisUnorderedFeedback {
        policy_path: policy,
        case_source: case,
        replay_report_path: report,
        rule_id: "membership".into(),
        selector: selector(),
        source_evidence: "service.py:216 department membership uses a set and map lookup".into(),
    };
    (temp, feedback, dependencies)
}
#[test]
fn discovery_and_source_proof_are_secret_free_and_authoring_is_retired() {
    let (_temp, feedback, dependencies) = fixture(SOURCE, TARGET);
    let evidence = discover(&feedback.replay_report_path).unwrap();
    assert_eq!(evidence["candidates"].as_array().unwrap().len(), 1);
    assert!(!evidence.to_string().contains("secret-a"));
    verify(
        &feedback.case_source,
        &feedback.replay_report_path,
        &feedback.selector,
    )
    .unwrap();
    let before = [
        fs::read(&feedback.policy_path).unwrap(),
        fs::read(&feedback.replay_report_path).unwrap(),
        fs::read(&dependencies).unwrap(),
    ];
    let error = plan_redis_unordered(feedback.clone()).err().unwrap();
    assert!(
        error
            .to_string()
            .contains("legacy rule authoring is retired")
    );
    assert_eq!(
        before,
        [
            fs::read(&feedback.policy_path).unwrap(),
            fs::read(&feedback.replay_report_path).unwrap(),
            fs::read(&dependencies).unwrap()
        ]
    );
}
#[test]
fn source_proof_rejects_changed_request_and_response_bytes() {
    for change in ["source", "response"] {
        let (_temp, feedback, dependencies) = fixture(SOURCE, TARGET);
        verify(
            &feedback.case_source,
            &feedback.replay_report_path,
            &feedback.selector,
        )
        .unwrap();
        let mut record: Value = serde_json::from_slice(&fs::read(&dependencies).unwrap()).unwrap();
        if change == "source" {
            record["args"][0]["data"] = "changed".into();
        } else {
            record["response"]["data"] = "+OTHER\r\n".into();
        }
        fs::write(dependencies, record.to_string()).unwrap();
        assert!(
            verify(
                &feedback.case_source,
                &feedback.replay_report_path,
                &feedback.selector
            )
            .is_err()
        );
    }
}
#[test]
fn no_candidates_for_value_changes_wrong_scope_or_changed_options() {
    let mut state = state(SOURCE);
    let changed = br#"{"ids":["secret-a","secret-c","secret-a"],"ordered":[1,2]}"#;
    assert!(match_value(&mut state, changed).is_err());
    assert!(state.unordered_value.candidates.is_empty());
    let target = TargetKey {
        host: "redis.test".into(),
        port: 6379,
    };
    for (case, port, db, username) in [
        ("other", 6379, 0, None),
        ("case", 6380, 0, None),
        ("case", 6379, 1, None),
        ("case", 6379, 0, Some("other")),
    ] {
        assert!(
            state
                .match_redis(
                    Some(case),
                    &TargetKey {
                        port,
                        ..target.clone()
                    },
                    TargetConnection::default(),
                    2,
                    db,
                    username,
                    "SET",
                    &args(TARGET)
                )
                .is_err()
        );
    }
    let mut changed_args = args(TARGET);
    changed_args[3] = b"901".to_vec();
    assert!(
        state
            .match_redis(
                Some("case"),
                &target,
                TargetConnection::default(),
                2,
                0,
                None,
                "SET",
                &changed_args
            )
            .is_err()
    );
    assert!(state.unordered_value.candidates.is_empty());
}
#[test]
fn protobuf_discovery_requires_source_type_confirmation_and_plan_replays() {
    use crate::replay::policy::{ProtobufFieldPath, ProtobufRepeatedElementType};
    let source = b"\x22\x01b\x22\x01a\x28\x01";
    let target = b"\x22\x01a\x22\x01b\x28\x01";
    let (_temp, mut feedback, _) = fixture(source, target);
    let evidence = discover(&feedback.replay_report_path).unwrap();
    assert!(
        evidence["candidates"]
            .as_array()
            .unwrap()
            .iter()
            .any(|c| c["selector"]["field"]["element_type"] == "string")
    );
    feedback.selector.field = RedisUnorderedField::Protobuf {
        field_path: ProtobufFieldPath(vec![4]),
        element_type: ProtobufRepeatedElementType::Message,
        display_path: "value.ids".into(),
    };
    assert!(
        verify(
            &feedback.case_source,
            &feedback.replay_report_path,
            &feedback.selector
        )
        .is_err()
    );
    feedback.selector.field = RedisUnorderedField::Protobuf {
        field_path: ProtobufFieldPath(vec![4]),
        element_type: ProtobufRepeatedElementType::String,
        display_path: "value.ids".into(),
    };
    verify(
        &feedback.case_source,
        &feedback.replay_report_path,
        &feedback.selector,
    )
    .unwrap();
}
#[test]
fn old_unfinished_or_bounded_reports_cannot_authorize_rules() {
    let (_temp, feedback, _) = fixture(SOURCE, TARGET);
    let original = fs::read(&feedback.replay_report_path).unwrap();
    for kind in ["old", "unfinished", "bounded"] {
        let mut report: Value = serde_json::from_slice(&original).unwrap();
        match kind {
            "old" => {
                report["redis"]
                    .as_object_mut()
                    .unwrap()
                    .remove("unordered_value");
            }
            "unfinished" => report["finalized"] = false.into(),
            _ => report["redis"]["unordered_value"]["omitted_candidates"] = 1.into(),
        }
        fs::write(&feedback.replay_report_path, report.to_string()).unwrap();
        assert!(
            verify(
                &feedback.case_source,
                &feedback.replay_report_path,
                &feedback.selector
            )
            .is_err()
        );
    }
}
#[test]
fn overlapping_selectors_and_rule_id_collisions_are_rejected_by_the_shared_compiler() {
    let rule = json!({"id":"membership","surface":"dependency.request","match":{
        "api":"GET /api","resource":{"protocol":"redis","endpoint":"redis.test:6379"},"operation":"SET", "key":{"prefix":"erp:membership:"}},
        "slot":"value","codec":"json","contract":{"/ids":{"kind":"unordered"}},
        "proof":{"source":"service.py:216","fact":"Source builds membership from a set"}});
    let compile = |rules: Value| {
        crate::policy::parse_policy(
            &json!({"format":"traffic-policy/v1","rules":rules}).to_string(),
        )
    };
    compile(json!([rule])).unwrap();
    let mut overlapping = rule.clone();
    overlapping["id"] = json!("another");
    overlapping["match"]["key"] = json!({"exact":"erp:membership:1"});
    assert!(compile(json!([rule, overlapping])).is_err());
    let mut collision = rule.clone();
    collision["contract"] = json!({"/ordered":{"kind":"unordered"}});
    assert!(compile(json!([rule, collision])).is_err());
}

#[test]
fn packed_and_mixed_protobuf_repeated_fields_are_discovered() {
    use crate::replay::policy::{ProtobufFieldPath, ProtobufRepeatedElementType};
    // Nested message: packed varints at 1.1 and repeated strings at 1.2.
    let source = b"\x0a\x0b\x0a\x03\x03\x01\x02\x12\x01b\x12\x01a";
    let target = b"\x0a\x0b\x0a\x03\x01\x02\x03\x12\x01a\x12\x01b";
    let fields = discover_fields(source, target);
    assert!(fields.iter().any(|f| matches!(f,RedisUnorderedField::Protobuf {field_path,element_type:ProtobufRepeatedElementType::Int32,..} if *field_path == ProtobufFieldPath(vec![1,1]))));
    assert!(fields.iter().any(|f| matches!(f,RedisUnorderedField::Protobuf {field_path,element_type:ProtobufRepeatedElementType::String,..} if *field_path == ProtobufFieldPath(vec![1,2]))));
    assert!(discover_fields(source, b"\x0a\x0b\x0a\x03\x01\x02\x04\x12\x01a\x12\x01b").is_empty());
}
