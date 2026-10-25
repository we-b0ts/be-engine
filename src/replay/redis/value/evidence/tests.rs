use super::super::tests::{args, match_value, state};
use super::*;
use std::path::PathBuf;
const SOURCE: &[u8] = br#"{"ids":["secret-b","secret-a","secret-a"],"ordered":[1,2]}"#;
const TARGET: &[u8] = br#"{"ids":["secret-a","secret-b","secret-a"],"ordered":[1,2]}"#;
fn fixture(source: &[u8], target: &[u8]) -> (tempfile::TempDir, PathBuf) {
    let temp = tempfile::tempdir().unwrap();
    let mut state = state(source);
    assert!(match_value(&mut state, target).is_err());
    let report = temp.path().join("replay.json");
    fs::write(
        &report,
        json!({"finalized":true,"redis":state.snapshot()}).to_string(),
    )
    .unwrap();
    (temp, report)
}
#[test]
fn collection_diagnostics_are_secret_free_and_do_not_change_replay_evidence() {
    let (_temp, report) = fixture(SOURCE, TARGET);
    let original = fs::read(&report).unwrap();
    let evidence = discover(&report).unwrap();
    assert_eq!(evidence["candidates"].as_array().unwrap().len(), 1);
    assert!(!evidence.to_string().contains("secret-a"));
    assert!(
        evidence["does_not_prove"]
            .as_str()
            .unwrap()
            .contains("candidates do not change dependency ownership")
    );
    assert_eq!(fs::read(&report).unwrap(), original);
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
fn protobuf_candidates_are_diagnostics_without_implicit_replay_permission() {
    let (_temp, report) = fixture(b"\x22\x01b\x22\x01a\x28\x01", b"\x22\x01a\x22\x01b\x28\x01");
    assert!(
        discover(&report).unwrap()["candidates"]
            .as_array()
            .unwrap()
            .iter()
            .any(|candidate| candidate["selector"]["field"]["element_type"] == "string")
    );
}
#[test]
fn old_unfinished_and_bounded_reports_keep_their_missing_evidence_visible() {
    let (_temp, path) = fixture(SOURCE, TARGET);
    let original: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    let mut report = original.clone();
    report["finalized"] = false.into();
    fs::write(&path, report.to_string()).unwrap();
    assert!(discover(&path).is_err());
    let mut report = original.clone();
    report["redis"]
        .as_object_mut()
        .unwrap()
        .remove("unordered_value");
    fs::write(&path, report.to_string()).unwrap();
    assert_eq!(discover(&path).unwrap()["requires_fresh_replay"], true);
    let mut report = original;
    report["redis"]["unordered_value"]["omitted_candidates"] = 1.into();
    fs::write(&path, report.to_string()).unwrap();
    assert_eq!(discover(&path).unwrap()["omitted_candidates"], 1);
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
