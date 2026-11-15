use super::*;
use crate::{primary_protocol::assertion::RequestTimes, replay::ReplayCaseStatus};
use serde_json::json;

fn runtime() -> (tempfile::TempDir, ReplayPolicyRuntime) {
    let temp = tempfile::tempdir().unwrap();
    let case_dir = temp.path().join("case");
    std::fs::create_dir(&case_dir).unwrap();
    std::fs::write(
        case_dir.join("request.json"),
        json!({"method":"POST","uri":"/test","timestamp":"1970-01-01T00:16:40Z"}).to_string(),
    )
    .unwrap();
    std::fs::write(case_dir.join("expected-response.json"), "{}").unwrap();
    std::fs::write(case_dir.join("dependencies.jsonl"), "").unwrap();
    let policy_path = temp.path().join("policy.yaml");
    std::fs::write(&policy_path,"format: traffic-policy/v3\njson:\n  fields:\n    /created_at: {kind: time, formats: [unix_seconds]}\n    /members: {kind: unordered}\n").unwrap();
    let cases = BTreeMap::from([(
        "case".into(),
        ReplayCase {
            id: "case".into(),
            dir: case_dir.clone(),
            dependencies_path: case_dir.join("dependencies.jsonl"),
            status: ReplayCaseStatus::Pending,
        },
    )]);
    let runtime = ReplayPolicyRuntime::load(&policy_path, &cases).unwrap();
    runtime.request_contracts.set_request_times(
        "case",
        RequestTimes {
            source: DateTime::from_timestamp(1000, 0),
            target: DateTime::from_timestamp(1005, 0),
        },
    );
    (temp, runtime)
}

#[test]
fn global_json_uses_independent_dependency_start_clocks_without_resource_or_api_selectors() {
    let (_temp, mut runtime) = runtime();
    let source =
        serde_json::to_vec(&json!({"created_at":1000,"members":["a","b"],"stable":7})).unwrap();
    let target =
        serde_json::to_vec(&json!({"created_at":2000,"members":["b","a"],"stable":7})).unwrap();
    let endpoint = TargetKey {
        host: "unconfigured-cache.test".into(),
        port: 11212,
    };
    let context = MemcachedPolicyContext {
        case_id: Some("case"),
        target: &endpoint,
        command: "add",
        key: Some(b"unconfigured-key"),
        recorded_value: Some(&source),
        actual_value: Some(&target),
        recorded_request_started_at: DateTime::from_timestamp(1000, 0),
        actual_observed_at: DateTime::from_timestamp(2000, 0).unwrap(),
    };
    let decision = runtime.preview_memcached(&context).unwrap();
    assert_eq!(decision.value_contracts.len(), 1);
    assert_eq!(decision.value_contracts[0].ids, vec!["global.json"]);
    let clocks = runtime.request_contracts.contract_clocks(
        Some("case"),
        DateTime::from_timestamp(1000, 0),
        DateTime::from_timestamp(2000, 0),
        None,
        None,
    );
    let comparison = runtime
        .request_contracts
        .compare_global_value(&source, &target, &[], clocks)
        .unwrap();
    assert_eq!(comparison.time_validations["global.json"], 1);
    runtime.commit(Some("case"), decision).unwrap();
    let invalid =
        serde_json::to_vec(&json!({"created_at":2000,"members":["b","a"],"stable":8})).unwrap();
    assert!(
        runtime
            .preview_memcached(&MemcachedPolicyContext {
                actual_value: Some(&invalid),
                ..context
            })
            .is_err()
    );
}

#[test]
fn unrecognized_protobuf_values_keep_exact_bytes() {
    let (_temp, runtime) = runtime();
    let source = vec![8, 0xe8, 7, 18, 1, b'a', 18, 1, b'b', 24, 7];
    let target = vec![8, 0xd0, 15, 18, 1, b'b', 18, 1, b'a', 24, 7];
    let endpoint = TargetKey {
        host: "cache.test".into(),
        port: 11211,
    };
    let context = MemcachedPolicyContext {
        case_id: Some("case"),
        target: &endpoint,
        command: "set",
        key: Some(b"session"),
        recorded_value: Some(&source),
        actual_value: Some(&source),
        recorded_request_started_at: DateTime::from_timestamp(1000, 0),
        actual_observed_at: DateTime::from_timestamp(2000, 0).unwrap(),
    };
    let decision = runtime.preview_memcached(&context).unwrap();
    assert!(decision.value_contracts[0].ids.is_empty());
    assert!(
        runtime
            .preview_memcached(&MemcachedPolicyContext {
                actual_value: Some(&target),
                ..context
            })
            .is_err()
    );
}

#[test]
fn missing_memcached_request_clock_cannot_use_an_available_api_anchor() {
    let (_temp, runtime) = runtime();
    let source = br#"{"created_at":1000}"#;
    let target = br#"{"created_at":1005}"#;
    let endpoint = TargetKey {
        host: "cache.test".into(),
        port: 11211,
    };
    let context = MemcachedPolicyContext {
        case_id: Some("case"),
        target: &endpoint,
        command: "set",
        key: Some(b"key"),
        recorded_value: Some(source),
        actual_value: Some(target),
        recorded_request_started_at: None,
        actual_observed_at: DateTime::from_timestamp(1005, 0).unwrap(),
    };
    assert!(runtime.preview_memcached(&context).is_err());
    assert!(
        runtime
            .preview_memcached(&MemcachedPolicyContext {
                recorded_request_started_at: DateTime::from_timestamp(1000, 0),
                ..context
            })
            .is_ok()
    );
}
