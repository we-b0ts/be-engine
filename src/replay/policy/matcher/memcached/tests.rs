use super::*;
use crate::replay::{ReplayCaseStatus, assertion::RequestTimes};
use serde_json::json;

#[test]
fn json_and_protobuf_values_share_contracts_and_independent_dependency_start_clocks() {
    for (codec, source, target) in [
        (
            "json",
            serde_json::to_vec(&json!({"created_at":1000,"members":["a","b"],"stable":7})).unwrap(),
            serde_json::to_vec(&json!({"created_at":2000,"members":["b","a"],"stable":7})).unwrap(),
        ),
        (
            "{kind: protobuf, fields: {/created_at: {field_path: [1], field_type: uint64}, /members: {field_path: [2], field_type: string, repeated: true}}}",
            vec![8, 0xe8, 7, 18, 1, b'a', 18, 1, b'b', 24, 7],
            vec![8, 0xd0, 15, 18, 1, b'b', 18, 1, b'a', 24, 7],
        ),
    ] {
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
        std::fs::write(&policy_path, format!(r#"format: traffic-policy/v1
rules:
  - id: cache-write
    surface: dependency.request
    match:
      api: POST /test
      resource: {{protocol: memcached, endpoint: 'cache.test:11211'}}
      operation: SET
      key: {{exact: session}}
    slot: value
    codec: {codec}
    contract:
      /created_at: {{kind: time, format: unix_seconds, relation: preserve_offset, anchor: dependency.request_start}}
      /members: {{kind: unordered}}
    proof: {{source: 'src/session:build', fact: 'Members come from a set; the timestamp uses the dependency request clock'}}
"#)).unwrap();
        let cases = BTreeMap::from([(
            "case".into(),
            ReplayCase {
                id: "case".into(),
                dir: case_dir.clone(),
                dependencies_path: case_dir.join("dependencies.jsonl"),
                status: ReplayCaseStatus::Pending,
            },
        )]);
        let mut runtime = ReplayPolicyRuntime::load(&policy_path, &cases).unwrap();
        runtime.request_contracts.set_request_times(
            "case",
            RequestTimes {
                source: DateTime::from_timestamp(1000, 0),
                target: DateTime::from_timestamp(1005, 0),
            },
        );
        let target_key = TargetKey {
            host: "cache.test".into(),
            port: 11211,
        };
        let context = MemcachedPolicyContext {
            case_id: Some("case"),
            target: &target_key,
            command: "set",
            key: Some(b"session"),
            recorded_value: Some(&source),
            actual_value: Some(&target),
            recorded_observed_at: DateTime::from_timestamp(1010, 0).unwrap(),
            recorded_duration_ms: 10_000,
            actual_observed_at: DateTime::from_timestamp(2000, 0).unwrap(),
        };
        let decision = runtime.preview_memcached(&context).unwrap();
        assert_eq!(decision.value_contracts.len(), 1);
        runtime.commit(Some("case"), decision);
        let report = runtime.report();
        let entry = report
            .dependency_rules
            .iter()
            .find(|rule| rule.id == "cache-write")
            .unwrap();
        assert_eq!(entry.matches, 1);
        assert_eq!(entry.time_validations, 1);
        let invalid = if codec == "json" {
            let mut value: Value = serde_json::from_slice(&target).unwrap();
            value["stable"] = json!(8);
            serde_json::to_vec(&value).unwrap()
        } else {
            let mut value = target.clone();
            *value.last_mut().unwrap() = 8;
            value
        };
        assert!(
            runtime
                .preview_memcached(&MemcachedPolicyContext {
                    actual_value: Some(&invalid),
                    ..context
                })
                .is_err()
        );
    }
}
