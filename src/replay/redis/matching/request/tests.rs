use super::*;
use crate::replay::ReplayPolicyRuntime;
use crate::replay::{ReplayCase, ReplayCaseStatus};
use chrono::DateTime;
use serde_json::json;

const SOURCE: &str = "0123456789ab4def8123456789abcdef";
const TARGET: &str = "fedcba98765443218123456789abcdef";
fn payload(id: &str, time: Option<&str>, status: &str) -> Vec<u8> {
    let mut data = json!({"task_id":7,"status":status});
    if let Some(time) = time {
        data["completed_at"] = json!(time);
    }
    json!({"host_id":id,"event":"task:status","data":[data]})
        .to_string()
        .into_bytes()
}
fn arguments(id: &str, time: Option<&str>, status: &str) -> Vec<Vec<u8>> {
    vec![b"events".to_vec(), payload(id, time, status)]
}
#[test]
fn script_batches_use_each_physical_call_clock_and_consume_each_exchange_once() {
    let temp = tempfile::tempdir().unwrap();
    let case = temp.path().join("case");
    std::fs::create_dir(&case).unwrap();
    std::fs::write(
        case.join("request.json"),
        json!({"method":"DELETE","uri":"/tasks/bulk","timestamp":"1970-01-01T00:16:40Z"})
            .to_string(),
    )
    .unwrap();
    std::fs::write(case.join("expected-response.json"), "{}").unwrap();
    std::fs::write(case.join("dependencies.jsonl"), "").unwrap();
    let path = temp.path().join("policy.yaml");
    std::fs::write(&path,r#"format: traffic-policy/v1
rules:
- id: batch-clock
  match:
    api: DELETE /tasks/*
    resource: {protocol: redis, endpoint: 'redis.test:6379', database: 0}
    key: {kind: exact, value: metrics}
  effect:
    kind: redis_sequence
    commands:
    - operation: EVALSHA
      script: {sha1: '75f75be3d11e483c99c83f8b0b8836c2e2c5923b'}
      arguments:
        3: {relative_time: unix_seconds, anchor: dependency.request_start}
        4: {relative_time: unix_microseconds, anchor: dependency.request_start}
        5:
          kind: json
          fields:
            /changed_at_us: {relative_time: unix_microseconds, anchor: dependency.request_start}
  proof: {source: 'metrics.py:publish', fact: 'Each committed iteration publishes its own clock, retaining exact copied fields'}
"#).unwrap();
    let cases = BTreeMap::from([(
        "case".into(),
        ReplayCase {
            id: "case".into(),
            dir: case.clone(),
            dependencies_path: case.join("dependencies.jsonl"),
            status: ReplayCaseStatus::Pending,
        },
    )]);
    let policy = ReplayPolicyRuntime::load(&path, &cases).unwrap();
    policy.request_contracts.set_request_times(
        "case",
        crate::replay::assertion::RequestTimes {
            source: DateTime::from_timestamp(1000, 0),
            target: Some(chrono::Utc::now()),
        },
    );
    let mut state = RedisReplayState {
        request_contracts: policy.request_contracts.clone(),
        ..Default::default()
    };
    let args = |micros: i64| {
        vec![
            b"75f75be3d11e483c99c83f8b0b8836c2e2c5923b".to_vec(),
            b"1".to_vec(),
            b"metrics".to_vec(),
            format!("{}.{:06}", micros / 1_000_000, micros % 1_000_000).into_bytes(),
            micros.to_string().into_bytes(),
            json!({"changed_at_us":micros,"stable":7})
                .to_string()
                .into_bytes(),
        ]
    };
    let source_connection = Uuid::new_v4();
    for index in 0..50 {
        let source = DateTime::from_timestamp(1000 + index * 3, 0).unwrap();
        let arguments = args(source.timestamp_micros());
        let record=serde_json::from_value(json!({"connection_id":source_connection,"sequence":index+1,"target_host":"redis.test","target_port":6379,"resp_version":2,"database":0,"command":"EVALSHA",
            "timestamp":source,"request_started_at":source,"args":arguments.iter().map(|a|json!({"encoding":"utf8","data":std::str::from_utf8(a).unwrap()})).collect::<Vec<_>>(),
            "response_kind":"integer","response":{"encoding":"utf8","data":":1\r\n"},"replay_safe":true})).unwrap();
        state
            .register_exchange(
                record,
                ReplaySource::Case,
                Some("case"),
                &mut BTreeMap::new(),
                &[],
            )
            .unwrap();
    }
    let target = TargetKey {
        host: "redis.test".into(),
        port: 6379,
    };
    let connection = TargetConnection::default();
    let call = |state: &mut RedisReplayState, arguments: &[Vec<u8>]| {
        state.match_redis(
            Some("case"),
            &target,
            connection,
            2,
            0,
            None,
            "EVALSHA",
            arguments,
        )
    };
    for _ in 0..50 {
        let actual = args(chrono::Utc::now().timestamp_micros());
        let mut bad = actual.clone();
        bad[5] = b"{\"changed_at_us\":0,\"stable\":8}".to_vec();
        assert!(call(&mut state, &bad).is_err());
        let matched = call(&mut state, &actual).unwrap();
        state.complete_exchange(&matched);
    }
    assert!(state.snapshot().unused_case.is_empty());
    assert!(call(&mut state, &args(chrono::Utc::now().timestamp_micros())).is_err());
}

#[test]
fn publish_time_and_uuid_bind_only_after_complete_match_and_consume_once() {
    let temp = tempfile::tempdir().unwrap();
    let case = temp.path().join("case");
    std::fs::create_dir(&case).unwrap();
    std::fs::write(
        case.join("request.json"),
        json!({"method":"POST","uri":"/callback","timestamp":"1970-01-01T00:16:40Z"}).to_string(),
    )
    .unwrap();
    std::fs::write(case.join("expected-response.json"), "{}").unwrap();
    std::fs::write(case.join("dependencies.jsonl"), "").unwrap();
    let policy = temp.path().join("policy.yaml");
    crate::replay::write_policy_fixture(&policy,serde_yaml::to_string(&json!({"version":3,"expected_response":"assertions_only","dependency_rules":[
        {"id":"host-id","protocol":"redis","target":{"host":"redis.test","port":6379},"redis":{"publish":{"channel":"events","uuid_field":"host_id","source_evidence":"Emitter initializes one process UUID v4"}}},
        {"id":"time","protocol":"redis","case":{"method":"POST","path":"/callback"},"target":{"host":"redis.test","port":6379},"source_evidence":"Emitter generates local completion time","redis":{"key":"events","commands":[{"command":"PUBLISH","argument_values":{"1":{"json":{"/data/0/completed_at":{"time":"preserve_relative","format":"iso8601_naive","utc_offset":"+00:00"}}}}}]}}
    ]})).unwrap()).unwrap();
    let cases = BTreeMap::from([(
        "case".into(),
        ReplayCase {
            id: "case".into(),
            dir: case.clone(),
            dependencies_path: case.join("dependencies.jsonl"),
            status: ReplayCaseStatus::Pending,
        },
    )]);
    let policy = ReplayPolicyRuntime::load(&policy, &cases).unwrap();
    policy.request_contracts.set_request_times(
        "case",
        crate::replay::assertion::RequestTimes {
            source: DateTime::from_timestamp(1000, 0),
            target: DateTime::from_timestamp(2000, 0),
        },
    );
    let mut state = RedisReplayState {
        request_contracts: policy.request_contracts.clone(),
        ..Default::default()
    };
    state.configure_publish(policy.redis_publish_rules());
    for (sequence, time, status) in [
        (1, Some("1970-01-01T00:16:40.123456"), "COMPLETED"),
        (2, None, "RUNNING"),
    ] {
        let args = arguments(SOURCE, time, status);
        let record=serde_json::from_value(json!({"connection_id":Uuid::new_v4(),"sequence":sequence,"target_host":"redis.test","target_port":6379,"resp_version":2,"database":0,"command":"PUBLISH","args":args.iter().map(|a|json!({"encoding":"utf8","data":String::from_utf8(a.clone()).unwrap()})).collect::<Vec<_>>(),"response_kind":"integer","response":{"encoding":"utf8","data":":1\r\n"},"replay_safe":true})).unwrap();
        state
            .register_exchange(
                record,
                ReplaySource::Case,
                Some("case"),
                &mut BTreeMap::new(),
                &[],
            )
            .unwrap();
    }
    let target = TargetKey {
        host: "redis.test".into(),
        port: 6379,
    };
    let call = |state: &mut RedisReplayState, args: &[Vec<u8>]| {
        state.match_redis(
            Some("case"),
            &target,
            TargetConnection::default(),
            2,
            0,
            None,
            "PUBLISH",
            args,
        )
    };
    for (time, status) in [
        (Some("1970-01-01T00:33:26"), "COMPLETED"),
        (Some("1970-01-01T00:33:20.123456"), "FAILED"),
        (None, "COMPLETED"),
    ] {
        assert!(call(&mut state, &arguments(SOURCE, time, status)).is_err());
    }
    // Failed previews using SOURCE as target must not pin the UUID before this match.
    let actual = arguments(TARGET, Some("1970-01-01T00:33:20.123456"), "COMPLETED");
    let matched = call(&mut state, &actual).unwrap();
    state.complete_exchange(&matched);
    assert!(call(&mut state, &actual).is_err());
    assert!(call(&mut state, &arguments(SOURCE, None, "RUNNING")).is_err());
    let matched = call(&mut state, &arguments(TARGET, None, "RUNNING")).unwrap();
    state.complete_exchange(&matched);
    assert!(state.snapshot().unused_case.is_empty());
    assert!(call(&mut state, &arguments(TARGET, None, "RUNNING")).is_err());
}

#[test]
fn payload_evidence_budget_keeps_native_redis_matching_without_recounting_omissions() {
    let temp = tempfile::tempdir().unwrap();
    let local = temp.path().join(".traffic-e2e/local");
    let case = local.join("recordings/case");
    std::fs::create_dir_all(&case).unwrap();
    let key = local.join(crate::repository::LOCAL_ENCRYPTION_KEY_FROM_LOCAL);
    std::fs::create_dir_all(key.parent().unwrap()).unwrap();
    std::fs::write(
        key,
        crate::request_headers::generate_encryption_key().unwrap(),
    )
    .unwrap();
    std::fs::write(
        case.join("request.json"),
        json!({"method":"POST","uri":"/large","timestamp":"1970-01-01T00:16:40Z"}).to_string(),
    )
    .unwrap();
    std::fs::write(case.join("expected-response.json"), "{}").unwrap();
    std::fs::write(case.join("dependencies.jsonl"), "").unwrap();
    let path = temp.path().join("policy.yaml");
    std::fs::write(&path, "format: traffic-policy/v1\nrules: []\n").unwrap();
    let cases = BTreeMap::from([(
        "case".into(),
        ReplayCase {
            id: "case".into(),
            dir: case.clone(),
            dependencies_path: case.join("dependencies.jsonl"),
            status: ReplayCaseStatus::Pending,
        },
    )]);
    let mut runtime = ReplayPolicyRuntime::load(&path, &cases).unwrap();
    let artifacts = local.join("runtime/attempt");
    let store = crate::policy_evidence::WitnessStore::new(&artifacts).unwrap();
    runtime
        .request_contracts
        .configure_witnesses(store.clone(), false)
        .unwrap();
    let value = "x".repeat(1024 * 1024 + 32);
    let record = serde_json::from_value(json!({"connection_id":Uuid::new_v4(),"sequence":1,
        "target_host":"redis.test","target_port":6379,"resp_version":2,"database":0,"command":"SET",
        "args":[{"encoding":"utf8","data":"key"},{"encoding":"utf8","data":value}],
        "response_kind":"simple_string","response":{"encoding":"utf8","data":"+OK\r\n"},"replay_safe":true})).unwrap();
    let mut state = RedisReplayState {
        request_contracts: runtime.request_contracts.clone(),
        ..Default::default()
    };
    state
        .register_exchange(
            record,
            ReplaySource::Case,
            Some("case"),
            &mut BTreeMap::new(),
            &[],
        )
        .unwrap();
    assert!(
        state
            .match_redis(
                Some("case"),
                &TargetKey {
                    host: "redis.test".into(),
                    port: 6379
                },
                TargetConnection::default(),
                2,
                0,
                None,
                "SET",
                &[b"key".to_vec(), value.into_bytes()]
            )
            .is_ok()
    );
    let manifest = store.sealed_manifest().unwrap();
    assert_eq!(
        (manifest.observed, manifest.recorded, manifest.omitted),
        (1, 0, 1)
    );
    assert!(!manifest.complete);
    assert!(crate::policy_evidence::verify(&artifacts.join("replay.json"), &manifest).is_err());
}
