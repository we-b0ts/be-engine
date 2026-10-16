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
    let policy = temp.path().join("verification.yaml");
    std::fs::write(&policy,serde_yaml::to_string(&json!({"version":3,"expected_response":"assertions_only","dependency_rules":[
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
