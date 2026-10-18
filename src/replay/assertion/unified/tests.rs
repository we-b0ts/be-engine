use super::*;
use serde_json::{Value, json};

#[test]
fn new_policy_compares_json_without_weakening_status_or_stable_values() {
    let temp = tempfile::tempdir().unwrap();
    let policy = temp.path().join("policy.yaml");
    std::fs::write(&policy,r#"format: traffic-policy/v1
rules:
  - id: session-response
    surface: api.response
    match: {api: 'GET /sessions/*'}
    slot: body
    codec: json
    contract:
      /members: {kind: unordered}
      /expiry: {kind: time, format: unix_microseconds, relation: preserve_offset}
    proof: {source: 'src/session.py:30 create', fact: 'Source serializes a set and computes expiry from the request clock.'}
"#).unwrap();
    let loaded = load_replay_policy(&policy).unwrap();
    let request = serde_json::to_vec(
        &json!({"method":"GET","uri":"/sessions/42","timestamp":"2026-10-16T00:00:00Z"}),
    )
    .unwrap();
    let capture = |body: Value| json!({"encoding":"utf8","data":body.to_string(),"truncated":false,"decode_error":null});
    let expected=serde_json::to_vec(&json!({"status":200,"body":capture(json!({"members":[1,2,1],"expiry":1_792_108_810_000_001i64,"stable":"yes"}))})).unwrap();
    let evaluate = |body: Value, status: u16| {
        let actual=serde_json::to_vec(&json!({"version":1,"status":status,"request_sent_at":"2026-10-16T00:01:00Z","body":capture(body)})).unwrap();
        assert_recorded_response_with_policy(
            ResponseAssertionOptions {
                case_id: "session".into(),
                request: temp.path().join("request.json"),
                expected_response: temp.path().join("expected.json"),
                actual_response: temp.path().join("actual.json"),
                policy: policy.clone(),
            },
            &request,
            &expected,
            &actual,
            &loaded,
        )
        .unwrap()
    };
    let target = json!({"members":[2,1,1],"expiry":1_792_108_870_000_001i64,"stable":"yes"});
    assert!(evaluate(target.clone(), 200).passed);
    assert!(!evaluate(target, 500).passed);
    assert!(
        !evaluate(
            json!({"members":[2,1,1],"expiry":1_792_108_870_000_001i64,"stable":"changed"}),
            200
        )
        .passed
    );
    assert!(
        !evaluate(
            json!({"members":[2,2,1],"expiry":1_792_108_870_000_001i64,"stable":"yes"}),
            200
        )
        .passed
    );
}
