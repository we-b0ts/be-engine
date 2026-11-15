use super::*;
use serde_json::{Value, json};

#[test]
fn mixed_native_response_preserves_private_identity_constraints_without_report_tokens() {
    let temp = tempfile::tempdir().unwrap();
    let policy = temp.path().join("policy.yaml");
    std::fs::write(&policy, r#"format: traffic-policy/v3
json:
  fields:
    /id: {kind: identity, formats: [uuid]}
rules:
  - id: nonce
    match: {api: POST /sessions}
    effect:
      kind: response_generated
      fields:
        /nonce: {kind: random, format: hex, length: 4}
    proof: {source: 'handler.rs:21', fact: 'This independent generated nonce retains its lowercase hexadecimal representation'}
"#).unwrap();
    let loaded = load_replay_policy(&policy).unwrap();
    let source_id = "11111111-1111-4111-8111-111111111111";
    let target_id = "99999999-9999-4999-8999-999999999999";
    let capture = |id: &str, nonce: &str| json!({"encoding":"utf8","data":json!({"id":id,"nonce":nonce,"stable":true}).to_string(),"truncated":false});
    let report = assert_recorded_response_with_policy(
        ResponseAssertionOptions {case_id:"case".into(),request:temp.path().join("request.json"),expected_response:temp.path().join("expected.json"),actual_response:temp.path().join("actual.json"),policy},
        &serde_json::to_vec(&json!({"method":"POST","uri":"/sessions","timestamp":"2020-01-01T00:00:00Z"})).unwrap(),
        &serde_json::to_vec(&json!({"status":200,"body":capture(source_id,"aaaa")})).unwrap(),
        &serde_json::to_vec(&json!({"version":1,"status":200,"request_sent_at":"2020-01-01T00:00:01Z","body":capture(target_id,"bbbb")})).unwrap(),
        &loaded,
    ).unwrap();
    assert!(report.passed, "{:?}", report.differences);
    assert_eq!(report.identity_pairs.len(), 1);
    assert_eq!(
        report.identity_pairs[0].source,
        serde_json::to_string(source_id).unwrap()
    );
    assert_eq!(
        report.identity_pairs[0].target,
        serde_json::to_string(target_id).unwrap()
    );
    let persisted = serde_json::to_string(&report).unwrap();
    assert!(!persisted.contains("identity_pairs"));
    assert!(!persisted.contains(source_id));
    assert!(!persisted.contains(target_id));
}

#[test]
fn new_policy_compares_json_without_weakening_status_or_stable_values() {
    let temp = tempfile::tempdir().unwrap();
    let policy = temp.path().join("policy.yaml");
    std::fs::write(
        &policy,
        r#"format: traffic-policy/v3
json:
  fields:
    /members: {kind: unordered}
    /expiry: {kind: time, formats: [unix_microseconds]}
"#,
    )
    .unwrap();
    let loaded = load_replay_policy(&policy).unwrap();
    let request = serde_json::to_vec(
        &json!({"method":"GET","uri":"/sessions/42","timestamp":"2026-10-16T00:00:00Z"}),
    )
    .unwrap();
    let capture = |body: Value| json!({"encoding":"utf8","data":body.to_string(),"truncated":false,"decode_error":null});
    let expected=serde_json::to_vec(&json!({"status":200,"timestamp":"2026-10-16T00:00:00Z","body":capture(json!({"members":[1,2,1],"expiry":1_792_108_810_000_001i64,"stable":"yes"}))})).unwrap();
    let evaluate = |body: Value, status: u16| {
        let actual=serde_json::to_vec(&json!({"version":1,"status":status,"request_sent_at":"2026-10-16T00:01:00Z","response_completed_at":"2026-10-16T00:01:00Z","body":capture(body)})).unwrap();
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
