use crate::primary_protocol::assertion::*;
use serde_json::{Value, json};

fn check(headers: Value, body: Value) -> ResponseAssertionCaseReport {
    let temp = tempfile::tempdir().unwrap();
    let policy = temp.path().join("policy.yaml");
    std::fs::write(
        &policy,
        r#"format: traffic-policy/v3
json:
  fields:
    /id: {kind: identity, formats: [uuid]}
http:
  headers:
    x-amz-date: {kind: time, formats: [amz_date]}
    x-item-id: {kind: identity, formats: [uuid]}
"#,
    )
    .unwrap();
    let source_id = "11111111-1111-4111-8111-111111111111";
    let capture =
        |value: Value| json!({"encoding":"utf8","data":value.to_string(),"truncated":false});
    assert_recorded_response_with_policy(
        ResponseAssertionOptions {
            case_id: "case".into(), request: temp.path().join("request.json"),
            expected_response: temp.path().join("expected.json"),
            actual_response: temp.path().join("actual.json"), policy: policy.clone(),
        },
        &serde_json::to_vec(&json!({"method":"POST","uri":"/unrelated","timestamp":"1970-01-01T00:16:40Z"})).unwrap(),
        &serde_json::to_vec(&json!({"status":200,"timestamp":"1970-01-01T00:16:40Z","headers":{"X-Amz-Date":["19700101T001640Z"],"X-Item-Id":[source_id]},"body":capture(json!({"id":source_id}))})).unwrap(),
        &serde_json::to_vec(&json!({"version":1,"status":200,"headers":headers,"request_sent_at":"1970-01-01T00:33:20Z","response_completed_at":"1970-01-01T00:33:20Z","body":capture(body)})).unwrap(),
        &load_replay_policy(&policy).unwrap(),
    ).unwrap()
}

#[test]
fn response_header_formats_share_body_identity_and_retain_occurrence_presence() {
    let id = "22222222-2222-4222-8222-222222222222";
    let other = "33333333-3333-4333-8333-333333333333";
    let headers = json!({"x-amz-date":["19700101T003320Z"],"x-item-id":[id]});
    let passed = check(headers.clone(), json!({"id":id}));
    assert!(passed.passed, "{:?}", passed.differences);
    assert!(!check(headers.clone(), json!({"id":other})).passed);
    for headers in [
        json!({"x-amz-date":["19700101T003326Z"],"x-item-id":[id]}),
        json!({"x-item-id":[id]}),
        json!({"x-amz-date":["19700101T003320Z","19700101T003320Z"],"x-item-id":[id]}),
    ] {
        assert!(!check(headers, json!({"id":id})).passed);
    }
}
