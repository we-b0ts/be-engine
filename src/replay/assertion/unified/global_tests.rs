use super::*;
use serde_json::json;

#[test]
fn one_global_strategy_compares_unrelated_api_responses_and_preserves_identity_relations() {
    let temp = tempfile::tempdir().unwrap();
    let policy = temp.path().join("policy.yaml");
    std::fs::write(
        &policy,
        r#"format: traffic-policy/v2
json:
  fields:
    /created_at: {kind: time, formats: [unix_seconds]}
    /item_id: {kind: identity, formats: [uuid]}
    /item/id: {kind: identity, formats: [uuid]}
"#,
    )
    .unwrap();
    let loaded = load_replay_policy(&policy).unwrap();
    let a = "11111111-1111-4111-8111-111111111111";
    let x = "22222222-2222-4222-8222-222222222222";
    let y = "33333333-3333-4333-8333-333333333333";
    let capture = |id: &str, nested: &str, time: i64| json!({"encoding":"utf8","data":json!({"created_at":time,"item_id":id,"item":{"id":nested},"stable":true}).to_string(),"truncated":false});
    for uri in ["/responses", "/entirely/unrelated"] {
        let check = |id: &str, nested: &str, status: u16| {
            assert_recorded_response_with_policy(
            ResponseAssertionOptions {case_id:"case".into(),request:temp.path().join("request.json"),expected_response:temp.path().join("expected.json"),actual_response:temp.path().join("actual.json"),policy:policy.clone()},
            &serde_json::to_vec(&json!({"method":"POST","uri":uri,"timestamp":"1970-01-01T00:16:40Z"})).unwrap(),
            &serde_json::to_vec(&json!({"status":200,"body":capture(a,a,1005)})).unwrap(),
            &serde_json::to_vec(&json!({"version":1,"status":status,"request_sent_at":"1970-01-01T00:33:20Z","body":capture(id,nested,2005)})).unwrap(),
            &loaded).unwrap()
        };
        assert!(check(x, x, 200).passed);
        assert!(!check(x, y, 200).passed);
        assert!(!check(x, x, 500).passed);
    }
}
