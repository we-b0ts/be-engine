use super::*;
use crate::policy::{AsyncEnd, parse_and_compile_policy, parse_policy, render_policy};
use serde_json::{Value, json};

fn document(predicate: Option<Value>) -> Value {
    let mut end = json!({"operation":"GET", "key":"task:done:*"});
    if let Some(predicate) = predicate {
        end["when_response"] = predicate;
    }
    json!({"format":"traffic-policy/v3", "async_api":{"POST /jobs":{
        "end":[{"redis":end}]
    }}})
}

#[test]
fn omitted_and_any_reply_predicates_preserve_legacy_serialization_and_fingerprints() {
    let legacy = parse_and_compile_policy(&document(None).to_string()).unwrap();
    let explicit = document(Some(json!({"kind":"any"}))).to_string();
    assert_eq!(legacy, parse_and_compile_policy(&explicit).unwrap());
    let rendered = render_policy(&parse_policy(&explicit).unwrap()).unwrap();
    assert!(!rendered.contains("when_response"));
}

#[test]
fn native_nil_roundtrips_and_changes_capture_identity() {
    let legacy = parse_and_compile_policy(&document(None).to_string()).unwrap();
    let input = document(Some(json!({"kind":"nil"}))).to_string();
    let policy = parse_policy(&input).unwrap();
    let compiled = parse_and_compile_policy(&input).unwrap();
    let AsyncEnd::Redis(end) = &compiled.async_api["POST /jobs"][0].end[0] else {
        panic!("expected a Redis key terminal")
    };
    assert_eq!(end.when_response, AsyncRedisResponse::Nil);
    assert_ne!(compiled.fingerprints.capture, legacy.fingerprints.capture);
    assert_eq!(
        compiled,
        parse_and_compile_policy(&render_policy(&policy).unwrap()).unwrap()
    );
}

#[test]
fn reply_conditions_reject_ambiguous_values_and_impossible_publish_nil() {
    for value in [
        json!(null),
        json!("nil"),
        json!({}),
        json!({"kind":"null"}),
        json!({"kind":"nil", "value":null}),
        json!({"kind":"any", "extra":true}),
    ] {
        assert!(
            parse_and_compile_policy(&document(Some(value.clone())).to_string()).is_err(),
            "accepted ambiguous response predicate: {value}"
        );
    }
    for (kind, valid) in [("any", true), ("nil", false)] {
        let input = json!({"format":"traffic-policy/v3", "async_api":{"POST /jobs":{
            "end":[{"redis":{"operation":"PUBLISH", "channel":"events",
                "when_message":{"/event":"done"}, "when_response":{"kind":kind}}}]
        }}});
        assert_eq!(parse_and_compile_policy(&input.to_string()).is_ok(), valid);
    }
}
