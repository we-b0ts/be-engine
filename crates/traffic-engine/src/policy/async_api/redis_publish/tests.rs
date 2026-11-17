use super::*;
use crate::policy::{AsyncEnd, compile_policy, parse_policy, render_policy};
use serde_json::json;

fn declaration() -> Value {
    json!({
        "operation":"publish", "channel":"socketio", "database":0,
        "endpoint":"redis.test:6379",
        "when_message":{"/method":"emit","/event":"chat:start","/namespace":"/chat"}
    })
}

fn document(end: Value) -> String {
    json!({
        "format":"traffic-policy/v3",
        "async_api":{"POST /jobs":{
            "when_response":{"/status":"queued"}, "end":[{"redis":end}]
        }}
    })
    .to_string()
}

fn compiled(end: Value) -> anyhow::Result<crate::policy::CompiledPolicy> {
    compile_policy(&parse_policy(&document(end))?)
}

#[test]
fn publish_message_terminal_roundtrips_through_policy_and_recorder_configuration() {
    let input = document(declaration());
    let policy = parse_policy(&input).unwrap();
    let actual = compile_policy(&policy).unwrap();
    let AsyncEnd::RedisPublish(end) = &actual.async_api["POST /jobs"][0].end[0] else {
        panic!("PUBLISH terminal expected")
    };
    assert_eq!(end.operation, "PUBLISH");
    assert_eq!(end.channel, "socketio");
    assert_eq!(end.when_message["/event"], "chat:start");
    assert_eq!(end.database, Some(0));
    assert_eq!(end.endpoint.as_ref().unwrap().port, 6379);
    assert_eq!(
        compile_policy(&parse_policy(&render_policy(&policy).unwrap()).unwrap()).unwrap(),
        actual
    );
    let source = crate::config::SourceTrafficPolicyConfig::parse(
        &input,
        std::path::Path::new("policy.yaml"),
    )
    .unwrap();
    let mut config = crate::AppConfig::default();
    source.apply_to(&mut config).unwrap();
    assert_eq!(config.async_api, actual.async_api);
}

#[test]
fn terminal_message_changes_refresh_full_capture_and_runtime_fingerprints() {
    let original = compiled(declaration()).unwrap();
    for (pointer, value) in [
        ("/channel", json!("another-channel")),
        ("/when_message/~1event", json!("chat:done")),
        ("/database", json!(1)),
    ] {
        let mut changed = declaration();
        *changed.pointer_mut(pointer).unwrap() = value;
        let changed = compiled(changed).unwrap();
        assert_ne!(original.fingerprints.full, changed.fingerprints.full);
        assert_ne!(original.fingerprints.capture, changed.fingerprints.capture);
        assert_ne!(original.fingerprints.runtime, changed.fingerprints.runtime);
    }
}

#[test]
fn legacy_redis_key_serialization_and_rule_digest_remain_exact() {
    let rules: crate::policy::AsyncApiRules = serde_json::from_value(json!({
        "end":[{"redis":{"operation":"DEL","key":"done:*"}}]
    }))
    .unwrap();
    assert!(matches!(&rules[0].end[0], AsyncEnd::Redis(_)));
    let bytes = serde_json::to_vec(&rules).unwrap();
    assert_eq!(
        std::str::from_utf8(&bytes).unwrap(),
        r#"[{"when":{},"end":[{"redis":{"operation":"DEL","key":"done:*"}}]}]"#
    );
    assert_eq!(
        crate::policy_evidence::digest(&bytes),
        "sha256:aab61c4af777642873c9e096d33749dd778ef55d32eab50fea16cc004ed11466"
    );
}

#[test]
fn key_channel_mixing_and_unconstrained_or_non_publish_terminals_are_rejected() {
    let mut invalid = Vec::new();
    let mut mixed = declaration();
    mixed["key"] = json!("other-resource");
    invalid.push(mixed);
    let mut occurrence = declaration();
    occurrence["occurrence"] = json!(2);
    invalid.push(occurrence);
    let mut missing = declaration();
    missing.as_object_mut().unwrap().remove("when_message");
    invalid.push(missing);
    for (field, value) in [
        ("operation", json!("GET")),
        ("operation", json!("SPUBLISH")),
        ("when_message", json!({})),
        ("channel", json!("")),
        ("channel", json!("   ")),
        ("channel", json!("socket*")),
        ("channel", json!("socket\nchannel")),
        ("channel", json!("x".repeat(1025))),
        ("database", json!(-1)),
        ("endpoint", json!("redis.test:0")),
    ] {
        let mut changed = declaration();
        changed[field] = value;
        invalid.push(changed);
    }
    for end in invalid {
        assert!(compiled(end.clone()).is_err(), "accepted {end}");
    }
}

#[test]
fn message_predicates_require_bounded_exact_scalar_json_pointers() {
    for predicates in [
        json!({"event":"chat:start"}),
        json!({"/*":"chat:start"}),
        json!({"/~2event":"chat:start"}),
        json!({"/event\n":"chat:start"}),
        json!({"/event":["chat:start"]}),
        json!({"/event":{"name":"chat:start"}}),
        json!({"/event":"x".repeat(4097)}),
        Value::Object(
            (0..33)
                .map(|index| (format!("/{index}"), json!(true)))
                .collect(),
        ),
    ] {
        let mut changed = declaration();
        changed["when_message"] = predicates;
        assert!(compiled(changed).is_err());
    }
    let mut accepted = declaration();
    accepted["when_message"] = json!({
        "/event":"chat:start", "/optional":null, "/enabled":true,
        "/attempt":2, "/a~1b/~0key":false
    });
    compiled(accepted).unwrap();
}

#[test]
fn duplicate_message_selectors_are_rejected_in_the_redis_document() {
    let input = r#"{"redis":{"operation":"PUBLISH","channel":"socketio","when_message":{"/event":"chat:start","/event":"chat:done"}}}"#;
    assert!(serde_json::from_str::<AsyncEnd>(input).is_err());
}
