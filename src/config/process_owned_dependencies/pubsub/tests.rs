use super::*;
use crate::config::process_owned_dependencies::BackgroundDependencyRuleConfig;
use serde_json::json;

fn selector() -> RedisPubsubSelector {
    serde_json::from_value(
        json!({"resource":{"protocol":"redis","endpoint":"cache.test:6379","database":0},
        "kind":"message","channel":"socketio"}),
    )
    .unwrap()
}

fn body(raw: &[u8]) -> Value {
    serde_json::to_value(crate::recorder::capture_body(raw, 1024 * 1024)).unwrap()
}

fn event() -> Value {
    json!({"event_type":"redis_pub_sub_push","connection_id":uuid::Uuid::nil(),"subscription_sequence":1,
        "target_host":"cache.test","target_port":6379,"database":0,"username":null,"replay_safe":true,
        "response":body(&crate::redis::encode_array(&[b"message",b"socketio",b"original-input"]))})
}

#[test]
fn received_input_scope_is_exact_and_cannot_select_commands_or_rpc_callbacks() {
    let selector = selector();
    validate(&selector).unwrap();
    assert!(matches_value(&selector, &event()));
    for (field, value) in [
        ("target_host", json!("other.test")),
        ("target_port", json!(6380)),
        ("database", json!(1)),
        ("username", json!("named-user")),
        ("event_type", json!("redis_exchange")),
        ("subscription_sequence", json!(0)),
        (
            "rpc_request",
            json!({"connection_id":uuid::Uuid::nil(),"sequence":1}),
        ),
        ("replay_safe", json!(false)),
    ] {
        let mut other = event();
        other[field] = value;
        assert!(
            !matches_value(&selector, &other),
            "unexpected selection for {field}"
        );
    }
    for raw in [
        crate::redis::encode_array(&[b"message", b"other", b"original-input"]),
        crate::redis::encode_array(&[b"pmessage", b"socket*", b"socketio", b"original-input"]),
        crate::redis::encode_array(&[b"PUBLISH", b"socketio", b"original-input"]),
        b"*3\r\n$7\r\nmessage\r\n".to_vec(),
    ] {
        let mut other = event();
        other["response"] = body(&raw);
        assert!(!matches_value(&selector, &other));
    }
    let mut truncated = event();
    truncated["response"]["truncated"] = true.into();
    assert!(!matches_value(&selector, &truncated));
}

#[test]
fn original_subscription_confirmation_and_authentication_cannot_be_substituted() {
    let selector = selector();
    let push = event();
    let subscription = json!({"event_type":"redis_exchange","connection_id":uuid::Uuid::nil(),"sequence":1,
        "target_host":"cache.test","target_port":6379,"database":0,"username":null,"command":"SUBSCRIBE",
        "args":[body(b"socketio")],"response":body(b"*3\r\n$9\r\nsubscribe\r\n$8\r\nsocketio\r\n:1\r\n"),
        "outcome":"response","replay_safe":true});
    validate_subscription(&selector, &push, &subscription).unwrap();
    for (field, value) in [
        ("connection_id", json!(uuid::Uuid::new_v4())),
        ("sequence", json!(2)),
        ("database", json!(1)),
        ("username", json!("another-user")),
        ("command", json!("PSUBSCRIBE")),
        (
            "response",
            body(b"*3\r\n$9\r\nsubscribe\r\n$5\r\nother\r\n:1\r\n"),
        ),
    ] {
        let mut other = subscription.clone();
        other[field] = value;
        assert!(
            validate_subscription(&selector, &push, &other).is_err(),
            "invalid subscription {field}"
        );
    }
}

#[test]
fn pattern_and_shard_notifications_keep_their_distinct_native_subjects() {
    for (kind, pattern, raw) in [
        (
            RedisPubsubKind::Pmessage,
            Some("socket*"),
            crate::redis::encode_array(&[b"pmessage", b"socket*", b"socketio", b"input"]),
        ),
        (
            RedisPubsubKind::Smessage,
            None,
            crate::redis::encode_array(&[b"smessage", b"socketio", b"input"]),
        ),
    ] {
        let mut selected = selector();
        selected.kind = kind;
        selected.pattern = pattern.map(str::to_owned);
        validate(&selected).unwrap();
        let mut incoming = event();
        incoming["response"] = body(&raw);
        assert!(matches_value(&selected, &incoming));
        selected.channel = "different".into();
        assert!(!matches_value(&selected, &incoming));
    }
}

#[test]
fn pubsub_task_rule_roundtrips_and_rejects_missing_database_or_implicit_pattern() {
    let revision = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let raw = format!(
        "format: traffic-policy/v3\nsource_revision: {revision}\nprocess_dependencies:\n  tasks:\n    reader:\n      requests:\n        - redis_pubsub:\n            resource: {{protocol: redis, endpoint: cache.test:6379, database: 0}}\n            channel: socketio\n            kind: message\n"
    );
    let compiled = crate::policy::parse_and_compile_policy(&raw).unwrap();
    let projected = crate::config::native_policy::project_source_policy(&compiled.native).unwrap();
    super::super::validate(&projected.process_owned_dependencies).unwrap();
    assert_eq!(projected.process_owned_dependencies.len(), 1);
    assert_eq!(
        projected.process_dependency_tasks.values().next().unwrap(),
        "reader"
    );
    let rendered =
        crate::policy::render_policy(&crate::policy::parse_policy(&raw).unwrap()).unwrap();
    assert!(rendered.contains("redis_pubsub"));
    assert_eq!(
        crate::policy::parse_and_compile_policy(&rendered)
            .unwrap()
            .fingerprints
            .full,
        compiled.fingerprints.full
    );
    for invalid in [
        raw.replace(", database: 0", ""),
        raw.replace("kind: message", "kind: pmessage"),
        raw.replace("protocol: redis", "protocol: mysql"),
    ] {
        assert!(crate::policy::parse_and_compile_policy(&invalid).is_err());
    }
}

#[test]
fn process_set_ownership_is_finite_exact_and_never_a_snapshot() {
    let mut rule:BackgroundDependencyRuleConfig=serde_json::from_value(json!({"protocol":"redis","name":"shutdown",
        "ports":[6379],"command":"SET","keys":["shutdown:state"],"source_revision":"","source_evidence":""})).unwrap();
    super::super::validate(std::slice::from_ref(&rule)).unwrap();
    assert!(!rule.uses_redis_snapshot());
    assert!(super::super::redis_rule_matches(
        &rule,
        6379,
        "SET",
        &[b"shutdown:state".to_vec(), b"original".to_vec()]
    ));
    assert!(!super::super::redis_rule_matches(
        &rule,
        6379,
        "SET",
        &[b"shutdown:state".to_vec()]
    ));
    assert!(!super::super::redis_rule_matches(
        &rule,
        6379,
        "SET",
        &[b"other".to_vec(), b"original".to_vec()]
    ));
    let BackgroundDependencyRuleConfig::Redis {
        initial_load_timeout_ms,
        ..
    } = &mut rule
    else {
        unreachable!()
    };
    *initial_load_timeout_ms = Some(1000);
    assert!(super::super::validate(&[rule]).is_err());
}
