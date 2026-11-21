use super::{Value, json, policy};
use crate::policy::{NativeEffect, compile_policy, parse_policy, render_policy};

#[test]
fn physical_key_and_command_formats_roundtrip_without_authored_sequence_or_bindings() {
    let raw = policy(json!({
        "rate:*":{"key_format":{"kind":"time_window","seconds":60},"commands":["INCRBY","EXPIRE"]},
        "vnc:*":{"key_format":{"kind":"identity","formats":[{"prefix":"vnc-","base64url":24}]},"commands":["SET"]},
        "presence:*":{"commands":[
            {"operation":"ZADD","arguments":{"1":{"kind":"time","formats":["unix_seconds"]}}},
            {"operation":"ZREMRANGEBYSCORE","arguments":{"2":{"kind":"time","formats":["unix_seconds"]}}}]},
        "metrics:*":{"commands":[{"operation":"EVALSHA","script":{"sha1":"75f75be3d11e483c99c83f8b0b8836c2e2c5923b"},"arguments":{
            "13":{"kind":"time","formats":["unix_seconds"]},
            "14":{"kind":"time","formats":["unix_microseconds"]},
            "17":{"kind":"time","formats":["unix_seconds"]}}}]}
    }));
    let policy = parse_policy(&raw.to_string()).unwrap();
    let compiled = compile_policy(&policy).unwrap();
    assert_eq!(compiled.native.len(), 4);
    assert!(
        compiled
            .native
            .iter()
            .all(|r| r.rule.selector.api.is_none())
    );
    let counter = compiled
        .native
        .iter()
        .find(|r| {
            matches!(&r.rule.effect,
        NativeEffect::RedisSequence(e) if e.commands[0].operation=="INCRBY")
        })
        .unwrap();
    let NativeEffect::RedisSequence(sequence) = &counter.rule.effect else {
        unreachable!()
    };
    assert_eq!(sequence.commands[1].operation, "EXPIRE");
    let rendered = render_policy(&policy).unwrap();
    for hidden in [
        "redis_sequence",
        "clock_group",
        "relative_time",
        "capture:",
        "references:",
        "proof:",
        "redis.key.",
    ] {
        assert!(!rendered.contains(hidden), "{hidden}: {rendered}");
    }
    let authored: Value = serde_yaml::from_str(&rendered).unwrap();
    assert!(authored["redis"].get("rules").is_none());
    assert_eq!(
        compile_policy(&parse_policy(&rendered).unwrap())
            .unwrap()
            .fingerprints,
        compiled.fingerprints
    );
}

#[test]
fn streaming_key_requires_no_named_resource_and_stays_on_one_line() {
    let mut raw = policy(json!({"chat:*":{"state":{"append":"concatenate","expire":"refresh"}}}));
    raw.as_object_mut().unwrap().remove("resources");
    let policy = parse_policy(&raw.to_string()).unwrap();
    let compiled = compile_policy(&policy).unwrap();
    assert_eq!(compiled.native.len(), 2);
    assert!(
        compiled
            .native
            .iter()
            .all(|rule| rule.rule.selector.resource.is_none())
    );
    let rendered = render_policy(&policy).unwrap();
    let authored: Value = serde_yaml::from_str(&rendered).unwrap();
    assert_eq!(
        authored["redis"]["keys"]["chat:*"]["state"],
        json!({"append":"concatenate","expire":"refresh"})
    );
    assert_eq!(
        compile_policy(&parse_policy(&rendered).unwrap())
            .unwrap()
            .fingerprints,
        compiled.fingerprints
    );
}

#[test]
fn command_formats_do_not_accept_implicit_permissions_or_authored_relationships() {
    for entry in [
        json!({"key_format":{"kind":"identity","formats":["uuid_v4"]}}),
        json!({"commands":[]}),
        json!({"commands":["SET"]}),
        json!({"commands":[{"operation":"ZADD","arguments":{"1":{"kind":"time","formats":["unix_seconds"],"clock_group":"business"}}}]}),
        json!({"commands":[{"operation":"SET","arguments":{"1":{"kind":"identity","formats":["uuid"]}}}]}),
        json!({"commands":[{"operation":"EVALSHA","arguments":{"13":{"kind":"time","formats":["unix_seconds"]}}}]}),
    ] {
        assert!(
            parse_policy(&policy(json!({"key:*":entry.clone()})).to_string()).is_err(),
            "accepted {entry}"
        );
    }
}
