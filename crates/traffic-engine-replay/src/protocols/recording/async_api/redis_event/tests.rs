use super::*;
use crate::policy::{AsyncApiRule, AsyncEnd};
use crate::protocols::recording::async_api::{ResourceScope, publish};
use crate::recorder::capture_body;
use serde_json::json;

fn rule(end: serde_json::Value, count: usize) -> AsyncApiRule {
    serde_json::from_value(json!({"end":vec![end;count]})).unwrap()
}

#[test]
fn thirty_two_overlapping_keys_parse_one_reply_and_cache_failures() {
    let rule = rule(json!({"redis":{"operation":"GET","key":"done:*"}}), 32);
    let templates = templates::Templates::new(&rule);
    for (reply, success) in [(b":1\r\n".as_slice(), true), (b":1\r", false)] {
        let mut event = crate::protocols::recording::async_api::tests::redis("GET", b"done:42");
        if let RecorderEvent::RedisExchange(event) = &mut event {
            event.response = capture_body(reply, 100);
        }
        let cached = Event::from_event(&event).unwrap();
        for (index, end) in rule.end.iter().enumerate() {
            let AsyncEnd::Redis(end) = end else {
                unreachable!()
            };
            assert_eq!(cached.matches_key(end, index, &templates), success);
        }
        assert_eq!(cached.parses.get(), [1, 1, 1, 0]);
    }
}

#[test]
fn thirty_two_publications_parse_json_once_including_invalid_messages() {
    let rule = rule(
        json!({"redis":{"operation":"PUBLISH","channel":"socketio",
        "when_message":{"/event":"done"}}}),
        32,
    );
    for (message, success) in [
        (br#"{"event":"done"}"#.as_slice(), true),
        (b"not json", false),
    ] {
        let mut event =
            crate::protocols::recording::async_api::tests::redis("PUBLISH", b"socketio");
        if let RecorderEvent::RedisExchange(event) = &mut event {
            event.args.push(capture_body(message, 100));
        }
        let cached = Event::from_event(&event).unwrap();
        for end in &rule.end {
            let AsyncEnd::RedisPublish(end) = end else {
                unreachable!()
            };
            assert_eq!(publish::matches(end, &cached), success);
        }
        assert_eq!(cached.parses.get(), [1, 0, 1, 1]);
    }
}

#[test]
fn candidate_scopes_share_one_event_cache_and_cheap_mismatches_skip_native_parse() {
    let rule = rule(json!({"redis":{"operation":"GET","key":"done:*"}}), 1);
    let event = crate::protocols::recording::async_api::tests::redis("GET", b"done:42");
    let cached = Event::from_event(&event).unwrap();
    let actual_sql = OnceCell::new();
    for _ in 0..32 {
        let scope = ResourceScope::new(rule.clone());
        assert!(
            scope
                .observe_cached(&event, Some(&cached), &actual_sql)
                .is_some()
        );
    }
    assert_eq!(cached.parses.get(), [1, 1, 1, 0]);

    for (command, key, expected) in [
        ("DEL", b"done:42".as_slice(), [0, 0, 0, 0]),
        ("GET", b"other:42", [1, 1, 0, 0]),
    ] {
        let event = crate::protocols::recording::async_api::tests::redis(command, key);
        let cached = Event::from_event(&event).unwrap();
        let scope = ResourceScope::new(rule.clone());
        for _ in 0..32 {
            assert!(
                scope
                    .observe_cached(&event, Some(&cached), &actual_sql)
                    .is_none()
            );
        }
        assert_eq!(cached.parses.get(), expected);
    }
}
