use super::super::*;
use crate::recorder::{RedisExchangeEvent, capture_body};
use serde_json::json;

fn scope(kind: &str, occurrence: usize) -> ResourceScope {
    ResourceScope::new(
        serde_json::from_value(json!({"end":[{"redis":{
            "operation":"GET", "key":"done:*", "occurrence":occurrence,
            "when_response":{"kind":kind}
        }}]}))
        .unwrap(),
    )
}

fn event(version: u8, kind: &str, reply: &[u8]) -> RedisExchangeEvent {
    let RecorderEvent::RedisExchange(mut event) =
        crate::recorder::async_api::tests::redis("GET", b"done:42")
    else {
        unreachable!()
    };
    event.resp_version = version;
    event.response_kind = kind.into();
    event.response = capture_body(reply, 4096);
    event
}

fn completes(signal: Option<AsyncSignal>) -> bool {
    signal.is_some_and(|signal| signal.end_reason == AsyncEndReason::Resource)
}

fn assert_both(event: RedisExchangeEvent, predicate: &str, expected: bool) {
    let event = RecorderEvent::RedisExchange(event);
    assert_eq!(completes(scope(predicate, 1).observe(&event)), expected);
    assert_eq!(
        completes(
            scope(predicate, 1)
                .observe_recorded(&serde_json::to_value(event).unwrap())
                .unwrap()
        ),
        expected
    );
}

#[test]
fn nil_uses_native_null_instead_of_empty_strings_json_null_or_nested_nulls() {
    for (version, kind, reply, nil) in [
        (2, "null", b"$-1\r\n".as_slice(), true),
        (2, "null", b"*-1\r\n", true),
        (3, "null", b"_\r\n", true),
        (2, "bulk_string", b"$4\r\nnull\r\n", false),
        (2, "bulk_string", b"$0\r\n\r\n", false),
        (2, "bulk_string", b"$14\r\n{\"value\":null}\r\n", false),
        (2, "array", b"*1\r\n$-1\r\n", false),
        (3, "array", b"*1\r\n_\r\n", false),
        (2, "integer", b":0\r\n", false),
    ] {
        assert_both(event(version, kind, reply), "nil", nil);
        assert_both(event(version, kind, reply), "any", true);
    }
}

#[test]
fn any_requires_a_complete_successful_reply_and_request() {
    for (version, kind, reply) in [
        (2, "error", b"-ERR failed\r\n".as_slice()),
        (2, "null", b"-ERR failed\r\n"),
        (3, "blob_error", b"!3\r\nERR\r\n"),
        (3, "null", b"!3\r\nERR\r\n"),
        (3, "other", b">1\r\n+notification\r\n"),
        (2, "null", b"$-1\r"),
        (2, "null", b"$-1\r\n:1\r\n"),
        (2, "null", b"_\r\n"),
        (4, "null", b"_\r\n"),
        (2, "null", b"not RESP"),
    ] {
        assert_both(event(version, kind, reply), "any", false);
    }
    for outcome in [
        DependencyExchangeOutcome::NoResponse,
        DependencyExchangeOutcome::ClientTerminated,
    ] {
        let mut rejected = event(2, "null", b"$-1\r\n");
        rejected.outcome = outcome;
        assert_both(rejected, "any", false);
    }
    for body in [false, true] {
        for corruption in 0..4 {
            let mut rejected = event(2, "null", b"$-1\r\n");
            let capture = if body {
                &mut rejected.response
            } else {
                &mut rejected.args[0]
            };
            match corruption {
                0 => capture.truncated = true,
                1 => capture.stored_len += 1,
                2 => capture.original_len += 1,
                _ => {
                    capture.encoding = "base64";
                    capture.data = "invalid base64!".into();
                }
            }
            assert_both(rejected, "any", false);
        }
    }
    let mut warning = event(2, "null", b"$-1\r\n");
    warning.parse_warnings.push("unverified reply".into());
    assert_both(warning, "any", false);
}

#[test]
fn occurrence_counts_only_unique_matching_replies_for_the_same_key() {
    let live = scope("nil", 2);
    let recorded = scope("nil", 2);
    let first = event(2, "null", b"$-1\r\n");
    let other_value = event(2, "bulk_string", b"$4\r\nnull\r\n");
    let failed = event(2, "error", b"-ERR retry\r\n");
    let mut other_key = first.clone();
    other_key.id = uuid::Uuid::new_v4();
    other_key.args[0] = capture_body(b"done:43", 4096);
    for observation in [other_value, failed, first.clone(), first, other_key] {
        let observation = RecorderEvent::RedisExchange(observation);
        assert!(!completes(live.observe(&observation)));
        assert!(!completes(
            recorded
                .observe_recorded(&serde_json::to_value(observation).unwrap())
                .unwrap()
        ));
    }
    let final_reply = RecorderEvent::RedisExchange(event(2, "null", b"$-1\r\n"));
    assert!(completes(live.observe(&final_reply)));
    assert!(completes(
        recorded
            .observe_recorded(&serde_json::to_value(final_reply).unwrap())
            .unwrap()
    ));
}

#[test]
fn missing_historical_reply_evidence_cannot_prove_any_or_nil() {
    for field in ["response", "parse_warnings", "resp_version"] {
        let mut observation =
            serde_json::to_value(RecorderEvent::RedisExchange(event(2, "null", b"$-1\r\n")))
                .unwrap();
        observation.as_object_mut().unwrap().remove(field);
        for kind in ["any", "nil"] {
            assert!(!completes(
                scope(kind, 1).observe_recorded(&observation).unwrap()
            ));
        }
    }
}
