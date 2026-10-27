//! Refresh count changes preserve state, finite boundaries and genuine deliveries.
use super::*;
use crate::replay::redis::append::tests::{event, request, rule as append_rule, state_with_policy};
use serde_json::json;

#[path = "recorded_tests.rs"]
mod recorded_tests;
#[path = "tests/source.rs"]
mod source_tests;
#[path = "tcp_tests.rs"]
mod tcp_tests;

fn document(enabled: bool) -> Value {
    let mut value = json!({"format":"traffic-policy/v2","json":{"fields":{
        "/last_activity_at":{"kind":"time","formats":["rfc3339"]},
        "/started_at":{"kind":"time","formats":["rfc3339"]}
    }}, "rules":[append_rule()]});
    if enabled {
        value["redis"] = json!({"keys":{"activity:*":{"activity_refresh":{"fields":["/last_activity_at"]},
            "proof":{"source":"session.py:touch","fact":"Every owned activity lifetime reads its latest SET, changes only last_activity_at and writes the same positive TTL; event flushes change refresh counts"}}}});
    }
    value
}

fn object(start: &str, last: &str) -> Vec<u8> {
    serde_json::to_vec(
        &json!({"subtask_id":7,"user_id":3,"username":"synthetic-user",
        "started_at":start,"last_activity_at":last}),
    )
    .unwrap()
}

fn events() -> Vec<Value> {
    let first = object("2020-01-01T00:00:01Z", "2020-01-01T00:00:01Z");
    let second = object("2020-01-01T00:00:01Z", "2020-01-01T00:00:04Z");
    let third = object("2020-01-01T00:00:01Z", "2020-01-01T00:00:07Z");
    vec![
        event(
            1,
            "SET",
            &[b"activity:1", &first, b"EX", b"3600"],
            b"+OK\r\n",
        ),
        event(2, "APPEND", &[b"content:1", b"ab"], b":2\r\n"),
        event(3, "GET", &[b"activity:1"], &value::bulk(&first)),
        event(
            4,
            "SET",
            &[b"activity:1", &second, b"EX", b"3600"],
            b"+OK\r\n",
        ),
        event(5, "APPEND", &[b"content:1", b"cd"], b":4\r\n"),
        event(6, "GET", &[b"activity:1"], &value::bulk(&second)),
        event(
            7,
            "SET",
            &[b"activity:1", &third, b"EX", b"3600"],
            b"+OK\r\n",
        ),
        event(8, "DEL", &[b"activity:1"], b":1\r\n"),
        event(9, "GET", &[b"content:1"], b"$4\r\nabcd\r\n"),
    ]
}

fn fixture(enabled: bool) -> (tempfile::TempDir, RedisReplayState) {
    state_with_policy(&events(), document(enabled))
}

fn perform(state: &mut RedisReplayState, command: &str, args: &[&[u8]]) -> Vec<u8> {
    let matched = request(state, command, args).unwrap();
    let response = matched.response.clone();
    state.complete_exchange(&matched);
    response
}

fn create(state: &mut RedisReplayState) -> Vec<u8> {
    let now = chrono::Utc::now().to_rfc3339();
    let value = object(&now, &now);
    assert_eq!(
        perform(state, "SET", &[b"activity:1", &value, b"EX", b"3600"]),
        b"+OK\r\n"
    );
    value
}

fn touch(state: &mut RedisReplayState, previous: &[u8]) -> Vec<u8> {
    assert_eq!(
        perform(state, "GET", &[b"activity:1"]),
        value::bulk(previous)
    );
    let mut value: Value = serde_json::from_slice(previous).unwrap();
    value["last_activity_at"] = json!(chrono::Utc::now().to_rfc3339());
    let next = serde_json::to_vec(&value).unwrap();
    assert_eq!(
        perform(state, "SET", &[b"activity:1", &next, b"EX", b"3600"]),
        b"+OK\r\n"
    );
    next
}

#[test]
fn activity_refresh_supports_exact_fewer_and_more_flush_rounds_without_changing_bytes() {
    for (enabled, chunks) in [
        (true, vec![b"abcd".as_slice()]),
        (true, vec![b"a".as_slice(), b"b", b"c", b"d"]),
        (true, vec![b"ab".as_slice(), b"cd"]),
    ] {
        let (_root, mut state) = fixture(enabled);
        let mut current = create(&mut state);
        for chunk in chunks {
            perform(&mut state, "APPEND", &[b"content:1", chunk]);
            current = touch(&mut state, &current);
        }
        perform(&mut state, "DEL", &[b"activity:1"]);
        assert!(request(&mut state, "GET", &[b"activity:1"]).is_err());
        assert_eq!(
            perform(&mut state, "GET", &[b"content:1"]),
            b"$4\r\nabcd\r\n"
        );
        assert!(
            state.snapshot().unused_case.is_empty(),
            "{:?}",
            state.snapshot().unused_case
        );
        assert!(!state.has_case_in_flight());
        if enabled {
            let report = serde_json::to_value(state.snapshot()).unwrap();
            assert!(
                report["activity_refreshes"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|a| a["command"] == "GET")
            );
            assert!(!report.to_string().contains("synthetic-user"));
        }
    }
}

#[test]
fn activity_refresh_is_opt_in_and_preserves_unused_read_and_write_obligations() {
    let (_root, mut ordinary) = fixture(false);
    let mut current = create(&mut ordinary);
    perform(&mut ordinary, "APPEND", &[b"content:1", b"abcd"]);
    perform(&mut ordinary, "GET", &[b"activity:1"]);
    let mut next: Value = serde_json::from_slice(&current).unwrap();
    next["last_activity_at"] = json!(chrono::Utc::now().to_rfc3339());
    current = serde_json::to_vec(&next).unwrap();
    perform(
        &mut ordinary,
        "SET",
        &[b"activity:1", &current, b"EX", b"3600"],
    );
    assert!(request(&mut ordinary, "DEL", &[b"activity:1"]).is_err());
    let (_root, mut state) = fixture(true);
    create(&mut state);
    perform(&mut state, "APPEND", &[b"content:1", b"abcd"]);
    assert_eq!(state.exchanges[2].status, ReplayExchangeStatus::Available);
    let read = request(&mut state, "GET", &[b"activity:1"]).unwrap();
    assert_eq!(state.exchanges[2].status, ReplayExchangeStatus::Available);
    assert!(state.has_case_in_flight());
    state.complete_exchange(&read);
    assert_eq!(state.exchanges[2].status, ReplayExchangeStatus::Consumed);
    assert_eq!(state.exchanges[5].status, ReplayExchangeStatus::Consumed);
    assert_eq!(state.exchanges[3].status, ReplayExchangeStatus::Available);
    assert!(
        state
            .snapshot()
            .unused_case
            .iter()
            .any(|e| e.command == "SET")
    );
}

#[test]
fn activity_refresh_rejects_wrong_business_fields_timestamp_ttl_and_missing_get() {
    for scenario in [
        "before-get",
        "field",
        "field-set",
        "timestamp",
        "ttl",
        "options",
    ] {
        let (_root, mut state) = fixture(true);
        let current = create(&mut state);
        if scenario != "before-get" {
            perform(&mut state, "GET", &[b"activity:1"]);
        }
        let mut next: Value = serde_json::from_slice(&current).unwrap();
        match scenario {
            "field" => next["user_id"] = json!(99),
            "field-set" => {
                next.as_object_mut().unwrap().remove("username");
            }
            "timestamp" => next["last_activity_at"] = json!("2020-01-01T00:00:00Z"),
            _ => next["last_activity_at"] = json!(chrono::Utc::now().to_rfc3339()),
        }
        let raw = serde_json::to_vec(&next).unwrap();
        let ttl = if scenario == "ttl" {
            b"3601".as_slice()
        } else {
            b"3600"
        };
        let mut args = vec![b"activity:1".as_slice(), &raw, b"EX", ttl];
        if scenario == "options" {
            args.push(b"NX");
        }
        assert!(request(&mut state, "SET", &args).is_err(), "{scenario}");
        assert_eq!(state.exchanges[3].status, ReplayExchangeStatus::Available);
        assert_eq!(
            state.activity_refresh.profiles[0]
                .current
                .as_ref()
                .unwrap()
                .bytes,
            current
        );
    }
}

#[test]
fn activity_refresh_cannot_hide_failed_delivery_or_cross_pending_deletion_and_ttl() {
    for failed_write in [false, true] {
        let (_root, mut state) = fixture(true);
        let current = create(&mut state);
        let read = request(&mut state, "GET", &[b"activity:1"]).unwrap();
        assert!(request(&mut state, "DEL", &[b"activity:1"]).is_err());
        let failed = if failed_write {
            state.complete_exchange(&read);
            let mut next: Value = serde_json::from_slice(&current).unwrap();
            next["last_activity_at"] = json!(chrono::Utc::now().to_rfc3339());
            request(
                &mut state,
                "SET",
                &[
                    b"activity:1",
                    &serde_json::to_vec(&next).unwrap(),
                    b"EX",
                    b"3600",
                ],
            )
            .unwrap()
        } else {
            read
        };
        state.fail_exchange(&failed, "synthetic transport failure".into());
        assert!(request(&mut state, "GET", &[b"activity:1"]).is_err());
        assert!(!state.snapshot().unsafe_events.is_empty());
        assert!(!state.has_case_in_flight());
    }
    let (_root, mut state) = fixture(true);
    create(&mut state);
    state.activity_refresh.profiles[0]
        .current
        .as_mut()
        .unwrap()
        .established_at = tokio::time::Instant::now() - std::time::Duration::from_secs(3601);
    assert!(request(&mut state, "GET", &[b"activity:1"]).is_err());
}

#[test]
fn activity_refresh_does_not_borrow_observations_from_another_or_unqualified_lifetime() {
    let mut source = events();
    let second = object("2020-01-01T00:00:10Z", "2020-01-01T00:00:10Z");
    source.extend([
        event(
            10,
            "SET",
            &[b"activity:1", &second, b"EX", b"3600"],
            b"+OK\r\n",
        ),
        event(11, "GET", &[b"activity:1"], &value::bulk(&second)),
        event(12, "DEL", &[b"activity:1"], b":1\r\n"),
    ]);
    let (_root, mut state) = state_with_policy(&source, document(true));
    let first = create(&mut state);
    perform(&mut state, "APPEND", &[b"content:1", b"abcd"]);
    touch(&mut state, &first);
    perform(&mut state, "DEL", &[b"activity:1"]);
    assert!(request(&mut state, "GET", &[b"activity:1"]).is_err());
    perform(&mut state, "GET", &[b"content:1"]);
    let now = chrono::Utc::now().to_rfc3339();
    let next = object(&now, &now);
    perform(&mut state, "SET", &[b"activity:1", &next, b"EX", b"3600"]);
    perform(&mut state, "GET", &[b"activity:1"]);
    assert!(request(&mut state, "GET", &[b"activity:1"]).is_err());
    assert!(request(&mut state, "SET", &[b"activity:1", &next, b"EX", b"3600"]).is_err());
    perform(&mut state, "DEL", &[b"activity:1"]);
    assert!(state.snapshot().unused_case.is_empty());
}
