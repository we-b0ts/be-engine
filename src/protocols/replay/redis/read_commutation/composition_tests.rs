//! Nil ordering composes with existing read-back and ordinary final cleanup.
use super::*;

fn read_back(json: bool) -> Value {
    let mut value = json!({"id":"block","match":{"api":"POST /tasks",
        "resource":{"protocol":"redis","endpoint":"redis.test:6379","database":0},
        "operation":"SET","key":{"kind":"numeric","prefix":"cancel:"}},
        "effect":{"kind":"identity","value_type":"string",
            "references":[{"resource":{"protocol":"redis","endpoint":"redis.test:6379","database":0}}],
            "capture":{"kind":"redis_argument","index":1},
            "read_back":[{"operation":"GET","write_operation":"SET","argument_index":1,"state_epochs":true}]},
        "proof":{"source":"session.py:1","fact":"Source reads back its generated identity; nil has no payload to replace"}});
    if json {
        value["effect"]["capture"]["json_pointer"] = json!("/id");
        value["effect"]["read_back"][0]["json_pointers"] = json!(["/id"]);
        value["effect"]["read_back"][0]["state_epochs"] = json!(false);
    }
    value
}

#[test]
fn nil_read_back_commutes_and_multi_key_cleanup_keeps_its_response_and_order() {
    for json in [false, true] {
        let events = [
            event(1, "GET", &[b"content:1"], b"$1\r\nx\r\n"),
            event(2, "GET", &[b"cancel:1"], b"$-1\r\n"),
            event(3, "DEL", &[b"content:1", b"cancel:1", b"text:1"], b":2\r\n"),
        ];
        let (_root, mut state) = state(&events, vec![rule(), read_back(json)]);
        let nil = request(&mut state, "GET", &[b"cancel:1"]).unwrap();
        assert_eq!(nil.index, 1);
        assert_eq!(nil.response, b"$-1\r\n");
        assert_eq!(nil.rule_ids, ["poll"]);
        assert!(nil.read_back.is_none());
        state.complete_exchange(&nil);
        assert_eq!(state.snapshot().unused_case.len(), 2);
        assert!(request(&mut state, "GET", &[b"cancel:1"]).is_err());
        let cleanup = [b"content:1".as_slice(), b"cancel:1", b"text:1"];
        assert!(request(&mut state, "DEL", &cleanup).is_err());
        let content = request(&mut state, "GET", &[b"content:1"]).unwrap();
        state.complete_exchange(&content);
        assert!(request(&mut state, "DEL", &[b"content:1", b"cancel:1"]).is_err());
        let cleanup = request(&mut state, "DEL", &cleanup).unwrap();
        assert_eq!(cleanup.response, b":2\r\n");
        assert!(
            state.exchanges[cleanup.index]
                .read_commutation_rule
                .is_none()
        );
        state.complete_exchange(&cleanup);
        assert!(state.snapshot().unused_case.is_empty());
    }
}

#[test]
fn read_back_does_not_authorize_commutation_of_non_nil_or_written_keys() {
    for invalid in [
        event(2, "GET", &[b"cancel:1"], b"$1\r\nx\r\n"),
        event(2, "SET", &[b"cancel:1", b"x"], b"+OK\r\n"),
    ] {
        let events = [event(1, "GET", &[b"cancel:1"], b"$-1\r\n"), invalid];
        let (_root, mut state) = state(&events, vec![rule(), read_back(false)]);
        assert!(state.prepare_read_commutation("case").is_err());
        assert!(
            state
                .exchanges
                .iter()
                .all(|e| e.read_commutation_rule.is_none())
        );
    }
}

#[test]
fn multi_key_cleanup_requires_prior_nil_and_consistent_distinct_key_counts() {
    for (sequence, args, response) in [
        (
            3,
            vec![b"cancel:1".as_slice(), b"other"],
            b":2\r\n".as_slice(),
        ),
        (
            3,
            vec![b"cancel:1".as_slice(), b"other", b"other"],
            b":2\r\n",
        ),
        (3, vec![b"cancel:1".as_slice(), b"other"], b":-1\r\n"),
        (3, vec![b"cancel:1".as_slice(), b"other"], b"+OK\r\n"),
        (1, vec![b"cancel:1".as_slice(), b"other"], b":1\r\n"),
    ] {
        let events = [
            event(2, "GET", &[b"cancel:1"], b"$-1\r\n"),
            event(sequence, "DEL", &args, response),
        ];
        let (_root, mut state) = state(&events, vec![rule()]);
        assert!(state.prepare_read_commutation("case").is_err());
        assert!(
            state
                .exchanges
                .iter()
                .all(|e| e.read_commutation_rule.is_none())
        );
    }
}

#[test]
fn cross_connection_cleanup_requires_complete_non_overlapping_source_clocks() {
    for (read_end, cleanup_start, valid) in [
        (
            Some("2020-01-01T00:00:02Z"),
            Some("2020-01-01T00:00:03Z"),
            true,
        ),
        (
            Some("2020-01-01T00:00:04Z"),
            Some("2020-01-01T00:00:03Z"),
            false,
        ),
        (None, Some("2020-01-01T00:00:03Z"), false),
    ] {
        let mut read = event(1, "GET", &[b"cancel:1"], b"$-1\r\n");
        read["timestamp"] = json!(read_end);
        let mut cleanup = event(2, "DEL", &[b"other", b"cancel:1"], b":1\r\n");
        cleanup["connection_id"] = json!(Uuid::from_u128(1));
        cleanup["request_started_at"] = json!(cleanup_start);
        let (_root, mut state) = state(&[read, cleanup], vec![rule()]);
        assert_eq!(state.prepare_read_commutation("case").is_ok(), valid);
    }
}
