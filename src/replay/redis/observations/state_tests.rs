//! Variable loop counts never erase real writes or non-nil terminal observations.
use super::super::append::tests::{event, request, state_with_policy};
use super::tests::perform;
use super::*;
use serde_json::{Value, json};

fn policy(transient: bool) -> Value {
    json!({"format":"traffic-policy/v3","redis":{"keys":{
        "poll:*":{"state":{"get": if transient {json!({"transient":["nil"]})} else {json!("observe")}}}
    }}})
}

#[test]
fn nil_loop_allows_zero_or_many_calls_and_audits_only_omissions() {
    for calls in [0, 1, 8] {
        let events = [
            event(1, "GET", &[b"poll:1"], b"$-1\r\n"),
            event(2, "GET", &[b"poll:1"], b"$-1\r\n"),
            event(3, "DEL", &[b"poll:1", b"other"], b":1\r\n"),
        ];
        let (_root, mut s) = state_with_policy(&events, policy(true));
        s.prepare_observations("case").unwrap();
        for _ in 0..calls {
            assert_eq!(perform(&mut s, "GET", &[b"poll:1"]), b"$-1\r\n");
        }
        perform(&mut s, "DEL", &[b"poll:1", b"other"]);
        assert!(!s.case_is_dirty("case"));
        let report = s.snapshot();
        assert!(report.unused_case.is_empty());
        assert_eq!(
            report.allowed_state_omissions.len(),
            if calls == 0 { 2 } else { 0 }
        );
        assert_eq!(s.exchanges[0].status.is_consumed(), calls > 0);
        assert_eq!(s.exchanges[0].matched_once, calls > 0);
        assert!(
            request(&mut s, "GET", &[b"poll:1"]).is_err(),
            "cleanup closes the witnessed epoch"
        );
    }
}

#[test]
fn stable_observation_requires_a_delivery_unless_nil_is_explicitly_transient() {
    for response in [b"$-1\r\n".as_slice(), b"$4\r\ndone\r\n"] {
        let events = [
            event(1, "GET", &[b"poll:1"], response),
            event(2, "GET", &[b"poll:1"], response),
        ];
        let (_root, mut s) = state_with_policy(&events, policy(false));
        s.prepare_observations("case").unwrap();
        assert!(s.case_is_dirty("case"));
        assert_eq!(s.snapshot().unused_case.len(), 2);
        assert_eq!(perform(&mut s, "GET", &[b"poll:1"]), response);
        assert!(!s.case_is_dirty("case"));
    }
}

#[test]
fn transient_nil_prefix_can_disappear_but_terminal_value_stays_required() {
    let events = [
        event(1, "GET", &[b"poll:1"], b"$-1\r\n"),
        event(2, "GET", &[b"poll:1"], b"$-1\r\n"),
        event(3, "GET", &[b"poll:1"], b"$4\r\ndone\r\n"),
        event(4, "GET", &[b"poll:1"], b"$4\r\ndone\r\n"),
    ];
    let (_root, mut s) = state_with_policy(&events, policy(true));
    s.prepare_observations("case").unwrap();
    assert!(s.case_is_dirty("case"));
    assert_eq!(s.snapshot().unused_case.len(), 2);
    assert_eq!(perform(&mut s, "GET", &[b"poll:1"]), b"$4\r\ndone\r\n");
    assert!(!s.case_is_dirty("case"));
    assert_eq!(s.snapshot().allowed_state_omissions.len(), 2);
    assert!(!s.exchanges[0].status.is_consumed());
}

#[test]
fn nil_omission_preserves_set_and_read_back_correspondence() {
    let events = [
        event(1, "GET", &[b"poll:1"], b"$-1\r\n"),
        event(2, "SET", &[b"poll:1", b"old"], b"+OK\r\n"),
        event(3, "GET", &[b"poll:1"], b"$3\r\nold\r\n"),
    ];
    let mut p = policy(true);
    p["rules"] = json!([super::tests::read_rule(true)]);
    p["rules"][0]["match"]["key"]["prefix"] = json!("poll:");
    let (_root, mut s) = state_with_policy(&events, p);
    assert_eq!(perform(&mut s, "GET", &[b"poll:1"]), b"$-1\r\n");
    assert!(s.case_is_dirty("case"));
    perform(&mut s, "SET", &[b"poll:1", b"new"]);
    assert!(
        s.case_is_dirty("case"),
        "non-nil witness is required after actual SET"
    );
    assert_eq!(perform(&mut s, "GET", &[b"poll:1"]), b"$3\r\nnew\r\n");
    assert!(!s.case_is_dirty("case"));
}

#[test]
fn terminal_observation_waits_for_real_loop_body_writes() {
    let events = [
        event(1, "GET", &[b"poll:1"], b"$-1\r\n"),
        event(2, "SET", &[b"business:1", b"effect"], b"+OK\r\n"),
        event(3, "GET", &[b"poll:1"], b"$4\r\ndone\r\n"),
    ];
    let (_root, mut s) = state_with_policy(&events, policy(true));
    assert_eq!(perform(&mut s, "GET", &[b"poll:1"]), b"$-1\r\n");
    assert!(s.case_is_dirty("case"));
    assert_eq!(s.snapshot().unused_case[0].command, "SET");
    perform(&mut s, "SET", &[b"business:1", b"effect"]);
    assert!(s.case_is_dirty("case"));
    assert_eq!(perform(&mut s, "GET", &[b"poll:1"]), b"$4\r\ndone\r\n");
    assert!(!s.case_is_dirty("case"));
}

#[test]
fn optional_observation_failure_and_in_flight_are_real_obligations() {
    let events = [event(1, "GET", &[b"poll:1"], b"$-1\r\n")];
    let (_root, mut s) = state_with_policy(&events, policy(true));
    let pending = request(&mut s, "GET", &[b"poll:1"]).unwrap();
    assert!(s.has_case_in_flight());
    s.fail_exchange(&pending, "failed actual delivery".into());
    assert!(s.case_is_dirty("case"));
    assert!(!s.has_case_in_flight());
    assert!(s.snapshot().allowed_state_omissions.is_empty());
}

#[test]
fn invalid_complete_trace_installs_no_partial_permission() {
    for bad in [
        event(3, "GET", &[b"poll:1"], b"-ERR broken\r\n"),
        event(3, "TTL", &[b"poll:1"], b":100\r\n"),
        event(3, "APPEND", &[b"poll:1", b"x"], b":1\r\n"),
        event(3, "DEL", &[b"poll:1", b"other"], b":2\r\n"),
    ] {
        let events = [event(1, "GET", &[b"poll:1"], b"$-1\r\n"), bad];
        let (_root, mut s) = state_with_policy(&events, policy(true));
        assert!(s.prepare_observations("case").is_err());
        assert!(
            s.exchanges
                .iter()
                .all(|e| e.observation_rule.is_none() && e.optional_observation_rule.is_none())
        );
    }
}

#[test]
fn foreign_or_concurrent_transition_cannot_authorize_nil_omission() {
    let events = [
        event(1, "GET", &[b"poll:1"], b"$-1\r\n"),
        event(2, "GET", &[b"poll:1"], b"$4\r\ndone\r\n"),
    ];
    for foreign in [false, true] {
        let mut e = events.clone();
        e[1]["connection_id"] = json!(Uuid::from_u128(1));
        e[1]["request_started_at"] = json!("2019-12-31T23:59:59Z");
        let (_root, mut s) = state_with_policy(&e, policy(true));
        if foreign {
            s.exchanges[1].source = ReplaySource::Startup;
        }
        assert!(s.prepare_observations("case").is_err());
        assert!(
            s.exchanges
                .iter()
                .all(|e| e.optional_observation_rule.is_none())
        );
    }
}

fn overlapping_nil_cleanup() -> Vec<Value> {
    let mut events = vec![
        event(1, "GET", &[b"poll:1"], b"$-1\r\n"),
        event(2, "DEL", &[b"poll:1"], b":0\r\n"),
        event(3, "GET", &[b"poll:1"], b"$-1\r\n"),
        event(4, "UNLINK", &[b"poll:1"], b":0\r\n"),
    ];
    events[0]["timestamp"] = json!("2020-01-01T00:00:04Z");
    events[1]["timestamp"] = json!("2020-01-01T00:00:05Z");
    for (lane, exchange) in events.iter_mut().enumerate() {
        exchange["connection_id"] = json!(Uuid::from_u128(lane as u128));
    }
    events
}

#[test]
fn nil_state_allows_overlapping_noop_cleanup_but_keeps_every_finite_deletion() {
    for transient in [false, true] {
        for calls in [0, 1, 4] {
            if !transient && calls == 0 {
                continue;
            }
            let events = overlapping_nil_cleanup();
            let (_root, mut s) = state_with_policy(&events, policy(transient));
            s.prepare_observations("case").unwrap();
            for _ in 0..calls {
                assert_eq!(perform(&mut s, "GET", &[b"poll:1"]), b"$-1\r\n");
            }
            assert!(s.case_is_dirty("case"), "cleanup remains required");
            perform(&mut s, "DEL", &[b"poll:1"]);
            for _ in 0..calls {
                assert_eq!(perform(&mut s, "GET", &[b"poll:1"]), b"$-1\r\n");
            }
            perform(&mut s, "UNLINK", &[b"poll:1"]);
            assert!(!s.case_is_dirty("case"));
            assert!(s.exchanges[1].status.is_consumed());
            assert!(s.exchanges[3].status.is_consumed());
            assert_eq!(s.exchanges[0].status.is_consumed(), calls > 0);
            assert_eq!(s.exchanges[2].status.is_consumed(), calls > 0);
            assert!(request(&mut s, "GET", &[b"poll:1"]).is_err());
        }
    }
}

#[test]
fn nil_cleanup_proof_retains_all_accesses_before_a_terminal_value() {
    for long_access in [0, 1] {
        let mut events = overlapping_nil_cleanup();
        events[0]["timestamp"] = events[0]["request_started_at"].clone();
        events[1]["timestamp"] = events[1]["request_started_at"].clone();
        events[long_access]["timestamp"] = json!("2020-01-01T00:00:06Z");
        events[3] = event(4, "GET", &[b"poll:1"], b"$4\r\ndone\r\n");
        events[3]["connection_id"] = json!(Uuid::from_u128(3));
        let (_root, mut s) = state_with_policy(&events, policy(true));
        assert!(s.prepare_observations("case").is_err());
        assert!(s.observations.profiles.is_empty());
    }
}

#[test]
fn concurrent_nil_cleanup_rejects_unknown_clocks_and_contradictory_removal() {
    let mut unknown = overlapping_nil_cleanup();
    unknown[1]["timestamp"] = Value::Null;
    unknown[1]["request_started_at"] = Value::Null;
    let mut removal = overlapping_nil_cleanup();
    removal[1]["response"] = event(2, "DEL", &[b"poll:1"], b":1\r\n")["response"].clone();
    let mut real_removal = overlapping_nil_cleanup();
    real_removal[0]["response"] =
        event(1, "GET", &[b"poll:1"], b"$4\r\ndone\r\n")["response"].clone();
    real_removal[1]["response"] = event(2, "DEL", &[b"poll:1"], b":1\r\n")["response"].clone();
    for events in [unknown, removal, real_removal] {
        let (_root, mut s) = state_with_policy(&events, policy(true));
        assert!(s.prepare_observations("case").is_err());
        assert!(s.observations.profiles.is_empty());
        assert!(
            s.exchanges
                .iter()
                .all(|e| e.optional_observation_rule.is_none())
        );
    }
}
