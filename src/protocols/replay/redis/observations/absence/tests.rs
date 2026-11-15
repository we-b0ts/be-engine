use super::*;
use crate::protocols::replay::redis::append::tests::{event, request, state};
use serde_json::{Value, json};

fn rule() -> Value {
    json!({"id":"cancel-state","match":{"api":"POST /tasks",
        "resource":{"protocol":"redis","endpoint":"redis.test:6379","database":0},
        "operation":"GET","key":{"kind":"affix","prefix":"cancel:"}},
        "effect":{"kind":"redis_read_observation"},
        "proof":{"source":"cancel.py:10-30","fact":"An independent poll reads the absent flag between register and unregister deletion boundaries"}})
}

fn events() -> Vec<Value> {
    vec![
        event(1, "DEL", &[b"cancel:1"], b":1\r\n"),
        event(2, "GET", &[b"cancel:1"], b"$-1\r\n"),
        event(3, "GET", &[b"cancel:1"], b"$-1\r\n"),
        event(4, "DEL", &[b"cancel:1"], b":0\r\n"),
    ]
}

fn perform(state: &mut RedisReplayState, command: &str) -> Vec<u8> {
    let matched = request(state, command, &[b"cancel:1"]).unwrap();
    if matched.observation.is_some() {
        assert_eq!(
            matched.rule_ids,
            ["cancel-state"],
            "delivered observations must count toward the native rule's fresh Replay obligation"
        );
    }
    let response = matched.response.clone();
    state.complete_exchange(&matched);
    response
}

#[test]
fn absent_read_repeats_and_coalesces_only_inside_delivered_deletion_boundaries() {
    for target_reads in [1, 6] {
        let (_root, mut state) = state(&events(), vec![rule()]);
        assert_eq!(perform(&mut state, "DEL"), b":1\r\n");
        for _ in 0..target_reads {
            assert_eq!(perform(&mut state, "GET"), b"$-1\r\n");
        }
        assert_eq!(perform(&mut state, "DEL"), b":0\r\n");
        assert!(state.snapshot().unused_case.is_empty());
        let audits = state.observations.reports();
        assert_eq!(audits.len(), target_reads);
        assert_eq!(
            audits
                .iter()
                .map(|audit| audit.covered_source_observations)
                .sum::<usize>(),
            2
        );
        assert!(audits.iter().all(|audit| audit.kind == Kind::AbsentRead
            && audit.source_epoch_mutation.as_ref().unwrap().sequence == 1));
        assert!(request(&mut state, "GET", &[b"cancel:1"]).is_err());
    }
}

#[test]
fn absent_read_cannot_borrow_an_unstarted_or_in_flight_initial_deletion() {
    let (_root, mut state) = state(&events(), vec![rule()]);
    assert!(request(&mut state, "GET", &[b"cancel:1"]).is_err());
    let deletion = request(&mut state, "DEL", &[b"cancel:1"]).unwrap();
    assert!(request(&mut state, "GET", &[b"cancel:1"]).is_err());
    state.complete_exchange(&deletion);
    assert_eq!(perform(&mut state, "GET"), b"$-1\r\n");
}

#[test]
fn absent_read_requires_an_actual_observation_and_both_finite_mutations() {
    let (_root, mut state) = state(&events(), vec![rule()]);
    perform(&mut state, "DEL");
    assert_eq!(state.snapshot().unused_case.len(), 3);
    perform(&mut state, "GET");
    let unused = state.snapshot().unused_case;
    assert_eq!(unused.len(), 1);
    assert_eq!(unused[0].sequence, 4);
}

#[test]
fn absent_read_cannot_reuse_the_old_epoch_while_closing_deletion_is_in_flight() {
    let (_root, mut state) = state(&events(), vec![rule()]);
    perform(&mut state, "DEL");
    perform(&mut state, "GET");
    let closing = request(&mut state, "DEL", &[b"cancel:1"]).unwrap();
    assert!(request(&mut state, "GET", &[b"cancel:1"]).is_err());
    state.complete_exchange(&closing);
    assert!(request(&mut state, "GET", &[b"cancel:1"]).is_err());
}

#[test]
fn absent_read_rejects_non_nil_writers_missing_bounds_and_foreign_mutations_atomically() {
    let mut non_nil = events();
    non_nil[2] = event(3, "GET", &[b"cancel:1"], b"$4\r\ntrue\r\n");
    let mut writer = events();
    writer[2] = event(3, "SET", &[b"cancel:1", b"true"], b"+OK\r\n");
    let mut expiry = events();
    expiry[2] = event(3, "EXPIRE", &[b"cancel:1", b"300"], b":1\r\n");
    for source in [
        non_nil,
        writer,
        expiry,
        events()[1..].to_vec(),
        events()[..3].to_vec(),
    ] {
        let (_root, mut state) = state(&source, vec![rule()]);
        assert!(state.prepare_observations("case").is_err());
        assert!(
            state
                .exchanges
                .iter()
                .all(|exchange| exchange.observation_rule.is_none())
        );
    }
    let mut foreign = events();
    foreign.push(event(5, "DEL", &[b"cancel:1"], b":0\r\n"));
    let (_root, mut state) = state(&foreign, vec![rule()]);
    state.exchanges[4].source = ReplaySource::Startup;
    assert!(state.prepare_observations("case").is_err());
    assert!(state.observations.profiles.is_empty());
}

#[test]
fn absent_read_preserves_historical_reads_and_rejects_failed_delivery() {
    let mut source = events();
    source.insert(0, event(0, "GET", &[b"cancel:1"], b"$3\r\nold\r\n"));
    let (_root, mut state) = state(&source, vec![rule()]);
    assert_eq!(perform(&mut state, "GET"), b"$3\r\nold\r\n");
    assert!(request(&mut state, "GET", &[b"cancel:1"]).is_err());
    perform(&mut state, "DEL");
    let read = request(&mut state, "GET", &[b"cancel:1"]).unwrap();
    state.fail_exchange(&read, "transport failure".into());
    assert!(state.case_is_dirty("case"));
    assert!(request(&mut state, "GET", &[b"cancel:1"]).is_err());
}

fn concurrent_absent_reads() -> Vec<Value> {
    let mut source = events();
    source[1]["timestamp"] = json!("2020-01-01T00:00:03Z");
    source[2]["connection_id"] = json!(Uuid::from_u128(1));
    source[2]["request_started_at"] = json!("2020-01-01T00:00:02.500Z");
    source[2]["timestamp"] = json!("2020-01-01T00:00:03.500Z");
    source[3]["request_started_at"] = json!("2020-01-01T00:00:03.250Z");
    source
}

#[test]
fn concurrent_nil_reads_and_noop_closing_deletion_preserve_absent_state() {
    let mut source = concurrent_absent_reads();
    source.insert(0, event(0, "GET", &[b"unrelated:cache"], b"$-1\r\n"));
    let (_root, mut state) = state(&source, vec![rule()]);
    // A valid concurrent proof must not reject the Case's first unrelated call.
    let first = request(&mut state, "GET", &[b"unrelated:cache"]).unwrap();
    state.complete_exchange(&first);
    assert_eq!(perform(&mut state, "DEL"), b":1\r\n");
    for _ in 0..5 {
        assert_eq!(perform(&mut state, "GET"), b"$-1\r\n");
    }
    let closing = request(&mut state, "DEL", &[b"cancel:1"]).unwrap();
    assert!(request(&mut state, "GET", &[b"cancel:1"]).is_err());
    state.complete_exchange(&closing);
    assert!(request(&mut state, "GET", &[b"cancel:1"]).is_err());
    assert!(state.snapshot().unused_case.is_empty());
}

#[test]
fn concurrent_absent_proof_still_rejects_unknown_clocks_real_removal_and_lane_reversal() {
    let mut unknown = concurrent_absent_reads();
    unknown[2]["request_started_at"] = Value::Null;
    unknown[2]["timestamp"] = Value::Null;
    let mut removal = concurrent_absent_reads();
    removal[0]["timestamp"] = json!("2020-01-01T00:00:02.750Z");
    let mut reversal = concurrent_absent_reads();
    reversal[2]["connection_id"] = json!(Uuid::nil());
    reversal[2]["sequence"] = json!(1);
    let mut non_nil = concurrent_absent_reads();
    non_nil[2]["response"] = event(3, "GET", &[b"cancel:1"], b"$1\r\nx\r\n")["response"].clone();
    for (kind, source) in [
        ("unknown clocks", unknown),
        ("initial removal overlap", removal),
        ("lane reversal", reversal),
        ("non-nil observation", non_nil),
    ] {
        let (_root, mut state) = state(&source, vec![rule()]);
        assert!(state.prepare_observations("case").is_err(), "{kind}");
        assert!(state.observations.profiles.is_empty());
        assert!(state.exchanges.iter().all(|e| e.observation_rule.is_none()));
    }
}

#[test]
fn conflicting_boundary_reports_rule_key_and_both_source_access_clocks() {
    let mut source = concurrent_absent_reads();
    source[0]["timestamp"] = json!("2020-01-01T00:00:02.750Z");
    let (_root, mut state) = state(&source, vec![rule()]);
    let error = format!("{:#}", state.prepare_observations("case").unwrap_err());
    for location in [
        "rule=cancel-state",
        "key_fingerprint=",
        "before connection=",
        "after connection=",
        "sequence=1",
        "sequence=3",
        "start=",
        "end=",
    ] {
        assert!(error.contains(location), "missing {location}: {error}");
    }
    assert!(!error.contains("cancel:1"));
}
